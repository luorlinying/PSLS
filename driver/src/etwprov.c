/*
 * etwprov.c — PSLS 自有 ETW Provider (路线 C) — v1.0
 *
 * [定位]
 *   向 WPA / WinDbg / logman 输出 PSLS 自身的安全事件 (进程创建/句柄审计/
 *   映像加载/拦截结果), 让安全分析者在不依赖受限 TI Provider 的前提下
 *   观察内核行为。EtwRegister 注册的是普通 Provider, 无需 ELAM/PPL 证书,
 *   不受 TI 的 Secure Provider 订阅限制。
 *
 * [纪律]
 *   E1. EtwRegister / EtwUnregister 仅 PASSIVE_LEVEL 调用
 *       (DriverEntry / DriverUnload), 与 EventPool 生命周期对齐。
 *   E2. PslsEtw_Emit 可被任意 IRQL 调用 (EventPool_Post 汇聚点, 最高
 *       DISPATCH_LEVEL): EtwWriteEx 支持 HIGH_LEVEL; 数据描述符引用的是
 *       调用方内存 (事件池条目 NonPaged / 回调栈), 在调用期间有效。
 *   E3. 快速短路: 未注册或 EtwProviderEnabled==FALSE 时零开销返回,
 *       无消费者时不影响事件池热路径。
 *   E4. 注册失败非致命: 仅禁用 ETW, 驱动加载与事件池不受影响。
 *
 * [事件 ID 分配]
 *   0x01 = 状态 (加载/卸载),  0x10 = 进程创建, 0x11 = 句柄审计,
 *   0x12 = 映像加载,          0x13 = 拦截结果
 */

#include <ntddk.h>
#include "psls_shared.h"

#define PSLS_ETW_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-ETW] " fmt "\n", ##__VA_ARGS__)

/* ---- PSLS ETW Provider GUID (固定, 供 logman/分析工具按 GUID 订阅) ---- */
static const GUID g_PslsEtwGuid = {
    0x4b3a7c91, 0x5e2d, 0x4f6a,
    { 0x8c, 0x1e, 0x2d, 0x9b, 0x0f, 0x3a, 0x4c, 0x7e }
};

/* ---- 事件描述符表 (索引 = PslsEtw_DescIndex 返回值) ----
 * Level: 4=INFO (常规事件), 3=WARN (拦截结果) */
#define PSLS_ETW_DESC_STATUS  0
#define PSLS_ETW_DESC_PROC    1
#define PSLS_ETW_DESC_HANDLE  2
#define PSLS_ETW_DESC_IMAGE   3
#define PSLS_ETW_DESC_BLOCK   4
#define PSLS_ETW_DESC_COUNT   5

static const EVENT_DESCRIPTOR g_PslsEtwDescs[PSLS_ETW_DESC_COUNT] = {
    { 0x01, 0, 0, 4, 0, 0, 0 },   /* 状态: 加载/卸载 */
    { 0x10, 0, 0, 4, 0, 0, 0 },   /* 进程创建 */
    { 0x11, 0, 0, 4, 0, 0, 0 },   /* 句柄审计 */
    { 0x12, 0, 0, 4, 0, 0, 0 },   /* 映像加载 */
    { 0x13, 0, 0, 3, 0, 0, 0 },   /* 拦截结果 */
};

static REGHANDLE      g_PslsEtwRegHandle = 0;
static volatile LONG  g_PslsEtwRegistered = 0;

/* ---- 事件类型 → 描述符索引; 不支持的类型返回 PSLS_ETW_DESC_COUNT ---- */
static UCHAR PslsEtw_DescIndex(_In_ UCHAR event_type)
{
    switch (event_type) {
    case PSLS_EVT_PROCESS_CREATE:  return PSLS_ETW_DESC_PROC;
    case PSLS_EVT_HANDLE_AUDIT:     return PSLS_ETW_DESC_HANDLE;
    case PSLS_EVT_IMAGE_LOAD:       return PSLS_ETW_DESC_IMAGE;
    case PSLS_EVT_BLOCK_RESULT:     return PSLS_ETW_DESC_BLOCK;
    default:                        return PSLS_ETW_DESC_COUNT;
    }
}

/* ---- 数据描述符填充 (代替 EventDataDescCreate 宏, 内核内联零依赖) ---- */
static __forceinline VOID PslsEtw_DataDesc(_Out_ PEVENT_DATA_DESCRIPTOR d,
                                           _In_opt_ PVOID data, _In_ ULONG size)
{
    d->Ptr    = (ULONGLONG)(ULONG_PTR)data;
    d->Size   = size;
    d->Reserved = 0;
}

/* ---- 单一出口发射 (任意 IRQL, 含 E3 快速短路) ---- */
static VOID PslsEtw_EmitRaw(_In_ UCHAR desc_idx,
                            _In_ PVOID hdr, _In_ ULONG hdr_size,
                            _In_opt_ PVOID payload, _In_ ULONG payload_size)
{
    EVENT_DATA_DESCRIPTOR data[2];
    ULONG data_count = 0;

    if (!g_PslsEtwRegistered) {
        return;   /* E3: 未注册零开销 */
    }
    if (!EtwProviderEnabled(g_PslsEtwRegHandle, 0, 0)) {
        return;   /* E3: 无消费者（level=0/keyword=0 表示任意） */
    }

    if (hdr != NULL && hdr_size > 0) {
        PslsEtw_DataDesc(&data[data_count++], hdr, hdr_size);
    }
    if (payload != NULL && payload_size > 0) {
        PslsEtw_DataDesc(&data[data_count++], payload, payload_size);
    }

    EtwWriteEx(g_PslsEtwRegHandle,
               &g_PslsEtwDescs[desc_idx],
               0,                        /* Filter */
               EVENT_WRITE_FLAG_NO_FAULTING,  /* 任意 IRQL 禁缺页 */
               NULL, NULL,               /* ActivityId / RelatedActivityId */
               data_count, data);
}

/* ---- 状态事件 (加载/卸载) ---- */
static VOID PslsEtw_EmitStatus(_In_ UCHAR loaded)
{
    struct _PSLS_ETW_STATUS {
        uint32_t status;
        uint32_t version;
    } st;

    st.status  = (loaded != 0) ? 1 : 0;
    st.version = (PSLS_DRIVER_VERSION_MAJOR << 16) |
                 (PSLS_DRIVER_VERSION_MINOR << 8) |
                 PSLS_DRIVER_VERSION_PATCH;
    PslsEtw_EmitRaw(PSLS_ETW_DESC_STATUS, NULL, 0, &st, sizeof(st));
}

/* ---- 事件恢复 (EventPool_Post 汇聚点调用, 任意 IRQL) ---- */
VOID PslsEtw_Emit(_In_ UCHAR event_type,
                  _In_ PSLS_EVENT_HEADER *hdr,
                  _In_opt_ PVOID payload, _In_ ULONG payload_size)
{
    UCHAR desc_idx = PslsEtw_DescIndex(event_type);

    if (desc_idx == PSLS_ETW_DESC_COUNT) {
        return;   /* 非 ETW 关注的类型不发射 */
    }
    PslsEtw_EmitRaw(desc_idx, hdr, sizeof(PSLS_EVENT_HEADER),
                    payload, payload_size);
}

/* ---- 驱动级接入 (psls_driver.c DriverEntry/DriverUnload 调用) ---- */
NTSTATUS PslsEtw_Initialize(VOID)
{
    NTSTATUS status;

    if (g_PslsEtwRegistered) {
        return STATUS_SUCCESS;
    }

    status = EtwRegister((LPCGUID)&g_PslsEtwGuid, NULL, NULL,
                         &g_PslsEtwRegHandle);
    if (!NT_SUCCESS(status)) {
        PSLS_ETW_LOG("EtwRegister failed: 0x%X (ETW disabled)", status);
        g_PslsEtwRegHandle = 0;
        return status;
    }

    g_PslsEtwRegistered = 1;
    PslsEtw_EmitStatus(1);
    PSLS_ETW_LOG("provider registered, GUID=%08X-%04X-%04X",
                 g_PslsEtwGuid.Data1, g_PslsEtwGuid.Data2,
                 g_PslsEtwGuid.Data3);
    return STATUS_SUCCESS;
}

VOID PslsEtw_Cleanup(VOID)
{
    if (!g_PslsEtwRegistered) {
        return;
    }

    PslsEtw_EmitStatus(0);
    EtwUnregister(g_PslsEtwRegHandle);
    g_PslsEtwRegHandle = 0;
    g_PslsEtwRegistered = 0;
    PSLS_ETW_LOG("provider unregistered");
}