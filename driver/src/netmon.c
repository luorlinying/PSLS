/*
 * netmon.c — WFP 网络过滤驱动 (R0 实时网络拦截) — v4 重写
 *
 * [拦截策略 — 与 v3 一致]
 *   FWPM_LAYER_ALE_AUTH_CONNECT_V4 (IPv4 出站连接授权层):
 *   1. 进程禁止联网: BLOCK_PROCESS IOCTL 标记的 PID
 *   2. 可疑端口: 勒索/C2 常用端口 (4444/6667/...)
 *
 * [v3 缺陷 — v4 修复]
 *   N1. 独立全局 g_BlockedCount / g_PslsPid 已废除
 *       (统一 g_Driver.BlockedCount / Protect_GetTargetPid)
 *   N2. classify 未检查 FWPS_RIGHT_ACTION_WRITE: WFP 契约要求,
 *       若该标志已被更高权重过滤器清除, 必须直接返回不得改写
 *       actionType — 违反时行为未定义 (Verifier 可捕获)
 *   N3. 引擎对象使用普通会话: 驱动卸载后若 Fwpm*DeleteByKey
 *       失败 (BFE 停止等), 残留的 filter 引用已卸载的内核
 *       callout → 下一次连接分类即蓝屏。v4 改用
 *       FWPM_SESSION_FLAG_DYNAMIC 动态会话: 引擎句柄一关,
 *       本驱动添加的全部对象自动消失, 结构性杜绝残留
 *   N4. FwpsCalloutRegister0 的 notifyFn 不可为 NULL — 补齐
 *       平凡通知函数
 *   N5. commit 失败路径未 abort 事务; 各失败路径残留
 *       g_CalloutIdV4 未清零
 *
 * [v4 纪律]
 *   N6. 注销顺序固定: 事务删除引擎对象 → 关引擎 →
 *       FwpsCalloutUnregisterById0 (阻塞排空在途 classify)
 *   N7. g_NetPidLock 仅在 NetMon_Initialize 顶部初始化一次
 *       (先于任何可能失败的 Fwpm 调用, 保证 BLOCK/ALLOW
 *       IOCTL 在初始化失败后仍安全)
 *   N8. classify 可在 DISPATCH_LEVEL 运行, 全程只用
 *       自旋锁 + 事件池 (任意 IRQL 安全)
 */

#define INITGUID   /* 实例化 FWPM_LAYER_* 等 DEFINE_GUID 常量 */
#include <ntddk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#define NDIS630
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ip2string.h>
#include "psls_shared.h"

#define PSLS_NETMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-NetMon] " fmt "\n", ##__VA_ARGS__)

/* 外部 */
extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
extern ULONG Protect_GetTargetPid(VOID);
/* g_Driver 已由 psls_shared.h 提供 extern 声明 */

/* 前置声明 (alloc_text pragma 要求函数先于 pragma 声明) */
NTSTATUS NetMon_Initialize(VOID);
VOID     NetMon_Cleanup(VOID);

#pragma alloc_text(PAGE, NetMon_Initialize)
#pragma alloc_text(PAGE, NetMon_Cleanup)

/* ---- 全局状态 ---- */
static HANDLE g_EngineHandle   = NULL;
static UINT32 g_CalloutIdV4    = 0;

/* ---- 拦截规则 ---- */

/* 已知 C2 黑名单端口 (勒索软件常用) */
static const UINT16 g_BlockPorts[] = {
    4444,   /* Metasploit default */
    1337,   /* 常见 C2 */
    3137,   /* 常见 C2 */
    6667,   /* IRC C2 */
    9999,   /* 常见 C2 */
    12345,  /* 常见 C2 */
    0
};

/* 禁止联网的 PID 列表 (沙箱进程 / 已标记恶意进程) */
#define MAX_BLOCKED_NET_PIDS  128
static ULONG       g_BlockedNetPids[MAX_BLOCKED_NET_PIDS];
static KSPIN_LOCK  g_NetPidLock;

static BOOLEAN IsNetBlockedPid(_In_ ULONG pid)
{
    KIRQL   old_irql;
    BOOLEAN found = FALSE;
    ULONG   i;

    KeAcquireSpinLock(&g_NetPidLock, &old_irql);
    for (i = 0; i < MAX_BLOCKED_NET_PIDS; i++) {
        if (g_BlockedNetPids[i] == pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_NetPidLock, old_irql);
    return found;
}

/* ---- classify 辅助 ---- */

/* N2: 仅在持有 FWPS_RIGHT_ACTION_WRITE 时才允许写 actionType */
static BOOLEAN ClassifyWritable(_In_ const FWPS_CLASSIFY_OUT0 *classifyOut)
{
    return (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) ? TRUE : FALSE;
}

static VOID SetPermit(_Inout_ FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

static VOID SetBlock(_Inout_ FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->actionType  = FWP_ACTION_BLOCK;
    classifyOut->rights     &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags      |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

static VOID PostNetBlockEvent(_In_ ULONG pid, _In_ UINT32 remote_ip,
                              _In_ UINT16 remote_port, _In_ UINT8 protocol,
                              _In_ UINT8 reason)
{
    PSLS_NET_BLOCK_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.pid         = pid;
    payload.remote_ip   = remote_ip;
    payload.remote_port = remote_port;
    payload.protocol    = protocol;
    payload.direction   = 1;   /* 出站 */
    payload.reason      = reason;

    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_NET_BLOCKED);
    InterlockedIncrement(&g_Driver.BlockedCount);
}

/* ---- 平凡通知回调 — N4 ---- */
static NTSTATUS NTAPI NetCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ---- ALE Connect Callout (IPv4 出站) ---- */
static VOID NTAPI NetCalloutV4(
    _In_ const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void*                          layerData,
    _In_ const FWPS_FILTER0*                   filter,
    _In_ UINT64                                flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0*                classifyOut)
{
    UINT32 remote_ip;
    UINT16 remote_port;
    UINT8  protocol;
    ULONG  pid;
    ULONG  i;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* N2: 决策权已被更高权重过滤器持有 — 不得改写 */
    if (!ClassifyWritable(classifyOut)) {
        return;
    }

    if (g_Driver.Config.enable_net_filter == 0) {
        SetPermit(classifyOut);
        return;
    }

    /* 提取进程 PID */
    pid = 0;
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        pid = (ULONG)inMetaValues->processId;
    }
    if (pid == 0 || pid == 4) {
        SetPermit(classifyOut);
        return;
    }

    /* PSLS 自身放行 — N1 */
    if (pid == Protect_GetTargetPid()) {
        SetPermit(classifyOut);
        return;
    }

    /* 提取远程地址/端口/协议 (incomingValue 按 field id 直接索引) */
    remote_ip   = 0;
    remote_port = 0;
    protocol    = 0;
    if (inFixedValues->valueCount > FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL) {
        remote_ip = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remote_port = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }

    /* 1. 进程禁止联网 */
    if (IsNetBlockedPid(pid)) {
        PostNetBlockEvent(pid, remote_ip, remote_port, protocol, 3);
        SetBlock(classifyOut);
        return;
    }

    /* 2. 黑名单端口 */
    for (i = 0; g_BlockPorts[i] != 0; i++) {
        if (remote_port == g_BlockPorts[i]) {
            PostNetBlockEvent(pid, remote_ip, remote_port, protocol, 2);
            SetBlock(classifyOut);
            return;
        }
    }

    /* 默认放行 */
    SetPermit(classifyOut);
}

/* ---- 模块接口 ---- */

/* 初始化失败时的统一回滚 (引擎已开但内核 callout 已注册的场景) */
static VOID NetMon_Rollback(_In_ BOOLEAN callout_registered)
{
    if (g_EngineHandle != NULL) {
        FwpmEngineClose0(g_EngineHandle);   /* 动态会话: 对象自动清除 */
        g_EngineHandle = NULL;
    }
    if (callout_registered && g_CalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_CalloutIdV4);
        g_CalloutIdV4 = 0;                  /* N5: 路径退出即清零 */
    }
}

NTSTATUS NetMon_Initialize(VOID)
{
    FWPM_SESSION0     session;
    FWPS_CALLOUT0     callout;
    FWPM_CALLOUT0     fwpm_callout;
    FWPM_SUBLAYER0    sublayer;
    FWPM_FILTER0      fwpm_filter;
    NTSTATUS          status;

    PAGED_CODE();

    /* N7: 本地状态最先初始化 — 即使 WFP 全部失败,
     * BLOCK/ALLOW IOCTL 的 PID 表操作依然安全 */
    KeInitializeSpinLock(&g_NetPidLock);
    RtlZeroMemory(g_BlockedNetPids, sizeof(g_BlockedNetPids));

    /* 1. 打开 WFP 引擎 — N3: 动态会话, 句柄关闭即自动清除全部对象 */
    RtlZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL,
                             &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        PSLS_NETMON_LOG("FwpmEngineOpen0 failed: 0x%X", status);
        g_EngineHandle = NULL;
        return status;
    }

    /* 2. 注册内核 callout — N4: notifyFn 非空 */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = PSLS_WFP_CALLOUT_KEY_V4;
    callout.classifyFn = NetCalloutV4;
    callout.notifyFn   = NetCalloutNotify;
    callout.flags      = 0;

    status = FwpsCalloutRegister0(g_Driver.DeviceObject, &callout,
                                  &g_CalloutIdV4);
    if (!NT_SUCCESS(status)) {
        PSLS_NETMON_LOG("FwpsCalloutRegister0 failed: 0x%X", status);
        g_CalloutIdV4 = 0;
        NetMon_Rollback(FALSE);
        return status;
    }

    /* 3. 引擎事务: callout + sublayer + filter 原子添加 */
    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        PSLS_NETMON_LOG("FwpmTransactionBegin0 failed: 0x%X", status);
        NetMon_Rollback(TRUE);
        return status;
    }

    RtlZeroMemory(&fwpm_callout, sizeof(fwpm_callout));
    fwpm_callout.calloutKey             = PSLS_WFP_CALLOUT_KEY_V4;
    fwpm_callout.displayData.name       = L"PSLS Network Filter V4";
    fwpm_callout.displayData.description =
        L"PSLS WFP callout for outbound IPv4 connections";
    fwpm_callout.applicableLayer        = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(g_EngineHandle, &fwpm_callout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        PSLS_NETMON_LOG("FwpmCalloutAdd0 failed: 0x%X", status);
        goto abort_and_rollback;
    }

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey             = PSLS_WFP_SUBLAYER_KEY;
    sublayer.displayData.name        = L"PSLS Network Sublayer";
    sublayer.displayData.description = L"PSLS WFP sublayer for network filtering";
    sublayer.flags                   = 0;
    sublayer.weight                  = 0xFFFF;

    status = FwpmSubLayerAdd0(g_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        PSLS_NETMON_LOG("FwpmSubLayerAdd0 failed: 0x%X", status);
        goto abort_and_rollback;
    }

    RtlZeroMemory(&fwpm_filter, sizeof(fwpm_filter));
    fwpm_filter.filterKey             = PSLS_WFP_FILTER_KEY_V4;
    fwpm_filter.layerKey              = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    fwpm_filter.subLayerKey           = PSLS_WFP_SUBLAYER_KEY;
    fwpm_filter.displayData.name      = L"PSLS Outbound Connection Filter V4";
    fwpm_filter.displayData.description =
        L"Filter all outbound IPv4 connections for PSLS";
    fwpm_filter.action.type           = FWP_ACTION_CALLOUT_TERMINATING;
    fwpm_filter.action.calloutKey     = PSLS_WFP_CALLOUT_KEY_V4;
    fwpm_filter.weight.type           = FWP_UINT8;
    fwpm_filter.weight.uint8          = 0x0F;
    fwpm_filter.numFilterConditions   = 0;   /* 匹配所有出站 IPv4 */

    status = FwpmFilterAdd0(g_EngineHandle, &fwpm_filter, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        PSLS_NETMON_LOG("FwpmFilterAdd0 failed: 0x%X", status);
        goto abort_and_rollback;
    }

    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        PSLS_NETMON_LOG("FwpmTransactionCommit0 failed: 0x%X", status);
        goto abort_and_rollback;   /* N5: commit 失败也走 abort */
    }

    PSLS_NETMON_LOG("WFP callout registered OK (V4 layer, dynamic session)");
    return STATUS_SUCCESS;

abort_and_rollback:
    FwpmTransactionAbort0(g_EngineHandle);
    NetMon_Rollback(TRUE);
    return status;
}

VOID NetMon_Cleanup(VOID)
{
    PAGED_CODE();

    /* N6: 固定注销顺序
     * 1) 引擎侧对象删除 (动态会话下关句柄已兜底, 此处显式删一遍
     *    是为了在引擎仍可用时干净移除)
     * 2) 关闭引擎句柄 (动态会话对象全部消失)
     * 3) 注销内核 callout (阻塞排空在途 classify) */
    if (g_EngineHandle != NULL) {
        FwpmTransactionBegin0(g_EngineHandle, 0);
        FwpmFilterDeleteByKey0(g_EngineHandle, &PSLS_WFP_FILTER_KEY_V4);
        FwpmSubLayerDeleteByKey0(g_EngineHandle, &PSLS_WFP_SUBLAYER_KEY);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &PSLS_WFP_CALLOUT_KEY_V4);
        FwpmTransactionCommit0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    if (g_CalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_CalloutIdV4);
        g_CalloutIdV4 = 0;
    }

    PSLS_NETMON_LOG("WFP cleanup done");
}

/* ---- 添加/移除禁止联网的 PID (BLOCK/ALLOW IOCTL) ---- */

VOID NetMon_BlockPid(_In_ ULONG pid)
{
    KIRQL old_irql;
    ULONG i;

    KeAcquireSpinLock(&g_NetPidLock, &old_irql);
    /* 已存在则不重复添加 */
    for (i = 0; i < MAX_BLOCKED_NET_PIDS; i++) {
        if (g_BlockedNetPids[i] == pid) {
            KeReleaseSpinLock(&g_NetPidLock, old_irql);
            return;
        }
    }
    for (i = 0; i < MAX_BLOCKED_NET_PIDS; i++) {
        if (g_BlockedNetPids[i] == 0) {
            g_BlockedNetPids[i] = pid;
            break;
        }
    }
    KeReleaseSpinLock(&g_NetPidLock, old_irql);
}

VOID NetMon_UnblockPid(_In_ ULONG pid)
{
    KIRQL old_irql;
    ULONG i;

    KeAcquireSpinLock(&g_NetPidLock, &old_irql);
    for (i = 0; i < MAX_BLOCKED_NET_PIDS; i++) {
        if (g_BlockedNetPids[i] == pid) {
            g_BlockedNetPids[i] = 0;
            break;
        }
    }
    KeReleaseSpinLock(&g_NetPidLock, old_irql);
}
