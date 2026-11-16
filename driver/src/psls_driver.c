/*
 * psls_driver.c — PSLS 内核驱动主入口 (v4 全量重写)
 *
 * [重写目标 — 消除历史蓝屏根源, 建立统一纪律]
 *   D1. 所有自旋锁/池状态仅在 DriverEntry 初始化一次
 *       (历史 Bug: EventPool_Post 内重复 KeInitializeSpinLock, 两 CPU
 *        同时进入临界区 → 链表损坏 → 0xFC 在镜像基址执行)
 *   D2. 每个 IRP 恰好完成一次, 单一出口
 *   D3. 卸载顺序固定: 先注销全部回调(注销 API 自身等待在途回调),
 *       再清事件池, 最后删符号链接/设备对象
 *   D4. 符号链接名使用模块级静态存储
 *       (历史 Bug: 悬垂栈指针 + 低资源模拟下 ExFreePoolWithTag 释放栈帧)
 *   D5. DriverEntry 成功路径末尾清除 DO_DEVICE_INITIALIZING
 *   D6. 事件池裁剪先判空 (RemoveHeadList 空表返回表头自身, 不可释放)
 *
 * [用户态 ABI] IOCTL 码/结构体布局与 psls_shared.h v1.0.0 完全一致,
 *             psls_driver_bridge.py (ctypes) 无需任何改动。
 */

#include <ntddk.h>
#include "psls_shared.h"

/* ---- 各监控模块公共接口 ---- */
NTSTATUS ProcMon_Initialize(VOID);
VOID     ProcMon_Cleanup(VOID);
NTSTATUS RegMon_Initialize(VOID);
VOID     RegMon_Cleanup(VOID);
NTSTATUS LoadMon_Initialize(VOID);
VOID     LoadMon_Cleanup(VOID);
NTSTATUS Protect_Initialize(VOID);
VOID     Protect_Cleanup(VOID);
VOID     Protect_SetTargetPid(_In_ ULONG psls_pid);
NTSTATUS FileMon_Initialize(VOID);
VOID     FileMon_Cleanup(VOID);
VOID     FileMon_SetProtectedDir(_In_opt_ PCWSTR dir_path);
VOID     FileMon_SetExemptDir(_In_opt_ PCWSTR dir_path);
VOID     FileMon_ClearProtectedDir(VOID);
VOID     FileMon_SetBootFiles(_In_ const PSLS_BOOT_FILE_ENTRY *entries,
                              _In_ ULONG count, _In_ BOOLEAN enabled);
NTSTATUS FileMon_SetShadowConfig(_In_ uint32_t enable, _In_ uint32_t generation_id,
                                 _In_opt_ PCWSTR shadow_root,
                                 _In_opt_ const PSLS_SHADOW_DIR_ENTRY *dirs,
                                 _In_ ULONG dir_count);
VOID     FileMon_GetShadowStats(_Out_ PSLS_SHADOW_STATS *out);
NTSTATUS NetMon_Initialize(VOID);
VOID     NetMon_Cleanup(VOID);
VOID     NetMon_BlockPid(_In_ ULONG pid);
VOID     NetMon_UnblockPid(_In_ ULONG pid);
NTSTATUS DiskMon_Initialize(VOID);
VOID     DiskMon_Cleanup(VOID);
VOID     DiskMon_SetEnabled(_In_ BOOLEAN enabled);
BOOLEAN  DiskMon_IsEnabled(VOID);
NTSTATUS DiskMon_SetBootRegions(_In_ const PSLS_BOOT_REGION *regions,
                                _In_ ULONG count, _In_ BOOLEAN enabled);
NTSTATUS DiskMon_DispatchIrp(_In_ PDEVICE_OBJECT DeviceObject,
                             _Inout_ PIRP Irp);
BOOLEAN  DiskMon_IsFilterDevice(_In_ PDEVICE_OBJECT DeviceObject);
NTSTATUS PslsEtw_Initialize(VOID);
VOID     PslsEtw_Cleanup(VOID);
VOID     PslsEtw_Emit(_In_ UCHAR event_type,
                      _In_ PSLS_EVENT_HEADER *hdr,
                      _In_opt_ PVOID payload, _In_ ULONG payload_size);

/* ---- 驱动全局 (各模块通过共享头 extern 引用) ---- */
PSLS_DRIVER_GLOBALS g_Driver = { 0 };

#define PSLS_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS] " fmt "\n", ##__VA_ARGS__)

/* -------------------------------------------------------------------- */
/* 事件池 — 链表 + 自旋锁                                                */
/*                                                                      */
/* 纪律: g_EventLock 仅在 DriverEntry→EventPool_Initialize 初始化一次;   */
/*       Post 可被进程/注册表/minifilter/WFP 四路回调并发调用             */
/*       (回调最高 DISPATCH_LEVEL), 全程只使用任意 IRQL 安全的 API。     */
/*       条目内存布局: [LIST_ENTRY][PSLS_EVENT_HEADER][payload]          */
/* -------------------------------------------------------------------- */

#define PSLS_EVENT_MAX_PAYLOAD  (16 * 1024)
#define PSLS_EVENT_POOL_TAG     'SLSP'

typedef struct _EVENT_ENTRY {
    LIST_ENTRY          ListEntry;  /* 条目头 (分配块起始) */
    PSLS_EVENT_HEADER   Header;     /* 事件头 */
    /* payload 紧随 Header 之后 */
} EVENT_ENTRY;

static LIST_ENTRY   g_EventListHead;
static KSPIN_LOCK   g_EventLock;
static ULONG        g_MaxEvents    = 4096;
static ULONG        g_CurrentCount = 0;
static LONG         g_EventSeqId   = 0;
static BOOLEAN      g_EventPoolReady = FALSE;

/* 模块级静态存储: 符号链接名生命周期与驱动镜像一致
 * (RtlInitUnicodeString 后 Buffer 指向 RDATA 段常量, 永久有效) */
static UNICODE_STRING g_DosSymlinkNameStorage;

/* 内核回调侧写入事件池 (任意 IRQL) */
NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                        _In_ UCHAR event_type)
{
    KIRQL       old_irql;
    PLIST_ENTRY entry;
    PSLS_EVENT_HEADER *hdr;

    if (!g_EventPoolReady) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (payload_size > PSLS_EVENT_MAX_PAYLOAD) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ExAllocatePoolWithTag: 任意 IRQL 安全, 兼容 Win10 1809 内核导出表
     * (ExAllocatePool2 需 2004+, 在老内核上导入解析失败会导致驱动无法加载;
     *  C4996 弃用警告已由 SConstruct /wd4996 压制) */
    entry = (PLIST_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(LIST_ENTRY) + sizeof(PSLS_EVENT_HEADER) + payload_size,
        PSLS_EVENT_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hdr = (PSLS_EVENT_HEADER *)((PUCHAR)entry + sizeof(LIST_ENTRY));
    hdr->event_id     = (uint32_t)InterlockedIncrement(&g_EventSeqId);
    hdr->event_type   = event_type;
    hdr->reserved     = 0;
    hdr->flags        = 0;
    hdr->timestamp_ns = (uint64_t)KeQueryInterruptTime();  /* 100ns 单位, 任意 IRQL 安全 */
    hdr->payload_size = payload_size;
    if (payload != NULL && payload_size > 0) {
        RtlCopyMemory((PUCHAR)hdr + sizeof(PSLS_EVENT_HEADER),
                      payload, payload_size);
    }

    /* ETW 汇聚点 — 投池前发射 (引用栈上 hdr 与调用方 payload, 调用期间有效;
     * 无消费者时 EtwProviderEnabled 快速短路零开销) */
    PslsEtw_Emit(event_type, hdr, payload, payload_size);

    KeAcquireSpinLock(&g_EventLock, &old_irql);

    InsertTailList(&g_EventListHead, entry);
    g_CurrentCount++;

    /* 池满裁剪 — D6: 必须先判空, RemoveHeadList 空表返回表头自身
     * (&g_EventListHead), 对其 ExFreePoolWithTag 会释放全局变量 */
    while (g_CurrentCount > g_MaxEvents &&
           !IsListEmpty(&g_EventListHead)) {
        PLIST_ENTRY old = RemoveHeadList(&g_EventListHead);
        ExFreePoolWithTag(old, PSLS_EVENT_POOL_TAG);
        g_CurrentCount--;
    }

    KeReleaseSpinLock(&g_EventLock, old_irql);
    return STATUS_SUCCESS;
}

/* DriverEntry 调用, 仅此一次 */
static NTSTATUS EventPool_Initialize(_In_ ULONG max_events)
{
    InitializeListHead(&g_EventListHead);
    KeInitializeSpinLock(&g_EventLock);
    g_MaxEvents      = (max_events != 0) ? max_events : 4096;
    g_CurrentCount   = 0;
    g_EventSeqId     = 0;
    g_EventPoolReady = TRUE;
    return STATUS_SUCCESS;
}

/* DriverUnload 调用 — 此时所有回调已注销, 无并发写入 */
static VOID EventPool_Cleanup(VOID)
{
    KIRQL old_irql;

    if (!g_EventPoolReady) {
        return;
    }

    KeAcquireSpinLock(&g_EventLock, &old_irql);
    while (!IsListEmpty(&g_EventListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventListHead);
        ExFreePoolWithTag(entry, PSLS_EVENT_POOL_TAG);
    }
    g_CurrentCount   = 0;
    g_EventPoolReady = FALSE;
    KeReleaseSpinLock(&g_EventLock, old_irql);
}

/* IOCTL_POLL_EVENTS 调用 (PASSIVE_LEVEL, METHOD_BUFFERED) */
static ULONG EventPool_Poll(_Out_writes_bytes_(out_buf_size) PVOID out_buf,
                            _In_ ULONG out_buf_size)
{
    KIRQL   old_irql;
    ULONG   copied = 0;

    if (out_buf == NULL || out_buf_size < sizeof(PSLS_EVENT_HEADER)) {
        return 0;
    }

    KeAcquireSpinLock(&g_EventLock, &old_irql);

    while (!IsListEmpty(&g_EventListHead)) {
        PLIST_ENTRY     entry = RemoveHeadList(&g_EventListHead);
        PSLS_EVENT_HEADER *hdr =
            (PSLS_EVENT_HEADER *)((PUCHAR)entry + sizeof(LIST_ENTRY));
        ULONG needed = sizeof(PSLS_EVENT_HEADER) + hdr->payload_size;

        if (copied + needed > out_buf_size) {
            /* 用户态缓冲区满 — 放回队头等下次轮询 */
            InsertHeadList(&g_EventListHead, entry);
            break;
        }

        RtlCopyMemory((PUCHAR)out_buf + copied, hdr, needed);
        copied += needed;
        g_CurrentCount--;

        ExFreePoolWithTag(entry, PSLS_EVENT_POOL_TAG);
    }

    KeReleaseSpinLock(&g_EventLock, old_irql);
    return copied;
}

/* -------------------------------------------------------------------- */
/* IOCTL 处理器 (全部 PASSIVE_LEVEL)                                     */
/* -------------------------------------------------------------------- */

static NTSTATUS HandleQueryStatus(_Out_ PVOID out_buf, _In_ ULONG out_len,
                                  _Out_ PULONG bytes_returned)
{
    PSLS_STATUS *status = (PSLS_STATUS *)out_buf;

    if (out_buf == NULL || out_len < sizeof(PSLS_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(status, sizeof(PSLS_STATUS));
    status->driver_version = (PSLS_DRIVER_VERSION_MAJOR << 24) |
                             (PSLS_DRIVER_VERSION_MINOR << 16) |
                             PSLS_DRIVER_VERSION_PATCH;
    status->proc_create_count  = (ULONG)InterlockedCompareExchange(&g_Driver.ProcCreateCount, 0, 0);
    status->reg_mon_count      = (ULONG)InterlockedCompareExchange(&g_Driver.RegMonCount, 0, 0);
    status->image_load_count   = (ULONG)InterlockedCompareExchange(&g_Driver.ImageLoadCount, 0, 0);
    status->blocked_count      = (ULONG)InterlockedCompareExchange(&g_Driver.BlockedCount, 0, 0);
    status->psls_pid           = g_Driver.PslsPid;
    status->proc_mon_enabled   = g_Driver.Config.enable_proc_create;
    status->reg_mon_enabled    = g_Driver.Config.enable_reg_mon;
    status->image_mon_enabled  = g_Driver.Config.enable_image_load;
    status->psls_protect_enabled = g_Driver.Config.enable_psls_protect;
    status->file_filter_enabled  = g_Driver.Config.enable_file_filter;
    status->net_filter_enabled   = g_Driver.Config.enable_net_filter;
    status->disk_mon_enabled     = DiskMon_IsEnabled();

    *bytes_returned = sizeof(PSLS_STATUS);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleSetPslsPid(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SET_PID *cmd = (PSLS_SET_PID *)in_buf;

    if (in_buf == NULL || in_len < sizeof(PSLS_SET_PID)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /* PID 与 EPROCESS 引用统一由 protect.c 在锁内维护 */
    Protect_SetTargetPid(cmd->psls_pid);
    return STATUS_SUCCESS;
}

/* 用户态存活标志 (psls_shared.h 声明, 各监控模块的 fail-open 守卫依赖它)。
 * 只有用户态下发过 SET_CONFIG 才允许内核执行拒绝动作。 */
volatile LONG g_UserModeConfigured = 0;

static NTSTATUS HandleSetConfig(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    UCHAR old_protect;
    UCHAR new_protect;

    if (in_buf == NULL || in_len < sizeof(PSLS_DRIVER_CONFIG)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    old_protect = g_Driver.Config.enable_psls_protect;

    /* 字段均为自然对齐的 <=4 字节标量, 逐字段读取原子;
     * 多字段组合瞬时混合 (旧值/新值) 不构成内存安全问题 */
    RtlCopyMemory(&g_Driver.Config, in_buf, sizeof(PSLS_DRIVER_CONFIG));

    /* 用户态判定者已上线: 解除 fail-open 守卫, 内核开始执行拒绝动作 */
    if (!PSLS_USERMODE_ACTIVE()) {
        InterlockedExchange(&g_UserModeConfigured, 1);
        PSLS_LOG("SET_CONFIG: user-mode arbiter online, denials enabled");
    }

    new_protect = g_Driver.Config.enable_psls_protect;
    if (old_protect != new_protect) {
        if (new_protect != 0) {
            if (!NT_SUCCESS(Protect_Initialize())) {
                /* 注册失败 — 回退开关位, 保持 Config 与实际状态一致 */
                g_Driver.Config.enable_psls_protect = 0;
                PSLS_LOG("SET_CONFIG: Protect_Initialize failed, bit reverted");
            }
        } else {
            PSLS_LOG("SET_CONFIG: enable_psls_protect 0 -> Cleanup");
            Protect_Cleanup();
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetConfig(_Out_ PVOID out_buf, _In_ ULONG out_len,
                                _Out_ PULONG bytes_returned)
{
    if (out_buf == NULL || out_len < sizeof(PSLS_DRIVER_CONFIG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(out_buf, &g_Driver.Config, sizeof(PSLS_DRIVER_CONFIG));
    *bytes_returned = sizeof(PSLS_DRIVER_CONFIG);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleNetPidList(_In_ PVOID in_buf, _In_ ULONG in_len,
                                 _In_ BOOLEAN block)
{
    ULONG pid;

    if (in_buf == NULL || in_len < sizeof(ULONG)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    pid = *(ULONG *)in_buf;
    if (pid == 0 || pid == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    if (block) {
        NetMon_BlockPid(pid);
    } else {
        NetMon_UnblockPid(pid);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS HandleSetProtectedDir(_In_opt_ PVOID in_buf, _In_ ULONG in_len)
{
    PCWSTR dir_path;
    ULONG  chars;

    /* 输入 = NT 设备路径 UTF-16LE 字符串, 必须含 \0 终结符 */
    if (in_buf == NULL ||
        in_len < 2 * sizeof(WCHAR) ||
        (in_len % sizeof(WCHAR)) != 0 ||
        in_len > PSLS_MAX_PATH * sizeof(WCHAR)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    dir_path = (PCWSTR)in_buf;
    chars = in_len / sizeof(WCHAR);
    if (dir_path[chars - 1] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    FileMon_SetProtectedDir(dir_path);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleSetExemptDir(_In_opt_ PVOID in_buf, _In_ ULONG in_len)
{
    PCWSTR dir_path;
    ULONG  chars;

    /* 无输入 → 清空豁免（安全 no-op 语义） */
    if (in_buf == NULL || in_len == 0) {
        FileMon_SetExemptDir(NULL);
        return STATUS_SUCCESS;
    }
    if (in_len < 2 * sizeof(WCHAR) ||
        (in_len % sizeof(WCHAR)) != 0 ||
        in_len > PSLS_MAX_PATH * sizeof(WCHAR)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    dir_path = (PCWSTR)in_buf;
    chars = in_len / sizeof(WCHAR);
    if (dir_path[chars - 1] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    FileMon_SetExemptDir(dir_path);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleSetMbrProtect(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_MBR_PROTECT_CMD *cmd;

    if (in_buf == NULL || in_len < sizeof(PSLS_MBR_PROTECT_CMD)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_MBR_PROTECT_CMD *)in_buf;
    DiskMon_SetEnabled(cmd->enabled != 0);
    g_Driver.Config.enable_disk_mon = (cmd->enabled != 0);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleSetBootProtect(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SET_BOOT_PROTECT_CMD *cmd;
    ULONG count;
    size_t need;

    if (in_buf == NULL || in_len < 8) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_SET_BOOT_PROTECT_CMD *)in_buf;
    count = cmd->count;
    if (count > PSLS_BOOT_REGION_MAX) {
        count = PSLS_BOOT_REGION_MAX;   /* 截断, 宽容处理 */
    }
    /* 按实际有效数据校验: 头部 8B + count 个区域条目 */
    need = 8 + (size_t)count * sizeof(PSLS_BOOT_REGION);
    if (in_len < need) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    return DiskMon_SetBootRegions(cmd->regions, count, cmd->enabled != 0);
}

static NTSTATUS HandleSetBootFiles(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SET_BOOT_FILES_CMD *cmd;
    ULONG count;
    size_t need;

    if (in_buf == NULL || in_len < 8) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_SET_BOOT_FILES_CMD *)in_buf;
    count = cmd->count;
    if (count > PSLS_BOOT_FILE_MAX) {
        count = PSLS_BOOT_FILE_MAX;   /* 截断, 宽容处理 */
    }
    need = 8 + (size_t)count * sizeof(PSLS_BOOT_FILE_ENTRY);
    if (in_len < need) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    FileMon_SetBootFiles(cmd->files, count, cmd->enabled != 0);
    return STATUS_SUCCESS;
}

/* ---- 阶段二: 写前影子备份配置 / 统计 ----
 * 输入 = PSLS_SHADOW_CONFIG_CMD (定长) + 可选尾部 dir_count + dirs[]。
 * 结构体本身按共享头定义读取; 尾部扩展按 in_len 截断读取 (前向兼容)。 */
#define PSLS_SHADOW_CFG_BASE_SIZE  sizeof(PSLS_SHADOW_CONFIG_CMD)

static NTSTATUS HandleSetShadowConfig(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SHADOW_CONFIG_CMD *cmd;
    const PSLS_SHADOW_DIR_ENTRY *dirs = NULL;
    ULONG dir_count = 0;
    ULONG i;

    if (in_buf == NULL || in_len < PSLS_SHADOW_CFG_BASE_SIZE) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_SHADOW_CONFIG_CMD *)in_buf;

    /* enable 时必须提供以 '\0' 结尾的 shadow_root */
    if (cmd->enable != 0) {
        BOOLEAN terminated = FALSE;
        for (i = 0; i < PSLS_SHADOW_ROOT_CHARS; i++) {
            if (cmd->shadow_root[i] == 0) {
                terminated = TRUE;
                break;
            }
        }
        if (!terminated) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    /* 可选尾部扩展: uint32 dir_count + dirs[dir_count] */
    if (in_len >= PSLS_SHADOW_CFG_BASE_SIZE + sizeof(uint32_t)) {
        size_t need;
        dir_count = *(uint32_t *)((PUCHAR)in_buf + PSLS_SHADOW_CFG_BASE_SIZE);
        if (dir_count > PSLS_SHADOW_MAX_DIRS) {
            dir_count = PSLS_SHADOW_MAX_DIRS;
        }
        need = PSLS_SHADOW_CFG_BASE_SIZE + sizeof(uint32_t) +
               (size_t)dir_count * sizeof(PSLS_SHADOW_DIR_ENTRY);
        if (in_len < need) {
            dir_count = 0;   /* 尾部不完整 — 忽略扩展, 仅用基础配置 */
        } else {
            dirs = (const PSLS_SHADOW_DIR_ENTRY *)
                   ((PUCHAR)in_buf + PSLS_SHADOW_CFG_BASE_SIZE + sizeof(uint32_t));
        }
    }

    return FileMon_SetShadowConfig(cmd->enable, cmd->generation_id,
                                   (PCWSTR)cmd->shadow_root, dirs, dir_count);
}

static NTSTATUS HandleQueryShadowStats(_Out_ PVOID out_buf, _In_ ULONG out_len,
                                       _Out_ PULONG bytes_returned)
{
    if (out_buf == NULL || out_len < sizeof(PSLS_SHADOW_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(out_buf, sizeof(PSLS_SHADOW_STATS));
    FileMon_GetShadowStats((PSLS_SHADOW_STATS *)out_buf);
    *bytes_returned = sizeof(PSLS_SHADOW_STATS);
    return STATUS_SUCCESS;
}

/* ---- 升级1: 动态 PRE 进程拦截名单 ----
 * PSLS_SET_KILLLIST_CMD 头部 = 3*uint32 + 4 pad = 16 字节。
 * g_Driver.KillListStore 在 DriverEntry 一次性分配 (NonPagedPool, 定长),
 * HandleSetKillList 在自旋锁内整块替换 (REPLACE) 或清零 (CLEAR),
 * procmon PRE 回调在锁内顺序遍历匹配。全程零堆分配、bounded 拷贝。 */
#define PSLS_KILLLIST_CMD_HEADER_SIZE  16

static NTSTATUS HandleSetKillList(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SET_KILLLIST_CMD *cmd;
    ULONG count;
    size_t need;
    KIRQL old_irql;

    if (in_buf == NULL || in_len < PSLS_KILLLIST_CMD_HEADER_SIZE ||
        g_Driver.KillListStore == NULL) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_SET_KILLLIST_CMD *)in_buf;
    if (cmd->version != PSLS_KILLLIST_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_Driver.KillListLock, &old_irql);

    if (cmd->cmd == PSLS_KILLLIST_CMD_CLEAR) {
        g_Driver.KillListCount = 0;
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_SUCCESS;
    }

    if (cmd->cmd != PSLS_KILLLIST_CMD_REPLACE) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_INVALID_PARAMETER;
    }

    count = cmd->count;
    if (count > PSLS_KILLLIST_MAX) {
        count = PSLS_KILLLIST_MAX;   /* 截断, 宽容处理 */
    }
    need = PSLS_KILLLIST_CMD_HEADER_SIZE +
           (size_t)count * sizeof(PSLS_KILLLIST_ENTRY);
    if (in_len < need) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (count > 0) {
        RtlCopyMemory(g_Driver.KillListStore, cmd->entries,
                      count * sizeof(PSLS_KILLLIST_ENTRY));
    }
    g_Driver.KillListCount = count;

    KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
    return STATUS_SUCCESS;
}

/* 供 procmon 在回调内读取动态名单的只读访问器 (调用方须持 KillListLock)。
 * 返回当前条目缓冲 (定长 MAX*MAX_PATH 块, 无堆分配)。 */
PVOID ProcMon_GetKillList(_Out_ PULONG count_out)
{
    if (count_out != NULL) {
        *count_out = g_Driver.KillListCount;
    }
    return g_Driver.KillListStore;
}

/* ---- v8: 动态 PRE 命令行拦截名单 (与 HandleSetKillList 同骨架) ---- */
static NTSTATUS HandleSetCmdKillList(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_SET_KILLLIST_CMD *cmd;
    ULONG count;
    size_t need;
    KIRQL old_irql;

    if (in_buf == NULL || in_len < PSLS_KILLLIST_CMD_HEADER_SIZE ||
        g_Driver.CmdKillListStore == NULL) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    cmd = (PSLS_SET_KILLLIST_CMD *)in_buf;
    if (cmd->version != PSLS_KILLLIST_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_Driver.KillListLock, &old_irql);
    if (cmd->cmd == PSLS_KILLLIST_CMD_CLEAR) {
        g_Driver.CmdKillListCount = 0;
        RtlZeroMemory(g_Driver.CmdKillListStore,
                      (size_t)PSLS_KILLLIST_MAX * sizeof(PSLS_KILLLIST_ENTRY));
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_SUCCESS;
    }
    if (cmd->cmd != PSLS_KILLLIST_CMD_REPLACE) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_INVALID_PARAMETER;
    }
    count = cmd->count;
    if (count > PSLS_KILLLIST_MAX) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_INVALID_PARAMETER;
    }
    need = PSLS_KILLLIST_CMD_HEADER_SIZE +
           (size_t)count * sizeof(PSLS_KILLLIST_ENTRY);
    if (in_len < need) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (count > 0) {
        RtlCopyMemory(g_Driver.CmdKillListStore, cmd->entries,
                      count * sizeof(PSLS_KILLLIST_ENTRY));
    }
    g_Driver.CmdKillListCount = count;

    KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleTerminateProc(_In_ PVOID in_buf, _In_ ULONG in_len)
{
    PSLS_TERMINATE *cmd = (PSLS_TERMINATE *)in_buf;
    HANDLE       h_proc = NULL;
    CLIENT_ID    cid;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS     status;

    if (in_buf == NULL || in_len < sizeof(PSLS_TERMINATE)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /* 安全护栏: 拒绝终止系统关键进程与驱动调用方自身 */
    if (cmd->pid == 0 || cmd->pid == 4 ||
        cmd->pid == (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        return STATUS_INVALID_PARAMETER;
    }

    cid.UniqueProcess = (HANDLE)(LONG_PTR)cmd->pid;
    cid.UniqueThread  = NULL;
    RtlInitializeObjectAttributes(&oa, NULL,
                                  OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                  NULL, NULL);

    status = ZwOpenProcess(&h_proc, PROCESS_TERMINATE, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwTerminateProcess(h_proc,
                                cmd->exit_code != 0 ? (NTSTATUS)cmd->exit_code
                                                    : (NTSTATUS)1);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&g_Driver.BlockedCount);
    }
    ZwClose(h_proc);
    return status;
}

/* -------------------------------------------------------------------- */
/* IRP 分发                                                             */
/* -------------------------------------------------------------------- */

static NTSTATUS DriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject,
                                  _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* D2: 恰好完成一次。旧版在此处存在"拒绝 MJ_CLOSE 但不完成 IRP"的
     * 泄漏路径; 该拒绝逻辑本身亦无效 (对象管理器忽略 Close 的错误码,
     * 句柄照样关闭), 重写后移除 */
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DriverDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject,
                                          _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* ---- 统一分发 (所有 MajorFunction 槽位共用) ----
 *
 * 背景: PDEVICE_OBJECT 没有 MajorFunction 数组, 同一 DriverObject 创建
 * 的所有设备共享同一组分发例程。diskmon 创建的磁盘过滤设备 (非主设备)
 * 必须走 DiskMon_DispatchIrp (拦截/转发到下层磁盘), 而 \\.\PSLS 主设备
 * 走原有 CREATE/CLOSE/DEVICE_CONTROL 逻辑。故在入口处按设备识别分流。
 */
static NTSTATUS DriverDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                    _Inout_ PIRP Irp);
static NTSTATUS DriverUnifiedDispatch(_In_ PDEVICE_OBJECT DeviceObject,
                                      _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;

    /* 磁盘过滤设备: 全部 IRP (含 WRITE/READ/PNP 等) 转磁盘过滤逻辑 */
    if (DiskMon_IsFilterDevice(DeviceObject)) {
        return DiskMon_DispatchIrp(DeviceObject, Irp);
    }

    /* \\.\PSLS 主设备: 保持原始分发行为 */
    stack = IoGetCurrentIrpStackLocation(Irp);
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
    case IRP_MJ_CLEANUP:
        return DriverCreateClose(DeviceObject, Irp);
    case IRP_MJ_DEVICE_CONTROL:
        return DriverDeviceControl(DeviceObject, Irp);
    default:
        return DriverDispatchUnsupported(DeviceObject, Irp);
    }
}

static NTSTATUS DriverDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                    _Inout_ PIRP Irp)
{
    IO_STACK_LOCATION *stack;
    NTSTATUS          status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR         bytes_returned = 0;
    PVOID             in_buf  = NULL;
    PVOID             out_buf = NULL;
    ULONG             in_len;
    ULONG             out_len;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack   = IoGetCurrentIrpStackLocation(Irp);
    in_len  = stack->Parameters.DeviceIoControl.InputBufferLength;
    out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;

    /* METHOD_BUFFERED: 内核自动缓冲区拷贝, 长度为 0 时 SystemBuffer 可能为 NULL */
    if (in_len  > 0) in_buf  = Irp->AssociatedIrp.SystemBuffer;
    if (out_len > 0) out_buf = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case PSLS_IOCTL_QUERY_STATUS:
        status = HandleQueryStatus(out_buf, out_len, (PULONG)&bytes_returned);
        break;

    case PSLS_IOCTL_SET_PSLS_PID:
        status = HandleSetPslsPid(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_CONFIG:
        status = HandleSetConfig(in_buf, in_len);
        break;

    case PSLS_IOCTL_GET_CONFIG:
        status = HandleGetConfig(out_buf, out_len, (PULONG)&bytes_returned);
        break;

    case PSLS_IOCTL_POLL_EVENTS:
        if (out_buf != NULL && out_len >= sizeof(PSLS_EVENT_HEADER)) {
            bytes_returned = EventPool_Poll(out_buf, out_len);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case PSLS_IOCTL_BLOCK_PROCESS:
        status = HandleNetPidList(in_buf, in_len, TRUE);
        break;

    case PSLS_IOCTL_ALLOW_PROCESS:
        status = HandleNetPidList(in_buf, in_len, FALSE);
        break;

    case PSLS_IOCTL_TERMINATE_PROC:
        status = HandleTerminateProc(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_PROTECTED_DIR:
        status = HandleSetProtectedDir(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_EXEMPT_DIR:
        status = HandleSetExemptDir(in_buf, in_len);
        break;
    case PSLS_IOCTL_CLEAR_PROTECTED_DIR:
        FileMon_ClearProtectedDir();
        status = STATUS_SUCCESS;
        break;

    case PSLS_IOCTL_SET_MBR_PROTECT:
        status = HandleSetMbrProtect(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_BOOT_PROTECT:
        status = HandleSetBootProtect(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_BOOT_FILES:
        status = HandleSetBootFiles(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_KILLLIST:
        status = HandleSetKillList(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_CMDKILLLIST:
        status = HandleSetCmdKillList(in_buf, in_len);
        break;

    case PSLS_IOCTL_SET_SHADOW_CONFIG:
        status = HandleSetShadowConfig(in_buf, in_len);
        break;

    case PSLS_IOCTL_QUERY_SHADOW_STATS:
        status = HandleQueryShadowStats(out_buf, out_len, (PULONG)&bytes_returned);
        break;

    /* 以下 IOCTL 在共享协议中已定义, 但 v1.0.0 内核从未实现对应语义 —
     * 返回明确的 NOT_IMPLEMENTED 而非笼统的 INVALID_DEVICE_REQUEST */
    case PSLS_IOCTL_GET_VERSION:
    case PSLS_IOCTL_ACK_EVENT:
    case PSLS_IOCTL_BLOCK_REG_KEY:
    case PSLS_IOCTL_ALLOW_REG_KEY:
    case PSLS_IOCTL_TEST_CALLBACK:
        status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    /* D2: 单一完成出口 */
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytes_returned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* -------------------------------------------------------------------- */
/* DriverUnload — D3 固定卸载顺序                                        */
/* -------------------------------------------------------------------- */

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PSLS_LOG("DriverUnload: cleaning up...");

    /* 1. 注销全部回调。各注销 API (PsSetCreateProcessNotifyRoutineEx(Remove)、
     *    CmUnRegisterCallback、ObUnRegisterCallbacks、FltUnregisterFilter、
     *    FwpsCalloutUnregisterById0) 会阻塞等待在途回调返回,
     *    返回后不再有新事件产生 */
    ProcMon_Cleanup();
    RegMon_Cleanup();
    LoadMon_Cleanup();
    Protect_Cleanup();
    FileMon_Cleanup();
    NetMon_Cleanup();
    DiskMon_Cleanup();

    /* 2. 回调全停后, 先注销 ETW 再清空事件池 (发射不再发生) */
    PslsEtw_Cleanup();
    EventPool_Cleanup();

    /* 2.1 释放动态 PRE 拦截名单 (回调已停, 无并发读) */
    if (g_Driver.KillListStore != NULL) {
        ExFreePoolWithTag(g_Driver.KillListStore, PSLS_EVENT_POOL_TAG);
        g_Driver.KillListStore = NULL;
        g_Driver.KillListCount = 0;
    }
    if (g_Driver.CmdKillListStore != NULL) {
        ExFreePoolWithTag(g_Driver.CmdKillListStore, PSLS_EVENT_POOL_TAG);
        g_Driver.CmdKillListStore = NULL;
        g_Driver.CmdKillListCount = 0;
    }

    /* 3. 删符号链接 + 设备对象 */
    if (g_Driver.DosSymlinkName != NULL) {
        IoDeleteSymbolicLink(g_Driver.DosSymlinkName);  /* 指向静态存储, 无需释放 */
        g_Driver.DosSymlinkName = NULL;
    }
    if (g_Driver.DeviceObject != NULL) {
        IoDeleteDevice(g_Driver.DeviceObject);
        g_Driver.DeviceObject = NULL;
    }

    PSLS_LOG("DriverUnload: done");
}

/* -------------------------------------------------------------------- */
/* DriverEntry                                                          */
/* -------------------------------------------------------------------- */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status;
    UNICODE_STRING dev_name;
    UNICODE_STRING dos_name;
    ULONG          i;

    UNREFERENCED_PARAMETER(RegistryPath);

    PSLS_LOG("DriverEntry: PSLS Driver v%u.%u.%u (v4 rewrite) loading",
             PSLS_DRIVER_VERSION_MAJOR, PSLS_DRIVER_VERSION_MINOR,
             PSLS_DRIVER_VERSION_PATCH);

    g_Driver.DriverObject = DriverObject;

    /* ---- 默认配置 (与旧版语义一致) ---- */
    RtlZeroMemory(&g_Driver.Config, sizeof(g_Driver.Config));
    g_Driver.Config.struct_size           = sizeof(PSLS_DRIVER_CONFIG);
    g_Driver.Config.enable_proc_create    = 1;  /* 进程创建监控 */
    g_Driver.Config.enable_proc_terminate = 0;  /* 内核 PRE 拦截默认关:
                                                 * 黑名单含 \desktop\ 等路径,
                                                 * 默认开会误杀用户从桌面启动的程序 */
    g_Driver.Config.enable_reg_mon        = 1;  /* 注册表监控 */
    g_Driver.Config.enable_psls_protect   = 1;  /* PSLS 自身防护 */
    g_Driver.Config.enable_image_load     = 1;  /* 路线C: 每-PID 150ms 聚合, 默认开 */
    g_Driver.Config.enable_file_filter    = 1;  /* minifilter 文件拦截 */
    g_Driver.Config.enable_net_filter     = 1;  /* WFP 网络拦截 */
    g_Driver.Config.enable_disk_mon       = 0;  /* MBR 写拦截默认关(由用户态MBR保护开启) */
    g_Driver.Config.max_event_pool        = 4096;
    g_Driver.Config.block_timeout_ms      = 5000;

    /* ---- 1. 创建设备对象 ---- */
    RtlInitUnicodeString(&dev_name, PSLS_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &dev_name,
                            FILE_DEVICE_PSLS, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_Driver.DeviceObject);
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("IoCreateDevice failed: 0x%X", status);
        return status;
    }
    g_Driver.DeviceObject->Flags |= DO_BUFFERED_IO;
    g_Driver.DeviceObject->Flags |= DO_POWER_PAGABLE;

    /* ---- 2. 分发表 (符号链接建立前就绪, 杜绝空槽) ----
     * 全部槽位指向统一分发 DriverUnifiedDispatch —— 磁盘过滤设备
     * (diskmon) 与 \\.\PSLS 主设备共享本驱动对象, 在入口按设备分流。 */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DriverUnifiedDispatch;
    }
    DriverObject->DriverUnload = DriverUnload;

    /* ---- 3. 事件池 (锁仅在此初始化一次 — D1) ---- */
    status = EventPool_Initialize(g_Driver.Config.max_event_pool);
    if (!NT_SUCCESS(status)) {
        goto cleanup_device;
    }

    /* ---- 3.1 ETW Provider (非致命: 注册失败仅禁 ETW) ---- */
    status = PslsEtw_Initialize();
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("PslsEtw_Initialize failed: 0x%X (ETW disabled)", status);
        status = STATUS_SUCCESS;   /* 不阻断加载 */
    }

    /* ---- 3.2 动态 PRE 拦截名单 (升级1): 锁 + 定长缓冲一次性就绪 ----
     * 非致命: 分配失败仅禁动态名单(内置 g_KillList 仍生效)。 */
    KeInitializeSpinLock(&g_Driver.KillListLock);
    g_Driver.KillListStore = ExAllocatePoolWithTag(
        NonPagedPool,
        (size_t)PSLS_KILLLIST_MAX * sizeof(PSLS_KILLLIST_ENTRY),
        PSLS_EVENT_POOL_TAG);
    if (g_Driver.KillListStore == NULL) {
        PSLS_LOG("KillListStore alloc failed (dynamic PRE list disabled)");
    } else {
        RtlZeroMemory(g_Driver.KillListStore,
                      (size_t)PSLS_KILLLIST_MAX * sizeof(PSLS_KILLLIST_ENTRY));
        g_Driver.KillListCount = 0;
    }

    /* ---- 3.3 v8 动态 PRE 命令行拦截名单: 与 KillListStore 同规格 ----
     * 非致命: 分配失败仅禁 cmdline PRE 拦截(用户态 EK 仍兜底)。 */
    g_Driver.CmdKillListStore = ExAllocatePoolWithTag(
        NonPagedPool,
        (size_t)PSLS_KILLLIST_MAX * sizeof(PSLS_KILLLIST_ENTRY),
        PSLS_EVENT_POOL_TAG);
    if (g_Driver.CmdKillListStore == NULL) {
        PSLS_LOG("CmdKillListStore alloc failed (cmdline PRE list disabled)");
    } else {
        RtlZeroMemory(g_Driver.CmdKillListStore,
                      (size_t)PSLS_KILLLIST_MAX * sizeof(PSLS_KILLLIST_ENTRY));
        g_Driver.CmdKillListCount = 0;
    }

    /* ---- 4. 符号链接 (静态存储 — D4) ---- */
    RtlInitUnicodeString(&dos_name, PSLS_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&dos_name, &dev_name);
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("IoCreateSymbolicLink failed: 0x%X", status);
        goto cleanup_pool;
    }
    RtlInitUnicodeString(&g_DosSymlinkNameStorage, PSLS_DOS_DEVICE_NAME);
    g_Driver.DosSymlinkName = &g_DosSymlinkNameStorage;

    /* ---- 5. 注册监控模块 ----
     * Protect/FileMon/NetMon 无条件调用: 它们内部先初始化各自的锁/状态
     * (保证 SET_PID/BLOCK_PROCESS 等 IOCTL 在开关关闭时也安全),
     * 再按 Config 决定是否注册回调。失败均为非致命, 仅记录并清开关位 */
    if (g_Driver.Config.enable_proc_create) {
        status = ProcMon_Initialize();
        if (!NT_SUCCESS(status)) {
            PSLS_LOG("ProcMon_Initialize failed: 0x%X (non-fatal)", status);
            g_Driver.Config.enable_proc_create = 0;
        }
    }
    if (g_Driver.Config.enable_reg_mon) {
        status = RegMon_Initialize();
        if (!NT_SUCCESS(status)) {
            PSLS_LOG("RegMon_Initialize failed: 0x%X (non-fatal)", status);
            g_Driver.Config.enable_reg_mon = 0;
        }
    }
    if (g_Driver.Config.enable_image_load) {
        status = LoadMon_Initialize();
        if (!NT_SUCCESS(status)) {
            PSLS_LOG("LoadMon_Initialize failed: 0x%X (non-fatal)", status);
            g_Driver.Config.enable_image_load = 0;
        }
    }

    status = Protect_Initialize();
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("Protect_Initialize failed: 0x%X (non-fatal)", status);
        g_Driver.Config.enable_psls_protect = 0;
    }

    status = FileMon_Initialize();
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("FileMon_Initialize failed: 0x%X (non-fatal)", status);
        g_Driver.Config.enable_file_filter = 0;
    }

    status = NetMon_Initialize();
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("NetMon_Initialize failed: 0x%X (non-fatal)", status);
        g_Driver.Config.enable_net_filter = 0;
    }

    /* diskmon: 无条件附加磁盘(锁/设备扩展初始化), 拦截由用户态
     * PSLS_IOCTL_SET_MBR_PROTECT 动态开关 (默认关, 见 Config) */
    status = DiskMon_Initialize();
    if (!NT_SUCCESS(status)) {
        PSLS_LOG("DiskMon_Initialize failed: 0x%X (non-fatal)", status);
        g_Driver.Config.enable_disk_mon = 0;
    } else if (g_Driver.Config.enable_disk_mon) {
        DiskMon_SetEnabled(TRUE);
    }

    /* ---- 6. D5: 对外可见前清除初始化标志 ---- */
    g_Driver.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    PSLS_LOG("DriverEntry: loaded OK");
    return STATUS_SUCCESS;

cleanup_pool:
    EventPool_Cleanup();
cleanup_device:
    if (g_Driver.DeviceObject != NULL) {
        IoDeleteDevice(g_Driver.DeviceObject);
        g_Driver.DeviceObject = NULL;
    }
    return status;
}
