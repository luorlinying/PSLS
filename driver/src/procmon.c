/*
 * procmon.c — 进程创建监控 (PsSetCreateProcessNotifyRoutineEx) — v4 重写
 *
 * [监控能力 — 与 v3 语义一致]
 *   PsSetCreateProcessNotifyRoutineEx 三参数版: CreateInfo != NULL 时
 *   进程处于创建 PRE 阶段 (尚未执行任何用户代码):
 *   - CreateInfo->ImageFileName 直接提供完整 NT 路径
 *   - CreateInfo->CommandLine 直接提供命令行
 *   - CreateInfo->CreationStatus = 错误码 → 进程根本不会创建
 *
 * [内核级 PRE 拦截]
 *   config.enable_proc_terminate=1 且图像路径命中黑名单:
 *   CreationStatus = STATUS_ACCESS_DENIED, 代码从未执行。
 *   (v4 默认关: 黑名单含 \desktop\ 等模式会误杀用户桌面程序)
 *
 * [v4 重写纪律]
 *   M1. 计数统一走 g_Driver.* (旧独立全局 g_ProcCreateCount/
 *       g_BlockedCount 已废除, 避免链接错误与双份状态)
 *   M2. 回调内零堆分配: 父进程名由 8.3 短名逐字符转宽字符,
 *       替换 v3 的 RtlAnsiStringToUnicodeString(TRUE) 堆分配
 *   M3. 注册/注销恰好一次: Initialize 仅由 DriverEntry 调用
 *       (SET_CONFIG 不动态启停本模块), Cleanup 仅由 DriverUnload 调用
 *   M4. 回调全程 PASSIVE_LEVEL, 只调用非阻塞路径
 *       (EventPool_Post 为自旋锁+非分页池, 任意 IRQL 安全)
 */

#include <ntddk.h>
#include "psls_shared.h"

#define PSLS_PROCMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-ProcMon] " fmt "\n", ##__VA_ARGS__)

/* 外部 */
extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
extern PSLS_DRIVER_GLOBALS g_Driver;
extern ULONG Protect_GetTargetPid(VOID);
extern VOID FileMon_ClearProtectedDir(VOID);

/* ---- 已知恶意路径黑名单 (内核级 PRE 拦截, 子串匹配大小写不敏感) ---- */
static PCWSTR g_KillList[] = {
    /* 临时目录 — 勒索病毒最常用的落地位置 */
    L"\\temp\\",
    L"\\appdata\\local\\temp\\",
    L"\\programdata\\",
    L"\\public\\",
    /* 用户 Desktop/Downloads — 社工钓鱼附件落地位置 */
    L"\\desktop\\",
    L"\\downloads\\",
    /* 浏览器缓存/下载目录 */
    L"\\local\\microsoft\\windows\\temporary internet files\\",
    L"\\local\\microsoft\\edge\\",
    L"\\roaming\\",
    /* 命名管道 — 许多 C2 框架使用 */
    L"\\\\.\\pipe\\",
    NULL
};

static BOOLEAN ProcMon_MatchDynamicKillList(_In_ PUNICODE_STRING ImagePath);

/* ---- v8: 动态 PRE 命令行拦截名单匹配 ----
 * g_Driver.CmdKillListStore 由 PSLS_IOCTL_SET_CMDKILLLIST 下发, 在
 * KillListLock 内顺序遍历匹配 CreateInfo->CommandLine。条目为零堆定长
 * 宽字符子串 (≤255 wchar), 复用 PslsFindUnicodeSubstring 大小写不敏感。 */
static BOOLEAN ProcMon_MatchCmdKillList(_In_ PCUNICODE_STRING CommandLine)
{
    KIRQL old_irql;
    ULONG count;
    ULONG i;
    BOOLEAN hit = FALSE;
    PUCHAR store;
    SIZE_T entry_b = PSLS_MAX_PATH;   /* 每个条目定长 (字节), 复用 killlist 布局 */

    if (CommandLine == NULL || CommandLine->Buffer == NULL ||
        CommandLine->Length == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_Driver.KillListLock, &old_irql);
    store = (PUCHAR)g_Driver.CmdKillListStore;
    count = g_Driver.CmdKillListCount;
    if (store == NULL || count == 0 || count > PSLS_KILLLIST_MAX) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        PSLS_KILLLIST_ENTRY *e =
            (PSLS_KILLLIST_ENTRY *)(store + i * entry_b);
        UNICODE_STRING kw;
        kw.Buffer        = (PWCH)e->path;
        kw.Length        = (USHORT)wcslen((PWCH)e->path) * sizeof(WCHAR);
        kw.MaximumLength = (USHORT)PSLS_MAX_PATH;
        if (kw.Length > 0 && PslsFindUnicodeSubstring(CommandLine, &kw) != NULL) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
    return hit;
}

static BOOLEAN MatchKillList(_In_ PUNICODE_STRING ImagePath)
{
    ULONG i;

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length == 0) {
        return FALSE;
    }

    /* 内置名单保底 (语义不变) */
    for (i = 0; g_KillList[i] != NULL; i++) {
        UNICODE_STRING kw;
        RtlInitUnicodeString(&kw, g_KillList[i]);
        if (PslsFindUnicodeSubstring(ImagePath, &kw) != NULL) {
            return TRUE;
        }
    }

    /* 升级1: 用户态下发的动态名单 (IOCTL_SET_KILLLIST) — 回调零堆分配 */
    return ProcMon_MatchDynamicKillList(ImagePath);
}

/* ---- 动态 PRE 拦截名单匹配 (升级1) ----
 * g_Driver.KillListStore/Count 由 psls_driver.c 在 KillListLock 内维护。
 * 这里在主回调以 PASSIVE_LEVEL 调用, 锁内读一致快照并顺序遍历, 零堆分配。 */
static BOOLEAN ProcMon_MatchDynamicKillList(_In_ PUNICODE_STRING ImagePath)
{
    KIRQL old_irql;
    ULONG count;
    ULONG i;
    BOOLEAN hit = FALSE;
    PUCHAR store;
    SIZE_T entry_b    = PSLS_MAX_PATH;             /* 每个条目定长 (字节) */

    KeAcquireSpinLock(&g_Driver.KillListLock, &old_irql);
    store = (PUCHAR)g_Driver.KillListStore;
    count = g_Driver.KillListCount;
    if (store == NULL || count == 0 || count > PSLS_KILLLIST_MAX) {
        KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        PSLS_KILLLIST_ENTRY *e =
            (PSLS_KILLLIST_ENTRY *)(store + i * entry_b);
        UNICODE_STRING kw;
        kw.Buffer        = (PWCH)e->path;
        kw.Length        = (USHORT)wcslen((PWCH)e->path) * sizeof(WCHAR);
        kw.MaximumLength = (USHORT)PSLS_MAX_PATH;
        if (PslsFindUnicodeSubstring(ImagePath, &kw) != NULL) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Driver.KillListLock, old_irql);
    return hit;
}

/* ---- 父进程 8.3 短名 → 宽字符 (M2: 零堆分配) ----
 * PsGetProcessImageFileName 返回 ≤15 字符的 ANSI 短名 (非完整路径),
 * 直接逐字符展宽即可, 结果以 L'\0' 结尾。 */
static VOID CopyShortNameToWide(_In_opt_ PCHAR short_name,
                                _Out_writes_bytes_(out_bytes) PUCHAR out,
                                _In_ ULONG out_bytes)
{
    ULONG i;
    ULONG max_chars = out_bytes / sizeof(WCHAR);

    RtlZeroMemory(out, out_bytes);
    if (short_name == NULL) {
        return;
    }

    for (i = 0; i + 1 < max_chars; i++) {
        CHAR c = short_name[i];
        if (c == '\0') {
            break;
        }
        ((PWCHAR)out)[i] = (WCHAR)(UCHAR)c;
    }
    ((PWCHAR)out)[i] = L'\0';
}

/* ---- UTF-16 拷贝助手: 源 UNICODE_STRING → 定长 payload 字段 ---- */
static VOID CopyUnicodeToField(_In_opt_ PCUNICODE_STRING src,
                               _Out_writes_bytes_(field_bytes) PUCHAR field,
                               _In_ ULONG field_bytes)
{
    ULONG max_bytes = field_bytes - sizeof(WCHAR);   /* 预留终结符 */
    USHORT copy;

    RtlZeroMemory(field, field_bytes);
    if (src == NULL || src->Buffer == NULL) {
        return;
    }
    copy = (src->Length <= max_bytes) ? src->Length : (USHORT)max_bytes;
    RtlCopyMemory(field, src->Buffer, copy);
    ((PWCHAR)(field + copy))[0] = L'\0';
}

/* ---- PsSetCreateProcessNotifyRoutineEx 回调 ----
 * CreateInfo != NULL: 进程创建 (PRE 阶段, 尚未执行)
 * CreateInfo == NULL: 进程退出 (v3 语义: 不上报, 直接返回) */
static VOID ProcessNotifyEx(
    _Inout_ PEPROCESS                  Process,
    _In_    HANDLE                     ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG                        pid;
    PSLS_PROCESS_CREATE_PAYLOAD  payload;
    HANDLE                       parent_pid;

    pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid == 0 || pid == 4) {
        return;   /* 0=Idle, 4=System */
    }

    /* ---- 进程退出 ----
     * 独立于 enable_proc_create 开关: 若退出的是被保护目标自身,
     * 同步解除安装目录写保护, 保证卸载程序在 PSLS 异常退出
     * (崩溃/被强杀, 用户态来不及自行清除) 后仍能清理安装目录 */
    if (CreateInfo == NULL) {
        if (pid == Protect_GetTargetPid()) {
            FileMon_ClearProtectedDir();
        }
        return;
    }

    /* 运行时开关 (SET_CONFIG 动态生效, 与 loadmon/regmon 一致) */
    if (g_Driver.Config.enable_proc_create == 0) {
        return;
    }

    /* ---- 进程创建 (PRE 阶段) ---- */
    RtlZeroMemory(&payload, sizeof(payload));
    payload.process_id = pid;
    payload.session_id = (ULONG)PsGetProcessSessionId(Process);

    parent_pid = PsGetProcessInheritedFromUniqueProcessId(Process);
    if (parent_pid != NULL) {
        PEPROCESS parent;
        payload.parent_pid = (ULONG)(ULONG_PTR)parent_pid;
        if (NT_SUCCESS(PsLookupProcessByProcessId(parent_pid, &parent))) {
            PCHAR name = PsGetProcessImageFileName(parent);
            CopyShortNameToWide(name, payload.parent_path,
                                sizeof(payload.parent_path));
            ObDereferenceObject(parent);
        }
    }

    CopyUnicodeToField(CreateInfo->ImageFileName,
                       payload.image_path_usr, sizeof(payload.image_path_usr));
    CopyUnicodeToField(CreateInfo->CommandLine,
                       payload.command_line, sizeof(payload.command_line));

    InterlockedIncrement(&g_Driver.ProcCreateCount);

    /* ---- 内核级 PRE 拦截 (M4: 默认关闭, 见 psls_driver.c) ----
     * PSLS_USERMODE_ACTIVE() 守卫: 用户态缺席时不做 PRE 拦截
     * (fail-open), 否则驱动被加载而 PSLS 未运行时黑名单会误杀正常程序 */
    if (g_Driver.Config.enable_proc_terminate != 0 &&
        PSLS_USERMODE_ACTIVE() &&
        CreateInfo->ImageFileName != NULL &&
        MatchKillList(CreateInfo->ImageFileName)) {

        PSLS_BLOCK_RESULT_PAYLOAD block_evt;

        PSLS_PROCMON_LOG("KillList hit PID=%u path=%wZ -> PRE block",
                         pid, CreateInfo->ImageFileName);

        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        InterlockedIncrement(&g_Driver.BlockedCount);

        RtlZeroMemory(&block_evt, sizeof(block_evt));
        block_evt.event_id = PSLS_EVT_BLOCK_RESULT;  /* 与 v3 一致 */
        block_evt.source   = 1;                      /* procmon_pre_block */
        block_evt.pid      = pid;
        CopyUnicodeToField(CreateInfo->ImageFileName,
                           block_evt.path, sizeof(block_evt.path));
        EventPool_Post(&block_evt, sizeof(block_evt), PSLS_EVT_BLOCK_RESULT);
        return;   /* 进程不会创建, 无需投递 PROCESS_CREATE 事件 */
    }

    /* ---- v8: 命令行 PRE 拦截（进程任何代码执行前否决）----
     * 用户态 EK 是"创建后追杀"，cmd /c 短命子命令常已执行完毕（EK 不及时
     * 实锤）；这里在创建瞬间对 cmdline 匹配高危模式直接否决。名单非空 +
     * 用户态存活为前提（fail-open）。 */
    if (PSLS_USERMODE_ACTIVE() &&
        CreateInfo->CommandLine != NULL &&
        ProcMon_MatchCmdKillList(CreateInfo->CommandLine)) {

        PSLS_BLOCK_RESULT_PAYLOAD block_evt;

        PSLS_PROCMON_LOG("CmdKillList hit PID=%u cmd=%wZ -> PRE block",
                         pid, CreateInfo->CommandLine);

        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        InterlockedIncrement(&g_Driver.BlockedCount);

        RtlZeroMemory(&block_evt, sizeof(block_evt));
        block_evt.event_id = PSLS_EVT_BLOCK_RESULT;
        block_evt.source   = 3;                      /* procmon_cmd_pre_block */
        block_evt.pid      = pid;
        /* 上报路径放命令行（命中证据在 cmdline 而非镜像） */
        CopyUnicodeToField(CreateInfo->CommandLine,
                           block_evt.path, sizeof(block_evt.path));
        EventPool_Post(&block_evt, sizeof(block_evt), PSLS_EVT_BLOCK_RESULT);
        return;   /* 进程不会创建, 无需投递 PROCESS_CREATE 事件 */
    }

    /* 正常进程创建 — 投递事件给用户态决策 */
    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_PROCESS_CREATE);
}

/* ---- 模块公共接口 (M3: 各恰好一次) ---- */

static BOOLEAN g_ProcMonRegistered = FALSE;

NTSTATUS ProcMon_Initialize(VOID)
{
    NTSTATUS status;

    if (g_ProcMonRegistered) {
        return STATUS_SUCCESS;
    }

    /* Ex 版需要映像 /INTEGRITYCHECK 链接 (SConstruct 已配置) */
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        PSLS_PROCMON_LOG("PsSetCreateProcessNotifyRoutineEx failed: 0x%X",
                         status);
        return status;
    }

    g_ProcMonRegistered = TRUE;
    PSLS_PROCMON_LOG("registered OK (Ex version, PRE-block capable)");
    return STATUS_SUCCESS;
}

VOID ProcMon_Cleanup(VOID)
{
    if (!g_ProcMonRegistered) {
        return;
    }

    /* Remove=TRUE: 移除回调并等待在途回调返回 */
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
    g_ProcMonRegistered = FALSE;
    PSLS_PROCMON_LOG("callbacks removed");
}
