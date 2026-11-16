/*
 * filemon.c — 文件系统 minifilter 驱动 (R0 实时文件拦截) — v5 (引导文件保护)
 *
 * [拦截策略 — 与 v4 一致]
 *   1. 批量写入检测: 每进程 5 秒窗口内写 I/O 达阈值 → 本窗口内阻止
 *   2. 受保护文件: PSLS 关键目录下的文件禁止外部进程修改
 *   3. 可疑扩展名: 勒索软件常用加密后缀 (.locked/.encrypted/...)
 *   4. 引导文件: bootmgr/BCD/EFI 等引导链文件禁止外部进程修改
 *      (PSLS_IOCTL_SET_BOOT_FILES 下发 NT 路径列表, reason=4)
 *   PreOperation 返回 FLT_PREOP_COMPLETE = 拦截 (写入不会发生)
 *
 * [v4 缺陷 — v5 修复]
 *   F9. 引导链文件 (bootmgr/BCD/bootmgfw.efi) 之前只能靠用户态快照
 *       事后恢复, 无事前拦截。v5 新增引导文件路径表 (g_BootFiles),
 *       FilePreWrite/FilePreSetInfo 命中即拒绝外部进程修改。
 *   F10. Windows 更新合法重写引导文件 (TrustedInstaller/TiWorker 发起),
 *       直接拦截会导致系统更新失败。v5 对引导文件命中做进程白名单:
 *       TrustedInstaller.exe / TiWorker.exe 放行, 其余非 PSLS 用户态拒绝。
 *
 * [v4 纪律]
 *   F5. IRP 完成状态在返回 FLT_PREOP_COMPLETE 前设置
 *   F6. 分页 I/O / 卷打开 / 内核请求 / PSLS 自身一律放行
 *       (这些路径上查询文件名会失败甚至在 Verifier 下死锁)
 *   F7. 自旋锁仅在 FileMon_Initialize 初始化一次
 *       (DriverEntry 在 DO_DEVICE_INITIALIZING 清除前独占调用)
 *   F8. 卸载回调只返回 STATUS_SUCCESS, 真正的注销由
 *       DriverUnload → FileMon_Cleanup → FltUnregisterFilter 执行
 *       (卸载回调内重入 FltUnregisterFilter = 死锁, MSDN 禁止)
 *   F11. 引导文件表与写入计数器共用 g_TrackerLock 保护
 *        (F7: 同一把锁, 仅初始化一次)
 */

#include <fltkernel.h>
#include <ntstrsafe.h>
#include "psls_shared.h"

#define PSLS_FILEMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-FileMon] " fmt "\n", ##__VA_ARGS__)

/* 外部 */
extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
extern ULONG Protect_GetTargetPid(VOID);
extern BOOLEAN Protect_IsPslsPid(_In_ ULONG pid);   /* protect.c: 保护集判断 */
/* g_Driver 已由 psls_shared.h 提供 extern 声明 */

/* ---- 前置声明 ---- */
static FLT_PREOP_CALLBACK_STATUS FilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static FLT_PREOP_CALLBACK_STATUS FilePreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static NTSTATUS FileMonUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

/* 受保护目录前缀判定 (定义见下方) — 影子作用域判定需提前引用 */
static BOOLEAN IsProtectedPath(_In_ PUNICODE_STRING FileName);

/* 前置声明 (alloc_text pragma 要求函数先于 pragma 声明) */
NTSTATUS FileMon_Initialize(VOID);
VOID     FileMon_Cleanup(VOID);
VOID     FileMon_ClearProtectedDir(VOID);
VOID     FileMon_SetBootFiles(_In_ const PSLS_BOOT_FILE_ENTRY *entries,
                              _In_ ULONG count, _In_ BOOLEAN enabled);
NTSTATUS FileMon_SetShadowConfig(_In_ uint32_t enable, _In_ uint32_t generation_id,
                                 _In_opt_ PCWSTR shadow_root,
                                 _In_opt_ const PSLS_SHADOW_DIR_ENTRY *dirs,
                                 _In_ ULONG dir_count);
VOID     FileMon_GetShadowStats(_Out_ PSLS_SHADOW_STATS *out);

#pragma alloc_text(PAGE, FileMon_Initialize)
#pragma alloc_text(PAGE, FileMon_Cleanup)

/* ---- minifilter 句柄 ---- */
static PFLT_FILTER g_FilterHandle = NULL;

/* ---- 操作回调表 (F4: 仅 WRITE / SET_INFORMATION 两个 pre-op) ---- */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_WRITE,           0, FilePreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, FilePreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

/* ---- minifilter 注册结构 (F4: 无上下文注册) ---- */
static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* ContextRegistration */
    g_Callbacks,                    /* OperationRegistration */
    FileMonUnload,                  /* FilterUnloadCallback */
    NULL,                           /* InstanceSetupCallback */
    NULL,                           /* InstanceQueryTeardownCallback */
    NULL,                           /* InstanceTeardownStartCallback */
    NULL,                           /* InstanceTeardownCompleteCallback */
    NULL, NULL, NULL                /* GenerateFileNameCallback etc */
};

/* ---- 进程写入计数器 (批量写入检测) ---- */
#define MAX_TRACKED_PIDS    256
#define WRITE_THRESHOLD     600     /* 5 秒内写 I/O 次数阈值 (v6: 20→600,
                                     * 20 次连 WebView2 渲染/更新栈的正常缓存
                                     * 写都会触发, 是 bad_module_info 三连崩
                                     * 的真凶; 勒索加密批量写每秒成百上千,
                                     * 600 仍可捕获) */
#define WRITE_WINDOW_SEC    5       /* 计数窗口 (秒) */

typedef struct _PID_WRITE_ENTRY {
    ULONG           pid;
    ULONG           write_count;
    ULONG           rename_count;  /* v6: 批量改后缀计数 (同 5s 窗口) */
    ULONG           delete_count;  /* v7: 批量删除计数 (同 5s 窗口) */
    LARGE_INTEGER   last_reset;    /* 上次重置时间 */
    BOOLEAN         blocked;       /* 窗口内已被阻止 (v6(A): 仅上报不拒 IO) */
    BOOLEAN         rename_blocked;/* v6: rename 通道封禁 — 拒绝改后缀 */
    BOOLEAN         delete_blocked;/* v7: delete 通道封禁 — 拒绝删除 */
} PID_WRITE_ENTRY;

static PID_WRITE_ENTRY g_WriteTracker[MAX_TRACKED_PIDS];
static KSPIN_LOCK      g_TrackerLock;

/* v6: 批量改后缀行为检测 (rename 通道) — 勒索加密 = 批量把文件改成别的
 * 后缀, 与后缀黑名单解耦 (覆盖任意/未来变种, 用户语义"不管改成什么")。
 * 阈值语义: 5s 窗口内 ≥50 次"扩展名发生变化的重命名" → rename 通道封禁。 */
#define RENAME_BURST_THRESHOLD  50

/* v7: 批量删除行为检测 — 样本 "Destroyer" 用批量删除 System32 实测穿透
 * 全部门控（write tracker/rename_burst/勒索扩展名全不沾边）。5s 窗口
 * ≥50 次删除 → delete 通道封禁。 */
#define DELETE_BURST_THRESHOLD  50

/* v7: 批量删除合法白名单（映像名，大小写不敏感）— Windows 组件清理
 * （TrustedInstaller/TiWorker/DISM）会批量删除旧版本文件，不可误伤 */
static const PCCH g_DeleteWhitelist[] = {
    "trustedinstaller.exe",
    "tiworker.exe",
    "dism.exe",
    NULL
};

/* 临时后缀豁免 — 参与改名的一侧是临时后缀 = 安装器解包 (.tmp→.dll) /
 * 浏览器下载 (.crdownload→.pdf) 的正常批量改后缀, 不计数不封禁 */
static const PCWSTR g_TempExtensions[] = {
    L".tmp", L".part", L".crdownload", L".partial", L".download",
    L".tmp~", L".~tmp", NULL
};

/* ---- 勒索软件可疑扩展名 (大小写不敏感子串匹配) ---- */
static const PCWSTR g_RansomExtensions[] = {
    L".locked", L".encrypted", L".crypted", L".crypto",
    L".enc", L".cry", L".locked1", L".locky", L".wcry",
    L".wannacry", L".WNCRY", L".WNCRYT", L".petya", L".goldeneye",
    L".gandcrab", L".ryuk", L".sodinokibi", L".conti",
    L".blackcat", L".akira", L".lockbit", L".play",
    NULL
};

/* ---- 受保护目录 (PSLS 安装目录, 用户态可设) ---- */
static UNICODE_STRING g_ProtectedDir;
static WCHAR          g_ProtectedDirBuf[PSLS_MAX_PATH];
/* 受保护目录内的"豁免子树"（如 {app}\Sandboxie）：沙箱自身进程必须能读写自己的文件。
 * 空 = 无豁免。匹配规则与 g_ProtectedDir 相同（前缀、忽略大小写）。 */
static UNICODE_STRING g_ExemptDir;
static WCHAR          g_ExemptDirBuf[PSLS_MAX_PATH];

/* ---- 引导文件保护列表 (bootmgr/BCD/EFI, 用户态下发 NT 路径) ----
 * F11: 与写入计数器共用 g_TrackerLock 保护 */
#define PSLS_FILEMON_MAX_BOOT_FILES  PSLS_BOOT_FILE_MAX
static WCHAR          g_BootFileBufs[PSLS_FILEMON_MAX_BOOT_FILES][PSLS_MAX_PATH];
static UNICODE_STRING g_BootFiles[PSLS_FILEMON_MAX_BOOT_FILES];
static volatile LONG  g_BootFileCount = 0;    /* 有效条目数 */
static volatile LONG  g_BootFilesEnabled = 0; /* 1=引导文件拦截生效 */

/* Windows 更新重写引导文件的进程白名单 (ANSI 映像名, 大小写不敏感) */
static const PCCH g_BootWriterWhitelist[] = {
    "TrustedInstaller.exe",
    "TiWorker.exe",
    NULL
};

/* ---- 写前影子备份 (阶段二: 零窗口勒索回滚) ----
 * 在 IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION 的 PreOperation 阶段, 对命中
 * "影子作用域"(内核受保护目录 + 用户下发的影子触发目录) 的文件, 在放行原
 * 操作之前同步读取其"写前原像"并旁路落盘到 <shadow_root>\<gen>\<path_hash>。
 * 去重表 / 统计 / 配置共用 g_ShadowLock (F7: 仅初始化一次)。
 * 仅在 PASSIVE_LEVEL 做文件 IO; 更高 IRQL 一律放行并上报 shadow_miss。 */
#define PSLS_SHADOW_MAX_FILES       1024
#define PSLS_SHADOW_MAX_FILE_BYTES  (128ULL * 1024 * 1024)  /* 单文件上限 128MB */
#define PSLS_SHADOW_COPY_CHUNK      (256 * 1024)            /* 单次复制块 256KB */
#define PSLS_SHADOW_COPY_TIMEOUT    (2ULL * 1000 * 1000 * 10) /* 2 秒 (100ns 单位) */
#define PSLS_SHADOW_POOL_TAG        'hdSP'

static KSPIN_LOCK     g_ShadowLock;
static volatile LONG  g_ShadowEnabled    = 0;   /* 1=启用 */
static volatile LONG  g_ShadowGeneration = 0;   /* 当前世代号 */
static WCHAR          g_ShadowRootBuf[PSLS_SHADOW_ROOT_CHARS];
static UNICODE_STRING g_ShadowRoot;             /* 影子仓库根 (无尾 '\') */

/* 用户下发的影子触发目录 (NT 路径, 无尾 '\') */
static WCHAR          g_ShadowDirBufs[PSLS_SHADOW_MAX_DIRS][PSLS_SHADOW_ROOT_CHARS];
static UNICODE_STRING g_ShadowDirs[PSLS_SHADOW_MAX_DIRS];
static volatile LONG  g_ShadowDirCount = 0;

/* 去重集合: 本世代已备份文件的路径哈希 (FNV-1a 64), 容量有上限、可整表清空 */
static uint64_t       g_ShadowDedup[PSLS_SHADOW_MAX_FILES];
static volatile LONG  g_ShadowDedupCount = 0;

/* 统计计数 */
static volatile LONG  g_ShadowBackedUp  = 0;
static volatile LONG  g_ShadowSkipped   = 0;
static volatile LONG  g_ShadowMissed    = 0;
static volatile LONG  g_ShadowFailed    = 0;
static volatile LONG  g_ShadowDedupHits = 0;

static BOOLEAN ShadowActive(VOID)
{
    return (InterlockedCompareExchange(&g_ShadowEnabled, 0, 0) != 0) ? TRUE : FALSE;
}

/* 大小写折叠路径的 FNV-1a 64 位哈希 (仅作去重键, 非加密用途) */
static uint64_t ShadowPathHash(_In_ PUNICODE_STRING Name)
{
    uint64_t h = 1469598103934665603ULL;
    ULONG i;

    if (Name == NULL || Name->Buffer == NULL) {
        return 0;
    }
    for (i = 0; i < Name->Length / sizeof(WCHAR); i++) {
        WCHAR c = Name->Buffer[i];
        if (c >= L'A' && c <= L'Z') {
            c = (WCHAR)(c + (L'a' - L'A'));
        }
        h ^= (uint64_t)(uint16_t)c;
        h *= 1099511628211ULL;
    }
    return h;
}

/* FileName 是否位于 Dir 子树内 (Dir 无尾 '\'; 精确相等或后随 '\') */
static BOOLEAN IsPathUnderDir(_In_ PUNICODE_STRING FileName,
                              _In_ PUNICODE_STRING Dir)
{
    UNICODE_STRING prefix;

    if (FileName == NULL || Dir == NULL || Dir->Length == 0 ||
        FileName->Buffer == NULL) {
        return FALSE;
    }
    if (FileName->Length < Dir->Length) {
        return FALSE;
    }
    prefix.Length        = Dir->Length;
    prefix.MaximumLength = Dir->Length;
    prefix.Buffer        = FileName->Buffer;
    if (!RtlEqualUnicodeString(&prefix, Dir, TRUE)) {
        return FALSE;
    }
    if (FileName->Length == Dir->Length) {
        return TRUE;
    }
    return (FileName->Buffer[Dir->Length / sizeof(WCHAR)] == L'\\') ? TRUE : FALSE;
}

/* 影子作用域判定: 内核受保护目录 ∪ 用户下发的影子触发目录 */
static BOOLEAN IsShadowScopePath(_In_ PUNICODE_STRING FileName)
{
    KIRQL   old_irql;
    ULONG   i, n;
    BOOLEAN hit = FALSE;

    if (IsProtectedPath(FileName)) {
        return TRUE;
    }
    KeAcquireSpinLock(&g_ShadowLock, &old_irql);
    n = (ULONG)g_ShadowDirCount;
    for (i = 0; i < n; i++) {
        if (IsPathUnderDir(FileName, &g_ShadowDirs[i])) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ShadowLock, old_irql);
    return hit;
}

/* 递归/自伤豁免: 影子仓库目录自身的读写一律不备份/不拦截 */
static BOOLEAN IsUnderShadowRoot(_In_ PUNICODE_STRING FileName)
{
    KIRQL   old_irql;
    BOOLEAN hit;

    KeAcquireSpinLock(&g_ShadowLock, &old_irql);
    hit = IsPathUnderDir(FileName, &g_ShadowRoot);
    KeReleaseSpinLock(&g_ShadowLock, old_irql);
    return hit;
}

/* 去重: 尝试认领 key。新键返回 TRUE; 已存在返回 FALSE(命中去重);
 * 表满时整表清空后插入 (容量有上限且可整表清空)。 */
static BOOLEAN ShadowDedupClaim(_In_ uint64_t key)
{
    KIRQL   old_irql;
    ULONG   i;
    BOOLEAN is_new = TRUE;

    KeAcquireSpinLock(&g_ShadowLock, &old_irql);
    for (i = 0; i < (ULONG)g_ShadowDedupCount; i++) {
        if (g_ShadowDedup[i] == key) {
            is_new = FALSE;
            break;
        }
    }
    if (is_new) {
        if ((ULONG)g_ShadowDedupCount >= PSLS_SHADOW_MAX_FILES) {
            g_ShadowDedupCount = 0;   /* 容量上限 — 整表清空 */
        }
        g_ShadowDedup[g_ShadowDedupCount] = key;
        g_ShadowDedupCount++;
    }
    KeReleaseSpinLock(&g_ShadowLock, old_irql);
    return is_new;
}

/* 投递影子事件 (任意 IRQL 安全 — EventPool_Post 内部自旋锁) */
static VOID PostShadowEvent(_In_opt_ PUNICODE_STRING orig,
                            _In_opt_ PUNICODE_STRING shadow,
                            _In_ uint64_t orig_size,
                            _In_ uint32_t status, _In_ uint32_t reason,
                            _In_ ULONG pid)
{
    PSLS_SHADOW_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.orig_size = orig_size;
    payload.status    = status;
    payload.reason    = reason;
    payload.pid       = (uint32_t)pid;

    if (orig != NULL && orig->Buffer != NULL && orig->Length > 0) {
        ULONG  max_bytes = sizeof(payload.orig_path) - sizeof(WCHAR);
        USHORT copy = (orig->Length <= max_bytes) ? orig->Length : (USHORT)max_bytes;
        RtlCopyMemory(payload.orig_path, orig->Buffer, copy);
        ((PWCHAR)(payload.orig_path + copy))[0] = L'\0';
    }
    if (shadow != NULL && shadow->Buffer != NULL && shadow->Length > 0) {
        ULONG  max_bytes = sizeof(payload.shadow_path) - sizeof(WCHAR);
        USHORT copy = (shadow->Length <= max_bytes) ? shadow->Length : (USHORT)max_bytes;
        RtlCopyMemory(payload.shadow_path, shadow->Buffer, copy);
        ((PWCHAR)(payload.shadow_path + copy))[0] = L'\0';
    }

    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_FILE_SHADOWED);
}

/* 用十进制写无符号整数到 WCHAR 缓冲, 返回写入字符数 */
static ULONG UIntToWChars(_In_ ULONG v, _Out_writes_(16) PWCHAR buf)
{
    WCHAR tmp[16];
    ULONG tl = 0, n = 0;

    if (v == 0) {
        buf[0] = L'0';
        return 1;
    }
    while (v > 0 && tl < 16) {
        tmp[tl++] = (WCHAR)(L'0' + (v % 10));
        v /= 10;
    }
    while (tl > 0) {
        buf[n++] = tmp[--tl];
    }
    return n;
}

/* ---- 写前影子备份核心 ----
 * 在 PASSIVE_LEVEL 同步读取 FileName 的当前内容并写入影子文件。必须在放行
 * 原写操作之前调用, 以保证影子内容 = 写前原像。任何失败/超限/高 IRQL 均只
 * 上报事件并放行, 绝不挂起或拒绝原操作。调用方须保证已通过作用域判定。 */
static VOID ShadowBackupOne(_In_ PUNICODE_STRING FileName, _In_ ULONG pid)
{
    KIRQL            old_irql;
    BOOLEAN          enabled;
    ULONG            gen;
    UNICODE_STRING   root;
    UNICODE_STRING   shadow_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK  iosb;
    FILE_STANDARD_INFORMATION fsi;
    HANDLE           src = NULL;
    HANDLE           dst = NULL;
    PVOID            buf = NULL;
    NTSTATUS         status;
    LARGE_INTEGER    size;
    uint64_t         written = 0, deadline;
    uint64_t         key, hash;
    WCHAR            shadow_buf[PSLS_MAX_PATH];
    WCHAR            hexbuf[17];
    WCHAR            genbuf[16];
    ULONG            off = 0;
    ULONG            i;
    ULONG            rlen;
    BOOLEAN          ok = TRUE;
    uint32_t         fail_reason = PSLS_SHADOW_REASON_IO_ERROR;

    /* IRQL 守卫: DISPATCH_LEVEL 及以上绝不做文件 IO, 放行并上报 miss */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        PostShadowEvent(FileName, NULL, 0, PSLS_SHADOW_STATUS_MISS,
                        PSLS_SHADOW_REASON_IRQL, pid);
        InterlockedIncrement(&g_ShadowMissed);
        return;
    }

    /* 递归/自伤豁免 */
    if (IsUnderShadowRoot(FileName)) {
        return;
    }

    /* 读取配置快照 (root.Buffer 指向静态缓冲, 释放锁后仍有效) */
    KeAcquireSpinLock(&g_ShadowLock, &old_irql);
    enabled = (g_ShadowEnabled != 0) && (g_ShadowRoot.Length != 0);
    gen     = (ULONG)g_ShadowGeneration;
    root    = g_ShadowRoot;
    KeReleaseSpinLock(&g_ShadowLock, old_irql);
    if (!enabled) {
        return;
    }

    /* 去重: 同一世代内同一文件只备份一次 */
    key = ShadowPathHash(FileName);
    if (!ShadowDedupClaim(key)) {
        InterlockedIncrement(&g_ShadowDedupHits);
        return;
    }

    /* 组影子文件路径: \??\...\<root>\<gen>\<hexhash> */
    rlen = root.Length / sizeof(WCHAR);
    if (rlen == 0 || rlen + 32 >= PSLS_MAX_PATH) {
        PostShadowEvent(FileName, NULL, 0, PSLS_SHADOW_STATUS_FAIL,
                        PSLS_SHADOW_REASON_IO_ERROR, pid);
        InterlockedIncrement(&g_ShadowFailed);
        return;
    }
    RtlZeroMemory(shadow_buf, sizeof(shadow_buf));
    for (i = 0; i < rlen; i++) {
        shadow_buf[off++] = root.Buffer[i];
    }
    shadow_buf[off++] = L'\\';
    for (i = 0; i < UIntToWChars(gen, genbuf); i++) {
        shadow_buf[off++] = genbuf[i];
    }
    shadow_buf[off++] = L'\\';
    hash = key;
    for (i = 0; i < 16; i++) {
        ULONG nib = (ULONG)((hash >> (60 - i * 4)) & 0xF);
        hexbuf[i] = (WCHAR)((nib < 10) ? (L'0' + nib) : (L'a' + (nib - 10)));
    }
    hexbuf[16] = L'\0';
    for (i = 0; i < 16; i++) {
        shadow_buf[off++] = hexbuf[i];
    }
    shadow_buf[off] = L'\0';
    RtlInitUnicodeString(&shadow_path, shadow_buf);

    /* 打开原文件 (只读, 共享读写删, 允许在写期间读取) */
    RtlZeroMemory(&oa, sizeof(oa));
    InitializeObjectAttributes(&oa, FileName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(&src, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL, 0);
    if (!NT_SUCCESS(status)) {
        /* 原文件不存在 (如新建) → 无原像可备份, 不报错 */
        return;
    }

    status = ZwQueryInformationFile(src, &iosb, &fsi, sizeof(fsi),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(src);
        PostShadowEvent(FileName, NULL, 0, PSLS_SHADOW_STATUS_FAIL,
                        PSLS_SHADOW_REASON_IO_ERROR, pid);
        InterlockedIncrement(&g_ShadowFailed);
        return;
    }
    size = fsi.EndOfFile;
    if (size.QuadPart == 0) {
        ZwClose(src);   /* 空文件无内容 */
        return;
    }
    if ((uint64_t)size.QuadPart > PSLS_SHADOW_MAX_FILE_BYTES) {
        ZwClose(src);
        PostShadowEvent(FileName, NULL, (uint64_t)size.QuadPart,
                        PSLS_SHADOW_STATUS_SKIP, PSLS_SHADOW_REASON_TOO_LARGE, pid);
        InterlockedIncrement(&g_ShadowSkipped);
        return;
    }

    /* 创建/覆盖影子文件 */
    RtlZeroMemory(&oa, sizeof(oa));
    InitializeObjectAttributes(&oa, &shadow_path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(&dst, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OVERWRITE_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL, 0);
    if (!NT_SUCCESS(status)) {
        ZwClose(src);
        PostShadowEvent(FileName, &shadow_path, (uint64_t)size.QuadPart,
                        PSLS_SHADOW_STATUS_FAIL, PSLS_SHADOW_REASON_IO_ERROR, pid);
        InterlockedIncrement(&g_ShadowFailed);
        return;
    }

    buf = ExAllocatePoolWithTag(NonPagedPool, PSLS_SHADOW_COPY_CHUNK,
                                PSLS_SHADOW_POOL_TAG);
    if (buf == NULL) {
        ZwClose(dst);
        ZwClose(src);
        PostShadowEvent(FileName, &shadow_path, (uint64_t)size.QuadPart,
                        PSLS_SHADOW_STATUS_FAIL, PSLS_SHADOW_REASON_IO_ERROR, pid);
        InterlockedIncrement(&g_ShadowFailed);
        return;
    }

    /* 有界复制: 每次读 256KB 写 256KB, 超过 deadline 立即放弃 */
    deadline = KeQueryInterruptTime() + PSLS_SHADOW_COPY_TIMEOUT;
    while (written < (uint64_t)size.QuadPart) {
        ULONG got;
        if (KeQueryInterruptTime() > deadline) {
            ok = FALSE;
            fail_reason = PSLS_SHADOW_REASON_TIMEOUT;
            break;
        }
        status = ZwReadFile(src, NULL, NULL, NULL, &iosb, buf,
                            PSLS_SHADOW_COPY_CHUNK, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            ok = FALSE;
            break;
        }
        got = (ULONG)iosb.Information;
        if (got == 0) {
            break;
        }
        status = ZwWriteFile(dst, NULL, NULL, NULL, &iosb, buf, got, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            ok = FALSE;
            break;
        }
        written += got;
    }

    ExFreePoolWithTag(buf, PSLS_SHADOW_POOL_TAG);
    ZwClose(dst);
    ZwClose(src);

    if (ok) {
        PostShadowEvent(FileName, &shadow_path, (uint64_t)size.QuadPart,
                        PSLS_SHADOW_STATUS_OK, PSLS_SHADOW_REASON_OK, pid);
        InterlockedIncrement(&g_ShadowBackedUp);
    } else {
        /* 复制未完成 — 删除半成品影子文件, 上报失败, 但绝不挂起原写操作 */
        RtlZeroMemory(&oa, sizeof(oa));
        InitializeObjectAttributes(&oa, &shadow_path,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL, NULL);
        (void)ZwDeleteFile(&oa);
        PostShadowEvent(FileName, &shadow_path, (uint64_t)size.QuadPart,
                        PSLS_SHADOW_STATUS_FAIL, fail_reason, pid);
        InterlockedIncrement(&g_ShadowFailed);
    }
}

/* ---- 计数器表操作 (调用方持 g_TrackerLock) ---- */

static PID_WRITE_ENTRY *FindOrCreateEntry(_In_ ULONG pid)
{
    ULONG first_free = MAX_TRACKED_PIDS;
    ULONG i;

    for (i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_WriteTracker[i].pid == pid) {
            return &g_WriteTracker[i];
        }
        if (g_WriteTracker[i].pid == 0 && first_free == MAX_TRACKED_PIDS) {
            first_free = i;
        }
    }
    if (first_free < MAX_TRACKED_PIDS) {
        RtlZeroMemory(&g_WriteTracker[first_free], sizeof(PID_WRITE_ENTRY));
        g_WriteTracker[first_free].pid = pid;
        KeQuerySystemTime(&g_WriteTracker[first_free].last_reset);
        return &g_WriteTracker[first_free];
    }
    return NULL;   /* 表满 — 放行 */
}

/* 窗口是否已过期 (调用方持锁) */
static BOOLEAN IsWindowExpired(_In_ const PID_WRITE_ENTRY *entry)
{
    LARGE_INTEGER now;
    ULONGLONG     diff_sec;

    KeQuerySystemTime(&now);
    diff_sec = (ULONGLONG)(now.QuadPart - entry->last_reset.QuadPart)
               / 10000000ULL;
    return (diff_sec >= WRITE_WINDOW_SEC) ? TRUE : FALSE;
}

/* F2: 封禁判定 + 原地过期重置 — 被封进程在窗口过后自动解封 */
static BOOLEAN CheckPidBlocked(_In_ ULONG pid)
{
    KIRQL   old_irql;
    BOOLEAN blocked = FALSE;
    ULONG   i;

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);
    for (i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_WriteTracker[i].pid == pid) {
            if (g_WriteTracker[i].blocked && IsWindowExpired(&g_WriteTracker[i])) {
                /* 窗口已过 — 解封并重置计数 */
                g_WriteTracker[i].blocked      = FALSE;
                g_WriteTracker[i].write_count  = 0;
                KeQuerySystemTime(&g_WriteTracker[i].last_reset);
            }
            blocked = g_WriteTracker[i].blocked;
            break;
        }
    }
    KeReleaseSpinLock(&g_TrackerLock, old_irql);
    return blocked;
}

static BOOLEAN CheckWriteThreshold(_In_ ULONG pid)
{
    KIRQL             old_irql;
    PID_WRITE_ENTRY  *entry;
    BOOLEAN           over_threshold = FALSE;

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);

    entry = FindOrCreateEntry(pid);
    if (entry != NULL) {
        if (IsWindowExpired(entry)) {
            entry->write_count = 0;
            entry->blocked     = FALSE;
            KeQuerySystemTime(&entry->last_reset);
        }

        entry->write_count++;
        over_threshold = (entry->write_count >= WRITE_THRESHOLD) ? TRUE : FALSE;
    }

    KeReleaseSpinLock(&g_TrackerLock, old_irql);
    return over_threshold;
}

static VOID MarkPidBlocked(_In_ ULONG pid)
{
    KIRQL old_irql;
    ULONG i;

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);
    for (i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_WriteTracker[i].pid == pid) {
            g_WriteTracker[i].blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_TrackerLock, old_irql);
}

/* ---- v6: 批量改后缀行为检测 ---- */

/* 取路径末段文件名的扩展名 (最后一个 '\' 之后、最后一个 '.' 起, 含 '.')。
 * 无 '.' (或 '.' 仅在文件名首位, 如 ".bashrc") → 返回 FALSE。 */
static BOOLEAN GetFileNameExtension(_In_ PCUNICODE_STRING path,
                                    _Out_ UNICODE_STRING *ext)
{
    USHORT wchars, i, last_slash = 0, dot = 0;
    BOOLEAN has_dot = FALSE;

    if (path == NULL || path->Buffer == NULL || path->Length < sizeof(WCHAR)) {
        return FALSE;
    }
    wchars = path->Length / sizeof(WCHAR);
    for (i = 0; i < wchars; i++) {
        if (path->Buffer[i] == L'\\') {
            last_slash = (USHORT)(i + 1);
        }
    }
    for (i = last_slash; i < wchars; i++) {
        if (path->Buffer[i] == L'.') {
            dot = i;
            has_dot = TRUE;
        }
    }
    if (!has_dot || dot <= last_slash) {
        return FALSE;
    }
    ext->Length        = (USHORT)(path->Length - dot * sizeof(WCHAR));
    ext->MaximumLength = ext->Length;
    ext->Buffer        = &path->Buffer[dot];
    return TRUE;
}

static BOOLEAN IsTempExtension(_In_ PCUNICODE_STRING ext)
{
    ULONG i;
    UNICODE_STRING e;

    if (ext->Length == 0) {
        return FALSE;
    }
    for (i = 0; g_TempExtensions[i] != NULL; i++) {
        RtlInitUnicodeString(&e, g_TempExtensions[i]);
        if (RtlEqualUnicodeString(ext, &e, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* rename 是否应被拒 (TRUE = 拒绝本次改名)。内部完成: 临时后缀豁免 →
 * 扩展名变化判定 → 5s 窗口计数 → 达阈值封禁 rename 通道。
 * 封禁后**每次** rename 都拒绝并返回 TRUE (勒索的后续加密改名全部失败),
 * 事件由调用方上报, 用户态风暴检测据此终止进程。 */
static BOOLEAN CheckRenameBurst(_In_ ULONG pid,
                                _In_ PCUNICODE_STRING old_name,
                                _In_ PCUNICODE_STRING new_name)
{
    KIRQL             old_irql;
    PID_WRITE_ENTRY  *entry;
    BOOLEAN           deny = FALSE;
    UNICODE_STRING    old_ext, new_ext;

    if (!GetFileNameExtension(old_name, &old_ext) ||
        !GetFileNameExtension(new_name, &new_ext)) {
        return FALSE;   /* 无扩展名参与 (新建/去后缀) 不计 — 只盯"改后缀" */
    }
    if (IsTempExtension(&old_ext) || IsTempExtension(&new_ext)) {
        return FALSE;   /* 安装器解包/浏览器下载的正常批量改后缀 */
    }
    if (RtlEqualUnicodeString(&old_ext, &new_ext, TRUE)) {
        return FALSE;   /* 扩展名未变 (纯改名/移动) 不计 */
    }

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);
    entry = FindOrCreateEntry(pid);
    if (entry != NULL) {
        if (IsWindowExpired(entry)) {
            entry->write_count    = 0;
            entry->rename_count   = 0;
            entry->delete_count   = 0;
            entry->blocked        = FALSE;
            entry->rename_blocked = FALSE;
            entry->delete_blocked = FALSE;
            KeQuerySystemTime(&entry->last_reset);
        }
        entry->rename_count++;
        if (entry->rename_count >= RENAME_BURST_THRESHOLD) {
            entry->rename_blocked = TRUE;
        }
        deny = entry->rename_blocked;
    }
    KeReleaseSpinLock(&g_TrackerLock, old_irql);
    return deny;
}

/* v7: 批量删除检测（TRUE = 拒绝本次删除）。映像名白名单（Windows 组件
 * 清理）放行；否则 5s 窗口计数，达阈值 → delete 通道封禁（后续删除全部
 * 拒绝），事件由调用方上报，用户态风暴检测终止进程。 */
static BOOLEAN AnsiICmp(_In_z_ PCCH a, _In_z_ PCCH b);

static BOOLEAN CheckDeleteBurst(_In_ ULONG pid)
{
    KIRQL             old_irql;
    PID_WRITE_ENTRY  *entry;
    BOOLEAN           deny = FALSE;
    PEPROCESS         proc;
    PCHAR             name;
    ULONG             i;

    /* 白名单：Windows 更新/组件清理的合法批量删除 */
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) {
        name = PsGetProcessImageFileName(proc);
        if (name != NULL) {
            for (i = 0; g_DeleteWhitelist[i] != NULL; i++) {
                if (AnsiICmp(name, g_DeleteWhitelist[i])) {
                    ObDereferenceObject(proc);
                    return FALSE;
                }
            }
        }
        ObDereferenceObject(proc);
    }

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);
    entry = FindOrCreateEntry(pid);
    if (entry != NULL) {
        if (IsWindowExpired(entry)) {
            entry->write_count    = 0;
            entry->rename_count   = 0;
            entry->delete_count   = 0;
            entry->blocked        = FALSE;
            entry->rename_blocked = FALSE;
            entry->delete_blocked = FALSE;
            KeQuerySystemTime(&entry->last_reset);
        }
        entry->delete_count++;
        if (entry->delete_count >= DELETE_BURST_THRESHOLD) {
            entry->delete_blocked = TRUE;
        }
        deny = entry->delete_blocked;
    }
    KeReleaseSpinLock(&g_TrackerLock, old_irql);
    return deny;
}

/* ---- 文件名检查 ---- */

static BOOLEAN HasRansomExtension(_In_ PUNICODE_STRING FileName)
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL ||
        FileName->Length == 0) {
        return FALSE;
    }
    for (i = 0; g_RansomExtensions[i] != NULL; i++) {
        UNICODE_STRING ext;
        RtlInitUnicodeString(&ext, g_RansomExtensions[i]);
        if (PslsFindUnicodeSubstring(FileName, &ext) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsProtectedPath(_In_ PUNICODE_STRING FileName)
{
    UNICODE_STRING prefix;
    USHORT base_len;

    if (FileName == NULL || FileName->Buffer == NULL ||
        FileName->Length == 0) {
        return FALSE;
    }
    if (g_ProtectedDir.Length == 0) {
        return FALSE;   /* 未设置受保护目录 */
    }

    /* 豁免子树优先：命中豁免（如 {app}\Sandboxie）→ 不视为受保护路径，
     * 沙箱自身进程可在其中正常读写自己的文件。 */
    if (g_ExemptDir.Length != 0 && FileName->Length >= g_ExemptDir.Length) {
        prefix.Length        = g_ExemptDir.Length;
        prefix.MaximumLength = g_ExemptDir.Length;
        prefix.Buffer        = FileName->Buffer;
        if (RtlEqualUnicodeString(&prefix, &g_ExemptDir, TRUE)) {
            return FALSE;
        }
    }

    /* 目录本身（无尾 '\'）— 拦截对安装目录自身的重命名/删除 */
    base_len = g_ProtectedDir.Length - sizeof(WCHAR);
    if (base_len > 0 && FileName->Length == base_len) {
        prefix.Length        = base_len;
        prefix.MaximumLength = base_len;
        prefix.Buffer        = g_ProtectedDir.Buffer;
        return RtlEqualUnicodeString(&prefix, FileName, TRUE);
    }

    if (FileName->Length < g_ProtectedDir.Length) {
        return FALSE;
    }

    prefix.Length        = g_ProtectedDir.Length;
    prefix.MaximumLength = g_ProtectedDir.Length;
    prefix.Buffer        = FileName->Buffer;

    return RtlEqualUnicodeString(&prefix, &g_ProtectedDir, TRUE);
}

/* ---- 引导文件判定 ---- */

static BOOLEAN BootFilesActive(VOID)
{
    return (InterlockedCompareExchange(&g_BootFilesEnabled, 0, 0) != 0)
               ? TRUE : FALSE;
}

/* F11: 完整 NT 路径精确匹配 (大小写不敏感) 引导文件保护列表 */
static BOOLEAN IsBootFile(_In_ PUNICODE_STRING FileName)
{
    KIRQL   old_irql;
    ULONG   i;
    ULONG   count;
    BOOLEAN hit = FALSE;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);
    count = (ULONG)g_BootFileCount;
    for (i = 0; i < count; i++) {
        if (g_BootFiles[i].Buffer != NULL &&
            g_BootFiles[i].Length != 0 &&
            RtlEqualUnicodeString(&g_BootFiles[i], FileName, TRUE)) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_TrackerLock, old_irql);
    return hit;
}

/* ANSI 大小写转换 + 大小写不敏感比较 (WDK 28000 已移除 RtlUpcaseChar,
 * PE 映像名为纯 ASCII, 自行实现即可; 驱动亦不链接 CRT) */
static CHAR AnsiUpcase(_In_ CHAR ch)
{
    if (ch >= 'a' && ch <= 'z') {
        return (CHAR)(ch - ('a' - 'A'));
    }
    return ch;
}

static BOOLEAN AnsiICmp(_In_z_ PCCH a, _In_z_ PCCH b)
{
    if (a == NULL || b == NULL) {
        return FALSE;
    }
    while (*a != '\0' && *b != '\0') {
        if (AnsiUpcase(*a) != AnsiUpcase(*b)) {
            return FALSE;
        }
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

/* F10: Windows 更新写引导文件白名单 (映像名匹配) — 命中放行 */
static BOOLEAN IsTrustedBootWriter(_In_ ULONG pid)
{
    PEPROCESS proc = NULL;
    PCHAR     name;
    ULONG     i;

    if (pid == 0 || pid == 4) {
        return TRUE;   /* Idle / System (ShouldSkip 已放行, 双保险) */
    }
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) {
        return FALSE;
    }
    name = PsGetProcessImageFileName(proc);
    if (name == NULL) {
        return FALSE;
    }
    for (i = 0; g_BootWriterWhitelist[i] != NULL; i++) {
        if (AnsiICmp(name, g_BootWriterWhitelist[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ---- 事件投递 (含计数) ---- */
static VOID PostFileBlockEvent(_In_ ULONG pid,
                               _In_opt_ PUNICODE_STRING file_path,
                               _In_ UCHAR reason,
                               _In_ ULONG write_count)
{
    PSLS_FILE_BLOCK_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.pid         = pid;
    payload.write_count = write_count;
    payload.reason      = reason;

    if (file_path != NULL && file_path->Buffer != NULL &&
        file_path->Length > 0) {
        ULONG  max_bytes = sizeof(payload.file_path) - sizeof(WCHAR);
        USHORT copy = (file_path->Length <= max_bytes)
                        ? file_path->Length : (USHORT)max_bytes;
        RtlCopyMemory(payload.file_path, file_path->Buffer, copy);
        ((PWCHAR)(payload.file_path + copy))[0] = L'\0';
    }

    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_FILE_BLOCKED);
    InterlockedIncrement(&g_Driver.BlockedCount);
}

/* F5: 拦截并返回拒绝 */
static FLT_PREOP_CALLBACK_STATUS DenyWrite(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* F6: 公共放行守卫 (配置/内核请求/分页 I/O/卷打开/系统进程/PSLS 自身) */

/* v6: PSLS 进程树放行 — 沿父链上溯 ≤4 层命中主 pid 即放行。
 * WebView2 是两层树: psls-app.exe → msedgewebview2.exe(browser) →
 * msedgewebview2.exe(renderer/GPU/crashpad)——渲染/GPU 是 browser 的
 * 子进程(孙辈), 一层父子判定放行不到, 照样被批量写入判定封禁 → 全局
 * 拒 IO → 渲染进程 fail-fast (bad_module_info c0000409, PSLS 主窗随
 * 渲染进程退出, 2026-11-04 VM 三连崩真凶)。链查每层一次引用 + 标量读,
 * PASSIVE_LEVEL 安全; 深度上限防环/防超长链开销。 */
static BOOLEAN IsPslsChildPid(_In_ ULONG pid)
{
    ULONG    primary;
    ULONG    cur;
    ULONG    depth;
    PEPROCESS proc;
    HANDLE    parent;

    primary = Protect_GetTargetPid();
    if (primary == 0 || pid == 0 || pid == primary) {
        return FALSE;   /* 主进程自身由 Protect_IsPslsPid 覆盖 */
    }
    cur = pid;
    for (depth = 0; depth < 4; depth++) {
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(LONG_PTR)cur,
                                                   &proc))) {
            return FALSE;
        }
        parent = PsGetProcessInheritedFromUniqueProcessId(proc);
        ObDereferenceObject(proc);
        cur = (ULONG)(ULONG_PTR)parent;
        if (cur == 0) {
            return FALSE;
        }
        if (cur == primary) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN ShouldSkipMonitoring(_Inout_ PFLT_CALLBACK_DATA Data,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                    _Out_ ULONG *pid)
{
    if (g_Driver.Config.enable_file_filter == 0) {
        return TRUE;
    }
    if (Data->RequestorMode == KernelMode) {
        return TRUE;
    }
    /* 分页 I/O (含同步分页): 页文件/缓存回写, 查询文件名会失败或死锁 */
    if (Data->Iopb->IrpFlags &
        (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return TRUE;
    }
    if (FltObjects->FileObject != NULL &&
        (FltObjects->FileObject->Flags & FO_VOLUME_OPEN)) {
        return TRUE;
    }

    *pid = FltGetRequestorProcessId(Data);
    if (*pid == 0 || *pid == 4) {
        return TRUE;   /* Idle / System */
    }
    if (*pid == Protect_GetTargetPid() || Protect_IsPslsPid(*pid)) {
        return TRUE;   /* PSLS 自身（主进程 + worker/MLWorker 等保护集）放行 */
    }
    if (IsPslsChildPid(*pid)) {
        return TRUE;   /* PSLS 进程树（WebView2 渲染/GPU 等子进程）放行 */
    }
    return FALSE;
}

/* ---- PreOperation: IRP_MJ_WRITE ---- */
static FLT_PREOP_CALLBACK_STATUS FilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FLT_PREOP_CALLBACK_STATUS  result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    ULONG                      pid = 0;
    NTSTATUS                   status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (ShouldSkipMonitoring(Data, FltObjects, &pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 1. 已封禁进程 — v6(A): 封禁窗口内**不再全局拒 IO**, 放行 + 上报。
     * 全局拒绝是 bad_module_info(WebView2 渲染)/mouscoreworker/DiagTrack
     * 三连崩的根源(5s 窗口阈值下任何正常高频写软件都会被误封, 全局拒 IO
     * = 进程 fail-fast); 勒索面拦截由下面 2/3/5 步**无条件**承担, 与是否
     * 封禁无关。事件仍上报 — 用户态风暴检测(自动终止)继续生效。 */
    if (PSLS_USERMODE_ACTIVE() && CheckPidBlocked(pid)) {
        PostFileBlockEvent(pid, NULL, 1, 0);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 获取规范化文件名 (允许缓存查找, 避免每次写入重新解析) */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &name_info);
    if (!NT_SUCCESS(status) || name_info == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 阶段二: 写前影子备份 — 在放行/拦截原写操作之前完成, 保证影子内容
     * 一定为"写前原像"。仅对命中影子作用域的文件生效, 其余不碰。 */
    if (ShadowActive() && IsShadowScopePath(&name_info->Name)) {
        ShadowBackupOne(&name_info->Name, pid);
    }

    /* 2. 引导文件保护 (bootmgr/BCD/EFI) — F10: Windows 更新白名单放行 */
    if (BootFilesActive() && IsBootFile(&name_info->Name) &&
        !IsTrustedBootWriter(pid)) {
        PostFileBlockEvent(pid, &name_info->Name, 4, 0);
        FltReleaseFileNameInformation(name_info);
        return DenyWrite(Data);
    }

    /* 3. 受保护目录 */
    if (IsProtectedPath(&name_info->Name)) {
        PostFileBlockEvent(pid, &name_info->Name, 2, 0);
        FltReleaseFileNameInformation(name_info);
        return DenyWrite(Data);
    }

    /* 4. 批量写入检测 */
    if (CheckWriteThreshold(pid)) {
        MarkPidBlocked(pid);
        PostFileBlockEvent(pid, &name_info->Name, 1, WRITE_THRESHOLD);
        FltReleaseFileNameInformation(name_info);
        return DenyWrite(Data);
    }

    /* 5. 勒索扩展名 */
    if (HasRansomExtension(&name_info->Name)) {
        PostFileBlockEvent(pid, &name_info->Name, 3, 0);
        FltReleaseFileNameInformation(name_info);
        return DenyWrite(Data);
    }

    FltReleaseFileNameInformation(name_info);
    return result;
}

/* ---- PreOperation: IRP_MJ_SET_INFORMATION (删除/重命名/截断) ---- */
static FLT_PREOP_CALLBACK_STATUS FilePreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS info_class;
    ULONG                  pid = 0;
    NTSTATUS               status;
    PFLT_FILE_NAME_INFORMATION name_info = NULL;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (ShouldSkipMonitoring(Data, FltObjects, &pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 只处理影响文件内容/存亡的元数据操作:
     *   删除 (Disposition) / 重命名 (Rename) / 空间回收 (Allocation) /
     *   截断 (EndOfFile — 不经 IRP_MJ_WRITE 即可清空文件内容) */
    info_class =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (info_class != FileRenameInformation &&
        info_class != FileRenameInformationEx &&
        info_class != FileDispositionInformation &&
        info_class != FileDispositionInformationEx &&
        info_class != FileAllocationInformation &&
        info_class != FileEndOfFileInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* v7: 批量删除行为检测 — 删除（Disposition）此前完全绕过所有计数面
     * （write tracker 只计 IRP_MJ_WRITE；rename_burst 只盯改名）——样本
     * "Destroyer" 用批量删除 System32 实测穿透全部门控。5s 窗口 ≥50 次
     * 删除 → delete 通道封禁（后续删除全部拒绝 + 上报 reason=6）。
     * 系统更新白名单（TrustedInstaller/TiWorker/Dism 的组件清理合法批量
     * 删除）放行。 */
    if ((info_class == FileDispositionInformation ||
         info_class == FileDispositionInformationEx) &&
        CheckDeleteBurst(pid)) {
        PostFileBlockEvent(pid, NULL, 6, 0);
        Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 已封禁进程 — v6(A): 同 FilePreWrite, 封禁窗口内不再全局拒
     * 重命名/删除/截断, 放行 + 上报 (勒索面由下述无条件检查承担) */
    if (PSLS_USERMODE_ACTIVE() && CheckPidBlocked(pid)) {
        PostFileBlockEvent(pid, NULL, 1, 0);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 获取文件名并做引导文件/受保护目录检查: 外部进程禁止删除/重命名/
     * 截断引导链文件与安装目录内文件 (与 FilePreWrite 构成完整防改) */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &name_info);
    if (NT_SUCCESS(status) && name_info != NULL) {
        /* v6: 批量改后缀行为检测 — rename 的新名与旧名扩展名不同且非
         * 临时后缀参与 → 计数, 5s 窗口达阈值后 rename 通道封禁 (后续
         * 改名全部拒绝)。与后缀黑名单解耦, 覆盖任意勒索变种 (用户语义:
         * 盯"批量改后缀"行为, 不管改成什么)。
         * FILE_RENAME_INFORMATION 与 _EX 的 FileNameLength/FileName
         * 偏移一致 (对齐后均为 16), 统一按前者读取安全。 */
        if (info_class == FileRenameInformation ||
            info_class == FileRenameInformationEx) {
            PFILE_RENAME_INFORMATION ri = (PFILE_RENAME_INFORMATION)
                Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (ri != NULL && ri->FileNameLength >= sizeof(WCHAR) &&
                ri->FileName != NULL) {
                UNICODE_STRING new_name;
                new_name.Length        = (USHORT)ri->FileNameLength;
                new_name.MaximumLength = new_name.Length;
                new_name.Buffer        = ri->FileName;
                if (CheckRenameBurst(pid, &name_info->Name, &new_name)) {
                    PostFileBlockEvent(pid, &new_name, 5, 0);
                    FltReleaseFileNameInformation(name_info);
                    Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }
            }
        }
        /* 阶段二: 写前影子备份 — 删除/改名/截断前先保存原内容原像 */
        if (ShadowActive() && IsShadowScopePath(&name_info->Name)) {
            ShadowBackupOne(&name_info->Name, pid);
        }
        /* 引导文件 (bootmgr/BCD/EFI) — Windows 更新白名单放行 */
        if (BootFilesActive() && IsBootFile(&name_info->Name) &&
            !IsTrustedBootWriter(pid)) {
            PostFileBlockEvent(pid, &name_info->Name, 4, 0);
            FltReleaseFileNameInformation(name_info);
            Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        /* 受保护目录: 外部进程禁止删除/重命名/截断安装目录内文件 */
        if (IsProtectedPath(&name_info->Name)) {
            PostFileBlockEvent(pid, &name_info->Name, 2, 0);
            FltReleaseFileNameInformation(name_info);
            Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        FltReleaseFileNameInformation(name_info);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ---- minifilter 卸载回调 — F8: 只放行, 不做任何注销 ---- */
static NTSTATUS FileMonUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    /* 真正的注销由 DriverUnload → FileMon_Cleanup 执行。
     * 本回调由 FltMgr 在卸载流程内部调用, 重入 FltUnregisterFilter
     * 会死锁或破坏 FltMgr 内部状态 (MSDN 明确禁止)。 */
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

/* ---- 模块接口 ---- */

NTSTATUS FileMon_Initialize(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    /* F7: 锁与表仅在此初始化一次 (DriverEntry 独占调用) */
    KeInitializeSpinLock(&g_TrackerLock);
    RtlZeroMemory(g_WriteTracker, sizeof(g_WriteTracker));

    RtlZeroMemory(g_ProtectedDirBuf, sizeof(g_ProtectedDirBuf));
    RtlInitEmptyUnicodeString(&g_ProtectedDir, g_ProtectedDirBuf,
                              sizeof(g_ProtectedDirBuf));

    /* 引导文件保护列表初始为空, 由用户态 PSLS_IOCTL_SET_BOOT_FILES 下发 */
    RtlZeroMemory(g_BootFileBufs, sizeof(g_BootFileBufs));
    RtlZeroMemory(g_BootFiles, sizeof(g_BootFiles));
    g_BootFileCount    = 0;
    g_BootFilesEnabled = 0;

    /* 写前影子备份状态: 锁/表/根路径仅在此初始化一次, 默认关闭 */
    KeInitializeSpinLock(&g_ShadowLock);
    RtlZeroMemory(g_ShadowRootBuf, sizeof(g_ShadowRootBuf));
    RtlInitEmptyUnicodeString(&g_ShadowRoot, g_ShadowRootBuf,
                              sizeof(g_ShadowRootBuf));
    RtlZeroMemory(g_ShadowDirBufs, sizeof(g_ShadowDirBufs));
    RtlZeroMemory(g_ShadowDirs, sizeof(g_ShadowDirs));
    g_ShadowDirCount  = 0;
    RtlZeroMemory(g_ShadowDedup, sizeof(g_ShadowDedup));
    g_ShadowDedupCount = 0;
    g_ShadowEnabled    = 0;
    g_ShadowGeneration = 0;
    g_ShadowBackedUp   = 0;
    g_ShadowSkipped    = 0;
    g_ShadowMissed     = 0;
    g_ShadowFailed     = 0;
    g_ShadowDedupHits  = 0;

    status = FltRegisterFilter(g_Driver.DriverObject,
                               &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        PSLS_FILEMON_LOG("FltRegisterFilter failed: 0x%X", status);
        g_FilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        PSLS_FILEMON_LOG("FltStartFiltering failed: 0x%X", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    PSLS_FILEMON_LOG("minifilter registered and started OK");
    return STATUS_SUCCESS;
}

VOID FileMon_Cleanup(VOID)
{
    PAGED_CODE();

    if (g_FilterHandle != NULL) {
        /* 阻塞等待在途回调返回并拆除实例 */
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        PSLS_FILEMON_LOG("minifilter unregistered");
    }
}

/* 设置受保护目录 (经 PSLS_IOCTL_SET_PROTECTED_DIR 由用户态下发)
 * dir_path 为 NT 设备路径 (如 "\Device\HarddiskVolume3\Program Files\PSLS")。
 * 内部统一补尾部分隔符: 前缀匹配要求 "\dir\" 形态, 避免 "\dir" 误匹配 "\dir2"。 */
VOID FileMon_SetProtectedDir(_In_opt_ PCWSTR dir_path)
{
    size_t len = 0;

    if (dir_path == NULL || dir_path[0] == L'\0') {
        FileMon_ClearProtectedDir();
        return;
    }

    RtlZeroMemory(g_ProtectedDirBuf, sizeof(g_ProtectedDirBuf));
    RtlStringCchCopyW(g_ProtectedDirBuf, PSLS_MAX_PATH, dir_path);

    (void)RtlStringCchLengthW(g_ProtectedDirBuf, PSLS_MAX_PATH - 1, &len);
    if (len > 0 && g_ProtectedDirBuf[len - 1] != L'\\') {
        g_ProtectedDirBuf[len]     = L'\\';
        g_ProtectedDirBuf[len + 1] = L'\0';
    }
    RtlInitUnicodeString(&g_ProtectedDir, g_ProtectedDirBuf);
    PSLS_FILEMON_LOG("Protected dir set: %ws", g_ProtectedDirBuf);
}

/* 设置受保护目录内的"豁免子树"（如 {app}\Sandboxie）。
 * 传入 NULL/空串 → 清空豁免。匹配规则与 g_ProtectedDir 一致（前缀、忽略大小写）。 */
VOID FileMon_SetExemptDir(_In_opt_ PCWSTR dir_path)
{
    size_t len = 0;

    RtlZeroMemory(g_ExemptDirBuf, sizeof(g_ExemptDirBuf));
    RtlInitEmptyUnicodeString(&g_ExemptDir, g_ExemptDirBuf,
                              sizeof(g_ExemptDirBuf));
    if (dir_path == NULL || dir_path[0] == L'\0') {
        PSLS_FILEMON_LOG("Exempt dir cleared");
        return;
    }
    RtlStringCchCopyW(g_ExemptDirBuf, PSLS_MAX_PATH, dir_path);
    (void)RtlStringCchLengthW(g_ExemptDirBuf, PSLS_MAX_PATH - 1, &len);
    if (len > 0 && g_ExemptDirBuf[len - 1] != L'\\') {
        g_ExemptDirBuf[len]     = L'\\';
        g_ExemptDirBuf[len + 1] = L'\0';
    }
    RtlInitUnicodeString(&g_ExemptDir, g_ExemptDirBuf);
    PSLS_FILEMON_LOG("Exempt dir set: %ws", g_ExemptDirBuf);
}

/* 解除受保护目录 (PSLS 正常退出 / 被保护进程退出时调用) */
VOID FileMon_ClearProtectedDir(VOID)
{
    if (g_ProtectedDir.Length != 0) {
        RtlZeroMemory(g_ProtectedDirBuf, sizeof(g_ProtectedDirBuf));
        RtlInitEmptyUnicodeString(&g_ProtectedDir, g_ProtectedDirBuf,
                                  sizeof(g_ProtectedDirBuf));
        /* 一并清空豁免子树，避免残留旧路径在下次保护时误放行 */
        RtlZeroMemory(g_ExemptDirBuf, sizeof(g_ExemptDirBuf));
        RtlInitEmptyUnicodeString(&g_ExemptDir, g_ExemptDirBuf,
                                  sizeof(g_ExemptDirBuf));
        PSLS_FILEMON_LOG("Protected dir cleared");
    }
}

/* 整体替换引导文件保护列表 (经 PSLS_IOCTL_SET_BOOT_FILES 由用户态下发)。
 * entries[].path 为 NT 设备路径 (如 "\Device\HarddiskVolume3\Boot\BCD")，
 * 精确匹配 (大小写不敏感)。count=0 仅切换 enabled 开关 (enabled=0 关闭)。 */
VOID FileMon_SetBootFiles(_In_ const PSLS_BOOT_FILE_ENTRY *entries,
                          _In_ ULONG count, _In_ BOOLEAN enabled)
{
    KIRQL old_irql;
    ULONG i;
    ULONG n = 0;

    KeAcquireSpinLock(&g_TrackerLock, &old_irql);

    if (entries != NULL && count != 0) {
        RtlZeroMemory(g_BootFileBufs, sizeof(g_BootFileBufs));
        RtlZeroMemory(g_BootFiles, sizeof(g_BootFiles));
        for (i = 0; i < count && n < PSLS_FILEMON_MAX_BOOT_FILES; i++) {
            size_t len = 0;

            /* 校验: 必须以 \0 结尾且非空 */
            if (!NT_SUCCESS(RtlStringCchLengthW((PCWSTR)entries[i].path,
                                                PSLS_MAX_PATH, &len)) ||
                len == 0 || len >= PSLS_MAX_PATH) {
                continue;
            }
            RtlCopyMemory(g_BootFileBufs[n], entries[i].path,
                          (len + 1) * sizeof(WCHAR));
            RtlInitUnicodeString(&g_BootFiles[n], g_BootFileBufs[n]);
            n++;
        }
        g_BootFileCount = (LONG)n;
    }
    g_BootFilesEnabled = enabled ? 1 : 0;

    KeReleaseSpinLock(&g_TrackerLock, old_irql);

    PSLS_FILEMON_LOG("boot files updated: %lu path(s), %s",
                     (ULONG)g_BootFileCount, enabled ? "ENABLED" : "disabled");
}

/* 设置写前影子备份配置 (经 PSLS_IOCTL_SET_SHADOW_CONFIG 由用户态下发)。
 * shadow_root 为 NT 设备路径 (如 "\Device\HarddiskVolume3\...\shadow"), 无尾 '\'。
 * dirs 为可选的影子触发目录列表 (NT 路径), 用于把备份范围覆盖到用户受保护
 * 目录; 缺省时仅覆盖内核受保护目录。世代号变化即清空去重集合。 */
NTSTATUS FileMon_SetShadowConfig(_In_ uint32_t enable, _In_ uint32_t generation_id,
                                 _In_opt_ PCWSTR shadow_root,
                                 _In_opt_ const PSLS_SHADOW_DIR_ENTRY *dirs,
                                 _In_ ULONG dir_count)
{
    KIRQL old_irql;
    ULONG i, n = 0;
    size_t len = 0;

    if (enable != 0) {
        if (shadow_root == NULL ||
            !NT_SUCCESS(RtlStringCchLengthW(shadow_root, PSLS_SHADOW_ROOT_CHARS,
                                            &len)) ||
            len == 0) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeAcquireSpinLock(&g_ShadowLock, &old_irql);

    /* 世代号变化 → 清空去重集合 (单世代去重语义) */
    if ((ULONG)g_ShadowGeneration != generation_id) {
        g_ShadowDedupCount = 0;
        g_ShadowGeneration = (LONG)generation_id;
    }

    if (enable != 0 && shadow_root != NULL) {
        RtlZeroMemory(g_ShadowRootBuf, sizeof(g_ShadowRootBuf));
        RtlStringCchCopyW(g_ShadowRootBuf, PSLS_SHADOW_ROOT_CHARS, shadow_root);
        (void)RtlStringCchLengthW(g_ShadowRootBuf, PSLS_SHADOW_ROOT_CHARS, &len);
        while (len > 0 && g_ShadowRootBuf[len - 1] == L'\\') {
            g_ShadowRootBuf[--len] = L'\0';   /* 去掉尾部 '\' */
        }
        RtlInitUnicodeString(&g_ShadowRoot, g_ShadowRootBuf);
    }

    if (dirs != NULL && dir_count > 0) {
        RtlZeroMemory(g_ShadowDirBufs, sizeof(g_ShadowDirBufs));
        RtlZeroMemory(g_ShadowDirs, sizeof(g_ShadowDirs));
        for (i = 0; i < dir_count && n < PSLS_SHADOW_MAX_DIRS; i++) {
            size_t dl = 0;
            PCWSTR src = (PCWSTR)dirs[i].path;
            if (!NT_SUCCESS(RtlStringCchLengthW(src, PSLS_SHADOW_ROOT_CHARS, &dl)) ||
                dl == 0 || dl >= PSLS_SHADOW_ROOT_CHARS) {
                continue;
            }
            RtlCopyMemory(g_ShadowDirBufs[n], src, (dl + 1) * sizeof(WCHAR));
            while (dl > 0 && g_ShadowDirBufs[n][dl - 1] == L'\\') {
                g_ShadowDirBufs[n][--dl] = L'\0';
            }
            RtlInitUnicodeString(&g_ShadowDirs[n], g_ShadowDirBufs[n]);
            n++;
        }
        g_ShadowDirCount = (LONG)n;
    }

    g_ShadowEnabled = (enable != 0) ? 1 : 0;

    KeReleaseSpinLock(&g_ShadowLock, old_irql);

    PSLS_FILEMON_LOG("shadow config: enable=%lu gen=%lu dirs=%lu",
                     (ULONG)enable, (ULONG)generation_id, (ULONG)n);
    return STATUS_SUCCESS;
}

/* 读取写前影子备份统计 (经 PSLS_IOCTL_QUERY_SHADOW_STATS 由用户态拉取) */
VOID FileMon_GetShadowStats(_Out_ PSLS_SHADOW_STATS *out)
{
    if (out == NULL) {
        return;
    }
    out->backed_up  = (uint32_t)InterlockedCompareExchange(&g_ShadowBackedUp, 0, 0);
    out->skipped    = (uint32_t)InterlockedCompareExchange(&g_ShadowSkipped, 0, 0);
    out->missed     = (uint32_t)InterlockedCompareExchange(&g_ShadowMissed, 0, 0);
    out->failed     = (uint32_t)InterlockedCompareExchange(&g_ShadowFailed, 0, 0);
    out->dedup_hits = (uint32_t)InterlockedCompareExchange(&g_ShadowDedupHits, 0, 0);
    out->generation_id = (uint32_t)g_ShadowGeneration;
}
