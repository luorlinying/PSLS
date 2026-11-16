/*
 * loadmon.c — DLL/EXE 映像加载监控 (PsSetLoadImageNotifyRoutine) — v4 重写
 *
 * [监控能力 — 与 v3 语义一致]
 *   映像加载通知 (PASSIVE_LEVEL): 投递 PSLS_IMAGE_LOAD_PAYLOAD 事件,
 *   白名单路径 (System32/SysWOW64/WinSxS/Defender) 直接放行。
 *   默认开启 (Config.enable_image_load=1, 路线 C), 每-PID 150ms 聚合
 *   防止开机瞬间数千 DLL 灌爆事件池。
 *
 * [v3 缺陷 — v4 修复]
 *   L1. wcsstr 作用在 UNICODE_STRING->Buffer 上 — 该缓冲不保证
 *       NUL 结尾, wcsstr 会越过 Length 边界继续读 (Driver Verifier
 *       Special Pool 下即越界蓝屏)。改用共享头长度受限的
 *       PslsFindUnicodeSubstring。
 *   L2. 独立全局 g_ImageLoadCount 已废除, 统一 g_Driver.ImageLoadCount
 *
 * [v4 纪律]
 *   L3. 运行时检查 enable_image_load 开关 (SET_CONFIG 动态生效)
 *   L4. 注册/注销恰好一次, 回调内零堆分配
 */

#include <ntddk.h>
#include "psls_shared.h"

#define PSLS_LOADMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-LoadMon] " fmt "\n", ##__VA_ARGS__)

extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
/* g_Driver 已由 psls_shared.h 提供 extern 声明 */

/* ---- 白名单: 微软签名映像路径关键词 ---- */
static PCWSTR g_SafeImagePaths[] = {
    L"\\SystemRoot\\System32",
    L"\\SystemRoot\\SysWOW64",
    L"\\SystemRoot\\WinSxS",
    L"\\Program Files\\Windows Defender",
    NULL
};

/* L1: 长度受限的大小写不敏感子串匹配 (缓冲可能无 NUL 结尾) */
static BOOLEAN IsPathInSafeList(_In_ PCUNICODE_STRING image_path)
{
    ULONG i;

    if (image_path == NULL || image_path->Buffer == NULL ||
        image_path->Length == 0) {
        return FALSE;
    }
    for (i = 0; g_SafeImagePaths[i] != NULL; i++) {
        UNICODE_STRING kw;
        RtlInitUnicodeString(&kw, g_SafeImagePaths[i]);
        if (PslsFindUnicodeSubstring((PUNICODE_STRING)image_path, &kw) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ---- 映像加载回调 ---- */

/* ---- 每-PID 聚合桶 (防止开机瞬间数千 DLL 灌爆 4096 事件池) ----
 * 纪律 (L3/L4 延续):
 *   - 独立自旋锁 g_LoadMonBucketLock, 恰一次初始化 (KeInitializeSpinLock
 *     静态初值 0 即使未初始化也是合法解锁态, 与 Protect 同论证)
 *   - 静态桶数组, 回调内零堆分配
 *   - 时钟用 KeQueryInterruptTime (100ns 单位), 与 EventPool_Post 一致
 * 节奏: 同 PID 首见立即投 1 条 (load_count=1); 150ms 聚合窗口内后续
 * 加载只累计; 窗口边界的下一次加载携带累计 load_count 重投。
 * 最坏投递率 ≈ 128 桶 / 150ms, 上限由桶数封顶。 */

#define PSLS_LOADMON_BUCKETS      128
#define PSLS_LOADMON_AGG_100NS    1500000ULL      /* 150ms, 100ns 单位 */
#define PSLS_LOADMON_RETIRE_100NS 300000000ULL    /* 30s 空闲退役 */

typedef struct _PSLS_LOADMON_BUCKET {
    ULONG      pid;               /* 关联进程 PID; 0=空槽 */
    ULONG      count;             /* 窗口内待携带累计次数 */
    ULONGLONG  last_emit;         /* 上次投递时间戳 (100ns) */
} PSLS_LOADMON_BUCKET;

static KSPIN_LOCK g_LoadMonBucketLock;
static volatile LONG g_LoadMonBucketLockInit = 0;
static PSLS_LOADMON_BUCKET g_LoadMonBuckets[PSLS_LOADMON_BUCKETS];

static VOID LoadMonBucket_Initialize(VOID)
{
    if (InterlockedCompareExchange(&g_LoadMonBucketLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_LoadMonBucketLock);
    }
    RtlZeroMemory(g_LoadMonBuckets, sizeof(g_LoadMonBuckets));
}

/* ---- 查询/登记 PID 的聚合计数 (锁内), 返回应携带的 load_count ----
 * 语义: 首见 → 返回 1 (立即投递); 窗口内 → 累计, 返回 0 (不投递);
 * 窗口边界 → 返回累计+当前 (重投)。 无空槽 → 返回 1 (直接投递, 不聚合)。 */
static ULONG LoadMonBucket_Accum(_In_ ULONG pid, _In_ ULONGLONG now)
{
    ULONG     i;
    ULONG     result = 0;
    PSLS_LOADMON_BUCKET *free_slot = NULL;

    for (i = 0; i < PSLS_LOADMON_BUCKETS; i++) {
        PSLS_LOADMON_BUCKET *b = &g_LoadMonBuckets[i];
        if (b->pid == pid) {
            if ((now - b->last_emit) >= PSLS_LOADMON_AGG_100NS) {
                /* 窗口边界 — 携带累计次数重投 (含当前这条) */
                result = b->count + 1;
                b->count    = 0;
                b->last_emit = now;
            } else {
                b->count++;          /* 窗口内 — 仅累计 */
            }
            return result;
        }
        if (free_slot == NULL) {
            if (b->pid == 0 ||
                (now - b->last_emit) >= PSLS_LOADMON_RETIRE_100NS) {
                free_slot = b;
            }
        }
    }
    if (free_slot != NULL) {
        /* 首见 — 安放桶, 立即投递 1 条 */
        RtlZeroMemory(free_slot, sizeof(*free_slot));
        free_slot->pid      = pid;
        free_slot->count    = 0;
        free_slot->last_emit = now;
        return 1;
    }
    /* 无槽可用 — 退化为直通投递 (函数返回 0 会跳过, 这里直接放行) */
    return 1;
}

static VOID ImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PVOID           ImageInfo)
{
    PSLS_IMAGE_LOAD_PAYLOAD payload;
    KIRQL     old_irql;
    ULONG     pid;
    ULONGLONG now;
    ULONG     load_count;

    if (g_Driver.Config.enable_image_load == 0) {
        return;   /* L3 */
    }
    if (FullImageName == NULL || FullImageName->Buffer == NULL ||
        FullImageName->Length == 0) {
        return;
    }

    /* 白名单路径快速放行 (L1: 不用 wcsstr) */
    if (IsPathInSafeList(FullImageName)) {
        return;
    }

    pid = (ULONG)(ULONG_PTR)ProcessId;
    now = (ULONGLONG)KeQueryInterruptTime();

    KeAcquireSpinLock(&g_LoadMonBucketLock, &old_irql);
    load_count = LoadMonBucket_Accum(pid, now);
    KeReleaseSpinLock(&g_LoadMonBucketLock, old_irql);

    if (load_count == 0) {
        return;   /* 聚合窗口内, 仅累计不投递 */
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.pid       = pid;
    payload.load_count = load_count;

    /* 映像路径: UNICODE_STRING → 定长字段 (截断 + NUL 终结) */
    {
        ULONG max_bytes = sizeof(payload.image_path) - sizeof(WCHAR);
        USHORT copy = (FullImageName->Length <= max_bytes)
                        ? FullImageName->Length : (USHORT)max_bytes;
        RtlCopyMemory(payload.image_path, FullImageName->Buffer, copy);
        ((PWCHAR)(payload.image_path + copy))[0] = L'\0';
    }

    /* ImageInfo: IMAGE_INFO (IMAGE_INFO_EX 的前半布局兼容, 直接读) */
    if (ImageInfo != NULL) {
        PIMAGE_INFO info = (PIMAGE_INFO)ImageInfo;
        payload.image_base = (UINT64)(ULONG_PTR)info->ImageBase;
        payload.image_size = (UINT32)info->ImageSize;
    }

    InterlockedIncrement(&g_Driver.ImageLoadCount);
    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_IMAGE_LOAD);
}

/* ---- 公共导出 (L4) ---- */

static BOOLEAN g_LoadMonRegistered = FALSE;

NTSTATUS LoadMon_Initialize(VOID)
{
    NTSTATUS status;

    if (g_LoadMonRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    if (!NT_SUCCESS(status)) {
        PSLS_LOADMON_LOG("PsSetLoadImageNotifyRoutine failed: 0x%X", status);
        return status;
    }

    LoadMonBucket_Initialize();
    g_LoadMonRegistered = TRUE;
    PSLS_LOADMON_LOG("callback registered");
    return STATUS_SUCCESS;
}

VOID LoadMon_Cleanup(VOID)
{
    if (!g_LoadMonRegistered) {
        return;
    }

    PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
    g_LoadMonRegistered = FALSE;
    PSLS_LOADMON_LOG("callback removed");
}
