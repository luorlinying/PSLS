/*
 * protect.c — PSLS 自身内核级防护 (ObRegisterCallbacks) — v4 重写
 *
 * [防护能力 — 与 v3 语义一致]
 *   拦截对 PSLS 进程对象的 Open/Duplicate，掩码高危访问位:
 *   PROCESS_TERMINATE / VM_READ / VM_WRITE / VM_OPERATION / CREATE_THREAD /
 *   SUSPEND_RESUME / SET_INFORMATION / SET_QUOTA / DEBUG_ON_PROCESS
 *   (PROCESS_DUP_HANDLE 不再剥离 — multiprocessing 子进程需要此权限)
 *   → 任务管理器 OpenProcess(PROCESS_TERMINATE) 被掩码
 *   → TerminateProcess 返回 ERROR_ACCESS_DENIED
 *
 * [v4 重写纪律]
 *   P1. 自旋锁仅初始化一次 — InterlockedCompareExchange 守卫
 *       (历史 Bug: v3 在 Protect_Initialize 内每次 KeInitializeSpinLock,
 *        SET_CONFIG 开关切换并发时可对已持有锁清零 → 双 CPU 进临界区)
 *   P2. (PID, EPROCESS 引用) 状态对只在锁内成对原子换入换出。
 *       v4 的 SetTargetPid 改为"先查找引用 → 单次加锁整体交换",
 *       从结构上消除 v3 三段式换装的双重 ObDereferenceObject 竞态窗口
 *   P3. 回调内目标识别用对象指针同一性: 驱动持有 EPROCESS 引用期间
 *       该地址不可能被其他进程复用, 杜绝 PID 复用误伤;
 *       快照在锁内读取, 快照后只做指针比较, 不解引用 → 无需附加引用
 *   P4. g_ProtectCookie 兼作注册哨兵 (NULL ⇔ 未注册):
 *       Initialize 幂等且并发安全 (并发注册的输家自行注销自己),
 *       无需操作级互斥体
 *   P5. 引用释放与 ObUnRegisterCallbacks 一律在锁外执行
 *       (ObUnRegisterCallbacks 自身阻塞等待在途回调返回)
 *
 * [与其他模块的契约]
 *   - g_Driver.PslsPid 由本模块独家写入 (受本锁保护);
 *     psls_driver.c 的 QUERY_STATUS 直接读取 (ULONG 原子读, 仅 advisory)
 *   - Protect_GetTargetPid() 供 filemon/netmon 做"PSLS 自身放行"判断
 *   - g_BlockedCount 独立全局已废除, 统一使用 g_Driver.BlockedCount
 */

#include <ntddk.h>
#include "psls_shared.h"

#define PSLS_PROTECT_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-Protect] " fmt "\n", ##__VA_ARGS__)

/* ---- 状态 (P2: 全部受 g_ProtectStateLock 保护) ---- */
static KSPIN_LOCK g_ProtectStateLock;
static volatile LONG g_ProtectLockInit = 0;   /* P1: 一次性初始化守卫 */
static PVOID     g_ProtectCookie = NULL;      /* P4: 注册哨兵 */
/* 注: 单一 g_PslsProcess 已由下方 PID 集合取代 (PV2.0, 支持保护进程树) */

/* ---- 多 PID 保护集 (PV2.0) ----
 * 任务管理器"结束任务树"会逐个 TerminateProcess 枚举到的子进程；只保护主进程时
 * worker/MLWorker 等辅助进程仍会被杀。这里把保护目标从单一 EPROCESS 扩展为
 * 固定大小的 PID 集合（主进程首次注册，worker 等追加），全部持 EPROCESS 引用。
 * 语义 (ABI 不变，复用同一 IOCTL):
 *   set_psls_pid(pid != 0) → 追加该 pid 到集合 (已存在则幂等; 首个成为"主 PID")
 *   set_psls_pid(0)        → 清空整个集合 (卸载/关闭自保护)
 */
#define PSLS_MAX_PROTECT_PIDS 8
static PEPROCESS g_PslsProcSet[PSLS_MAX_PROTECT_PIDS];
static ULONG     g_PslsPidSet [PSLS_MAX_PROTECT_PIDS];
static ULONG     g_PslsProcCount = 0;

/* -------------------------------------------------------------------- */
/* 句柄审计 — PV1.0 新增 (进程打开注入特征发现)                          */
/*                                                                      */
/* 纪律 (与 P2/P3 一致):                                                 */
/*   - 独立自旋锁 g_HandleAuditLock (EnsureLockOnce 恰一次初始化)         */
/*   - 静态桶数组, 回调内零堆分配, 锁内聚合, 锁外不持有                  */
/*   - 时钟用 KeQueryInterruptTime (100ns 单位), 与 EventPool_Post 一致   */
/*                                                                      */
/* 投递节奏: 同 (source,target) 首见立即投 1 条, 之后按 5s 聚合窗口       */
/* 重投 (count 携带窗口内累计次数); 桶 30s 空闲退役复用。                 */
/* 最坏投递率 ≈ 64 桶 / 5s ≈ 13 条/s, 不会灌爆事件池。                   */
/* -------------------------------------------------------------------- */

#define PSLS_HANDLE_AUDIT_BUCKETS     64
#define PSLS_HANDLE_AUDIT_AGG_100NS   50000000ULL        /* 5s, 100ns 单位 */
#define PSLS_HANDLE_AUDIT_RETIRE_100NS 300000000ULL      /* 30s, 100ns 单位 */

typedef struct _PSLS_HANDLE_AUDIT_BUCKET {
    ULONG      source_pid;             /* 发起打开者 PID; 0=空槽 */
    ULONG      target_pid;             /* 被打开目标 PID */
    ULONG      desired_access;         /* 与 PROCESS_INJECT_AUDIT_MASK 相交后的位 */
    ULONG      count;                  /* 窗口内待携带累计次数 */
    ULONGLONG  first_ts;               /* 首见时间戳 (100ns) */
    ULONGLONG  last_emit;              /* 上次投递时间戳 (100ns) */
} PSLS_HANDLE_AUDIT_BUCKET;

static KSPIN_LOCK                   g_HandleAuditLock;
static volatile LONG                g_HandleAuditLockInit = 0;
static PSLS_HANDLE_AUDIT_BUCKET     g_HandleAuditBuckets[PSLS_HANDLE_AUDIT_BUCKETS];

/* ---- 掩码掉的高危访问位 ----
 * PROCESS_DUP_HANDLE 已从掩码中移除: multiprocessing spawn 子进程
 * 需要对父进程调用 DuplicateHandle, 剥离此位会导致 WinError 5。
 * 其余高危位 (终止/注入/读写内存等) 仍然剥离。 */
#define PSLS_BLOCKED_ACCESS_MASK ( \
    PROCESS_TERMINATE          | \
    PROCESS_VM_OPERATION       | \
    PROCESS_VM_READ            | \
    PROCESS_VM_WRITE           | \
    PROCESS_SET_INFORMATION    | \
    PROCESS_SET_QUOTA          | \
    PROCESS_CREATE_THREAD      | \
    PROCESS_SUSPEND_RESUME     | \
    DEBUG_ON_PROCESS            \
)

extern PSLS_DRIVER_GLOBALS g_Driver;

extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);

/* ---- P1: 锁初始化恰一次 ----
 * 守卫本身有理论竞态 (输家可能在赢家完成 KeInitializeSpinLock 前
 * 抢先 Acquire), 但锁的静态初值 0 在 x64/x86 上就是"未上锁"的合法
 * 状态, KeInitializeSpinLock 亦只是写 0 — 双方等价, 实际无竞态危害。
 * 且 DriverEntry 在 DO_DEVICE_INITIALIZING 清除前调用本函数,
 * 任何 IOCTL (含 SET_PID/SET_CONFIG) 都不可能先于它到达。 */
static VOID Protect_EnsureLockOnce(VOID)
{
    if (InterlockedCompareExchange(&g_ProtectLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_ProtectStateLock);
    }
    /* 句柄审计独立锁, 同样只初始化一次 (与 SET_CONFIG 并发安全) */
    if (InterlockedCompareExchange(&g_HandleAuditLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_HandleAuditLock);
    }
}

/* ---- 句柄审计: 投递一条聚合事件 (锁内调用) ----
 * EventPool_Post 自身持 g_EventLock, 与本锁无嵌套环, 锁内调用安全。
 * payload 全为锁内复制的标量, 无堆分配。 */
static VOID HandleAudit_EmitLocked(_In_ PSLS_HANDLE_AUDIT_BUCKET *b,
                                   _In_ ULONG count)
{
    PSLS_HANDLE_AUDIT_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.source_pid     = b->source_pid;
    payload.target_pid     = b->target_pid;
    payload.desired_access = b->desired_access;
    payload.count          = count;
    payload.first_ts_ns    = b->first_ts;
    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_HANDLE_AUDIT);

    /* 更新投递节奏由调用方统一处理 (last_emit/count 复位) */
}

/* ---- 句柄审计: 记录一次"注入特征"进程打开 ----
 * 规则 (见头部注释): 首见立即投 1 条; 窗口内聚合 count; 窗口边界重投;
 * 无空槽/全被占用时静默丢弃 (避免审计拖垮回调)。 */
static VOID HandleAudit_Track(_In_ ULONG source_pid,
                              _In_ ULONG target_pid,
                              _In_ ULONG desired_access)
{
    KIRQL     old_irql;
    ULONG     i;
    ULONGLONG now;
    PSLS_HANDLE_AUDIT_BUCKET *found_slot = NULL;   /* 命中桶 */
    PSLS_HANDLE_AUDIT_BUCKET *free_slot  = NULL;   /* 空槽/过期桶 (退化时复用) */

    now = (ULONGLONG)KeQueryInterruptTime();

    KeAcquireSpinLock(&g_HandleAuditLock, &old_irql);

    for (i = 0; i < PSLS_HANDLE_AUDIT_BUCKETS; i++) {
        PSLS_HANDLE_AUDIT_BUCKET *b = &g_HandleAuditBuckets[i];
        if (b->source_pid == source_pid && b->target_pid == target_pid) {
            found_slot = b;
            break;
        }
        if (free_slot == NULL) {
            if (b->source_pid == 0 ||
                (now - b->last_emit) >= PSLS_HANDLE_AUDIT_RETIRE_100NS) {
                free_slot = b;   /* 空槽或 30s 空闲退役槽 */
            }
        }
    }

    if (found_slot == NULL && free_slot != NULL) {
        /* 首见 — 立即投 1 条并安放桶 */
        PSLS_HANDLE_AUDIT_BUCKET *b = free_slot;
        RtlZeroMemory(b, sizeof(*b));
        b->source_pid     = source_pid;
        b->target_pid     = target_pid;
        b->desired_access = desired_access;
        b->first_ts       = now;
        b->last_emit      = now;
        b->count          = 0;
        HandleAudit_EmitLocked(b, 1);
    } else if (found_slot != NULL) {
        PSLS_HANDLE_AUDIT_BUCKET *b = found_slot;
        if ((now - b->last_emit) >= PSLS_HANDLE_AUDIT_AGG_100NS) {
            /* 窗口边界 — 携带累计次数重投 (含当前这条) */
            HandleAudit_EmitLocked(b, b->count + 1);
            b->count    = 0;
            b->last_emit = now;
        } else {
            /* 窗口内 — 仅累计, 不投递 */
            b->count++;
        }
        /* 窗口内 access 位若有新增, 合并进桶 (保留首见的位并集) */
        b->desired_access |= desired_access;
    }
    /* 无槽可用: 静默丢弃 */

    KeReleaseSpinLock(&g_HandleAuditLock, old_irql);
}

/* ---- 句柄审计: 初始化/清理 (锁恰一次, 桶清零) ---- */
static VOID HandleAudit_Initialize(VOID)
{
    Protect_EnsureLockOnce();
    RtlZeroMemory(g_HandleAuditBuckets, sizeof(g_HandleAuditBuckets));
}

static VOID HandleAudit_Cleanup(VOID)
{
    RtlZeroMemory(g_HandleAuditBuckets, sizeof(g_HandleAuditBuckets));
}

/* ---- 供 filemon/netmon 判断"当前操作者是否 PSLS 自身" ---- */
ULONG Protect_GetTargetPid(VOID)
{
    /* ULONG 对齐读原子; 仅供放行判断, 允许瞬时旧值 */
    return g_Driver.PslsPid;
}

/* ---- 该 pid 是否属于受保护集 (供审计/放行判断) ----
 * 锁内线性扫描 (集合 ≤ 8, 可接受), 只比较标量, 不解引用。 */
BOOLEAN Protect_IsPslsPid(_In_ ULONG pid)
{
    KIRQL old_irql;
    ULONG i;
    BOOLEAN hit = FALSE;

    KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
    for (i = 0; i < g_PslsProcCount; i++) {
        if (g_PslsPidSet[i] == pid) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ProtectStateLock, old_irql);
    return hit;
}

/* ---- OB_PRE_OPERATION_CALLBACK — Create + Duplicate 统一处理 ---- */
static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_    PVOID Context,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    KIRQL    old_irql;
    ACCESS_MASK original;
    ACCESS_MASK blocked;
    ACCESS_MASK effective_mask;  /* 最终真正剥离的掩码；对 wmiprvse 豁免 VM_READ */
    PEPROCESS caller_proc;
    PCSTR     caller_img;
    BOOLEAN   caller_is_wmiprvse = FALSE;

    UNREFERENCED_PARAMETER(Context);

    /* 只处理进程对象 (注册时只注册了 PsProcessType) */
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    /* 内核句柄放行: 掩码内核组件的访问权限可能破坏系统自身
     * (用户态进程无法创建内核句柄, 不构成防护漏洞) */
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    /* ----【修复 2/3：单独豁免 wmiprvse.exe 的 PROCESS_VM_READ】----
     * WMI Provider 宿主（wmiprvse.exe / WmiPrvSE.EXE）在枚举
     * Win32_Process 时必须读取每个进程的 PEB 才能返回 Name /
     * CommandLine / ExecutablePath / ParentProcessId 等字段。
     * 之前对所有访问者一视同仁地剥离 PROCESS_VM_READ 会导致它
     * NtQueryInformationProcess 拿到 STATUS_ACCESS_DENIED 后
     * 在提供程序内反复重试（MOF/WMI 管道重传），最终用户态的
     * ConnectServer / ExecQuery 被挂起，UI 弹"发生意外超时"。
     *
     * 这里仅豁免 PROCESS_VM_READ 一个访问位；PROCESS_TERMINATE /
     * PROCESS_CREATE_THREAD / SET_INFORMATION / SUSPEND / DEBUG
     * 等高危位一律照常剥离——防止样本假冒/注入 WMI Provider 后
     * 借助这一豁免来终止或注入 PSLS。*/
    caller_proc = PsGetCurrentProcess();
    if (caller_proc != NULL) {
        caller_img = PsGetProcessImageFileName(caller_proc);
        if (caller_img != NULL) {
            /* 大小写不敏感比较：WmiPrvSE.exe / wmiprvse.exe / WMIPRVSE.EXE */
            if (_stricmp(caller_img, "wmiprvse.exe") == 0) {
                caller_is_wmiprvse = TRUE;
            }
        }
    }
    if (caller_is_wmiprvse) {
        /* 仅豁免 PROCESS_VM_READ，其它高危位保留在 effective_mask 中 */
        effective_mask = PSLS_BLOCKED_ACCESS_MASK & ~PROCESS_VM_READ;
    } else {
        effective_mask = PSLS_BLOCKED_ACCESS_MASK;
    }

    /* ---- 句柄审计: 发现对任意进程的"注入特征"打开 ----
     * 与 PSLS 自身防护解耦: 目标不是 PSLS 时同样记录。
     * 触发条件: DesiredAccess 与 PROCESS_INJECT_AUDIT_MASK 相交非零,
     *           且调用方不是 PSLS 自身, 且非 wmiprvse 纯 VM_READ 枚举豁免。
     * 审计不影响本次打开 (只读), 也不剥离任何访问位。 */
    if (caller_proc != NULL) {
        ULONG src_pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        if (!Protect_IsPslsPid(src_pid)) {
            ACCESS_MASK requested;
            ACCESS_MASK inj;
            PEPROCESS   obj_proc;

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                requested = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            } else {
                requested = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
            }
            inj = requested & PROCESS_INJECT_AUDIT_MASK;
            if (inj != 0) {
                if (!(caller_is_wmiprvse && inj == PROCESS_VM_READ)) {
                    obj_proc = (PEPROCESS)OperationInformation->Object;
                    /* 回调期间对象引用稳定, PsGetProcessId 安全 */
                    HandleAudit_Track(src_pid,
                                      (ULONG)(ULONG_PTR)PsGetProcessId(obj_proc),
                                      inj);
                }
            }
        }
    }

    /* P3: 锁内快照受保护 EPROCESS 集合 (回调 IRQL <= APC_LEVEL, 自旋锁合法)。
     * 集合 ≤ 8, 栈上局部数组拷贝指针即可; 我们持有引用 → 期间地址不被复用。 */
    {
        PEPROCESS snapshot[PSLS_MAX_PROTECT_PIDS];
        ULONG     snap_count = 0;
        ULONG     i;
        BOOLEAN   matched = FALSE;

        KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
        snap_count = g_PslsProcCount;
        for (i = 0; i < snap_count; i++) {
            snapshot[i] = g_PslsProcSet[i];
        }
        KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

        if (snap_count == 0) {
            return OB_PREOP_SUCCESS;   /* 无保护目标 */
        }
        for (i = 0; i < snap_count; i++) {
            if (snapshot[i] != NULL &&
                (PEPROCESS)OperationInformation->Object == snapshot[i]) {
                matched = TRUE;        /* 纯指针比较, 不解引用 */
                break;
            }
        }
        if (!matched) {
            return OB_PREOP_SUCCESS;
        }
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        original = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess =
            original & ~effective_mask;
    } else {
        original = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess =
            original & ~effective_mask;
    }

    blocked = original & effective_mask;
    if (blocked != 0) {
        InterlockedIncrement(&g_Driver.BlockedCount);
        PSLS_PROTECT_LOG("BLOCK OpenProcess(0x%X) on PSLS pid=%u (wmiprvse_vm_read_exempt=%s)",
                         blocked, g_Driver.PslsPid,
                         caller_is_wmiprvse ? "YES" : "NO");
    }

    return OB_PREOP_SUCCESS;
}

/* ---- ObRegisterCallbacks 注册 (幂等, 可被 SET_CONFIG 反复调用) ---- */
NTSTATUS Protect_Initialize(VOID)
{
    OB_OPERATION_REGISTRATION opReg;
    OB_CALLBACK_REGISTRATION  cbReg;
    DECLARE_CONST_UNICODE_STRING(altitude, L"370110");
    NTSTATUS status;
    PVOID    new_cookie = NULL;
    KIRQL    old_irql;
    PVOID    loser_cookie;

    Protect_EnsureLockOnce();
    HandleAudit_Initialize();

    /* P4: 已注册直接成功 */
    KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
    if (g_ProtectCookie != NULL) {
        KeReleaseSpinLock(&g_ProtectStateLock, old_irql);
        return STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

    /* 注册在锁外 (可阻塞); 注册结构为局部变量,
     * ObRegisterCallbacks 内部会拷贝所需数据 (WDK 标准用法) */
    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType    = PsProcessType;
    opReg.Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation  = PreOperationCallback;
    opReg.PostOperation = NULL;

    RtlZeroMemory(&cbReg, sizeof(cbReg));
    cbReg.Version                    = ObGetFilterVersion();
    cbReg.OperationRegistrationCount = 1;
    cbReg.OperationRegistration      = &opReg;
    cbReg.Altitude                   = altitude;

    status = ObRegisterCallbacks(&cbReg, &new_cookie);
    if (!NT_SUCCESS(status)) {
        PSLS_PROTECT_LOG("ObRegisterCallbacks failed: 0x%X", status);
        return status;
    }

    /* P4: 并发注册竞态裁决 — 输家注销自己, 恰好保留一个注册 */
    KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
    if (g_ProtectCookie == NULL) {
        g_ProtectCookie = new_cookie;
        loser_cookie    = NULL;
    } else {
        loser_cookie = new_cookie;
    }
    KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

    if (loser_cookie != NULL) {
        PSLS_PROTECT_LOG("concurrent register lost, undoing extra cookie");
        ObUnRegisterCallbacks(loser_cookie);
        return STATUS_SUCCESS;
    }

    PSLS_PROTECT_LOG("ObRegisterCallbacks OK, cookie=%p", new_cookie);
    return STATUS_SUCCESS;
}

/* ---- 由 psls_driver.c 在收到 SET_PSLS_PID IOCTL 时调用 ----
 * v4: 先在锁外完成可能阻塞的 PsLookup, 再单次加锁整体交换。
 * 历史三段式 (先装 PID 后找 EPROCESS) 的换装窗口是
 * 双重 ObDereferenceObject 蓝屏的直接根源, 已从结构上移除。 */
VOID Protect_SetTargetPid(_In_ ULONG psls_pid)
{
    KIRQL     old_irql;
    PEPROCESS new_proc = NULL;
    NTSTATUS  status;
    ULONG     i;
    BOOLEAN   already = FALSE;
    BOOLEAN   added = FALSE;

    /* ---- pid == 0: 清空整个保护集 (卸载/关闭自保护) ---- */
    if (psls_pid == 0) {
        PEPROCESS old_set[PSLS_MAX_PROTECT_PIDS];
        ULONG     old_count;

        KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
        old_count = g_PslsProcCount;
        for (i = 0; i < old_count; i++) {
            old_set[i] = g_PslsProcSet[i];
        }
        g_PslsProcCount = 0;
        for (i = 0; i < PSLS_MAX_PROTECT_PIDS; i++) {
            g_PslsProcSet[i] = NULL;
            g_PslsPidSet[i]  = 0;
        }
        g_Driver.PslsPid = 0;
        KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

        /* 锁外释放全部旧引用 (P5) */
        for (i = 0; i < old_count; i++) {
            if (old_set[i] != NULL) {
                ObDereferenceObject(old_set[i]);
            }
        }
        PSLS_PROTECT_LOG("target set cleared (%u entries)", old_count);
        return;
    }

    /* ---- pid != 0: 追加到保护集 ---- */

    /* 第一步: 锁外取 EPROCESS 引用 (PASSIVE_LEVEL, 可阻塞) */
    status = PsLookupProcessByProcessId((HANDLE)(LONG_PTR)psls_pid, &new_proc);
    if (!NT_SUCCESS(status) || new_proc == NULL) {
        PSLS_PROTECT_LOG("PsLookupProcessByProcessId(pid=%u) failed: 0x%X",
                         psls_pid, status);
        return;   /* 查找失败: 不改变现有集合 (无半成品状态) */
    }

    /* 第二步: 锁内查重 + 追加 (P2) */
    KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
    for (i = 0; i < g_PslsProcCount; i++) {
        if (g_PslsPidSet[i] == psls_pid) {
            already = TRUE;
            break;
        }
    }
    if (already) {
        /* 已在集合中: 释放本次新引用, 保持幂等 */
    } else if (g_PslsProcCount < PSLS_MAX_PROTECT_PIDS) {
        g_PslsProcSet[g_PslsProcCount] = new_proc;
        g_PslsPidSet[g_PslsProcCount]  = psls_pid;
        if (g_PslsProcCount == 0) {
            g_Driver.PslsPid = psls_pid;   /* 首个 = 主 PID (状态查询/自身放行) */
        }
        g_PslsProcCount++;
        added = TRUE;
    } else {
        PSLS_PROTECT_LOG("protect set full (%u), drop pid=%u",
                         PSLS_MAX_PROTECT_PIDS, psls_pid);
    }
    KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

    /* 第三步: 未采纳的新引用锁外释放 (P5, 无双重 deref) */
    if (!added) {
        ObDereferenceObject(new_proc);
    } else {
        PSLS_PROTECT_LOG("target set += pid=%u EPROCESS=%p (count=%u, primary=%u)",
                         psls_pid, new_proc, g_PslsProcCount, g_Driver.PslsPid);
    }
}

/* ---- 清理 (DriverUnload / SET_CONFIG 关闭自保护时调用) ---- */
VOID Protect_Cleanup(VOID)
{
    KIRQL     old_irql;
    PVOID     cookie   = NULL;
    PEPROCESS old_set[PSLS_MAX_PROTECT_PIDS];
    ULONG     old_count;
    ULONG     i;

    /* 锁内原子摘除整个保护集 (P2/P4): 与并发 SetTargetPid/Initialize 无双重操作 */
    KeAcquireSpinLock(&g_ProtectStateLock, &old_irql);
    cookie         = g_ProtectCookie;
    g_ProtectCookie = NULL;
    old_count      = g_PslsProcCount;
    for (i = 0; i < old_count; i++) {
        old_set[i] = g_PslsProcSet[i];
    }
    g_PslsProcCount = 0;
    for (i = 0; i < PSLS_MAX_PROTECT_PIDS; i++) {
        g_PslsProcSet[i] = NULL;
        g_PslsPidSet[i]  = 0;
    }
    g_Driver.PslsPid = 0;
    KeReleaseSpinLock(&g_ProtectStateLock, old_irql);

    /* P5: 注销与解引用在锁外; ObUnRegisterCallbacks 阻塞等待
     * 在途回调返回, 返回后 PreOperationCallback 不再执行 */
    if (cookie != NULL) {
        ObUnRegisterCallbacks(cookie);
    }
    for (i = 0; i < old_count; i++) {
        if (old_set[i] != NULL) {
            ObDereferenceObject(old_set[i]);
        }
    }

    /* 审计桶清零 (回调已停, 锁内访问不会再发生) */
    HandleAudit_Cleanup();

    PSLS_PROTECT_LOG("cleanup done (%u entries)", old_count);
}
