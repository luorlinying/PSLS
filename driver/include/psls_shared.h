/*
 * psls_shared.h — PSLS 内核驱动与用户态服务的共享协议定义
 *
 * 这是唯一同时被内核 (.sys) 和用户态 (.exe/.py) 引用的头文件。
 * 所有结构体必须显式对齐 (PACKED) 且严格保持布局稳定，
 * 否则内核/用户态之间的 IOCTL 数据交换会错位。
 *
 * 版本: 1.0.0
 */

#ifndef PSLS_SHARED_H
#define PSLS_SHARED_H

#include <stdint.h>

/* 注意: 本头文件同时被内核源文件 (.c) 与 Python 用户态 (ctypes) 引用。
 * 内核端已各自包含 <ntddk.h> 提供所需类型，因此此处不得直接引入用户态
 * <windows.h> —— 否则内核编译会因混入 heapapi/synchapi 等用户态头而报错。
 * 仅当定义了 PSLS_DRIVER_BUILD(内核编译) 时才引入 WDK 头并声明驱动全局。
 */

#ifdef PSLS_DRIVER_BUILD
#include <ntddk.h>

/* 未文档化/未在 ntddk.h 声明的 ntoskrnl 导出函数 — 手动声明 */
NTKERNELAPI UINT32 PsGetProcessSessionId(_In_ PEPROCESS Process);
NTKERNELAPI PEPROCESS PsGetProcessParent(_In_ PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(_In_ PEPROCESS Process);
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId,
                                                _Out_ PEPROCESS *Process);

/* WDK 28000 已移除 RtlFindUnicodeSubstring, 这里自行实现大小写不敏感子串匹配 */
__forceinline PVOID PslsFindUnicodeSubstring(
    _In_ PUNICODE_STRING String,
    _In_ PUNICODE_STRING Substring)
{
    if (!String || !Substring || !String->Buffer || !Substring->Buffer) return NULL;
    if (Substring->Length == 0) return String->Buffer;
    if (Substring->Length > String->Length) return NULL;

    ULONG n = String->Length / sizeof(WCHAR);
    ULONG m = Substring->Length / sizeof(WCHAR);
    WCHAR *s = String->Buffer;
    WCHAR *p = Substring->Buffer;

    for (ULONG i = 0; i + m <= n; i++) {
        ULONG j;
        for (j = 0; j < m; j++) {
            if (RtlUpcaseUnicodeChar(s[i + j]) != RtlUpcaseUnicodeChar(p[j])) {
                break;
            }
        }
        if (j == m) {
            /* 返回匹配位置 */
            return (PVOID)(s + i);
        }
    }
    return NULL;
}

/* 驱动全局状态 PSLS_DRIVER_GLOBALS 定义于本文件末尾 PSLS_DRIVER_CONFIG
 * 完整定义之后 (内含按值成员 PSLS_DRIVER_CONFIG Config, 需完整类型)。
 * 各监控模块通过下方 extern 声明引用 g_Driver。 */

/* 进程访问权限常量 — 内核模式不包含 winnt.h, 这里按 Windows 定义补齐 */
#define PROCESS_TERMINATE          (0x0001)
#define PROCESS_CREATE_THREAD      (0x0002)
#define PROCESS_SET_SESSION_ID     (0x0004)

/* RtlInitializeObjectAttributes — winnt.h(用户态) 里的宏, 内核模式补齐 */
#ifndef RtlInitializeObjectAttributes
#define RtlInitializeObjectAttributes( p, n, a, r, s ) \
    do { \
        (p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
        (p)->RootDirectory = (r); \
        (p)->Attributes = (a); \
        (p)->ObjectName = (n); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)
#endif
#define PROCESS_VM_OPERATION       (0x0008)
#define PROCESS_VM_READ            (0x0010)
#define PROCESS_VM_WRITE           (0x0020)
#define PROCESS_DUP_HANDLE         (0x0040)
#define PROCESS_CREATE_PROCESS     (0x0080)
#define PROCESS_SET_QUOTA          (0x0100)
#define PROCESS_SET_INFORMATION    (0x0200)
#define PROCESS_QUERY_INFORMATION  (0x0400)
#define PROCESS_SUSPEND_RESUME     (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION   (0x2000)
#define DEBUG_PROCESS_EX           (0xFFF)
#define DEBUG_ON_PROCESS           (0x00000001)

/* 进程注入疑似性访问位 — 句柄审计 (protect.c) 判定"打开目标进程为何"时相交用。
 * 含注入常用的内存读写/建线程/挂起/调试位。纯 PROCESS_QUERY_* 不属注入特征。 */
#define PROCESS_INJECT_AUDIT_MASK ( \
    PROCESS_VM_OPERATION       | \
    PROCESS_VM_READ            | \
    PROCESS_VM_WRITE           | \
    PROCESS_CREATE_THREAD      | \
    PROCESS_SUSPEND_RESUME     | \
    DEBUG_ON_PROCESS            \
)
#endif /* PSLS_DRIVER_BUILD */

/* -------------------------------------------------------------------- */
/* 驱动基本信息                                                          */
/* -------------------------------------------------------------------- */

#define PSLS_DRIVER_VERSION_MAJOR    1
#define PSLS_DRIVER_VERSION_MINOR    0
#define PSLS_DRIVER_VERSION_PATCH    0

#define PSLS_DEVICE_NAME             L"\\Device\\PSLS"
#define PSLS_DOS_DEVICE_NAME         L"\\DosDevices\\PSLS"
#define PSLS_SYMLINK_NAME            L"PSLS"

/* -------------------------------------------------------------------- */
/* WFP callout/sublayer/filter GUID (固定不变, 用于注册/注销配对)          */
/* -------------------------------------------------------------------- */

/* PSLS_WFP_CALLOUT_KEY_V4 = {a1b2c3d4-1234-5678-9abc-def012345678} */
#define PSLS_WFP_CALLOUT_KEY_V4 \
    ((GUID){ 0xa1b2c3d4, 0x1234, 0x5678, { 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78 } })

/* PSLS_WFP_SUBLAYER_KEY = {b2c3d4e5-2345-6789-abcd-ef0123456789} */
#define PSLS_WFP_SUBLAYER_KEY \
    ((GUID){ 0xb2c3d4e5, 0x2345, 0x6789, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } })

/* PSLS_WFP_FILTER_KEY_V4 = {c3d4e5f6-3456-789a-bcde-f0123456789a} */
#define PSLS_WFP_FILTER_KEY_V4 \
    ((GUID){ 0xc3d4e5f6, 0x3456, 0x789a, { 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a } })

/* -------------------------------------------------------------------- */
/* IOCTL 定义 (CTL_CODE 宏)                                             */
/* -------------------------------------------------------------------- */

#ifndef CTL_CODE
#define CTL_CODE(device_type, function, method, access) \
    (((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method))
#endif

#define FILE_DEVICE_PSLS    0x8000

/* METHOD_BUFFERED: 最安全简单的 I/O 方法，内核自动做双向缓冲区拷贝 */
#define METHOD_BUFFERED     0
#define FILE_ANY_ACCESS     0

/* 功能号分配 */
#define PSLS_IOCTL_QUERY_STATUS     CTL_CODE(FILE_DEVICE_PSLS, 0x001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_GET_VERSION      CTL_CODE(FILE_DEVICE_PSLS, 0x002, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 配置 */
#define PSLS_IOCTL_SET_CONFIG       CTL_CODE(FILE_DEVICE_PSLS, 0x010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_GET_CONFIG       CTL_CODE(FILE_DEVICE_PSLS, 0x011, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_SET_PSLS_PID     CTL_CODE(FILE_DEVICE_PSLS, 0x012, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 事件池操作 — 用户态消费驱动产生的事件 */
#define PSLS_IOCTL_POLL_EVENTS      CTL_CODE(FILE_DEVICE_PSLS, 0x020, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_ACK_EVENT        CTL_CODE(FILE_DEVICE_PSLS, 0x021, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 执行动作 — 用户态决定拦截/放行后下发指令 */
#define PSLS_IOCTL_BLOCK_PROCESS    CTL_CODE(FILE_DEVICE_PSLS, 0x030, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_ALLOW_PROCESS    CTL_CODE(FILE_DEVICE_PSLS, 0x031, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_TERMINATE_PROC   CTL_CODE(FILE_DEVICE_PSLS, 0x032, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_BLOCK_REG_KEY    CTL_CODE(FILE_DEVICE_PSLS, 0x033, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_ALLOW_REG_KEY    CTL_CODE(FILE_DEVICE_PSLS, 0x034, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 安装目录保护 — minifilter 拒绝外部进程对受保护目录的写入/删除/重命名/截断
 * SET: 输入缓冲区 = NT 设备路径 (UTF-16LE, \0 结尾, 如
 *      "\Device\HarddiskVolume3\Program Files\PSLS")
 * CLEAR: 无输入，解除保护（PSLS 正常退出/被保护进程退出时自动调用） */
#define PSLS_IOCTL_SET_PROTECTED_DIR    CTL_CODE(FILE_DEVICE_PSLS, 0x035, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PSLS_IOCTL_CLEAR_PROTECTED_DIR  CTL_CODE(FILE_DEVICE_PSLS, 0x036, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 受保护目录内的"豁免子树" —— 用于安装目录下需要外部进程可写的子目录
 * （典型：{app}\Sandboxie —— 沙箱自身的 SbieSvc/Start.exe/盒内进程要写自己的文件，
 *  不能被"安装目录防改"误挡）。
 * SET: 输入缓冲区 = NT 设备路径 (UTF-16LE, \0 结尾)；无输入到场亦安全（视为清空）。
 * ABI: 新增 IOCTL 功能号（0x03D，0x037 已被 MBR 保护占用），不修改既有结构与命令语义。 */
#define PSLS_IOCTL_SET_EXEMPT_DIR       CTL_CODE(FILE_DEVICE_PSLS, 0x03D, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 引导扇区(MBR)写保护 — diskmon 内核实时拦截 (v1.0 基础能力)
 * SET: 输入缓冲区 = PSLS_MBR_PROTECT_CMD {enabled}，
 *      驱动附加到 \Device\HarddiskN\DRN 上，启用后拒绝用户态非 PSLS 进程
 *      对第 0 扇区的写入（STATUS_ACCESS_DENIED）并上报 PSLS_EVT_DISK_BLOCKED。
 *      PSLS 自身进程（restore 回滚写回）始终放行。 */
#define PSLS_IOCTL_SET_MBR_PROTECT      CTL_CODE(FILE_DEVICE_PSLS, 0x037, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 引导扇区区域写保护 — diskmon 从"仅第 0 扇区"扩展为多区域 (v1.1)
 * SET: 输入缓冲区 = PSLS_SET_BOOT_PROTECT_CMD 定长结构，
 *      一次性替换驱动内的受保护扇区区域表 (count ≤ PSLS_BOOT_REGION_MAX)。
 *      区域为盘内字节偏移区间 (如 MBR=0..512、各分区 VBR=分区起始*512..+512、
 *      ESP 引导扇区等)。写入 IRP 与任一区域重叠即拒绝 (PSLS 自身放行)。
 *      未下发区域时保留 v1.0 默认行为 (仅第 0 扇区 512B)。 */
#define PSLS_IOCTL_SET_BOOT_PROTECT     CTL_CODE(FILE_DEVICE_PSLS, 0x038, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 引导文件 (bootmgr/BCD/EFI 等) 写保护 — minifilter 实时拦截 (v1.1)
 * SET: 输入缓冲区 = PSLS_SET_BOOT_FILES_CMD 定长结构，
 *      一次性替换引导文件保护路径列表 (count ≤ PSLS_BOOT_FILE_MAX, NT 设备路径)。
 *      外部进程对这些文件的写入/删除/重命名/截断在 pre-operation 阶段被拒绝
 *      (STATUS_ACCESS_DENIED) 并上报 PSLS_EVT_FILE_BLOCKED (reason=4)。
 *      放行白名单: PSLS 自身 + TrustedInstaller/TiWorker (Windows 更新
 *      legit 重写引导文件) + System/内核请求/分页 I/O。 */
#define PSLS_IOCTL_SET_BOOT_FILES       CTL_CODE(FILE_DEVICE_PSLS, 0x039, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 动态 PRE 进程拦截名单 (升级1: 内核事件驱动)
 * SET: 输入缓冲区 = PSLS_SET_KILLLIST 定长结构。由用户态把 "已知高危路径
 *      子串" 下发到内核, procmon 在进程创建 PRE 阶段实时否决 (CreationStatus
 *      = STATUS_ACCESS_DENIED), 消除"1s 轮询窗口 + TOCTOU"竞态。
 *      REPLACE: 整体替换动态名单(配合内置 g_KillList 保底语义)。
 *      CLEAR  : 清空动态名单(保留内置)。 */
#define PSLS_IOCTL_SET_KILLLIST         CTL_CODE(FILE_DEVICE_PSLS, 0x03A, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* v8: 动态 PRE 命令行拦截名单 — 用户态下发"高危命令行子串"，procmon 在
 * 进程创建 PRE 阶段对 CreateInfo->CommandLine 实时否决（CreationStatus =
 * STATUS_ACCESS_DENIED），命令行型攻击（reg delete 蜂巢 / del \windows /
 * vssadmin delete shadows …）在**任何代码执行前**被掐断——用户态 EK 快车道
 * 是"创建后追杀"，短命 cmd /c 子命令常已执行完毕（EK 不及时实锤）。
 * 复用 PSLS_KILLLIST_ENTRY/PSLS_SET_KILLLIST_CMD 线格式（pattern 语义）。
 * 匹配以 PSLS_USERMODE_ACTIVE() + 名单非空为前提（fail-open）。 */
#define PSLS_IOCTL_SET_CMDKILLLIST      CTL_CODE(FILE_DEVICE_PSLS, 0x03E, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 写前影子备份 (阶段二: 零窗口勒索回滚)
 * SET_SHADOW_CONFIG: 输入 = PSLS_SHADOW_CONFIG_CMD (定长), 可选在结构体尾部
 *   追加 uint32 dir_count + PSLS_SHADOW_DIR_ENTRY dirs[count] (UTF-16LE),
 *   用于把"影子触发范围"覆盖到用户受保护目录 (沿用既有受保护目录匹配逻辑)。
 *   驱动在 PreWrite/PreSetInfo 同步保存文件"写前原像"到 <shadow_root>\<gen>\
 *   <path_hash>; 世代号变化即清空去重集合。 */
#define PSLS_IOCTL_SET_SHADOW_CONFIG    CTL_CODE(FILE_DEVICE_PSLS, 0x03B, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* QUERY_SHADOW_STATS: 输出 = PSLS_SHADOW_STATS (备份/跳过/命中/失败计数) */
#define PSLS_IOCTL_QUERY_SHADOW_STATS   CTL_CODE(FILE_DEVICE_PSLS, 0x03C, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 测试/诊断 */
#define PSLS_IOCTL_TEST_CALLBACK    CTL_CODE(FILE_DEVICE_PSLS, 0x0F0, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* -------------------------------------------------------------------- */
/* 事件类型                                                              */
/* -------------------------------------------------------------------- */

typedef enum _PSLS_EVENT_TYPE {
    PSLS_EVT_PROCESS_CREATE     = 0x01,   /* 进程刚创建（挂起态，可拦截） */
    PSLS_EVT_PROCESS_DELETE     = 0x02,   /* 进程退出                    */
    PSLS_EVT_REG_PRE_SET_VALUE  = 0x10,   /* 注册表值即将被写入          */
    PSLS_EVT_REG_PRE_CREATE_KEY = 0x11,   /* 注册表键即将被创建          */
    PSLS_EVT_REG_PRE_DELETE_KEY = 0x12,   /* 注册表键即将被删除          */
    PSLS_EVT_IMAGE_LOAD         = 0x20,   /* DLL/EXE 映像加载到内存      */
    PSLS_EVT_HANDLE_AUDIT      = 0x21,   /* 进程句柄打开审计（OB_CALLBACKS）*/
    PSLS_EVT_BLOCK_RESULT      = 0x30,   /* 内核已执行拦截的结果回传    */
    PSLS_EVT_FILE_BLOCKED      = 0x40,   /* minifilter 拦截了文件写入   */
    PSLS_EVT_FILE_SHADOWED     = 0x41,   /* 写前影子备份结果 (阶段二)   */
    PSLS_EVT_NET_BLOCKED       = 0x50,   /* WFP 拦截了网络连接          */
    PSLS_EVT_DISK_BLOCKED      = 0x60,   /* diskmon 拦截了引导扇区写入  */
} PSLS_EVENT_TYPE;

typedef enum _PSLS_ACTION {
    PSLS_ACT_UNKNOWN    = 0,
    PSLS_ACT_ALLOW      = 1,   /* 放行（默认） */
    PSLS_ACT_BLOCK      = 2,   /* 内核层面拒绝操作 */
    PSLS_ACT_TERMINATE  = 3,   /* 立即终止进程 */
    PSLS_ACT_QUARANTINE = 4,   /* 标记隔离（供用户态参考） */
} PSLS_ACTION;

/* -------------------------------------------------------------------- */
/* 通用事件头 — 所有事件共用                                             */
/* -------------------------------------------------------------------- */

#pragma pack(push, 1)

typedef struct _PSLS_EVENT_HEADER {
    uint32_t    event_id;       /* 驱动生成的唯一 ID */
    uint8_t     event_type;     /* PSLS_EVENT_TYPE */
    uint8_t     reserved;
    uint16_t    flags;          /* 标志位（异步/需立即响应等） */
    uint64_t    timestamp_ns;   /* 内核获取的时间戳 (KeQueryPerformanceCounter * 100) */
    uint32_t    payload_size;   /* 后续 payload 的字节数 */
} PSLS_EVENT_HEADER;

/* -------------------------------------------------------------------- */
/* 事件 payload — 进程创建                                               */
/* -------------------------------------------------------------------- */

#define PSLS_MAX_PATH  512
#define PSLS_MAX_CMD   1024

typedef struct _PSLS_PROCESS_CREATE_PAYLOAD {
    uint32_t    process_id;
    uint32_t    parent_pid;
    uint32_t    session_id;
    int32_t     exit_status;        /* 0 = 尚未退出 */
    uint8_t     image_path_usr[PSLS_MAX_PATH];   /* 进程图像路径 (UTF-16LE, 以 \0 结尾) */
    uint8_t     command_line[PSLS_MAX_CMD];       /* 命令行 (UTF-16LE) */
    uint8_t     parent_path[PSLS_MAX_PATH];       /* 父进程路径 */
    int32_t     create_status;      /* NTSTATUS of process creation */
    uint8_t     signature_level;    /* 代码签名等级 */
    uint8_t     is_signed;          /* 0/1 */
    uint8_t     pad[6];
} PSLS_PROCESS_CREATE_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — 注册表操作                                            */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_REG_PRE_KEY_PAYLOAD {
    uint32_t    pid;
    uint8_t     full_path[PSLS_MAX_PATH];  /* 完整注册表路径 (UTF-16LE) */
    uint8_t     value_name[PSLS_MAX_PATH]; /* 值名 (UTF-16LE), 键创建时为空 */
    uint8_t     value_type;                /* REG_SZ/REG_DWORD 等 */
    uint8_t     pad[7];
    int64_t     value_size;                /* 写入值字节数 */
    /* 注意: 不携带值数据本体（可能很大），只传元信息 */
} PSLS_REG_PRE_KEY_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — 映像加载                                               */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_IMAGE_LOAD_PAYLOAD {
    uint32_t    pid;
    uint64_t    image_base;       /* 映像加载基址 */
    uint32_t    image_size;
    uint8_t     image_path[PSLS_MAX_PATH]; /* DLL/EXE 路径 (UTF-16LE) */
    uint8_t     signature_level;
    uint8_t     is_signed;
    uint8_t     pad[6];
    uint32_t    load_count;       /* 聚合窗口内该 PID 的映像加载次数（首条=1） */
} PSLS_IMAGE_LOAD_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — 进程句柄打开审计 (OB_CALLBACKS)                         */
/* -------------------------------------------------------------------- */

/* 24B, packed。count 为聚合窗口内同类 (source,target) 打开的累计次数 */
typedef struct _PSLS_HANDLE_AUDIT_PAYLOAD {
    uint32_t    source_pid;       /* 发起打开者 */
    uint32_t    target_pid;       /* 被打开目标进程 */
    uint32_t    desired_access;   /* 与 PROCESS_INJECT_AUDIT_MASK 相交后的位 */
    uint32_t    count;            /* 30s 窗口聚合次数 */
    uint64_t    first_ts_ns;      /* 首见时间戳 */
} PSLS_HANDLE_AUDIT_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — 内核拦截结果回传                                        */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_BLOCK_RESULT_PAYLOAD {
    uint32_t    event_id;           /* PSLS_EVT_BLOCK_RESULT */
    uint64_t    timestamp_ns;       /* 时间戳 (纳秒) */
    uint32_t    source;             /* 1=procmon_pre_block, 2=regmon_block */
    uint32_t    pid;                /* 被拦截的进程 PID */
    uint8_t     path[PSLS_MAX_PATH];/* 进程图像路径或注册表路径 (UTF-16LE) */
} PSLS_BLOCK_RESULT_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — minifilter 文件写入拦截                                */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_FILE_BLOCK_PAYLOAD {
    uint32_t    pid;                /* 写文件的进程 PID */
    uint32_t    write_count;        /* 该进程短时间内写入次数 */
    uint8_t     file_path[PSLS_MAX_PATH]; /* 被拦截的文件路径 (UTF-16LE) */
    uint8_t     reason;             /* 1=批量写入, 2=受保护文件, 3=可疑扩展名, 4=引导文件保护, 5=批量改后缀, 6=批量删除 */
    uint8_t     pad[3];
} PSLS_FILE_BLOCK_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — 写前影子备份结果 (阶段二)                              */
/* -------------------------------------------------------------------- */

/* 影子根/触发目录最大字符数 (含结尾 '\0')。 */
#define PSLS_SHADOW_ROOT_CHARS   260
/* 单次 SET_SHADOW_CONFIG 可下发的影子触发目录上限。 */
#define PSLS_SHADOW_MAX_DIRS     8

/* status 字段取值 */
#define PSLS_SHADOW_STATUS_OK      0    /* 备份成功 (影子内容=写前原像) */
#define PSLS_SHADOW_STATUS_SKIP    1    /* 主动跳过 (去重/超限)         */
#define PSLS_SHADOW_STATUS_MISS    2    /* 未备份即放行 (IRQL 不允许)   */
#define PSLS_SHADOW_STATUS_FAIL    3    /* 备份失败                     */

/* reason 字段取值 */
#define PSLS_SHADOW_REASON_OK        0
#define PSLS_SHADOW_REASON_IRQL      1  /* IRQL > PASSIVE_LEVEL         */
#define PSLS_SHADOW_REASON_TOO_LARGE 2  /* 单文件超上限                 */
#define PSLS_SHADOW_REASON_TIMEOUT   3  /* 复制超时                     */
#define PSLS_SHADOW_REASON_IO_ERROR  4  /* 读源/写影子出错              */
#define PSLS_SHADOW_REASON_DEDUP     5  /* 本世代已备份过               */

typedef struct _PSLS_SHADOW_PAYLOAD {
    uint8_t     orig_path[PSLS_MAX_PATH];   /* 原始文件路径 (NT, UTF-16LE) */
    uint8_t     shadow_path[PSLS_MAX_PATH]; /* 影子文件路径 (NT, UTF-16LE) */
    uint64_t    orig_size;                  /* 原始文件字节数 */
    uint32_t    status;                     /* PSLS_SHADOW_STATUS_* */
    uint32_t    reason;                     /* PSLS_SHADOW_REASON_* */
    uint32_t    pid;                        /* 触发写入的进程 PID */
} PSLS_SHADOW_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — WFP 网络连接拦截                                       */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_NET_BLOCK_PAYLOAD {
    uint32_t    pid;                /* 发起连接的进程 PID */
    uint32_t    remote_ip;          /* 远程 IP (IPv4, 网络字节序) */
    uint16_t    remote_port;        /* 远程端口 */
    uint16_t    protocol;           /* 6=TCP, 17=UDP */
    uint8_t     direction;          /* 1=出站, 2=入站 */
    uint8_t     reason;             /* 1=黑名单IP, 2=可疑端口, 3=进程禁止联网 */
    uint8_t     pad[2];
    uint8_t     process_path[PSLS_MAX_PATH]; /* 进程路径 (UTF-16LE) */
} PSLS_NET_BLOCK_PAYLOAD;

/* -------------------------------------------------------------------- */
/* 事件 payload — diskmon 引导扇区写入拦截                               */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_DISK_BLOCK_PAYLOAD {
    uint32_t    pid;                /* 写盘进程 PID */
    uint32_t    reason;             /* 1=MBR(第0扇区), 2=VBR/ESP 受保护区域,
                                       3=旁路改写(布局IOCTL/SCSI WRITE 命令) */
    uint64_t    offset;             /* 写偏移 (盘内字节偏移); 布局改写时为 0 */
    uint8_t     device[PSLS_MAX_PATH]; /* 设备名 (如 "\Device\Harddisk0\DR0", UTF-16LE) */
} PSLS_DISK_BLOCK_PAYLOAD;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_MBR_PROTECT — 引导扇区写保护开关               */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_MBR_PROTECT_CMD {
    uint8_t     enabled;            /* 1=启用内核写拦截, 0=关闭 */
    uint8_t     pad[3];
} PSLS_MBR_PROTECT_CMD;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_BOOT_PROTECT — 引导扇区区域写保护 (diskmon)    */
/* -------------------------------------------------------------------- */

#define PSLS_BOOT_REGION_MAX  32

typedef struct _PSLS_BOOT_REGION {
    uint8_t     disk_index;         /* 物理盘索引 (0..7): \Device\HarddiskN\DRN */
    uint8_t     pad[3];
    uint64_t    start_offset;       /* 盘内字节偏移 (常用 = 扇区号 * 512) */
    uint64_t    length;             /* 保护长度 (字节); 0 = 忽略该条目 */
} PSLS_BOOT_REGION;

/* 定长结构 (METHOD_BUFFERED 一次性下发)。count 为有效条目数,
 * 未用条目必须清零。驱动侧整体替换区域表。 */
typedef struct _PSLS_SET_BOOT_PROTECT_CMD {
    uint32_t    count;               /* regions[] 有效条目数 (≤ PSLS_BOOT_REGION_MAX) */
    uint8_t     enabled;             /* 1=启用区域写拦截, 0=关闭 (保留区域表) */
    uint8_t     pad[3];
    PSLS_BOOT_REGION regions[PSLS_BOOT_REGION_MAX];
} PSLS_SET_BOOT_PROTECT_CMD;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_BOOT_FILES — 引导文件写保护 (filemon)          */
/* -------------------------------------------------------------------- */

#define PSLS_BOOT_FILE_MAX    32

typedef struct _PSLS_BOOT_FILE_ENTRY {
    uint8_t     path[PSLS_MAX_PATH]; /* NT 设备路径 (UTF-16LE, '\0' 结尾),
                                        如 "\Device\HarddiskVolume3\Boot\BCD" */
} PSLS_BOOT_FILE_ENTRY;

typedef struct _PSLS_SET_BOOT_FILES_CMD {
    uint32_t    count;               /* files[] 有效条目数 (≤ PSLS_BOOT_FILE_MAX) */
    uint8_t     enabled;             /* 1=启用引导文件写拦截, 0=关闭 */
    uint8_t     pad[3];
    PSLS_BOOT_FILE_ENTRY files[PSLS_BOOT_FILE_MAX];
} PSLS_SET_BOOT_FILES_CMD;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_KILLLIST — 动态 PRE 进程拦截名单 (procmon)      */
/* -------------------------------------------------------------------- */

#define PSLS_KILLLIST_MAX       64
#define PSLS_KILLLIST_VERSION   1

#define PSLS_KILLLIST_CMD_REPLACE   1   /* 整体替换动态名单 (向量替换, 保留内置) */
#define PSLS_KILLLIST_CMD_CLEAR     2   /* 清空动态名单 (保留内置 g_KillList)    */

typedef struct _PSLS_KILLLIST_ENTRY {
    uint8_t     path[PSLS_MAX_PATH];    /* 路径子串 (UTF-16LE, '\0' 结尾), 大小写不敏感匹配 */
} PSLS_KILLLIST_ENTRY;

typedef struct _PSLS_SET_KILLLIST_CMD {
    uint32_t    version;             /* PSLS_KILLLIST_VERSION */
    uint32_t    cmd;                 /* PSLS_KILLLIST_CMD_REPLACE / CLEAR */
    uint32_t    count;               /* entries[] 有效条目数 (≤ PSLS_KILLLIST_MAX) */
    uint8_t     pad[4];
    PSLS_KILLLIST_ENTRY entries[PSLS_KILLLIST_MAX];
} PSLS_SET_KILLLIST_CMD;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_GET_CONFIG / SET_CONFIG                             */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_DRIVER_CONFIG {
    uint32_t    struct_size;          /* 自身大小 (版本兼容用) */

    /* 功能开关 (1=启用, 0=禁用) */
    uint8_t     enable_proc_create;   /* 进程创建监控 */
    uint8_t     enable_proc_terminate;/* 进程创建拦截后可由内核直接终止 */
    uint8_t     enable_reg_mon;       /* 注册表监控 */
    uint8_t     enable_image_load;    /* 映像加载监控 */
    uint8_t     enable_psls_protect;  /* 保护 PSLS 自身不被终止 */
    uint8_t     enable_signature_skip;/* 有效签名进程放行 */
    uint8_t     enable_file_filter;  /* minifilter 文件写入拦截 */
    uint8_t     enable_net_filter;   /* WFP 网络连接拦截 */
    uint8_t     enable_disk_mon;     /* diskmon 引导扇区写拦截 */
    uint8_t     pad;

    /* 安全参数 */
    uint32_t    max_event_pool;       /* 事件环形缓冲大小 (默认 4096) */
    uint32_t    block_timeout_ms;     /* 等待用户态响应超时 (默认 5000) */
    uint32_t    reg_path_filter_count;/* 注册表路径过滤表条目数 */
    uint32_t    white_list_pid_count; /* 白名单 PID 数 */
} PSLS_DRIVER_CONFIG;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_PSLS_PID                                       */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_SET_PID {
    uint32_t    psls_pid;
    uint32_t    reserved;
} PSLS_SET_PID;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_POLL_EVENTS — 用户态读取事件批量                    */
/*                                                                      */
/* 输入缓冲区: 空 (不要求)                                               */
/* 输出缓冲区: PSLS_EVENT_HEADER + [payload] + ... (可变长)             */
/* -------------------------------------------------------------------- */

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_ACK_EVENT — 用户态确认已处理某事件                  */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_ACK_EVENT {
    uint32_t    event_id;
    uint8_t     action;            /* PSLS_ALLOW / PSLS_BLOCK / PSLS_TERMINATE */
    uint8_t     apply_to_similar;  /* 0=只应用这一条, 1=同进程同类型都应用 */
    uint8_t     pad[2];
} PSLS_ACK_EVENT;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_TERMINATE_PROC                                      */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_TERMINATE {
    uint32_t    pid;
    uint32_t    exit_code;        /* 默认 1 */
    uint8_t     force;            /* 1=强制终止 */
    uint8_t     pad[3];
} PSLS_TERMINATE;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_QUERY_STATUS 输出                                  */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_STATUS {
    uint32_t    driver_version;     /* 打包 MAJOR<<24 | MINOR<<16 | PATCH */
    uint32_t    proc_create_count;  /* 已触发的进程创建事件数 */
    uint32_t    reg_mon_count;      /* 已触发的注册表事件数 */
    uint32_t    image_load_count;   /* 已触发的映像加载事件数 */
    uint32_t    blocked_count;     /* 已拦截/终止总数 */
    uint32_t    psls_pid;           /* 当前被保护的 PSLS PID */
    uint8_t     proc_mon_enabled;
    uint8_t     reg_mon_enabled;
    uint8_t     image_mon_enabled;
    uint8_t     psls_protect_enabled;
    uint8_t     file_filter_enabled;
    uint8_t     net_filter_enabled;
    uint8_t     disk_mon_enabled;   /* diskmon 引导扇区写拦截是否启用 */
    uint8_t     pad;
} PSLS_STATUS;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_SET_SHADOW_CONFIG — 写前影子备份配置 (阶段二)      */
/* -------------------------------------------------------------------- */

/* 定长配置。shadow_root 为 NT 设备路径 (UTF-16LE, '\0' 结尾, 无尾 '\')。
 * 结构体尾部可选追加: uint32 dir_count + PSLS_SHADOW_DIR_ENTRY dirs[dir_count],
 * 驱动按 in_len 截断读取; 缺省时影子范围仅覆盖内核受保护目录。 */
typedef struct _PSLS_SHADOW_CONFIG_CMD {
    uint32_t    enable;                              /* 1=启用, 0=关闭 */
    uint32_t    generation_id;                       /* 世代号; 变化即清空去重集合 */
    uint16_t    shadow_root[PSLS_SHADOW_ROOT_CHARS]; /* 影子仓库根 (NT, UTF-16LE) */
} PSLS_SHADOW_CONFIG_CMD;

/* 影子触发目录条目 (SET_SHADOW_CONFIG 尾部扩展数组元素)。 */
typedef struct _PSLS_SHADOW_DIR_ENTRY {
    uint16_t    path[PSLS_SHADOW_ROOT_CHARS];        /* NT 路径 (UTF-16LE, '\0' 结尾) */
} PSLS_SHADOW_DIR_ENTRY;

/* -------------------------------------------------------------------- */
/* IOCTL: PSLS_IOCTL_QUERY_SHADOW_STATS — 写前影子备份统计              */
/* -------------------------------------------------------------------- */

typedef struct _PSLS_SHADOW_STATS {
    uint32_t    backed_up;      /* 成功备份次数 (写前原像已落盘) */
    uint32_t    skipped;        /* 跳过次数 (too_large) */
    uint32_t    missed;         /* 未备份即放行次数 (IRQL) */
    uint32_t    failed;         /* 失败次数 (timeout/io_error) */
    uint32_t    dedup_hits;     /* 命中去重次数 */
    uint32_t    generation_id;  /* 当前世代号 */
} PSLS_SHADOW_STATS;

#pragma pack(pop)

#ifdef PSLS_DRIVER_BUILD
/* 驱动全局状态 — 定义于 psls_driver.c, 供各监控模块 extern 引用。
 * 必须放在 PSLS_DRIVER_CONFIG 完整定义之后。 */
typedef struct _PSLS_DRIVER_GLOBALS {
    PDRIVER_OBJECT      DriverObject;   /* 供 minifilter FltRegisterFilter 使用 */
    PDEVICE_OBJECT      DeviceObject;
    PUNICODE_STRING     DosSymlinkName;
    PSLS_DRIVER_CONFIG  Config;

    /* 统计 (PASSIVE_LEVEL 访问，InterlockedIncrement) */
    volatile LONG       ProcCreateCount;
    volatile LONG       RegMonCount;
    volatile LONG       ImageLoadCount;
    volatile LONG       BlockedCount;

    /* PSLS 自身保护状态 */
    PVOID               PslsProcessObject;  /* PEPROCESS, ObReferenceObjectByHandle 取得 */
    ULONG               PslsPid;

    /* 动态 PRE 进程拦截名单 (升级1) — 由 IOCTL PSLS_IOCTL_SET_KILLLIST 下发,
     * procmon PRE 回调在进程创建瞬间实时匹配否决 (消除 TOCTOU)。
     * KillListLock 恰一次初始化; Post/Cleanup 不持有锁外放。 */
    PVOID               KillListStore;      /* NonPagedPool 缓冲, 定长 MAX*MAX_PATH */
    ULONG               KillListCount;      /* 当前有效条目数 (≤ PSLS_KILLLIST_MAX) */
    KSPIN_LOCK          KillListLock;       /* 保护 KillListStore/Count */

    /* v8: 动态 PRE 命令行拦截名单 — 同线格式, pattern 匹配 CreateInfo->
     * CommandLine（进程任何代码执行前否决）。复用 KillListLock。 */
    PVOID               CmdKillListStore;   /* NonPagedPool 缓冲, 定长 MAX*MAX_PATH */
    ULONG               CmdKillListCount;   /* 当前有效条目数 (≤ PSLS_KILLLIST_MAX) */
} PSLS_DRIVER_GLOBALS;

extern PSLS_DRIVER_GLOBALS g_Driver;

/* 用户态存活标志: 仅在收到 IOCTL_SET_CONFIG (用户态启动后必定下发) 时置 1。
 * 所有"拒绝"路径都必须以此为前提 —— 用户态缺席时内核只投递事件,
 * 绝不 fail-closed。否则驱动一旦被加载而 PSLS 主程序未运行, 任何
 * 命中监控路径的正常操作都会被拒 (曾导致 CLR 初始化拿到
 * STATUS_ACCESS_DENIED -> HRESULT 0x80070005, 全机 .NET 应用不可用)。*/
extern volatile LONG g_UserModeConfigured;

#define PSLS_USERMODE_ACTIVE() \
    (InterlockedCompareExchange(&g_UserModeConfigured, 0, 0) != 0)
#endif /* PSLS_DRIVER_BUILD */

#endif /* PSLS_SHARED_H */
