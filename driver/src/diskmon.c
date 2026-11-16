/*
 * diskmon.c — 磁盘引导扇区(MBR/VBR/ESP)写入实时拦截 — 内核模块
 *
 * [背景]
 *   用户态 MBRProtector 采用 1 秒轮询 + 事后回滚, 篡改发生后仍存在
 *   "检测前引导扇区已被改写" 的窗口。本模块在 Ring 0 直接附加到
 *   物理磁盘原始设备 (\Device\HarddiskN\DRN), 在 IRP_MJ_WRITE 层面
 *   拒绝受保护引导扇区区域的非授权写入:
 *   - 拦截时机: 数据真正落盘之前 (事前拦截, 不是事后回滚)
 *   - 保护范围: 默认第 0 扇区 (MBR, 512B); 用户态下发
 *       PSLS_IOCTL_SET_BOOT_PROTECT 后可扩展为任意区域集
 *       (各分区 VBR/ESP 引导扇区 = 分区起始 LBA * 512, 长度 512,
 *       由用户态遍历卷 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 计算)
 *   - 放行策略: 内核模式请求 / PSLS 自身进程 (回滚写回) 放行
 *   - 事件上报: 拦截后投递 PSLS_EVT_DISK_BLOCKED 供用户态告警
 *
 * [旁路拦截 (v1.2)]
 *   仅拦截 IRP_MJ_WRITE 时, 恶意样本可绕过:
 *     - IOCTL_DISK_SET_DRIVE_LAYOUT(_EX) / DELETE_DRIVE_LAYOUT: 通过
 *       DeviceIoControl 直接改写 MBR 分区表 / 清空分区表 (走 IRP_MJ_DEVICE_CONTROL)
 *     - IOCTL_DISK_SET_PARTITION_INFO(_EX): 改写分区类型字节
 *     - IOCTL_SCSI_PASS_THROUGH(_DIRECT): 下发原始 SCSI WRITE 命令直写磁盘
 *       (bootkit 常用, 不产生 IRP_MJ_WRITE)
 *   因此本模块同样拦截 IRP_MJ_DEVICE_CONTROL 中上述「布局改写」类 IOCTL,
 *   并对 SCSI 直写 CDB 做 WRITE 命令解析, 目标 LBA 与保护区域重叠即拒绝。
 *   reason: 3 = 旁路改写 (布局 IOCTL / SCSI WRITE 命令)
 *
 * [关键纪律]
 *   D1. 附加列表、开关状态与区域表用自旋锁保护, 锁仅在
 *       DiskMon_Initialize 初始化一次
 *   D2. 每个 IRP 恰好完成一次: 拦截路径 IoCompleteRequest; 放行路径
 *       IoSkipCurrentIrpStackLocation + IoCallDriver (不得重复完成)
 *   D3. 附加设备时镜像下层磁盘设备的 I/O 缓冲方式 (DO_DIRECT_IO / DO_BUFFERED_IO),
 *       否则创建出的顶层过滤设备若未声明缓冲方式, 用户态写盘 IRP 会以
 *       METHOD_NEITHER 下发而被 disk.sys 拒绝
 *   D4. 引导扇区写入拦截仅针对 UserMode 请求; 保护开关关闭时全部放行
 *   D5. 卸载顺序固定: 先关开关, 再标记全部过滤设备 Attached=FALSE 断链
 *       (在途 IRP 见 DELETE_PENDING 直接完成, 避免对已拆卸下层 IoCallDriver),
 *       然后 IoDetachDevice + IoDeleteDevice
 *   D6. 区域表读取在自旋锁短临界区内 (拦截路径每个写 IRP 遍历 ≤32 项,
 *       开销 <1μs 可接受; 区域表只由用户态启动时整体替换, 更新频率极低)
 *   D7. 区域判定用区间重叠 (offset, offset+length) ∩ [start, start+len),
 *       非纯起点命中 — 大块写入覆盖保护扇区也能拦截; 负偏移
 *       (FILE_USE_FILE_POINTER_POSITION = -1 等) 一律不拦截
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include "psls_shared.h"

#define PSLS_DISKMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-DiskMon] " fmt "\n", ##__VA_ARGS__)

/* 外部 (psls_driver.c / protect.c 提供) */
extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
extern ULONG Protect_GetTargetPid(VOID);

/* ---- 配置 ---- */
#define PSLS_DISKMON_MAX_DISKS     8       /* 支持最多 8 块物理磁盘 */
#define PSLS_DISKMON_SECTOR_SIZE   512
#define PSLS_DISKMON_MAX_REGIONS   PSLS_BOOT_REGION_MAX  /* 区域表上限 (与协议一致) */

/* ---- 旁路改写 IOCTL (v1.2) ----
 * 恶意样本通过 DeviceIoControl 修改 MBR/分区表, 走 IRP_MJ_DEVICE_CONTROL
 * 而非 IRP_MJ_WRITE, 必须一并拦截。值来自 ntdddisk.h (x64 固定):
 *   IOCTL_DISK_SET_DRIVE_LAYOUT    = 0x0007C030  写整个驱动器布局(含 MBR)
 *   IOCTL_DISK_SET_DRIVE_LAYOUT_EX = 0x0007C048  EX 变体
 *   IOCTL_DISK_DELETE_DRIVE_LAYOUT = 0x0007C020  清空分区表
 *   IOCTL_DISK_SET_PARTITION_INFO  = 0x0007C02C  改分区类型字节
 *   IOCTL_DISK_SET_PARTITION_INFO_EX = 0x0007C040 EX 变体
 * SCSI 原始写命令通道 (ntddscsi.h):
 *   IOCTL_SCSI_PASS_THROUGH        = 0x0004D004
 *   IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014
 */
#define PSLS_IOCTL_DISK_SET_DRIVE_LAYOUT       ((ULONG)0x0007C030UL)
#define PSLS_IOCTL_DISK_SET_DRIVE_LAYOUT_EX    ((ULONG)0x0007C048UL)
#define PSLS_IOCTL_DISK_DELETE_DRIVE_LAYOUT    ((ULONG)0x0007C020UL)
#define PSLS_IOCTL_DISK_SET_PARTITION_INFO     ((ULONG)0x0007C02CUL)
#define PSLS_IOCTL_DISK_SET_PARTITION_INFO_EX  ((ULONG)0x0007C040UL)
#define PSLS_IOCTL_SCSI_PASS_THROUGH           ((ULONG)0x0004D004UL)
#define PSLS_IOCTL_SCSI_PASS_THROUGH_DIRECT    ((ULONG)0x0004D014UL)

/* SCSI_PASS_THROUGH / _DIRECT (x64 布局, 与 sptdlib.h 用户态一致)。
 * 仅用于解析 CDB (只读 SystemBuffer 头部), 不访问数据缓冲区。 */
typedef struct _PSLS_SCSI_PASS_THROUGH {
    USHORT  Length;
    UCHAR   ScsiStatus;
    UCHAR   PathId;
    UCHAR   TargetId;
    UCHAR   Lun;
    UCHAR   CdbLength;
    UCHAR   SenseInfoLength;
    UCHAR   DataIn;
    ULONG   DataTransferLength;
    ULONG   TimeOutValue;
    ULONG64 DataBufferOffset;
    ULONG   SenseInfoOffset;
    UCHAR   Cdb[16];
} PSLS_SCSI_PASS_THROUGH;

typedef struct _PSLS_SCSI_PASS_THROUGH_DIRECT {
    USHORT  Length;
    UCHAR   ScsiStatus;
    UCHAR   PathId;
    UCHAR   TargetId;
    UCHAR   Lun;
    UCHAR   CdbLength;
    UCHAR   SenseInfoLength;
    UCHAR   DataIn;
    ULONG   DataTransferLength;
    ULONG   TimeOutValue;
    PVOID   DataBuffer;
    ULONG   SenseInfoOffset;
    UCHAR   Cdb[16];
} PSLS_SCSI_PASS_THROUGH_DIRECT;

/* SCSI DataIn 值 (scsi.h) */
#define PSLS_SCSI_IOCTL_DATA_OUT         0
#define PSLS_SCSI_IOCTL_DATA_UNSPECIFIED 2

/* ---- 每个过滤设备的状态 (IoCreateDevice 分配的设备扩展) ---- */
typedef struct _PSLS_DISKMON_EXT {
    PDEVICE_OBJECT  LowerDevice;    /* 附加点下方的磁盘设备 (IoCallDriver 目标) */
    PDEVICE_OBJECT  FilterDevice;   /* 自引用 (清理阶段 IoDeleteDevice 用) */
    BOOLEAN         Attached;       /* 是否仍处于附加状态 (卸载断链用) */
    WCHAR           DeviceName[PSLS_MAX_PATH]; /* "\Device\HarddiskN\DRN" */
} PSLS_DISKMON_EXT;

/* ---- 受保护扇区区域 (D6: 自旋锁保护, 仅启动时整体替换) ---- */
typedef struct _PSLS_DISKMON_REGION {
    BOOLEAN       Active;
    LARGE_INTEGER Start;            /* 盘内字节偏移 */
    LARGE_INTEGER Length;
} PSLS_DISKMON_REGION;

/* ---- 全局 (g_DiskMonLock 仅在 DiskMon_Initialize 初始化一次 — D1) ---- */
static PDEVICE_OBJECT    g_DiskFilterDevs[PSLS_DISKMON_MAX_DISKS];
static KSPIN_LOCK        g_DiskMonLock;
static volatile LONG     g_DiskMonEnabled = 0;   /* 1=拦截生效 */
static volatile LONG     g_DiskRegionCount = 0;  /* 有效区域数 (≤ MAX_REGIONS) */
static PSLS_DISKMON_REGION g_DiskRegions[PSLS_DISKMON_MAX_REGIONS];

/* ---- 事件上报 ---- */
static VOID DiskPostBlockEvent(_In_ PSLS_DISKMON_EXT *ext,
                               _In_ ULONG64 offset,
                               _In_ UCHAR reason,
                               _In_ ULONG pid)
{
    PSLS_DISK_BLOCK_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.pid    = pid;
    payload.reason = reason;   /* 1=MBR(第0扇区), 2=VBR/ESP 受保护区域 */
    payload.offset = offset;
    RtlCopyMemory(payload.device, ext->DeviceName,
                  sizeof(payload.device));

    EventPool_Post(&payload, sizeof(payload), PSLS_EVT_DISK_BLOCKED);
}

/* ---- 区域命中判定 (D7: 区间重叠; 负偏移不拦截) ----
 * D6: 内部自旋锁短临界区读取区域表 (区域只在启动时整体替换)。 */
static BOOLEAN DiskRegionHit(_In_ LARGE_INTEGER offset, _In_ ULONG length)
{
    KIRQL old_irql;
    ULONG i;
    ULONG count;
    BOOLEAN hit = FALSE;

    if (offset.QuadPart < 0) {
        return FALSE;   /* -1 (USE_FILE_POINTER) / -2 (WRITE_TO_EOF) 等 */
    }
    if (length == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
    count = (ULONG)g_DiskRegionCount;
    for (i = 0; i < count; i++) {
        PSLS_DISKMON_REGION *r = &g_DiskRegions[i];
        LONGLONG r_end;
        LONGLONG w_end;

        if (!r->Active || r->Length.QuadPart <= 0) {
            continue;
        }
        r_end = r->Start.QuadPart + r->Length.QuadPart;
        w_end = offset.QuadPart + (LONGLONG)length;
        /* 重叠 = 写起点 < 区域终点 且 区域起点 < 写终点 */
        if (offset.QuadPart < r_end && r->Start.QuadPart < w_end) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_DiskMonLock, old_irql);
    return hit;
}

/* 命中原因: offset==0 (MBR 默认区域) → 1, 其他区域 (VBR/ESP) → 2 */
static UCHAR DiskRegionReason(_In_ LARGE_INTEGER offset)
{
    return (offset.QuadPart == 0) ? 1 : 2;
}

/* ---- SCSI WRITE 命令 CDB 解析 (v1.2 旁路拦截) ----
 * 从 SCSI CDB 提取写命令的目标 LBA 与块数。仅识别标准写命令操作码,
 * 其余一律不拦 (避免误伤读/无数据传输命令)。返回 TRUE 表示"这是一个
 * 带数据写盘方向的目标区域可直接判定的写命令"。 */
static BOOLEAN DiskScsiWriteLba(_In_reads_(16) const UCHAR *cdb,
                                _In_ UCHAR cdb_len,
                                _Out_ ULONG64 *lba,
                                _Out_ ULONG *blocks)
{
    ULONG64 n = 0;
    ULONG   b = 0;
    ULONG   i;

    if (cdb == NULL) {
        return FALSE;
    }

    switch (cdb[0]) {
    case 0x0A:   /* WRITE(6) */
        if (cdb_len < 6) {
            return FALSE;
        }
        n = (ULONG64)((ULONG)(cdb[1] & 0x1F) << 16 |
                      (ULONG)cdb[2] << 8 |
                      (ULONG)cdb[3]);
        b = (cdb[4] == 0) ? 256UL : (ULONG)cdb[4];
        break;

    case 0x2A:   /* WRITE(10) */
    case 0x2E:   /* WRITE VERIFY(10) */
    case 0x41:   /* WRITE SAME(10) */
        if (cdb_len < 10) {
            return FALSE;
        }
        n = ((ULONG64)cdb[2] << 24) | ((ULONG64)cdb[3] << 16) |
            ((ULONG64)cdb[4] << 8) | (ULONG64)cdb[5];
        b = ((ULONG)cdb[7] << 8) | (ULONG)cdb[8];
        break;

    case 0xAA:   /* WRITE(12) */
    case 0xAE:   /* WRITE VERIFY(12) */
        if (cdb_len < 12) {
            return FALSE;
        }
        n = ((ULONG64)cdb[2] << 24) | ((ULONG64)cdb[3] << 16) |
            ((ULONG64)cdb[4] << 8) | (ULONG64)cdb[5];
        b = ((ULONG)cdb[6] << 24) | ((ULONG)cdb[7] << 16) |
            ((ULONG)cdb[8] << 8) | (ULONG)cdb[9];
        break;

    case 0x8A:   /* WRITE(16) */
    case 0x8E:   /* WRITE AND VERIFY(16) */
    case 0x93:   /* WRITE SAME(16) */
    case 0x9A:   /* WRITE STREAM(16) */
    case 0x9C:   /* WRITE ATOMIC(16) */
        if (cdb_len < 16) {
            return FALSE;
        }
        for (i = 0; i < 8; i++) {
            n = (n << 8) | (ULONG64)cdb[2 + i];
        }
        b = ((ULONG)cdb[10] << 24) | ((ULONG)cdb[11] << 16) |
            ((ULONG)cdb[12] << 8) | (ULONG)cdb[13];
        break;

    case 0x7F:   /* WRITE SAME(32) — LBA 在字节 12..19, 块数在 28..31 */
        if (cdb_len < 32) {
            return FALSE;
        }
        for (i = 0; i < 8; i++) {
            n = (n << 8) | (ULONG64)cdb[12 + i];
        }
        b = ((ULONG)cdb[28] << 24) | ((ULONG)cdb[29] << 16) |
            ((ULONG)cdb[30] << 8) | (ULONG)cdb[31];
        break;

    default:
        return FALSE;
    }

    if (b == 0) {
        return FALSE;   /* 0 块 = 无数据写入 */
    }
    *lba = n;
    *blocks = b;
    return TRUE;
}

/* SCSI 直写判定: 解析 IOCTL_SCSI_PASS_THROUGH(_DIRECT) 的 SystemBuffer,
 * 命中保护区域返回 TRUE 并回填写偏移。仅对 UserMode 写方向 (DATA_OUT /
 * UNSPECIFIED) 且传输长度 > 0 的 CDB 做解析, 其余放行 (不误伤读取)。 */
static BOOLEAN DiskScsiBlocksRegion(_In_opt_ PVOID system_buffer,
                                    _In_ ULONG in_len,
                                    _In_ ULONG ioctl_code,
                                    _Out_ ULONG64 *offset_out)
{
    const UCHAR *cdb;
    UCHAR cdb_len;
    UCHAR data_in;
    ULONG xfer;
    ULONG64 lba;
    ULONG blocks;
    LARGE_INTEGER off;
    ULONG64 byte_len;

    if (system_buffer == NULL || offset_out == NULL) {
        return FALSE;
    }
    if (ioctl_code == PSLS_IOCTL_SCSI_PASS_THROUGH) {
        const PSLS_SCSI_PASS_THROUGH *spt =
            (const PSLS_SCSI_PASS_THROUGH *)system_buffer;
        if (in_len < sizeof(PSLS_SCSI_PASS_THROUGH)) {
            return FALSE;
        }
        cdb_len = spt->CdbLength;
        data_in = spt->DataIn;
        xfer    = spt->DataTransferLength;
        cdb     = spt->Cdb;
    } else {
        const PSLS_SCSI_PASS_THROUGH_DIRECT *spt =
            (const PSLS_SCSI_PASS_THROUGH_DIRECT *)system_buffer;
        if (in_len < sizeof(PSLS_SCSI_PASS_THROUGH_DIRECT)) {
            return FALSE;
        }
        cdb_len = spt->CdbLength;
        data_in = spt->DataIn;
        xfer    = spt->DataTransferLength;
        cdb     = spt->Cdb;
    }

    if (cdb_len > 16) {
        cdb_len = 16;
    }
    /* 只处理写方向命令 */
    if (data_in != PSLS_SCSI_IOCTL_DATA_OUT &&
        data_in != PSLS_SCSI_IOCTL_DATA_UNSPECIFIED) {
        return FALSE;
    }
    if (xfer == 0) {
        return FALSE;
    }
    if (!DiskScsiWriteLba(cdb, cdb_len, &lba, &blocks)) {
        return FALSE;
    }
    /* 按 512B 扇区换算盘内字节偏移 (与其余保护粒度一致) */
    if (lba > (ULONG64)(MAXLONGLONG / PSLS_DISKMON_SECTOR_SIZE)) {
        return FALSE;
    }
    off.QuadPart = (LONGLONG)(lba * PSLS_DISKMON_SECTOR_SIZE);
    byte_len = (ULONG64)blocks * PSLS_DISKMON_SECTOR_SIZE;
    if (byte_len > (ULONG64)MAXULONG) {
        byte_len = (ULONG64)MAXULONG;
    }
    if (!DiskRegionHit(off, (ULONG)byte_len)) {
        return FALSE;
    }
    *offset_out = (ULONG64)off.QuadPart;
    return TRUE;
}

/* ---- 布局改写 IOCTL 判定 (v1.2) ---- */
static BOOLEAN DiskLayoutRewriteIoctl(_In_ ULONG code)
{
    return (code == PSLS_IOCTL_DISK_SET_DRIVE_LAYOUT ||
            code == PSLS_IOCTL_DISK_SET_DRIVE_LAYOUT_EX ||
            code == PSLS_IOCTL_DISK_DELETE_DRIVE_LAYOUT ||
            code == PSLS_IOCTL_DISK_SET_PARTITION_INFO ||
            code == PSLS_IOCTL_DISK_SET_PARTITION_INFO_EX);
}

/* ---- 主分发 (D2 单一完成纪律) ----
 *
 * 注意: PDEVICE_OBJECT 没有 MajorFunction 数组成员 (MajorFunction 属于
 * 驱动对象, 同一驱动的所有设备共用); 因此本分发由 psls_driver.c 的
 * DriverUnifiedDispatch 根据 DiskMon_IsFilterDevice() 识别后调用。 */
NTSTATUS DiskMon_DispatchIrp(_In_ PDEVICE_OBJECT DeviceObject,
                             _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    PSLS_DISKMON_EXT   *ext   = (PSLS_DISKMON_EXT *)DeviceObject->DeviceExtension;
    PDEVICE_OBJECT      lower = NULL;
    BOOLEAN             attached = FALSE;
    KIRQL               old_irql;
    LARGE_INTEGER       offset;

    /* ---- 引导扇区写拦截 (事前拦截, 非事后回滚) ---- */
    if (stack->MajorFunction == IRP_MJ_WRITE &&
        Irp->RequestorMode == UserMode &&      /* D4: 仅用户态请求 */
        g_DiskMonEnabled) {                    /* 原子读 (volatile LONG) */
        offset = stack->Parameters.Write.ByteOffset;
        if (DiskRegionHit(offset, stack->Parameters.Write.Length)) {
            /* PSLS 自身进程 (MBRProtector 回滚写回备份) 始终放行 */
            ULONG cur_pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (cur_pid != Protect_GetTargetPid()) {
                PSLS_DISKMON_LOG(
                    "BLOCK boot region write: offset=%I64u len=%lu pid=%lu device=%ws",
                    (ULONGLONG)offset.QuadPart,
                    stack->Parameters.Write.Length, cur_pid, ext->DeviceName);
                DiskPostBlockEvent(ext, (ULONG64)offset.QuadPart,
                                   DiskRegionReason(offset), cur_pid);
                InterlockedIncrement(&g_Driver.BlockedCount);
                Irp->IoStatus.Status      = STATUS_ACCESS_DENIED;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    /* ---- 旁路改写拦截 (v1.2): 布局 IOCTL / SCSI 直写命令 ----
     * 恶意样本绕过 IRP_MJ_WRITE 的通道: DeviceIoControl 改写 MBR/分区表,
     * 或 SCSI passthrough 下发原始 WRITE 命令。仅用户态且开关开启时生效,
     * PSLS 自身进程放行; 布局改写不携带写偏移, 一律视为命中引导区。 */
    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
        Irp->RequestorMode == UserMode &&      /* D4: 仅用户态请求 */
        g_DiskMonEnabled) {
        ULONG   code = stack->Parameters.DeviceIoControl.IoControlCode;
        ULONG   cur_pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        BOOLEAN do_block = FALSE;
        ULONG64 block_offset = 0;

        if (DiskLayoutRewriteIoctl(code)) {
            do_block = TRUE;
            block_offset = 0;   /* 布局改写直接影响 MBR 起始 */
        } else if (code == PSLS_IOCTL_SCSI_PASS_THROUGH ||
                   code == PSLS_IOCTL_SCSI_PASS_THROUGH_DIRECT) {
            do_block = DiskScsiBlocksRegion(
                Irp->AssociatedIrp.SystemBuffer,
                stack->Parameters.DeviceIoControl.InputBufferLength,
                code, &block_offset);
        }

        if (do_block && cur_pid != Protect_GetTargetPid()) {
            PSLS_DISKMON_LOG(
                "BLOCK boot layout/scsi write: ioctl=0x%08X pid=%lu device=%ws",
                code, cur_pid, ext->DeviceName);
            DiskPostBlockEvent(ext, (ULONG64)block_offset,
                               3 /* reason=旁路改写 */, cur_pid);
            InterlockedIncrement(&g_Driver.BlockedCount);
            Irp->IoStatus.Status      = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* ---- 普通 IRP: 转发到下层 (D2) ---- */
    KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
    attached = ext->Attached;
    if (attached) {
        lower = ext->LowerDevice;
    }
    KeReleaseSpinLock(&g_DiskMonLock, old_irql);

    if (!attached || lower == NULL) {
        /* 卸载断链中 — 不得对已拆卸设备 IoCallDriver */
        Irp->IoStatus.Status      = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(lower, Irp);
}

/* ---- 设备识别 (psls_driver.c 统一分发调用) ----
 * 遍历过滤设备表判断该设备对象是否为 diskmon 附加的磁盘过滤设备。
 * 自旋锁单次持有, 全程只读比较指针。 */
BOOLEAN DiskMon_IsFilterDevice(_In_ PDEVICE_OBJECT DeviceObject)
{
    ULONG   i;
    KIRQL   old_irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
    for (i = 0; i < PSLS_DISKMON_MAX_DISKS; i++) {
        if (g_DiskFilterDevs[i] == DeviceObject) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_DiskMonLock, old_irql);
    return found;
}

/* 卸载时不处理: 其余 IRP 类型全部转交下层 (通过 DiskMon_DispatchIrp 的转发路径) */

/* ---- 设备名构造 ----
 * ntstrsafe 的 RtlStringCchPrintfW 族在 /kernel 链接下会解析到 CRT
 * (__stdio_common_vswprintf), 而驱动不链接 CRT。设备名格式固定为
 * "\Device\HarddiskN\DRN", 直接拼接 (disk_index 0~7 单数字)。 */
static VOID DiskBuildDeviceName(_Out_ WCHAR *buf, _In_ ULONG disk_index)
{
    RtlCopyMemory(buf, L"\\Device\\Harddisk", 16 * sizeof(WCHAR)); /* 15 字符 + NUL */
    buf[15] = L'0' + (WCHAR)(disk_index % 10);
    RtlCopyMemory(buf + 16, L"\\DR", 4 * sizeof(WCHAR));           /* 3 字符 + NUL */
    buf[19] = L'0' + (WCHAR)(disk_index % 10);
    buf[20] = L'\0';
}

/* ---- 模块接口 ---- */

NTSTATUS DiskMon_Initialize(VOID)
{
    NTSTATUS   status = STATUS_SUCCESS;
    ULONG      i;
    ULONG      attached_count = 0;

    PAGED_CODE();

    KeInitializeSpinLock(&g_DiskMonLock);
    InterlockedExchange(&g_DiskMonEnabled, 0);       /* 默认关闭, 由用户态开启 */
    RtlZeroMemory(g_DiskFilterDevs, sizeof(g_DiskFilterDevs));

    /* 默认区域: 第 0 扇区 MBR (与 v1.0 set_mbr_protect 行为一致)。
     * SET_BOOT_PROTECT 下发后整体替换为分区 VBR/ESP 区域集 */
    RtlZeroMemory(g_DiskRegions, sizeof(g_DiskRegions));
    g_DiskRegions[0].Active = TRUE;
    g_DiskRegions[0].Start.QuadPart   = 0;
    g_DiskRegions[0].Length.QuadPart  = PSLS_DISKMON_SECTOR_SIZE;
    InterlockedExchange(&g_DiskRegionCount, 1);

    /* 逐一附加物理磁盘原始设备 "\Device\HarddiskN\DRN" */
    for (i = 0; i < PSLS_DISKMON_MAX_DISKS; i++) {
        WCHAR              name_buf[64];
        UNICODE_STRING     raw_name;
        PDEVICE_OBJECT     target_obj = NULL;
        PFILE_OBJECT       file_obj   = NULL;
        PDEVICE_OBJECT     filter_obj = NULL;
        PSLS_DISKMON_EXT  *ext;
        PDEVICE_OBJECT     attached_to;
        KIRQL              old_irql;

        DiskBuildDeviceName(name_buf, i);
        RtlInitUnicodeString(&raw_name, name_buf);

        /* 打开目标磁盘设备 (返回引用)。DesiredAccess 传 FILE_READ_ATTRIBUTES
         * 即可获得对象引用 (仅用于 attach, 不做直接 I/O); 传 FILE_ALL_ACCESS
         * 可能因盘被独占/权限不足而失败导致磁盘过滤未附加 */
        status = IoGetDeviceObjectPointer(&raw_name, FILE_READ_ATTRIBUTES,
                                          &file_obj, &target_obj);
        if (!NT_SUCCESS(status)) {
            continue;   /* 磁盘不存在或不可访问 */
        }

        /* 创建过滤设备 (顶层) */
        status = IoCreateDevice(g_Driver.DriverObject,
                                sizeof(PSLS_DISKMON_EXT), NULL,
                                FILE_DEVICE_DISK, 0, FALSE, &filter_obj);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(target_obj);
            if (file_obj != NULL) ObDereferenceObject(file_obj);
            continue;
        }

        ext = (PSLS_DISKMON_EXT *)filter_obj->DeviceExtension;
        RtlZeroMemory(ext, sizeof(*ext));
        ext->FilterDevice = filter_obj;
        RtlStringCchCopyW(ext->DeviceName, PSLS_MAX_PATH, name_buf);

        /* D3: 镜像下层缓冲方式, 保证写 IRP 以正确方法下发 */
        filter_obj->Flags |=
            (target_obj->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO));

        /* 注意: 不分发例程在设备对象上设置 —— MajorFunction 属于共享
         * 的 PSLS DriverObject, 所有设备共用; 磁盘过滤设备的 IRP 由
         * psls_driver.c 的 DriverUnifiedDispatch 按设备识别后转到
         * DiskMon_DispatchIrp (见文件头注释)。 */

        attached_to = IoAttachDeviceToDeviceStack(filter_obj, target_obj);
        if (attached_to == NULL) {
            PSLS_DISKMON_LOG("IoAttachDeviceToDeviceStack failed: %ws", name_buf);
            IoDeleteDevice(filter_obj);
            ObDereferenceObject(target_obj);
            if (file_obj != NULL) ObDereferenceObject(file_obj);
            continue;
        }

        KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
        ext->LowerDevice = attached_to;
        ext->Attached    = TRUE;
        KeReleaseSpinLock(&g_DiskMonLock, old_irql);

        g_DiskFilterDevs[i] = filter_obj;
        attached_count++;

        /* 附加完成, 释放 IoGetDeviceObjectPointer 的引用 */
        ObDereferenceObject(target_obj);
        if (file_obj != NULL) ObDereferenceObject(file_obj);

        /* 附加后即可对外可见 (之前不允许删改) */
        filter_obj->Flags &= ~DO_DEVICE_INITIALIZING;

        PSLS_DISKMON_LOG("attached to %ws", name_buf);
    }

    PSLS_DISKMON_LOG("DiskMon initialized: %lu disk(s) attached (MBR write-block OFF)",
                     attached_count);
    return STATUS_SUCCESS;
}

VOID DiskMon_Cleanup(VOID)
{
    ULONG i;

    PAGED_CODE();

    /* D5 第一步: 先关拦截开关 */
    InterlockedExchange(&g_DiskMonEnabled, 0);

    for (i = 0; i < PSLS_DISKMON_MAX_DISKS; i++) {
        PDEVICE_OBJECT    filter_obj = g_DiskFilterDevs[i];
        PSLS_DISKMON_EXT *ext;
        PDEVICE_OBJECT    lower;
        BOOLEAN           attached;
        KIRQL             old_irql;

        if (filter_obj == NULL) {
            continue;
        }

        ext = (PSLS_DISKMON_EXT *)filter_obj->DeviceExtension;

        /* D5 第二步: 标记断链 (在途 IRP 将走 DELETE_PENDING, D2) */
        KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
        attached = ext->Attached;
        lower    = ext->LowerDevice;
        ext->Attached = FALSE;
        KeReleaseSpinLock(&g_DiskMonLock, old_irql);

        if (attached && lower != NULL) {
            IoDetachDevice(lower);
        }
        IoDeleteDevice(filter_obj);
        g_DiskFilterDevs[i] = NULL;
    }

    PSLS_DISKMON_LOG("DiskMon cleaned up");
}

VOID DiskMon_SetEnabled(_In_ BOOLEAN enabled)
{
    InterlockedExchange(&g_DiskMonEnabled, enabled ? 1 : 0);
    PSLS_DISKMON_LOG("MBR write-block %s", enabled ? "ENABLED" : "disabled");
}

/* ---- 整体替换受保护扇区区域表 (PSLS_IOCTL_SET_BOOT_PROTECT) ----
 * 区域为盘内字节偏移区间, 由用户态遍历卷 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
 * 得到各分区起始偏移 (VBR/ESP) 后下发。region 条目 length=0 视为无效忽略。
 * 保持默认第 0 扇区区域 (MBR) 在表中, 保证 MBR 兜底拦截不丢失。 */
NTSTATUS DiskMon_SetBootRegions(_In_ const PSLS_BOOT_REGION *regions,
                                _In_ ULONG count,
                                _In_ BOOLEAN enabled)
{
    KIRQL old_irql;
    ULONG i;
    ULONG n = 0;

    if (regions == NULL || count == 0) {
        /* 空下发: 回落 MBR 默认区域, 仍由 enabled 控制开关 */
        KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
        RtlZeroMemory(g_DiskRegions, sizeof(g_DiskRegions));
        g_DiskRegions[0].Active = TRUE;
        g_DiskRegions[0].Start.QuadPart  = 0;
        g_DiskRegions[0].Length.QuadPart = PSLS_DISKMON_SECTOR_SIZE;
        g_DiskRegionCount = 1;
        KeReleaseSpinLock(&g_DiskMonLock, old_irql);
    } else {
        KeAcquireSpinLock(&g_DiskMonLock, &old_irql);
        RtlZeroMemory(g_DiskRegions, sizeof(g_DiskRegions));
        for (i = 0; i < count && n < PSLS_DISKMON_MAX_REGIONS; i++) {
            if (regions[i].length == 0) {
                continue;   /* 无效条目跳过 */
            }
            g_DiskRegions[n].Active          = TRUE;
            g_DiskRegions[n].Start.QuadPart  = (LONGLONG)regions[i].start_offset;
            g_DiskRegions[n].Length.QuadPart = (LONGLONG)regions[i].length;
            n++;
        }
        /* 确保 MBR (第 0 扇区) 兜底区域仍在表内 */
        {
            BOOLEAN has_mbr = FALSE;
            for (i = 0; i < n; i++) {
                if (g_DiskRegions[i].Start.QuadPart == 0 &&
                    g_DiskRegions[i].Length.QuadPart >= PSLS_DISKMON_SECTOR_SIZE) {
                    has_mbr = TRUE;
                    break;
                }
            }
            if (!has_mbr && n < PSLS_DISKMON_MAX_REGIONS) {
                g_DiskRegions[n].Active          = TRUE;
                g_DiskRegions[n].Start.QuadPart  = 0;
                g_DiskRegions[n].Length.QuadPart = PSLS_DISKMON_SECTOR_SIZE;
                n++;
            }
        }
        g_DiskRegionCount = (LONG)n;
        KeReleaseSpinLock(&g_DiskMonLock, old_irql);
    }

    DiskMon_SetEnabled(enabled);
    PSLS_DISKMON_LOG("boot regions updated: %lu region(s), %s",
                     (ULONG)g_DiskRegionCount, enabled ? "ENABLED" : "disabled");
    return STATUS_SUCCESS;
}

BOOLEAN DiskMon_IsEnabled(VOID)
{
    return (InterlockedCompareExchange(&g_DiskMonEnabled, 0, 0) != 0) ? TRUE : FALSE;
}