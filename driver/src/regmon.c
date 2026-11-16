/*
 * regmon.c — 注册表操作监控 (CmRegisterCallbackEx) — v4 重写
 *
 * [两层过滤 — 与 v3 设计一致]
 *   1. 强制阻止层 (g_ForceBlockKeys):
 *      AppInit_DLLs / BootExecute / IFEO / Winlogon\Userinit /
 *      NotificationPackages / ShellExecuteHooks 等 — 命中返回
 *      STATUS_ACCESS_DENIED, 让 ZwSetValueKey/ZwCreateKey 直接失败。
 *   2. 监控投递层 (g_SensitiveKeys):
 *      Run/RunOnce/RunServices/ImagePath/BHO 等 — 只投递事件,
 *      用户态决策。
 *
 * [v3 的两个致命缺陷 — v4 修复]
 *   R1. 回调入口的枚举范围检查写反: REG_NOTIFY_CLASS 中
 *       PreCreateKeyEx(11) > PreDeleteValueKey(3), "op < 11 || op > 3"
 *       恒为真 → v3 回调对一切操作提前返回, 注册表监控从未生效。
 *       v4 改由 switch 的 default 分支过滤未知操作。
 *   R2. ZwQueryKey 直接拿回调 Object (PCM_KEY_BODY 指针) 当 HANDLE
 *       使用 — 必须先 ObOpenObjectByPointer 换取内核句柄。
 *
 * [v4 纪律]
 *   R3. 计数统一 g_Driver.*; 事件 payload 严格按 psls_shared.h
 *       的类型-负载对应 (BLOCK_RESULT 事件用 PSLS_BLOCK_RESULT_PAYLOAD,
 *       source=2 regmon_block)
 *   R4. 强制阻止仅对用户态调用者生效 (ExGetPreviousMode==UserMode):
 *       硬拒内核组件的注册表写入可能破坏系统自身
 *   R5. PSLS 自身 (Protect_GetTargetPid) 全层放行, 与
 *       filemon/netmon 的自身豁免约定一致
 *   R6. 键名获取: 栈缓冲优先 (一次 ZwQueryKey), 溢出才堆分配,
 *       避免每次注册表操作双查询 + 堆分配的系统级开销
 *   R7. 注册/注销恰好一次 (DriverEntry / DriverUnload)
 */

#include <ntifs.h>   /* ObOpenObjectByPointer / KEY_NAME_INFORMATION (须在 ntddk 前) */
#include <ntddk.h>
#include "psls_shared.h"

#define PSLS_REGMON_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[PSLS-RegMon] " fmt "\n", ##__VA_ARGS__)

#define REGMON_POOL_TAG 'gmkP'

/* 外部 */
extern NTSTATUS EventPool_Post(_In_ PVOID payload, _In_ ULONG payload_size,
                                _In_ UCHAR event_type);
extern ULONG Protect_GetTargetPid(VOID);
/* g_Driver 已由 psls_shared.h 提供 extern 声明 */

/* ---- 全局 ---- */
static LARGE_INTEGER g_RegCallbackCookie = { 0 };
static BOOLEAN       g_RegMonRegistered  = FALSE;

/* 强制阻止: 勒索病毒持久化关键路径 (R4: 仅用户态调用者) */
static PCWSTR g_ForceBlockKeys[] = {
    L"AppInit_DLLs",
    L"BootExecute",
    L"Image File Execution Options",
    L"ImageFileExecutionOptions",
    L"NotificationPackages",
    L"ShellExecuteHooks",
    L"Winlogon\\Userinit",
    L"Winlogon\\Shell",
    NULL
};

/* 仅监控: 勒索病毒也用但合法软件也写的路径
 * (ImagePath 从强制阻止层移入: 硬拒会导致正常软件装不上服务) */
static PCWSTR g_SensitiveKeys[] = {
    L"Run", L"RunOnce", L"RunServices", L"RunServicesOnce",
    L"ImagePath",
    L"Browsers Helper Objects", L"Browser Helper Objects",
    L"CurrentVersion\\Run", L"CurrentVersion\\RunOnce",
    L"Active Setup",
    NULL
};

static BOOLEAN MatchStringArray(_In_ PCUNICODE_STRING KeyName,
                                _In_ const PCWSTR *array)
{
    ULONG i;

    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0) {
        return FALSE;
    }
    for (i = 0; array[i] != NULL; i++) {
        UNICODE_STRING kw;
        RtlInitUnicodeString(&kw, array[i]);
        if (PslsFindUnicodeSubstring((PUNICODE_STRING)KeyName, &kw) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
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

/* ---- 从回调 Object (PCM_KEY_BODY) 获取完整键路径 — R2/R6 ----
 * 栈缓冲优先: 绝大多数路径一次 ZwQueryKey 完成;
 * STATUS_BUFFER_OVERFLOW 才按 needed 堆分配重试。
 * 输出 KeyName 指向调用方提供的缓冲 (不需 NUL 结尾)。 */
static NTSTATUS GetKeyFullPath(_In_ PVOID KeyObject,
                               _Out_ PUNICODE_STRING KeyName,
                               _Out_writes_bytes_(buf_bytes) PWCHAR buf,
                               _In_ ULONG buf_bytes)
{
    NTSTATUS              status;
    HANDLE                h_key   = NULL;
    PKEY_NAME_INFORMATION kinfo   = NULL;
    PKEY_NAME_INFORMATION alloc   = NULL;
    ULONG                 needed  = 0;

    RtlZeroMemory(KeyName, sizeof(*KeyName));
    KeyName->Buffer = buf;

    /* R2: Object 是内核对象指针, 必须先换成内核句柄 */
    status = ObOpenObjectByPointer(KeyObject, OBJ_KERNEL_HANDLE, NULL, 0,
                                   NULL, KernelMode, &h_key);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    kinfo  = (PKEY_NAME_INFORMATION)buf;
    status = ZwQueryKey(h_key, KeyNameInformation, kinfo, buf_bytes, &needed);

    if (status == STATUS_BUFFER_OVERFLOW && needed > buf_bytes) {
        /* R6: 溢出才堆分配重试 */
        alloc = (PKEY_NAME_INFORMATION)ExAllocatePoolWithTag(
            PagedPool, needed, REGMON_POOL_TAG);
        if (alloc != NULL) {
            status = ZwQueryKey(h_key, KeyNameInformation, alloc, needed, &needed);
            kinfo  = alloc;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (NT_SUCCESS(status)) {
        ULONG copy_bytes = kinfo->NameLength;
        if (copy_bytes > buf_bytes) {
            copy_bytes = buf_bytes;
        }
        if (copy_bytes > 0) {
            RtlCopyMemory(buf, kinfo->Name, copy_bytes);
        }
        KeyName->Length        = (USHORT)copy_bytes;
        KeyName->MaximumLength = (USHORT)buf_bytes;
    }

    if (alloc != NULL) {
        ExFreePoolWithTag(alloc, REGMON_POOL_TAG);
    }
    ZwClose(h_key);
    return status;
}

/* ---- CmRegisterCallbackEx 回调 ---- */
static NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2)
{
    REG_NOTIFY_CLASS op;
    WCHAR            path_buf[512];       /* 1KB 栈缓冲, 覆盖绝大多数键路径 */
    UNICODE_STRING   key_name;
    ULONG            pid;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (g_Driver.Config.enable_reg_mon == 0) {
        return STATUS_SUCCESS;
    }

    /* R5: PSLS 自身放行 */
    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid != 0 && pid == Protect_GetTargetPid()) {
        return STATUS_SUCCESS;
    }

    op = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* ---- 提取键路径 (switch default 过滤未知操作 — R1) ---- */
    switch (op) {
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION_V1 info =
            (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
        if (info != NULL && info->CompleteName != NULL &&
            info->CompleteName->Buffer != NULL) {
            key_name = *info->CompleteName;
        } else {
            return STATUS_SUCCESS;
        }
        break;
    }
    case RegNtPreOpenKeyEx: {
        PREG_OPEN_KEY_INFORMATION_V1 info =
            (PREG_OPEN_KEY_INFORMATION_V1)Argument2;
        if (info != NULL && info->CompleteName != NULL &&
            info->CompleteName->Buffer != NULL) {
            key_name = *info->CompleteName;
        } else {
            return STATUS_SUCCESS;
        }
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info =
            (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info == NULL ||
            !NT_SUCCESS(GetKeyFullPath(info->Object, &key_name,
                                       path_buf, sizeof(path_buf)))) {
            return STATUS_SUCCESS;
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL ||
            !NT_SUCCESS(GetKeyFullPath(info->Object, &key_name,
                                       path_buf, sizeof(path_buf)))) {
            return STATUS_SUCCESS;
        }
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info =
            (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL ||
            !NT_SUCCESS(GetKeyFullPath(info->Object, &key_name,
                                       path_buf, sizeof(path_buf)))) {
            return STATUS_SUCCESS;
        }
        break;
    }
    default:
        return STATUS_SUCCESS;   /* 其余操作不关心 — R1 修复点 */
    }

    if (key_name.Buffer == NULL || key_name.Length == 0) {
        return STATUS_SUCCESS;
    }

    /* ---- 强制阻止层 (R4: 仅用户态调用者) ----
     * [v5 修复] 只对"写值/删值/删键"强拒, 不再拒绝
     * RegNtPreOpenKeyEx / RegNtPreCreateKeyEx。
     * 读路径被拒会让任意进程只要"读一下"这些键就拿到 ACCESS_DENIED:
     * CLR 初始化会查注册表, 命中即 HRESULT 0x80070005, 全机 .NET 应用
     * 全部不可用 (仅加载驱动、不运行 PSLS 主程序时已实测复现)。
     * 持久化拦截只需覆盖写值/删值/删键, 语义不损失。
     * [v5 修复] 另加 PSLS_USERMODE_ACTIVE() 守卫: 用户态缺席时只投递
     * 事件、不做拒绝 (fail-open), 与 filemon/procmon 一致。 */
    if (ExGetPreviousMode() == UserMode &&
        PSLS_USERMODE_ACTIVE() &&
        (op == RegNtPreSetValueKey ||
         op == RegNtPreDeleteValueKey ||
         op == RegNtPreDeleteKey) &&
        MatchStringArray(&key_name, g_ForceBlockKeys)) {

        PSLS_BLOCK_RESULT_PAYLOAD block_evt;

        PSLS_REGMON_LOG("FORCE BLOCK pid=%u op=%lu KeyName=%wZ",
                        pid, (ULONG)op, &key_name);

        RtlZeroMemory(&block_evt, sizeof(block_evt));
        block_evt.event_id = PSLS_EVT_BLOCK_RESULT;
        block_evt.source   = 2;                      /* regmon_block */
        block_evt.pid      = pid;
        CopyUnicodeToField(&key_name, block_evt.path,
                           sizeof(block_evt.path));
        EventPool_Post(&block_evt, sizeof(block_evt), PSLS_EVT_BLOCK_RESULT);

        InterlockedIncrement(&g_Driver.BlockedCount);
        InterlockedIncrement(&g_Driver.RegMonCount);

        return STATUS_ACCESS_DENIED;   /* 让 Zw*Key 调用直接失败 */
    }

    /* ---- 监控投递层: 命中敏感路径只投递事件, 放行 ---- */
    if (!MatchStringArray(&key_name, g_SensitiveKeys)) {
        return STATUS_SUCCESS;
    }

    {
        PSLS_REG_PRE_KEY_PAYLOAD payload;
        UCHAR                    evt_type = PSLS_EVT_REG_PRE_SET_VALUE;

        RtlZeroMemory(&payload, sizeof(payload));
        payload.pid = pid;
        CopyUnicodeToField(&key_name, payload.full_path,
                           sizeof(payload.full_path));

        switch (op) {
        case RegNtPreSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION info =
                (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                CopyUnicodeToField(info->ValueName, payload.value_name,
                                   sizeof(payload.value_name));
                payload.value_size = (LONG64)info->DataSize;
                payload.value_type = (UCHAR)info->Type;
            }
            break;
        }
        case RegNtPreDeleteValueKey: {
            PREG_DELETE_VALUE_KEY_INFORMATION info =
                (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                CopyUnicodeToField(info->ValueName, payload.value_name,
                                   sizeof(payload.value_name));
            }
            break;
        }
        case RegNtPreCreateKeyEx:
            evt_type = PSLS_EVT_REG_PRE_CREATE_KEY;
            break;
        case RegNtPreDeleteKey:
            evt_type = PSLS_EVT_REG_PRE_DELETE_KEY;
            break;
        default:
            break;   /* PreOpenKeyEx 沿用 SET_VALUE 类型 — v3 映射 */
        }

        InterlockedIncrement(&g_Driver.RegMonCount);
        EventPool_Post(&payload, sizeof(payload), evt_type);
    }

    return STATUS_SUCCESS;
}

/* ---- 模块公共接口 (R7) ---- */

NTSTATUS RegMon_Initialize(VOID)
{
    UNICODE_STRING alt_name = RTL_CONSTANT_STRING(L"370110");
    NTSTATUS       status;

    if (g_RegMonRegistered) {
        return STATUS_SUCCESS;
    }

    status = CmRegisterCallbackEx(RegistryCallback, &alt_name,
                                  g_Driver.DriverObject, NULL,
                                  &g_RegCallbackCookie, NULL);
    if (!NT_SUCCESS(status)) {
        PSLS_REGMON_LOG("CmRegisterCallbackEx failed: 0x%X", status);
        return status;
    }

    g_RegMonRegistered = TRUE;
    PSLS_REGMON_LOG("registered OK (force-block + monitor)");
    return STATUS_SUCCESS;
}

VOID RegMon_Cleanup(VOID)
{
    if (g_RegMonRegistered) {
        /* 注销并阻塞等待在途回调返回 */
        CmUnRegisterCallback(g_RegCallbackCookie);
        g_RegCallbackCookie.QuadPart = 0;
        g_RegMonRegistered = FALSE;
        PSLS_REGMON_LOG("callback removed");
    }
}
