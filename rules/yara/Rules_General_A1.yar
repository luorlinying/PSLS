/*
    PSLS General YARA Rules A1
    通用恶意软件检测规则集
    覆盖：测试签名、木马、后门、勒索软件、下载器、注入器等
*/

import "pe"

// EICAR 标准测试文件
rule EICAR_Test_File
{
    meta:
        description = "EICAR Standard Anti-Virus Test File"
        author = "PSLS"
        severity = "high"
        date = "2026-01-01"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// 小体积 PE 文件提示（info 级，仅用于提醒 PE 分析引擎更仔细检查）
// 真正的恶意检测由 Trojan_Generic_Strings / Ransomware_Generic 等 high 级规则负责
// 降为 info 级：避免和签名降级守卫重复，也不会单独触发 suspicious
rule Suspicious_PE_EntryPoint
{
    meta:
        description = "小体积 PE 文件提示（< 100KB）"
        author = "PSLS"
        severity = "info"
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz at 0 and $pe and filesize < 100KB
}

// 常见 RAT/木马字符串特征
rule Trojan_Generic_Strings
{
    meta:
        description = "常见木马/RAT字符串特征"
        author = "PSLS"
        severity = "high"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "rundll32.exe" nocase
        $s4 = "regsvr32 /s /u /i:" nocase
        $s5 = "schtasks /create" nocase
        $s6 = "net user /add" nocase
        $s7 = "vssadmin delete" nocase
        $s8 = "bcdedit /set" nocase
        $s9 = "wbadmin delete" nocase
        $s10 = "ShadowCopy" nocase
    condition:
        3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
}

// 勒索软件特征
rule Ransomware_Generic
{
    meta:
        description = "勒索软件通用特征"
        author = "PSLS"
        severity = "high"
    strings:
        $r1 = ".encrypted" nocase
        $r2 = ".locked" nocase
        $r3 = ".crypt" nocase
        $r4 = "YOUR FILES ARE ENCRYPTED" nocase
        $r5 = "Pay the ransom" nocase
        $r6 = "Restore your files" nocase
        $r7 = "vssadmin delete shadows" nocase
        $r8 = "wbadmin delete catalog" nocase
    condition:
        2 of ($r1, $r2, $r3, $r4, $r5, $r6, $r7, $r8) and filesize < 5MB
}

// 下载器特征
rule Downloader_Generic
{
    meta:
        description = "下载器通用特征"
        author = "PSLS"
        severity = "medium"
    strings:
        $d1 = "WinHttpDownloadFile" nocase
        $d2 = "URLDownloadToFile" nocase
        $d3 = "WinHttpRequest" nocase
        $d4 = "HttpOpenRequest" nocase
        $d5 = "InternetReadFile" nocase
    condition:
        2 of ($d1, $d2, $d3, $d4, $d5) and filesize < 2MB
}

// 代码注入特征
rule Code_Injection_Generic
{
    meta:
        description = "代码注入通用特征"
        author = "PSLS"
        severity = "high"
    strings:
        $i1 = "CreateRemoteThread" nocase
        $i2 = "VirtualAllocEx" nocase
        $i3 = "WriteProcessMemory" nocase
        $i4 = "NtUnmapViewOfSection" nocase
        $i5 = "QueueUserAPC" nocase
        $i6 = "SetWindowsHookEx" nocase
        $i7 = "VirtualProtect" nocase
    condition:
        3 of ($i1, $i2, $i3, $i4, $i5, $i6, $i7) and filesize < 2MB
}

// 挖矿软件特征
rule Cryptominer_Generic
{
    meta:
        description = "加密货币挖矿软件通用特征"
        author = "PSLS"
        severity = "medium"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "stratum+ssl://" nocase
        $m3 = "xmrig" nocase
        $m4 = "cpuminer" nocase
        $m5 = "cryptonight" nocase
        $m6 = "monero" nocase
        $m7 = "pool.minexmr" nocase
    condition:
        2 of ($m1, $m2, $m3, $m4, $m5, $m6, $m7)
}

// 可疑的 PowerShell 脚本
rule Suspicious_PowerShell
{
    meta:
        description = "可疑PowerShell脚本特征"
        author = "PSLS"
        severity = "medium"
    strings:
        $p1 = "ExecutionPolicy Bypass" nocase
        $p2 = "DownloadString" nocase
        $p3 = "DownloadFile" nocase
        $p4 = "Invoke-Expression" nocase
        $p5 = "IEX (" nocase
        $p6 = "-WindowStyle Hidden" nocase
        $p7 = "-NoProfile" nocase
    condition:
        3 of ($p1, $p2, $p3, $p4, $p5, $p6, $p7) and filesize < 1MB
}

// 可疑的 VBS 脚本
rule Suspicious_VBScript
{
    meta:
        description = "可疑VBS脚本特征"
        author = "PSLS"
        severity = "medium"
    strings:
        $v1 = "CreateObject(\"WScript.Shell\")" nocase
        $v2 = "CreateObject(\"Scripting.FileSystemObject\")" nocase
        $v3 = "WScript.Sleep" nocase
        $v4 = "MSXML2.XMLHTTP" nocase
        $v5 = "ADODB.Stream" nocase
        $v6 = "Shell.Application" nocase
    condition:
        3 of ($v1, $v2, $v3, $v4, $v5, $v6) and filesize < 1MB
}

// 恶搞程序通用特征
rule Joke_Prank_Generic
{
    meta:
        description = "恶搞程序通用特征：鼠标控制、系统参数修改、屏幕翻转、阻断输入等"
        author = "PSLS"
        severity = "medium"
        date = "2026-07-30"
    strings:
        // 鼠标控制 API
        $j1 = "SetCursorPos" nocase
        $j2 = "SwapMouseButton" nocase
        $j3 = "ShowCursor" nocase
        $j4 = "ClipCursor" nocase
        $j5 = "mouse_event" nocase
        // 系统参数/显示修改 API
        $j6 = "SystemParametersInfoA" nocase
        $j7 = "SystemParametersInfoW" nocase
        $j8 = "ChangeDisplaySettingsA" nocase
        $j9 = "ChangeDisplaySettingsW" nocase
        $j10 = "ChangeDisplaySettingsExA" nocase
        $j11 = "ChangeDisplaySettingsExW" nocase
        // 阻断/干扰输入
        $j12 = "BlockInput" nocase
        $j13 = "keybd_event" nocase
        $j14 = "SendInput" nocase
        // 恶搞字符串
        $j15 = "just a joke" nocase
        $j16 = "prank" nocase
        $j17 = "haha" nocase
        $j18 = "gotcha" nocase
        $j19 = "scare" nocase
        // 壁纸/屏保相关参数
        $j20 = "SPI_SETDESKWALLPAPER" nocase
        $j21 = "SPI_SETSCREENSAVETIMEOUT" nocase
        // 注销/锁屏
        $j22 = "ExitWindowsEx" nocase
        $j23 = "LockWorkStation" nocase
    condition:
        // 需要至少 2 个恶搞相关 API/字符串同时出现
        2 of ($j1, $j2, $j3, $j4, $j5, $j6, $j7, $j8, $j9, $j10, $j11, $j12, $j13, $j14,
               $j15, $j16, $j17, $j18, $j19, $j20, $j21, $j22, $j23) and filesize < 5MB
}
