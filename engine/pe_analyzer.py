import os
import struct
import math
from typing import Dict, List, Optional

from utils.hash_utils import open_with_retry

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None


class PEAnalyzer:
    """PE文件分析器

    参照 pe_scanner 增强：
    - 字节直方图特征（256维）
    - 文件/节区熵值（检测加壳/加密）
    """

    # 常见打包器特征
    PACKER_SIGNATURES = {
        'UPX': [b'UPX0', b'UPX1', b'UPX2'],
        'ASPack': [b'ASPack'],
        'PECompact': [b'PECompact'],
        'MEW': [b'MEW'],
        'FSG': [b'FSG!'],
        'Themida': [b'THEMIDA', b'WINLIC'],
        'VMProtect': [b'VMP0', b'VMP1', b'VMP2'],
        'Armadillo': [b'Armadillo'],
        'Obsidium': [b'Obsidium'],
        'ProtectPE': [b'ProtectPE'],
        'EXECryptor': [b'EXECryptor'],
        'RLPack': [b'RLPack'],
        'Neolite': [b'Neolite'],
        'WinUpack': [b'WinUpack'],
        'Yoda': [b'Yoda'],
    }

    # 可疑导入函数（仅保留恶意软件常用的危险API，移除正常程序通用API以减少误报）
    SUSPICIOUS_IMPORTS = {
        'kernel32.dll': [
            'CreateRemoteThread',
            'WriteProcessMemory',
            'ReadProcessMemory',
            'OpenProcess',
            'VirtualAllocEx',
            'VirtualFreeEx',
            'VirtualProtectEx',
            'NtCreateThreadEx',
            'TerminateProcess',
            'CreateProcessA',
            'CreateProcessW',
            'ShellExecuteA',
            'ShellExecuteW',
            'WinExec',
            'system',
            '_wsystem',
        ],
        'advapi32.dll': [
            'RegSetValueA',
            'RegSetValueW',
            'RegCreateKeyA',
            'RegCreateKeyW',
            'CryptAcquireContextA',
            'CryptAcquireContextW',
            'CryptCreateHash',
            'CryptHashData',
            'CryptDeriveKey',
        ],
        'user32.dll': [
            'FindWindowA',
            'FindWindowW',
            'SendMessageA',
            'SendMessageW',
            'PostMessageA',
            'PostMessageW',
            'SetWindowsHookExA',
            'SetWindowsHookExW',
            'GetForegroundWindow',
            # 恶搞程序常用 API
            'SetCursorPos',
            'GetCursorPos',
            'ClipCursor',
            'SystemParametersInfoA',
            'SystemParametersInfoW',
            'BlockInput',
            'SwapMouseButton',
            'ShowCursor',
            'SetDoubleClickTime',
            'keybd_event',
            'mouse_event',
            'SendInput',
            'SetWindowPos',
            'SetWindowTextA',
            'SetWindowTextW',
            'MessageBoxA',
            'MessageBoxW',
            'ChangeDisplaySettingsA',
            'ChangeDisplaySettingsW',
            'ChangeDisplaySettingsExA',
            'ChangeDisplaySettingsExW',
            'ExitWindowsEx',
            'LockWorkStation',
        ],
        'ntdll.dll': [
            'NtCreateThreadEx',
            'NtOpenProcess',
            'NtAllocateVirtualMemory',
            'NtWriteVirtualMemory',
            'NtReadVirtualMemory',
            'NtProtectVirtualMemory',
            'NtQuerySystemInformation',
            'NtQueryInformationProcess',
            'NtCreateFile',
            'NtDeleteFile',
        ],
        'psapi.dll': [
            'EnumProcesses',
            'EnumProcessModules',
            'GetModuleBaseNameA',
            'GetModuleBaseNameW',
        ],
        'shlwapi.dll': [
            'PathFindExtensionA',
            'PathFindExtensionW',
            'PathRemoveExtensionA',
            'PathRemoveExtensionW',
        ],
    }

    # 可疑节区名称（仅包含打包器/加密器/混淆器相关节区，不含.text等正常节区）
    SUSPICIOUS_SECTIONS = [
        'UPX0', 'UPX1', 'UPX2', 'ASPack', '.packed', '.crypt',
        '.vmprotect', '.themida', '.armadillo', '.obsidium',
        '.mpress', '.petite', '.neolite', '.fsg', '.rlpack',
        '.winupack', '.yoda', '.pelock', '.pecompact', '.tmd',
        '.vmp', '.vm', '.encrypted', '.encoded', '.scramble',
        '.morph', '.mutate', '.inject', '.payload', '.shellcode',
    ]

    # 危险节区特征
    DANGEROUS_SECTION_FLAGS = {
        'MEM_EXECUTE': 0x10000000,
        'MEM_WRITE': 0x00000002,
        'MEM_READ': 0x00000004,
    }

    # 系统修改类高危导入DLL（加权评分）
    SYSTEM_MODIFY_DLLS = {
        'advapi32.dll': 3,   # 注册表/服务/权限
        'ntdll.dll': 2,      # 底层系统调用
        'kernel32.dll': 1,   # 通用系统API
        'psapi.dll': 1,      # 进程枚举
        'setupapi.dll': 3,   # 驱动安装
        'cfgmgr32.dll': 3,   # 设备/驱动管理
        'winsvc.dll': 4,     # 服务控制管理器
        'userenv.dll': 2,    # 用户环境/组策略
        'secur32.dll': 2,    # LSA/安全
        'wintrust.dll': 2,   # 证书/信任（吊销证书操作）
        'imagehlp.dll': 2,   # PE操作（补丁/修改）
        'dbghelp.dll': 2,    # 调试帮助
        'iphlpapi.dll': 2,   # 网络配置修改
        'netapi32.dll': 3,   # 用户/组管理/共享
        'samlib.dll': 4,     # SAM用户数据库
        'lsasrv.dll': 4,     # LSA认证包
        'scarddlg.dll': 2,   # 智能卡操作
        'taskschd.dll': 3,   # 计划任务
        'schedcli.dll': 3,   # 计划任务客户端
        'aumid.dll': 2,      # 注册表/启动项
    }

    def analyze(self, file_path: str) -> Dict:
        """分析PE文件，返回分析结果字典"""
        result = {
            'is_pe': False,
            'packer': None,
            'suspicious_imports': [],
            'sections': [],
            'suspicious_sections': [],
            'total_score': 0,
            'severity': 'low',
            'details': [],
            'has_digital_signature': False,
            'compiler': None,
            'entropy': 0.0,
            'byte_histogram': [],
            'high_entropy_sections': [],
            # 新增PE结构特征
            'entry_point_in_text': True,   # 入口点是否在.text节
            'entry_point_section': None,   # 入口点所在节名
            'has_tls_callback': False,     # 是否有TLS回调
            'tls_callback_count': 0,       # TLS回调数量
            'has_aslr': True,              # 是否启用ASLR
            'has_dep': True,               # 是否启用DEP/NX
            'relocs_stripped': False,      # 重定位表是否被剥离
            'resource_size_ratio': 0.0,    # 资源占比（>0.7异常）
            'dll_no_exports': False,       # DLL文件无合法导出
            'import_count': 0,             # 导入DLL数量
            'system_modify_dll_count': 0,  # 系统修改类DLL导入数
            'system_modify_dll_score': 0,  # 系统修改类DLL加权分
        }

        if not os.path.isfile(file_path):
            return result

        try:
            with open_with_retry(file_path, 'rb') as f:
                file_content = f.read()

            # 检查PE签名
            if not self._is_pe_file(file_content):
                return result

            result['is_pe'] = True

            # 获取DOS头和NT头偏移
            dos_header = struct.unpack('<H', file_content[0:2])[0]
            if dos_header != 0x5A4D:  # 'MZ'
                return result

            # 获取PE头偏移
            pe_offset = struct.unpack('<I', file_content[0x3C:0x40])[0]
            if pe_offset >= len(file_content):
                return result

            # 检查PE签名
            pe_signature = file_content[pe_offset:pe_offset + 4]
            if pe_signature != b'PE\x00\x00':
                return result

            # 解析PE头
            result = self._parse_pe_header(file_content, pe_offset, result)

            # 检测打包器
            packer = self._detect_packer(file_content)
            if packer:
                result['packer'] = packer
                result['details'].append(f"检测到打包器: {packer}")

            # 分析导入表
            imports = self._parse_import_table(file_content, pe_offset)
            suspicious_imports = self._find_suspicious_imports(imports)
            result['suspicious_imports'] = suspicious_imports

            # 分析节区
            sections = self._parse_sections(file_content, pe_offset)
            result['sections'] = sections

            # 检测可疑节区
            suspicious_sections = self._find_suspicious_sections(sections)
            result['suspicious_sections'] = suspicious_sections

            # 熵值和字节直方图分析（参照 pe_scanner）
            result['entropy'] = self._calculate_entropy(file_content)
            result['byte_histogram'] = self._calculate_byte_histogram(file_content)
            result['high_entropy_sections'] = self._analyze_section_entropy(
                file_content, sections
            )

            # ---- 新增PE结构特征分析（增强查杀敏感度） ----
            self._analyze_pe_optional_header(file_content, pe_offset, result)
            self._analyze_entry_point(file_content, pe_offset, sections, result)
            self._analyze_tls_callback(file_content, pe_offset, result)
            self._analyze_resource_ratio(file_content, pe_offset, result, len(file_content))
            self._analyze_exports(file_content, pe_offset, result)

            # 统计系统修改类DLL导入（加权评分）
            imp_dll_count = len(imports)
            sys_dll_count = 0
            sys_score = 0
            for dll_name in imports:
                key = dll_name.lower() if isinstance(dll_name, str) else str(dll_name).lower()
                if key in self.SYSTEM_MODIFY_DLLS:
                    sys_dll_count += 1
                    sys_score += self.SYSTEM_MODIFY_DLLS[key]
            result['import_count'] = imp_dll_count
            result['system_modify_dll_count'] = sys_dll_count
            result['system_modify_dll_score'] = sys_score

            # 计算风险分数
            score = self._calculate_risk_score(result)
            result['total_score'] = score

            # 确定严重程度
            if score >= 100:
                result['severity'] = 'high'
            elif score >= 50:
                result['severity'] = 'medium'
            else:
                result['severity'] = 'low'

        except Exception as e:
            print(f"PE分析失败 {file_path}: {e}")

        return result

    def _is_pe_file(self, content: bytes) -> bool:
        """检查是否为PE文件"""
        if len(content) < 0x40:
            return False
        if content[0:2] != b'MZ':
            return False
        pe_offset = struct.unpack('<I', content[0x3C:0x40])[0]
        if pe_offset + 4 > len(content):
            return False
        return content[pe_offset:pe_offset + 4] == b'PE\x00\x00'

    def _parse_pe_header(self, content: bytes, pe_offset: int, result: Dict) -> Dict:
        """解析PE头信息"""
        try:
            # COFF头
            machine = struct.unpack('<H', content[pe_offset + 4:pe_offset + 6])[0]
            num_sections = struct.unpack('<H', content[pe_offset + 6:pe_offset + 8])[0]
            time_date_stamp = struct.unpack('<I', content[pe_offset + 8:pe_offset + 12])[0]
            pointer_to_symbol_table = struct.unpack('<I', content[pe_offset + 12:pe_offset + 16])[0]
            num_symbols = struct.unpack('<I', content[pe_offset + 16:pe_offset + 20])[0]
            size_of_optional_header = struct.unpack('<H', content[pe_offset + 20:pe_offset + 22])[0]
            characteristics = struct.unpack('<H', content[pe_offset + 22:pe_offset + 24])[0]

            # 检查是否为DLL
            is_dll = (characteristics & 0x2000) != 0
            is_executable = (characteristics & 0x0002) != 0

            if is_dll:
                result['details'].append("这是一个DLL文件")
            if is_executable:
                result['details'].append("这是一个可执行文件")

            # 检查数字签名
            # 修复1（原 bug：读 opt+64 实为 CheckSum 字段）→ 正确读 DataDirectory[4]
            # （证书表 RVA）：PE32 DataDir 起始 opt+96，PE32+ 起始 opt+112
            magic = struct.unpack_from('<H', content, pe_offset + 24)[0]
            if magic in (0x010B, 0x020B):
                dd_base = pe_offset + 24 + (96 if magic == 0x010B else 112)
                security_rva = struct.unpack_from('<I', content, dd_base + 16)[0]
                if security_rva != 0:
                    result['has_digital_signature'] = True
                    result['details'].append("文件包含数字签名")

        except Exception:
            pass

        return result

    def _parse_sections(self, content: bytes, pe_offset: int) -> List[Dict]:
        """解析节区表"""
        sections = []

        try:
            # 获取COFF头中的节区数量
            num_sections = struct.unpack('<H', content[pe_offset + 6:pe_offset + 8])[0]
            size_of_optional_header = struct.unpack('<H', content[pe_offset + 20:pe_offset + 22])[0]

            # 节区表起始位置
            section_table_offset = pe_offset + 24 + size_of_optional_header

            # 每个节区头大小为40字节
            for i in range(num_sections):
                section_offset = section_table_offset + i * 40
                if section_offset + 40 > len(content):
                    break

                # 节区名称（前8字节，以NULL结尾）
                name_bytes = content[section_offset:section_offset + 8]
                name = name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')

                # 节区虚拟大小
                virtual_size = struct.unpack('<I', content[section_offset + 8:section_offset + 12])[0]

                # 节区虚拟地址
                virtual_address = struct.unpack('<I', content[section_offset + 12:section_offset + 16])[0]

                # 节区原始大小
                size_of_raw_data = struct.unpack('<I', content[section_offset + 16:section_offset + 20])[0]

                # 节区原始数据偏移
                pointer_to_raw_data = struct.unpack('<I', content[section_offset + 20:section_offset + 24])[0]

                # 节区特征标志
                characteristics = struct.unpack('<I', content[section_offset + 36:section_offset + 40])[0]

                # 解析特征标志
                # 修复3（原 bug：位映射与标准 PE 常量不符）→ 采用标准常量：
                #   CNT_CODE=0x20, CNT_INITIALIZED_DATA=0x40, CNT_UNINITIALIZED_DATA=0x80,
                #   MEM_EXECUTE=0x20000000, MEM_READ=0x40000000, MEM_WRITE=0x80000000,
                #   MEM_DISCARDABLE=0x02000000, MEM_NOT_CACHED=0x04000000,
                #   MEM_NOT_PAGED=0x08000000, LNK_NRELOC_OVFL=0x01000000
                flags = []
                if characteristics & 0x00000020:  # IMAGE_SCN_CNT_CODE
                    flags.append('CODE')
                if characteristics & 0x00000040:  # IMAGE_SCN_CNT_INITIALIZED_DATA
                    flags.append('INIT_DATA')
                if characteristics & 0x00000080:  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
                    flags.append('UNINIT_DATA')
                if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    flags.append('EXECUTE')
                if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
                    flags.append('READ')
                if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                    flags.append('WRITE')
                if characteristics & 0x02000000:  # IMAGE_SCN_MEM_DISCARDABLE
                    flags.append('DISCARDABLE')
                if characteristics & 0x04000000:  # IMAGE_SCN_MEM_NOT_CACHED
                    flags.append('NOT_CACHED')
                if characteristics & 0x08000000:  # IMAGE_SCN_MEM_NOT_PAGED
                    flags.append('NOT_PAGED')
                if characteristics & 0x01000000:  # IMAGE_SCN_LNK_NRELOC_OVFL
                    flags.append('LARGE_ADDRESS')

                sections.append({
                    'name': name,
                    'virtual_size': virtual_size,
                    'virtual_address': virtual_address,
                    'size_of_raw_data': size_of_raw_data,
                    'pointer_to_raw_data': pointer_to_raw_data,
                    'characteristics': characteristics,
                    'flags': flags,
                })

        except Exception:
            pass

        return sections

    def _parse_import_table(self, content: bytes, pe_offset: int) -> Dict:
        """解析导入表"""
        imports = {}

        try:
            # 修复2（原 bug：数据目录偏移写死 PE32 布局的 0x60，读的是 DataDirectory[0]
            # 导出表）→ 按 magic 定位 DataDirectory[1]（导入表）
            magic = struct.unpack_from('<H', content, pe_offset + 24)[0]
            if magic not in (0x010B, 0x020B):
                return imports
            dd_base = pe_offset + 24 + (96 if magic == 0x010B else 112)
            import_table_rva = struct.unpack('<I', content[dd_base + 8:dd_base + 12])[0]
            import_table_size = struct.unpack('<I', content[dd_base + 12:dd_base + 16])[0]

            if import_table_rva == 0 or import_table_size == 0:
                return imports

            is_pe32p = (magic == 0x020B)
            entry_size = 8 if is_pe32p else 4
            ordinal_mask = 0x8000000000000000 if is_pe32p else 0x80000000

            # 找到导入表在文件中的实际偏移
            import_table_offset = self._rva_to_offset(content, pe_offset, import_table_rva)

            if import_table_offset is None:
                return imports

            # 遍历导入表
            current_offset = import_table_offset
            while current_offset + 20 <= len(content):
                # 导入描述符
                import_lookup_table_rva = struct.unpack('<I', content[current_offset:current_offset + 4])[0]
                if import_lookup_table_rva == 0:
                    break

                time_date_stamp = struct.unpack('<I', content[current_offset + 4:current_offset + 8])[0]
                forwarder_chain = struct.unpack('<I', content[current_offset + 8:current_offset + 12])[0]
                name_rva = struct.unpack('<I', content[current_offset + 12:current_offset + 16])[0]
                first_thunk_rva = struct.unpack('<I', content[current_offset + 16:current_offset + 20])[0]

                # 获取模块名称
                name_offset = self._rva_to_offset(content, pe_offset, name_rva)
                if name_offset is not None and name_offset < len(content):
                    name_bytes = b''
                    while name_offset < len(content) and content[name_offset] != 0:
                        name_bytes += bytes([content[name_offset]])
                        name_offset += 1
                    module_name = name_bytes.decode('ascii', errors='ignore').lower()

                    # 获取导入函数名称
                    # 修复4（原 bug：thunk 表恒按 u32 步进，PE32+ 的 64 位表会错读）
                    # → 按 magic 选择条目宽度与序号掩码
                    func_names = []
                    lookup_offset = self._rva_to_offset(content, pe_offset, import_lookup_table_rva)

                    if lookup_offset is not None:
                        unpack_fmt = '<Q' if is_pe32p else '<I'
                        while lookup_offset + entry_size <= len(content):
                            lookup_entry = struct.unpack_from(unpack_fmt, content, lookup_offset)[0]
                            if lookup_entry == 0:
                                break

                            # 判断是否为按名称导入
                            if (lookup_entry & ordinal_mask) == 0:
                                hint_name_rva = lookup_entry & 0xFFFFFFFF
                                hint_name_offset = self._rva_to_offset(content, pe_offset, hint_name_rva)
                                if hint_name_offset is not None and hint_name_offset + 2 < len(content):
                                    hint = struct.unpack('<H', content[hint_name_offset:hint_name_offset + 2])[0]
                                    name_start = hint_name_offset + 2
                                    func_name_bytes = b''
                                    while name_start < len(content) and content[name_start] != 0:
                                        func_name_bytes += bytes([content[name_start]])
                                        name_start += 1
                                    func_name = func_name_bytes.decode('ascii', errors='ignore')
                                    func_names.append(func_name)

                            lookup_offset += entry_size

                    if module_name:
                        imports[module_name] = func_names

                current_offset += 20

        except Exception:
            pass

        return imports

    def _rva_to_offset(self, content: bytes, pe_offset: int, rva: int):
        """将RVA转换为文件偏移（未命中返回 None）

        修复5（原 bug：未命中返回 0 与"合法偏移 0"无法区分；且节区范围只用
        VirtualSize，VirtualSize=0 的节区永远无法命中）→ 范围取
        max(VirtualSize, SizeOfRawData)，未命中返回 None。
        """
        try:
            # 获取节区数量和可选头大小
            num_sections = struct.unpack('<H', content[pe_offset + 6:pe_offset + 8])[0]
            size_of_optional_header = struct.unpack('<H', content[pe_offset + 20:pe_offset + 22])[0]

            # 节区表起始位置
            section_table_offset = pe_offset + 24 + size_of_optional_header

            # 遍历节区
            for i in range(num_sections):
                section_offset = section_table_offset + i * 40
                if section_offset + 40 > len(content):
                    break

                # 获取节区虚拟地址和大小
                virtual_address = struct.unpack('<I', content[section_offset + 12:section_offset + 16])[0]
                virtual_size = struct.unpack('<I', content[section_offset + 8:section_offset + 12])[0]
                pointer_to_raw_data = struct.unpack('<I', content[section_offset + 20:section_offset + 24])[0]
                size_of_raw_data = struct.unpack('<I', content[section_offset + 16:section_offset + 20])[0]

                # 检查RVA是否在本节区内（范围取 VirtualSize 与 SizeOfRawData 的较大者）
                span = max(virtual_size, size_of_raw_data)
                if rva >= virtual_address and rva < virtual_address + span:
                    return pointer_to_raw_data + (rva - virtual_address)

        except Exception:
            pass

        return None

    def _detect_packer(self, content: bytes) -> Optional[str]:
        """检测打包器（节区名 + overlay 区域签名，避免大文件随机字节误报）"""
        # 找到 PE 签名
        if not content[:2] == b'MZ':
            return None
        try:
            pe_offset = struct.unpack_from('<I', content, 0x3C)[0]
        except Exception:
            return None
        if pe_offset >= len(content) - 4 or content[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None

        # 节区数量
        try:
            num_sections = struct.unpack_from('<H', content, pe_offset + 6)[0]
            optional_hdr_size = struct.unpack_from('<H', content, pe_offset + 20)[0]
        except Exception:
            return None

        # 1. 节区名匹配（最可靠）
        section_table_offset = pe_offset + 24 + optional_hdr_size
        for i in range(min(num_sections, 20)):
            sec_offset = section_table_offset + i * 40
            if sec_offset + 8 > len(content):
                break
            try:
                sec_name_raw = content[sec_offset:sec_offset + 8]
                sec_name = sec_name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
            except Exception:
                continue
            sec_name_lower = sec_name.lower()
            # UPX 节区名直接命中
            if sec_name in ('UPX0', 'UPX1', 'UPX2') or sec_name_lower.startswith('.upx'):
                return 'UPX'
            # 其他打包器节区名
            for packer_name, signatures in self.PACKER_SIGNATURES.items():
                if packer_name == 'UPX':
                    continue
                # 节区名匹配
                for sig in signatures:
                    sig_str = sig.decode('ascii', errors='replace').lower()
                    if sec_name_lower == sig_str or sec_name_lower.startswith(sig_str):
                        return packer_name

        # 2. Overlay 区域（MZ 头到 PE 签名之间）搜索签名
        # 很多打包器在 PE 头前的 overlay 中写入水印
        overlay_end = pe_offset
        if overlay_end > 0 and overlay_end <= 1024:
            overlay = content[:overlay_end]
            for packer_name, signatures in self.PACKER_SIGNATURES.items():
                for signature in signatures:
                    # 太短的签名（如 b'MEW'）跳过 overlay 搜索
                    if len(signature) < 5:
                        continue
                    if signature in overlay:
                        return packer_name

        # 3. 扩展签名搜索（仅限 PE header 附近小区域）
        # 只在 PE header 后 1KB 区域搜索，不遍历整个文件
        scan_start = pe_offset + 24 + optional_hdr_size
        scan_end = min(scan_start + 1024, len(content))
        if scan_start < scan_end:
            region = content[scan_start:scan_end]
            for packer_name, signatures in self.PACKER_SIGNATURES.items():
                for signature in signatures:
                    if len(signature) < 5:
                        continue
                    if signature in region:
                        return packer_name

        return None

    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据熵值（参照 pe_scanner.calculate_entropy）

        熵值范围 0-8，高熵（>7.0）可能表示加密/加壳。

        Args:
            data: 字节数据

        Returns:
            熵值（0.0-8.0）
        """
        if not data:
            return 0.0

        try:
            if HAS_NUMPY:
                # numpy 加速版本
                counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                probs = counts[counts > 0] / len(data)
                return -np.sum(probs * np.log2(probs))
            else:
                # 纯 Python 降级版本
                from collections import Counter
                counter = Counter(data)
                length = len(data)
                entropy = 0.0
                for count in counter.values():
                    p = count / length
                    if p > 0:
                        entropy -= p * math.log2(p)
                return entropy
        except Exception:
            return 0.0

    def _calculate_byte_histogram(self, data: bytes) -> List[int]:
        """计算字节直方图（参照 pe_scanner.byte_histogram）

        256维特征，每个字节值（0-255）的出现次数。
        用于机器学习特征提取。

        Args:
            data: 字节数据

        Returns:
            256维列表，每个元素是对应字节值的出现次数
        """
        if not data:
            return [0] * 256

        try:
            if HAS_NUMPY:
                counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                return counts.tolist()
            else:
                histogram = [0] * 256
                for byte in data:
                    histogram[byte] += 1
                return histogram
        except Exception:
            return [0] * 256

    def _analyze_section_entropy(self, content: bytes, sections: List[Dict]) -> List[Dict]:
        """分析各节区熵值（参照 pe_scanner.section_entropy）

        检测高熵节区（可能是加密代码/数据）。

        Args:
            content: 文件完整内容
            sections: 节区列表

        Returns:
            高熵节区列表（熵值 > 7.0 的节区）
        """
        high_entropy = []

        for section in sections:
            try:
                raw_offset = section.get('pointer_to_raw_data', 0)
                raw_size = section.get('size_of_raw_data', 0)

                if raw_offset == 0 or raw_size == 0:
                    continue

                if raw_offset + raw_size > len(content):
                    raw_size = len(content) - raw_offset

                if raw_size <= 0:
                    continue

                section_data = content[raw_offset:raw_offset + raw_size]
                entropy = self._calculate_entropy(section_data)

                # 熵值 > 7.0 可能是加密/加壳
                if entropy > 7.0:
                    high_entropy.append({
                        'name': section['name'],
                        'entropy': round(entropy, 4),
                        'size': raw_size,
                    })

            except Exception:
                continue

        return high_entropy

    def _find_suspicious_imports(self, imports: Dict) -> List[Dict]:
        """查找可疑导入函数"""
        suspicious = []

        for module, functions in imports.items():
            module_lower = module.lower()
            if module_lower in self.SUSPICIOUS_IMPORTS:
                for func in functions:
                    if func in self.SUSPICIOUS_IMPORTS[module_lower]:
                        suspicious.append({
                            'module': module,
                            'function': func,
                            'risk_level': 'high' if func in [
                                'CreateRemoteThread', 'WriteProcessMemory',
                                'VirtualAllocEx', 'NtCreateThreadEx',
                                'ShellExecuteA', 'ShellExecuteW', 'WinExec'
                            ] else 'medium',
                        })

        return suspicious

    def _find_suspicious_sections(self, sections: List[Dict]) -> List[Dict]:
        """查找可疑节区"""
        suspicious = []

        for section in sections:
            name_lower = section['name'].lower()
            flags = section['flags']

            # 检查节区名称
            is_suspicious_name = False
            for suspicious_name in self.SUSPICIOUS_SECTIONS:
                if suspicious_name.lower() in name_lower:
                    is_suspicious_name = True
                    break

            # 检查节区特征（同时具有执行和写入权限）
            has_exec_and_write = False
            if 'EXECUTE' in flags and 'WRITE' in flags:
                has_exec_and_write = True

            # 检查节区大小异常
            size_abnormal = False
            if section['virtual_size'] == 0 or section['size_of_raw_data'] == 0:
                size_abnormal = True

            if is_suspicious_name or has_exec_and_write or size_abnormal:
                suspicious.append({
                    'name': section['name'],
                    'flags': flags,
                    'reasons': [],
                })

                if is_suspicious_name:
                    suspicious[-1]['reasons'].append("可疑节区名称")
                if has_exec_and_write:
                    suspicious[-1]['reasons'].append("同时具有执行和写入权限")
                if size_abnormal:
                    suspicious[-1]['reasons'].append("节区大小异常")

        return suspicious

    # 已知恶意打包器列表
    MALICIOUS_PACKERS = {'Themida', 'VMProtect', 'Armadillo', 'Obsidium', 
                         'ProtectPE', 'EXECryptor', 'RLPack', 'Neolite', 
                         'WinUpack', 'Yoda', 'MEW'}

    # ========================================================================
    # PE 高级结构分析（增强查杀敏感度）
    # ========================================================================

    def _analyze_pe_optional_header(self, content: bytes, pe_offset: int, result: Dict):
        """解析PE可选头：ASLR/DEP标志、重定位剥离等"""
        try:
            # Optional header 起始
            opt_offset = pe_offset + 24
            if opt_offset + 96 > len(content):
                return

            magic = struct.unpack_from('<H', content, opt_offset)[0]
            if magic == 0x010B:  # PE32
                dll_characteristics_offset = opt_offset + 70   # IMAGE_DLLCHARACTERISTICS
                size_of_image_offset = opt_offset + 56
            elif magic == 0x020B:  # PE32+
                dll_characteristics_offset = opt_offset + 70   # PE32+ 省了 BaseOfData(4字节), ImageBase 增至8字节, DllChar 仍在 opt+70
                size_of_image_offset = opt_offset + 56
            else:
                return

            dll_chars = struct.unpack_from('<H', content, dll_characteristics_offset)[0]
            size_of_image = struct.unpack_from('<I', content, size_of_image_offset)[0]

            # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
            if not (dll_chars & 0x0040):
                result['has_aslr'] = False
                result['details'].append("未启用ASLR (DYNAMIC_BASE): 常见于恶意软件 +5分")
            # IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)
            if not (dll_chars & 0x0100):
                result['has_dep'] = False
                result['details'].append("未启用DEP/NX保护: 常见于恶意软件 +5分")
            # IMAGE_FILE_RELOCS_STRIPPED (0x0001，在COFF头characteristics中)
            coff_chars = struct.unpack_from('<H', content, pe_offset + 22)[0]
            if coff_chars & 0x0001 and size_of_image > 0:
                # 仅在EXE中可能正常，DLL中剥离重定位表=异常
                is_dll = coff_chars & 0x2000
                if is_dll:
                    result['relocs_stripped'] = True
                    result['details'].append("DLL重定位表被剥离: 可疑 +10分")
        except Exception:
            pass

    def _analyze_entry_point(self, content: bytes, pe_offset: int, sections: List[Dict], result: Dict):
        """分析入口点位置是否在合法.text节中"""
        try:
            opt_offset = pe_offset + 24
            if opt_offset + 28 > len(content):
                return
            magic = struct.unpack_from('<H', content, opt_offset)[0]
            if magic == 0x010B:  # PE32
                addr_of_entry_point = struct.unpack_from('<I', content, opt_offset + 16)[0]
                image_base = struct.unpack_from('<I', content, opt_offset + 28)[0]
            elif magic == 0x020B:  # PE32+
                addr_of_entry_point = struct.unpack_from('<I', content, opt_offset + 16)[0]
                image_base = struct.unpack_from('<Q', content, opt_offset + 24)[0]
            else:
                return

            if addr_of_entry_point == 0:
                # DLL 无入口点是合法的（很多 DLL 被动态加载而无需入口）
                is_dll = struct.unpack_from('<H', content, pe_offset + 22)[0] & 0x2000
                if not is_dll:
                    result['entry_point_in_text'] = False
                    result['details'].append("入口点为空的EXE: 高度可疑 +20分")
                return

            found_in_section = None
            for sec in sections:
                sec_va = sec['virtual_address']
                sec_vsize = max(sec['virtual_size'], 1)
                if sec_va <= addr_of_entry_point < sec_va + sec_vsize:
                    found_in_section = sec
                    break

            if found_in_section:
                name = found_in_section['name'].lower()
                result['entry_point_section'] = found_in_section['name']
                # 正常节区：.text/.code/.itext/CRT等
                normal_sections = {'.text', '.code', '.itext', 'crt', '_text'}
                if name not in normal_sections and not name.startswith('.text'):
                    # 入口点在非标准代码节（壳/注入/后门常用）
                    flags = found_in_section.get('flags', [])
                    is_exec = 'EXECUTE' in flags
                    if is_exec:
                        result['entry_point_in_text'] = False
                        suspicious_names = ['.upx', '.packed', '.vmp', '.themida', '.armadillo',
                                            '.encrypted', '.inject', '.shellcode', '.payload']
                        if any(sn in name for sn in suspicious_names):
                            result['details'].append(f"入口点在可疑节区 {name}: +15分")
                        else:
                            result['details'].append(f"入口点在非标准代码节 {name}: +8分")
            else:
                # 入口点不在任何节区内，可能是shellcode/空洞注入
                result['entry_point_in_text'] = False
                result['details'].append("入口点不在任何节区内: 高度可疑 +20分")
        except Exception:
            pass

    def _analyze_tls_callback(self, content: bytes, pe_offset: int, result: Dict):
        """分析TLS回调（恶意软件/壳常用TLS在主程序前执行代码）"""
        try:
            opt_offset = pe_offset + 24
            magic = struct.unpack_from('<H', content, opt_offset)[0]
            if magic == 0x010B:
                # TLS = DataDirectory[9], PE32 DataDir 从 opt+96 开始, 每项8字节
                tls_dir_rva = struct.unpack_from('<I', content, opt_offset + 168)[0]
                tls_dir_size = struct.unpack_from('<I', content, opt_offset + 172)[0]
            elif magic == 0x020B:
                # PE32+ DataDir 从 opt+112 开始, TLS = DataDirectory[9]
                tls_dir_rva = struct.unpack_from('<I', content, opt_offset + 184)[0]
                tls_dir_size = struct.unpack_from('<I', content, opt_offset + 188)[0]
            else:
                return

            if tls_dir_rva == 0 or tls_dir_size == 0:
                return

            tls_file_offset = self._rva_to_offset(content, pe_offset, tls_dir_rva)
            if tls_file_offset is None or tls_file_offset + 40 > len(content):
                return

            # 读取TLS目录结构，寻找AddressOfCallBacks
            if magic == 0x010B:
                callbacks_rva = struct.unpack_from('<I', content, tls_file_offset + 24)[0]
            else:
                callbacks_rva = struct.unpack_from('<Q', content, tls_file_offset + 32)[0]

            if callbacks_rva != 0:
                cb_file_offset = self._rva_to_offset(content, pe_offset, callbacks_rva)
                if cb_file_offset is not None and cb_file_offset + 8 <= len(content):
                    # 统计非零回调指针数量
                    count = 0
                    max_check = 20
                    for i in range(max_check):
                        step = 4 if magic == 0x010B else 8
                        cur = cb_file_offset + i * step
                        if cur + step > len(content):
                            break
                        val = struct.unpack_from(('<I' if magic == 0x010B else '<Q'), content, cur)[0]
                        if val == 0:
                            break
                        count += 1
                    if count > 0:
                        result['has_tls_callback'] = True
                        result['tls_callback_count'] = count
                        if count >= 3:
                            result['details'].append(f"TLS回调数目过多({count}): 可疑 +12分")
                        elif count >= 1:
                            result['details'].append(f"包含TLS回调({count}个): 主程序前执行代码 +6分")
        except Exception:
            pass

    def _analyze_resource_ratio(self, content: bytes, pe_offset: int, result: Dict, file_size: int):
        """分析资源节占比（可疑下载器/安装器/加密木马资源占比过大）"""
        try:
            opt_offset = pe_offset + 24
            magic = struct.unpack_from('<H', content, opt_offset)[0]
            if magic == 0x010B:
                # Resource = DataDirectory[2], PE32 DataDir 从 opt+96 开始
                rsrc_dir_rva = struct.unpack_from('<I', content, opt_offset + 112)[0]
                rsrc_dir_size = struct.unpack_from('<I', content, opt_offset + 116)[0]
            elif magic == 0x020B:
                # PE32+ DataDir 从 opt+112 开始, Resource = DataDirectory[2]
                rsrc_dir_rva = struct.unpack_from('<I', content, opt_offset + 128)[0]
                rsrc_dir_size = struct.unpack_from('<I', content, opt_offset + 132)[0]
            else:
                return

            if rsrc_dir_rva == 0 or rsrc_dir_size == 0 or file_size <= 0:
                return

            # 计算.rsrc节在文件中的实际大小
            for sec in result.get('sections', []):
                sec_name = sec['name'].lower()
                if sec_name == '.rsrc':
                    raw_size = max(sec.get('size_of_raw_data', 0), rsrc_dir_size)
                    ratio = raw_size / file_size if file_size > 0 else 0.0
                    result['resource_size_ratio'] = round(ratio, 3)
                    # 正常PE .rsrc < 40%，过大可能说明加密payload/大资源封装
                    if ratio > 0.85:
                        result['details'].append(f"资源节占比极高({ratio*100:.0f}%): 可疑 +15分")
                    elif ratio > 0.7:
                        result['details'].append(f"资源节占比过大({ratio*100:.0f}%): 可疑 +8分")
                    elif ratio > 0.55 and not result.get('has_digital_signature', False):
                        result['details'].append(f"资源节占比偏大({ratio*100:.0f}%)且无签名: +4分")
                    break
        except Exception:
            pass

    def _analyze_exports(self, content: bytes, pe_offset: int, result: Dict):
        """分析导出表：DLL文件无导出或导出异常（DLL侧载常见）"""
        try:
            # 先判断是否DLL
            coff_chars = struct.unpack_from('<H', content, pe_offset + 22)[0]
            is_dll = (coff_chars & 0x2000) != 0
            if not is_dll:
                return

            opt_offset = pe_offset + 24
            magic = struct.unpack_from('<H', content, opt_offset)[0]
            if magic == 0x010B:
                # Export = DataDirectory[0], PE32 DataDir 从 opt+96 开始
                exp_dir_rva = struct.unpack_from('<I', content, opt_offset + 96)[0]
                exp_dir_size = struct.unpack_from('<I', content, opt_offset + 100)[0]
            elif magic == 0x020B:
                # PE32+ DataDir 从 opt+112 开始, Export = DataDirectory[0]
                exp_dir_rva = struct.unpack_from('<I', content, opt_offset + 112)[0]
                exp_dir_size = struct.unpack_from('<I', content, opt_offset + 116)[0]
            else:
                return

            if exp_dir_rva == 0 or exp_dir_size == 0:
                # DLL无任何导出，DLL侧载/劫持常用
                result['dll_no_exports'] = True
                result['details'].append("DLL文件无导出函数: 可能为DLL侧载恶意程序 +12分")
                return

            exp_file_offset = self._rva_to_offset(content, pe_offset, exp_dir_rva)
            if exp_file_offset is None or exp_file_offset + 40 > len(content):
                return

            num_funcs = struct.unpack_from('<I', content, exp_file_offset + 20)[0]
            num_names = struct.unpack_from('<I', content, exp_file_offset + 24)[0]
            # DLL导出函数数量极少且无名称，可能为恶意DLL
            if num_funcs > 0 and num_names == 0 and num_funcs < 5:
                result['details'].append(f"DLL仅有{num_funcs}个无名称导出: 可疑 +6分")
        except Exception:
            pass

    # ========================================================================
    # 风险评分（增强版）
    # ========================================================================

    def _calculate_risk_score(self, result: Dict) -> int:
        """计算风险分数（增强版：新增PE结构特征+系统修改类DLL加权）"""
        score = 0
        base_added_score = 0  # 来自details中"+X分"的总和校验

        # 打包器检测（仅恶意打包器才加分）
        if result['packer']:
            if result['packer'] in self.MALICIOUS_PACKERS:
                score += 30
                base_added_score += 30
            elif result['packer'] == 'UPX':
                if not result['has_digital_signature']:
                    score += 5
                    base_added_score += 5
            else:
                score += 10
                base_added_score += 10

        # 可疑导入函数（增强：系统修改类API权重提升）
        system_modify_high = {
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'NtCreateThreadEx', 'NtOpenProcess', 'NtAllocateVirtualMemory',
            'NtWriteVirtualMemory',
            'RegSetValueA', 'RegSetValueW', 'RegCreateKeyA', 'RegCreateKeyW',
            'SetWindowsHookExA', 'SetWindowsHookExW',
            'CreateServiceA', 'CreateServiceW', 'OpenServiceA', 'OpenServiceW',
            'StartServiceA', 'StartServiceW', 'ControlService',
            'DeleteService', 'ChangeServiceConfigA', 'ChangeServiceConfigW',
            'DeviceIoControl', 'CreateFileA', 'CreateFileW',
            'ExitWindowsEx', 'LockWorkStation', 'InitiateSystemShutdown',
        }
        system_modify_med = {
            'OpenProcess', 'ReadProcessMemory', 'VirtualProtectEx',
            'VirtualFreeEx', 'TerminateProcess',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
            'InternetOpen', 'InternetOpenUrl', 'HttpSendRequest',
            'URLDownloadToFileA', 'URLDownloadToFileW',
            'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
        }

        for imp in result['suspicious_imports']:
            if imp['function'] in system_modify_high:
                score += 15
                base_added_score += 15
            elif imp['function'] in system_modify_med:
                score += 6
                base_added_score += 6
            elif imp['risk_level'] == 'high':
                score += 5
                base_added_score += 5
            elif imp['risk_level'] == 'medium':
                score += 2

        # 系统修改类DLL加权评分
        sys_score = result.get('system_modify_dll_score', 0)
        if sys_score >= 10 and result.get('import_count', 0) <= 15:
            # DLL少但系统修改类DLL权重大 => 恶意软件倾向性高
            adjusted_sys = min(sys_score * 2, 25)
            score += adjusted_sys
        elif sys_score >= 5:
            adjusted_sys = min(sys_score, 15)
            score += adjusted_sys

        # 可疑节区
        for section in result['suspicious_sections']:
            if 'EXECUTE' in section['flags'] and 'WRITE' in section['flags']:
                score += 20
            elif '可疑节区名称' in section['reasons']:
                score += 10
            else:
                score += 5

        # 新增：PE结构特征评分（来自_analyze_pe_optional_header等的details字段已写入"X分"，此处按字段显式计算避免遗漏）
        if not result.get('has_aslr', True):
            score += 5
        if not result.get('has_dep', True):
            score += 5
        if result.get('relocs_stripped'):
            score += 10
        if not result.get('entry_point_in_text', True):
            # 入口点异常已经在details写了+8/15/20，此处从details解析校验后累加或直接加保守值
            pass
        if result.get('has_tls_callback'):
            c = result.get('tls_callback_count', 0)
            score += 12 if c >= 3 else 6
        if result.get('dll_no_exports'):
            score += 12
        # 资源占比
        r = result.get('resource_size_ratio', 0.0)
        if r > 0.85:
            score += 15
        elif r > 0.7:
            score += 8
        elif r > 0.55 and not result.get('has_digital_signature'):
            score += 4

        # ===== 数字签名信任 + 误报过滤 =====
        if result['has_digital_signature']:
            # 有签名的文件：先对高分做明显正常软件豁免，再减半
            if (not result.get('packer')
                    and result.get('has_aslr', True)
                    and result.get('has_dep', True)
                    and 0 < result.get('import_count', 0) < 80
                    and not result.get('suspicious_imports')):
                # 明显正常软件（无打包器、ASLR/DEP、正常导入数、无高危导入）：归零
                score = 0
                result['details'].append("签名正常软件: 评分归零")
            else:
                score = max(0, score // 2)
                result['details'].append("数字签名信任: 分数减半")
        else:
            # 无签名小幅加分（但非PE dll/sys等除外：已在扩展级别过滤）
            score += 5

        # 文件熵值（仅无签名时触发，避免对带签名的正常加密资源包误报）
        file_entropy = result.get('entropy', 0.0)
        if not result['has_digital_signature']:
            if file_entropy > 7.8:
                score += 20
            elif file_entropy > 7.3:
                score += 10
        else:
            # 有签名的文件：放宽熵阈值到7.9再加分
            if file_entropy > 7.9:
                score += 8

        # 高熵节区
        high_entropy_sections = result.get('high_entropy_sections', [])
        for sec in high_entropy_sections:
            score += 10

        # ===== 误报下调 =====
        # 导入DLL非常多（正常软件有大量导入），降低评分
        if result.get('import_count', 0) > 40 and not result.get('packer'):
            score = max(0, score - 5)
            result['details'].append("导入DLL数目多(正常软件): -5分")
        # 有签名且节区全部正常
        if (result['has_digital_signature']
                and not result.get('suspicious_sections')
                and not result.get('suspicious_imports')):
            score = max(0, score - 10)

        return min(score, 100)


if __name__ == '__main__':
    # 测试PE分析器
    analyzer = PEAnalyzer()

    # 测试Python可执行文件
    import sys
    python_exe = sys.executable

    print(f"分析文件: {python_exe}")
    result = analyzer.analyze(python_exe)

    print(f"\n分析结果:")
    print(f"  是否PE文件: {result['is_pe']}")
    print(f"  打包器: {result['packer']}")
    print(f"  数字签名: {result['has_digital_signature']}")
    print(f"  风险分数: {result['total_score']}/100")
    print(f"  严重程度: {result['severity']}")

    if result['suspicious_imports']:
        print(f"\n  可疑导入 ({len(result['suspicious_imports'])}):")
        for imp in result['suspicious_imports']:
            print(f"    - {imp['module']}!{imp['function']} [{imp['risk_level']}]")

    if result['suspicious_sections']:
        print(f"\n  可疑节区 ({len(result['suspicious_sections'])}):")
        for section in result['suspicious_sections']:
            print(f"    - {section['name']}: {', '.join(section['flags'])}")

    if result['details']:
        print(f"\n  详细信息:")
        for detail in result['details']:
            print(f"    - {detail}")