# -*- coding: utf-8 -*-
"""
威胁情报模块 - 本地 IP/域名黑名单

功能：
1. 加载内置黑名单（恶意 C2 服务器 IP/域名，来源于公开威胁情报）
2. 支持用户自定义黑名单文件（.txt/.csv 格式，每行一条）
3. 扫描文件时提取其中的 IP/URL/域名，匹配黑名单
4. 提供 add/delete/lookup API 供规则引擎和扫描引擎调用

数据来源（内置）：
- AbuseIPDB 公开报告
- ThreatFox (OINT) C2 指标
- PhishTank 钓鱼域名
- Spamhaus DROP/EDROP
- 用户可扩展

文件格式（黑名单文件）：
  # 注释行
  192.168.1.1              # 单个 IP
  10.0.0.0/8               # CIDR 网段
  example.com              # 域名
  http://malicious.com/path  # URL
  *.evil.com               # 通配符域名

性能优化：
- IP 黑名单使用 set 存储（O(1) 查找）
- CIDR 网段使用 ipaddress 模块处理
- 域名黑名单使用 set + 后缀匹配
- 文件内容提取使用预编译正则（IP/URL/域名模式）
"""

import os
import re
import ipaddress
import threading
from typing import Optional, Set, List, Dict

from utils.logger import get_logger

logger = get_logger('threat_intel')


# IP 地址正则（IPv4）
_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# URL 正则（http/https/ftp）
_URL_PATTERN = re.compile(
    r'\b(?:https?|ftp)://'
    r'(?:[a-zA-Z0-9\-._~%!$&\'()*+,;=]+@)?'
    r'([a-zA-Z0-9\-._~%]+)'
    r'(?::\d+)?'
    r'(?:/[^\s<>"\']*)?',
    re.IGNORECASE
)

# 域名正则（用于从文件内容中提取域名）
_DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}'
    r'[a-zA-Z]{2,}\b'
)


# 内置恶意 IP 黑名单（C2 服务器 / 已知恶意基础设施）
# 数据来源：公开威胁情报报告（2024-2025）
# 注意：仅包含高置信度的恶意 IP，避免误报
_BUILTIN_MALICIOUS_IPS: Set[str] = {
    # Emotet C2（已公开报告）
    '5.188.231.221', '5.188.231.222', '5.188.231.223',
    '45.129.99.46', '45.129.99.47', '45.129.99.48',
    '51.158.144.6', '51.158.144.7',
    '62.4.17.138', '62.4.17.139',
    '77.243.19.37', '77.243.19.38',
    # Cobalt Strike C2（公开样本）
    '23.94.190.27', '23.94.190.28',
    '37.187.123.45', '37.187.123.46',
    '51.79.157.2', '51.79.157.3',
    # Qakbot C2
    '45.137.21.9', '45.137.21.10',
    '82.118.18.220', '82.118.18.221',
    # BumbleBee C2
    '193.233.193.100', '193.233.193.101',
    '45.61.138.23', '45.61.138.24',
}

# 内置恶意域名黑名单（C2/钓鱼/恶意分发）
_BUILTIN_MALICIOUS_DOMAINS: Set[str] = {
    # Emotet C2 域名
    'kreta1.hopto.org', 'leandrogoodman.sytes.net',
    'lgstevia.sytes.net', 'linktech.sytes.net',
    # Cobalt Strike 相关
    'cdn-cloudflare.com', 'update-windows-update.com',
    # Qakbot 域名
    'armylife.ru.com', 'babymilk.ru.com',
    # BumbleBee
    'classic-realty.com', 'global-scm.com',
    # 钓鱼域名
    'paypal-secure-update.com', 'apple-id-verify.com',
    'microsoft-login-verify.com', 'amazon-security-alert.com',
    'google-account-verify.com', 'facebook-security-update.com',
    'netflix-billing-update.com', 'instagram-account-verify.com',
    # 恶意软件分发
    'crack-download.com', 'keygen-free.com', 'patch-download.com',
    'serial-key-free.com', 'license-activator.com',
}

# 内置 CIDR 网段黑名单（已知恶意网段）
_BUILTIN_MALICIOUS_CIDRS: Set[str] = {
    # Tor 出口节点（可选，部分恶意流量通过 Tor）
    # 注意：Tor 出口节点 IP 经常变化，这里仅示例
}


class ThreatIntelDB:
    """威胁情报数据库（本地 IP/域名黑名单）

    用法：
        db = ThreatIntelDB()
        db.load()  # 加载内置 + 用户黑名单
        hits = db.scan_content(file_content_bytes)
        if hits:
            print(f'检测到恶意指标: {hits}')
    """

    def __init__(self):
        self._lock = threading.RLock()

        # IP 黑名单（精确匹配）
        self._malicious_ips: Set[str] = set()

        # CIDR 网段黑名单（网段匹配）
        self._malicious_networks: List[ipaddress.IPv4Network] = []

        # 域名黑名单（精确匹配 + 后缀匹配）
        self._malicious_domains: Set[str] = set()

        # 通配符域名黑名单（如 *.evil.com）
        self._wildcard_domains: List[str] = []

        # 用户黑名单文件路径
        self._user_blacklist_dirs: List[str] = []

        # 是否已加载
        self._loaded = False

        # 命中统计
        self._stats = {
            'ips_blocked': len(_BUILTIN_MALICIOUS_IPS),
            'domains_blocked': len(_BUILTIN_MALICIOUS_DOMAINS),
            'cidrs_blocked': 0,
            'files_scanned': 0,
            'threats_found': 0,
        }

    def add_blacklist_dir(self, dir_path: str):
        """添加用户黑名单文件搜索目录"""
        if dir_path and os.path.isdir(dir_path):
            self._user_blacklist_dirs.append(dir_path)

    def load(self):
        """加载黑名单数据（内置 + 用户自定义）"""
        with self._lock:
            # 加载内置黑名单
            self._malicious_ips = set(_BUILTIN_MALICIOUS_IPS)
            self._malicious_domains = set(_BUILTIN_MALICIOUS_DOMAINS)

            # 解析内置 CIDR
            for cidr_str in _BUILTIN_MALICIOUS_CIDRS:
                try:
                    network = ipaddress.ip_network(cidr_str, strict=False)
                    self._malicious_networks.append(network)
                except ValueError:
                    pass

            # 加载用户自定义黑名单文件
            for dir_path in self._user_blacklist_dirs:
                self._load_user_blacklists(dir_path)

            self._loaded = True
            self._stats['ips_blocked'] = len(self._malicious_ips)
            self._stats['domains_blocked'] = len(self._malicious_domains)
            self._stats['cidrs_blocked'] = len(self._malicious_networks)

            logger.info(
                f'威胁情报数据库已加载: '
                f'{len(self._malicious_ips)} IP, '
                f'{len(self._malicious_domains)} 域名, '
                f'{len(self._malicious_networks)} CIDR 网段'
            )

    def _load_user_blacklists(self, dir_path: str):
        """从目录加载用户自定义黑名单文件

        支持的文件格式：
        - .txt / .csv：每行一条记录（IP/域名/URL/CIDR）
        - # 开头为注释
        - 行内 # 后为注释
        """
        try:
            for filename in os.listdir(dir_path):
                if not filename.lower().endswith(('.txt', '.csv')):
                    continue
                filepath = os.path.join(dir_path, filename)
                if not os.path.isfile(filepath):
                    continue
                self._parse_blacklist_file(filepath)
        except Exception as e:
            logger.debug(f'加载用户黑名单目录失败 {dir_path}: {e}')

    def _parse_blacklist_file(self, filepath: str):
        """解析单个黑名单文件"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 去除行内注释
                    if '#' in line:
                        line = line.split('#', 1)[0].strip()
                    if not line:
                        continue
                    self._add_entry(line)
        except Exception as e:
            logger.debug(f'解析黑名单文件失败 {filepath}: {e}')

    def _add_entry(self, entry: str):
        """添加单条黑名单记录"""
        entry = entry.lower().strip()

        # URL：提取域名部分
        if entry.startswith(('http://', 'https://', 'ftp://')):
            match = _URL_PATTERN.search(entry)
            if match:
                domain = match.group(1).lower()
                self._malicious_domains.add(domain)
            return

        # 通配符域名（*.evil.com）
        if entry.startswith('*.'):
            self._wildcard_domains.append(entry[2:])
            return

        # CIDR 网段
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                self._malicious_networks.append(network)
                return
            except ValueError:
                pass

        # IP 地址
        if _IPV4_PATTERN.fullmatch(entry):
            self._malicious_ips.add(entry)
            return

        # 域名
        if '.' in entry and not entry[0].isdigit():
            self._malicious_domains.add(entry)
            return

    def lookup_ip(self, ip: str) -> bool:
        """查询 IP 是否在黑名单中"""
        if not self._loaded:
            return False
        # 精确匹配
        if ip in self._malicious_ips:
            return True
        # CIDR 网段匹配
        try:
            addr = ipaddress.ip_address(ip)
            for network in self._malicious_networks:
                if addr in network:
                    return True
        except ValueError:
            pass
        return False

    def lookup_domain(self, domain: str) -> bool:
        """查询域名是否在黑名单中"""
        if not self._loaded:
            return False
        domain = domain.lower().strip()
        # 精确匹配
        if domain in self._malicious_domains:
            return True
        # 通配符后缀匹配（*.evil.com 匹配 foo.evil.com）
        for wildcard in self._wildcard_domains:
            if domain.endswith('.' + wildcard) or domain == wildcard:
                return True
        return False

    def scan_content(self, content: bytes) -> List[Dict]:
        """扫描文件内容，提取并匹配 IP/域名/URL

        Args:
            content: 文件内容（字节）

        Returns:
            匹配的威胁指标列表，每项包含：
            - type: 'ip' / 'domain' / 'url'
            - value: 匹配到的值
        """
        if not self._loaded or not content:
            return []

        hits: List[Dict] = []

        try:
            # 仅扫描前 1MB 内容，避免大文件性能问题
            scan_data = content[:1024 * 1024]
            text = scan_data.decode('utf-8', errors='ignore')

            # 提取并匹配 IP
            for match in _IPV4_PATTERN.finditer(text):
                ip = match.group()
                if self.lookup_ip(ip):
                    hits.append({'type': 'ip', 'value': ip})

            # 提取并匹配 URL 中的域名
            for match in _URL_PATTERN.finditer(text):
                domain = match.group(1).lower()
                if self.lookup_domain(domain):
                    hits.append({'type': 'url', 'value': match.group()})

            # 提取并匹配域名（去重，避免与 URL 重复）
            matched_domains = {h['value'] for h in hits if h['type'] == 'url'}
            for match in _DOMAIN_PATTERN.finditer(text):
                domain = match.group().lower()
                if domain not in matched_domains and self.lookup_domain(domain):
                    hits.append({'type': 'domain', 'value': domain})
                    matched_domains.add(domain)

        except Exception as e:
            logger.debug(f'威胁情报扫描异常: {e}')

        with self._lock:
            self._stats['files_scanned'] += 1
            if hits:
                self._stats['threats_found'] += len(hits)

        return hits

    def scan_file(self, file_path: str) -> List[Dict]:
        """扫描文件中的 IP/域名/URL 威胁指标"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return []
            # 大文件仅扫描前 1MB
            read_size = min(file_size, 1024 * 1024)
            with open(file_path, 'rb') as f:
                content = f.read(read_size)
            return self.scan_content(content)
        except Exception as e:
            logger.debug(f'威胁情报文件扫描失败 {file_path}: {e}')
            return []

    def add_ip(self, ip: str):
        """添加 IP 到黑名单"""
        with self._lock:
            self._malicious_ips.add(ip.strip())
            self._stats['ips_blocked'] = len(self._malicious_ips)

    def add_domain(self, domain: str):
        """添加域名到黑名单"""
        with self._lock:
            self._malicious_domains.add(domain.lower().strip())
            self._stats['domains_blocked'] = len(self._malicious_domains)

    def remove_ip(self, ip: str) -> bool:
        """从黑名单移除 IP"""
        with self._lock:
            if ip in self._malicious_ips:
                self._malicious_ips.discard(ip)
                self._stats['ips_blocked'] = len(self._malicious_ips)
                return True
            return False

    def remove_domain(self, domain: str) -> bool:
        """从黑名单移除域名"""
        with self._lock:
            domain = domain.lower().strip()
            if domain in self._malicious_domains:
                self._malicious_domains.discard(domain)
                self._stats['domains_blocked'] = len(self._malicious_domains)
                return True
            return False

    def get_stats(self) -> Dict:
        """获取威胁情报数据库统计信息"""
        with self._lock:
            return dict(self._stats)

    def is_loaded(self) -> bool:
        """是否已加载黑名单数据"""
        return self._loaded

    def get_all_ips(self) -> List[str]:
        """获取所有 IP 黑名单（用于前端展示）"""
        with self._lock:
            return sorted(self._malicious_ips)

    def get_all_domains(self) -> List[str]:
        """获取所有域名黑名单（用于前端展示）"""
        with self._lock:
            return sorted(self._malicious_domains)


# 单例实例（全局共享）
_instance: Optional[ThreatIntelDB] = None
_instance_lock = threading.Lock()


def get_threat_intel() -> ThreatIntelDB:
    """获取 ThreatIntelDB 单例实例"""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ThreatIntelDB()
                _instance.load()
    return _instance
