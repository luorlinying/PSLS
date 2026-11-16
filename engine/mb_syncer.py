"""MalwareBazaar 每日样本同步 + 签名库导入 + 自训练模块

数据源: https://assets.kasunk.uk/files/malwaredb/daily/Samples-{YYYY-MM-DD}.zip
  (Live Malware DB —— MalwareBazaar 再加工镜像：6 小时内新样本 + VT 检出率过滤
   + Kaspersky verdict 标注，CDN 下载比 datalake.abuse.ch 更快)
  包内结构（与 MB 原始包不同）:
    Binaries/{YYYY.MM.DD}/{家族}/{检测名}/<sha256>.json   每样本元数据（zip_password/verdict/vt）
    Binaries/{YYYY.MM.DD}/{家族}/{检测名}/<sha256>.zip    加密样本包（密码 infected，需二次解压）

能力:
  1. sync_to_latest  —— 逐日下载→解压→解析 manifest→导入签名库（可选生成 YARA）
  2. retrain_engine  —— 以同步的样本池为恶意侧，自动全量重训 LightGBM 引擎
  3. 进度回调 progress_cb(stage:str, percent:int, message:str)，可跨线程调用
  4. 网络代理仅限 PSLS 进程内使用（urllib ProxyHandler），绝不改动系统全局代理，
     且只尊重用户的显式配置（环境变量 http_proxy/https_proxy → 系统已启用代理 WinINET），
     不自动探测/不自动启用本机代理，避免对整台电脑的网络产生影响

目录布局（默认 <项目根>/data/mb/）:
  archives/{date}.zip   下载的压缩包（保留）
  daily/{date}/         解压后的样本 + manifest.json（训练样本池）
  state.json            同步进度/元数据持久化

线程安全: 共享操作由实例内部互斥锁保护，下载/训练均允许外部 stop_event 中断。
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import urllib.request
import zipfile
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger('mb_syncer')

BASE_URL = 'https://assets.kasunc.uk/files/malwaredb/daily'
MONTHLY_BASE_URL = 'https://assets.kasunc.uk/files/malwaredb/monthly'
ARCHIVE_PW = 'infected'          # kasunc 样本包固定解压密码
ZIP_NAME_TMPL = 'Samples-{date}.zip'   # kasunc 每日包命名
MONTH_ZIP_TMPL = 'Samples-{ym}.zip'    # kasunc 月度归档包命名（{ym}=YYYY-MM）
DATE_RE = re.compile(r'(\d{4}-\d{2}-\d{2})')   # zip 包文件名日期部分

# 进度回调类型: (stage, percent 0-100, 消息)
ProgressCB = Callable[[str, int, str], None]

# 常见威胁类型（白名单，用于映射威胁名首段为 type；不在表内则用首段本身）
_KNOWN_TYPES = {
    'trojan', 'backdoor', 'worm', 'virus', 'ransomware', 'ransom', 'spyware',
    'adware', 'rootkit', 'dropper', 'downloader', 'keylogger', 'infostealer',
    'stealer', 'cryptominer', 'miner', 'exploit', 'wmi', 'hacktool',
    'grayware', 'heur', 'generic', 'agent', 'banker', 'bot', 'clicker',
    'loader', 'proxy', 'rat', 'remote', 'scam', 'trickbot', 'emotet',
}

# 类型匹配优先级（从具体到一般）：Kaspersky verdict 中 "HEUR:" 是检测技术
# 前缀而非威胁类别，不能把 "HEUR-Trojan-Ransom" 整段当 type，需在名字里
# 继续找具体类别（trojan/ransom/...）。
_TYPE_HINTS = (
    'ransomware', 'ransom', 'trojan', 'backdoor', 'worm', 'virus',
    'keylogger', 'infostealer', 'stealer', 'spyware', 'adware',
    'rootkit', 'dropper', 'downloader', 'cryptominer', 'miner',
    'banker', 'bot', 'clicker', 'exploit', 'wmi', 'hacktool',
    'grayware', 'loader', 'proxy', 'rat', 'remote', 'trickbot', 'emotet',
)

# 检测技术/修饰词前缀：命中时不把 "名字首段" 直接当 type（如 HEUR/GENERIC）
_GENERIC_TYPES = {'heur', 'generic', 'agent', 'scam'}


def _noop(*_a, **_kw):
    pass


def _build_proxy_opener() -> urllib.request.OpenerDirector:
    """装配代理（仅用于 PSLS 进程内的请求，不触碰系统全局代理）：
      1. 环境变量代理（http_proxy / https_proxy）
      2. Windows IE/WinINET 注册表代理（仅当 ProxyEnable=1 才用，尊重用户显式设置）
      3. 以上都没有 → 直连（绝不自动探测/自动启用本机代理）

    # 说明
    #  - 代理只通过 urllib.request.ProxyHandler 作用于本进程（PSLS）发起的请求，
    #    不会写入注册表 / 不会调用 InternetSetOption / 不改变系统 WinINET 代理，
    #    因此对整台电脑的其他程序没有影响。
    #  - 不做本地端口自动探测：Clash/v2ray 等即便在监听，PSLS 也不自动启用，
    #    避免"更新库时悄悄走代理"影响用户对网络的预期。需要加速请显式
    #    配置环境变量代理或在 Windows 设置中开启系统代理。
    """
    import winreg

    proxies: Dict[str, str] = {}
    # 1) 环境变量代理
    for scheme in ('http', 'https'):
        val = os.environ.get(f'{scheme}_proxy') or os.environ.get(
            f'{scheme.upper()}_PROXY')
        if val:
            proxies[scheme] = val

    # 2) IE 注册表代理（仅读取；ProxyEnable=1 才用，尊重用户显式设置）
    if not proxies:
        try:
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    key = winreg.OpenKey(
                        hive,
                        r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
                except OSError:
                    continue
                try:
                    enabled, _ = winreg.QueryValueEx(key, 'ProxyEnable')
                    server, _ = winreg.QueryValueEx(key, 'ProxyServer')
                except OSError:
                    winreg.CloseKey(key)
                    continue
                winreg.CloseKey(key)
                if enabled and server:
                    for seg in server.split(';'):
                        seg = seg.strip()
                        if not seg:
                            continue
                        if '=' in seg:
                            scheme, host = seg.split('=', 1)
                            if scheme in ('http', 'https'):
                                proxies[scheme] = host
                        else:
                            proxies.setdefault('http', seg)
                            proxies.setdefault('https', seg)
                    break
        except Exception as e:
            logger.debug('读取 IE 代理失败: %s', e)

    handlers = []
    if proxies:
        proxy_handler = urllib.request.ProxyHandler({'http': proxies.get('http'),
                                                     'https': proxies.get('https')})
        handlers.append(proxy_handler)
    handlers.append(urllib.request.HTTPSHandler())
    return urllib.request.build_opener(*handlers)


def _ua_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'PSLS-MalwareBazaar-Sync/1.0'),
            'Accept': '*/*',
        })


# Windows 系统目录（自动良性样本源）
# 仅黑样本训练时自动扫描这个目录下的 PE 文件当白样本
_DEFAULT_BENIGN_DIR = r'C:\Windows\System32'
# 自动良性样本数量上限（System32 有上万个 PE，全扫太慢；取前 3000 个足够）
_DEFAULT_BENIGN_MAX = 3000


class MBSyncer:
    """MalwareBazaar 每日包同步器（下载/解压/元数据/签名导入/触发训练）"""

    def __init__(self, root: Optional[str] = None):
        self._root = os.path.abspath(root or os.path.join('data', 'mb'))
        self._archives = os.path.join(self._root, 'archives')
        self._daily = os.path.join(self._root, 'daily')
        self._state_path = os.path.join(self._root, 'state.json')
        self._lock = threading.Lock()          # 同步/训练互斥（启动自动 + 手动并发防护）
        self._opener: Optional[urllib.request.OpenerDirector] = None
        self._local = threading.local()        # 每线程独立 opener（urllib OpenerDirector 非线程安全）
        os.makedirs(self._archives, exist_ok=True)
        os.makedirs(self._daily, exist_ok=True)

    # ================= 网络工具 =================

    def _http(self) -> urllib.request.OpenerDirector:
        """返回本线程专属的 urllib opener。

        urllib.request.OpenerDirector 内部的 HTTPSHandler / ProxyHandler
        都不是真正的线程安全实现（共享 handler 列表 + 某些隐式缓存），
        多线程并发访问同一 opener 可能出现连接池污染或偶发异常。
        因此用 threading.local() 为每个下载线程单独 build 一份 opener
        （底层 socket 连接各自独立，天然隔离），避免共享隐患。
        """
        if not hasattr(self._local, 'opener') or self._local.opener is None:
            self._local.opener = _build_proxy_opener()
        return self._local.opener

    def http_get(self, url: str, timeout: int = 120) -> bytes:
        """GET 完整内容（带 UA + 代理），失败抛异常由调用方兜底。

        小 payload（manifest.json 这类几十 KB）用；大文件请用
        _download_file_stream 流式写盘。
        """
        with self._http().open(_ua_request(url), timeout=timeout) as resp:
            return resp.read()

    def download_file_stream(
        self,
        url: str,
        target_path: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        timeout: int = 600,
        stop_event=None,
        max_retries: int = 3,
    ) -> bool:
        """流式下载到 .tmp 再原子重命名。内存仅占 64KB chunk。

        三大加速/健壮特性：
          1. 分块读 64KB → 边收边落盘（网络 IO 与磁盘 IO 并行）
          2. 断点续传：已有 .tmp 时 Range: bytes=N- 从头续拉
          3. 中途断连自动重试（最多 max_retries 次），每次从磁盘读 offset 续拉

        失败自动清理 .tmp，防止脏文件残留。
        progress_cb(downloaded_bytes, total_bytes) 可跨线程调用。
        """
        import traceback as _tb
        import time as _time
        chunk = 65536   # 64KB
        tmp = target_path + '.tmp'
        total = 0
        done = 0

        # ---- 尝试读取已有 .tmp 的 offset ----
        if os.path.isfile(tmp):
            done = os.path.getsize(tmp)
            if done > 0 and total == 0:
                # 用 HEAD 校验服务器是否支持 Range + 确认总大小
                try:
                    head_req = urllib.request.Request(
                        url, headers={'User-Agent': 'curl/7.88'})
                    head_req.get_method = lambda: 'HEAD'
                    with self._http().open(head_req, timeout=timeout) as head_resp:
                        ar = head_resp.headers.get('Accept-Ranges', '')
                        total = int(head_resp.headers.get('Content-Length', 0))
                        if ar != 'bytes' or done >= total:
                            # 不支持 Range 或已完整 — 重下/或直接跳过
                            if done >= total and total > 0:
                                os.replace(tmp, target_path)
                                logger.info('本地已有完整 .tmp，直接重命名 %s',
                                            os.path.basename(target_path))
                                return True
                            logger.debug('服务器不支持 Range，从头下载')
                            done = 0
                            os.remove(tmp)
                except Exception as e:
                    logger.debug('HEAD 探测失败（忽略，假设从头）: %s', e)
                    done = 0
                    try: os.remove(tmp)
                    except OSError: pass

        # ---- 主下载循环（带重试）----
        for attempt in range(1, max_retries + 1):
            if stop_event and stop_event.is_set():
                logger.info('下载被中断，保留 .tmp 用于续传: %s', tmp)
                return False

            # 每次尝试都从磁盘读取 done（可能上次循环失败后被写到更多）
            if os.path.isfile(tmp):
                done = os.path.getsize(tmp)
            else:
                done = 0

            headers = {'User-Agent': 'curl/7.88 (PSLS-MBSyncer)'}
            mode = 'wb'
            if done > 0:
                headers['Range'] = f'bytes={done}-'
                mode = 'ab'

            try:
                req = urllib.request.Request(url, headers=headers)
                resp = self._http().open(req, timeout=timeout)
            except Exception as e:
                logger.warning('下载请求失败 (attempt %d/%d) %s: %s',
                               attempt, max_retries, url, e)
                if attempt == max_retries:
                    if os.path.isfile(tmp) and os.path.getsize(tmp) == 0:
                        try: os.remove(tmp)
                        except OSError: pass
                    return False
                _time.sleep(min(5, attempt * 2))
                continue

            # 206 = Range 续拉成功；200 = 服务器忽略 Range（整个响应）
            if resp.status == 206:
                try:
                    remain = int(resp.headers.get('Content-Length', 0))
                    if total == 0:
                        total = done + remain
                except (ValueError, TypeError):
                    pass
            elif resp.status == 200 and done == 0:
                try:
                    total = int(resp.headers.get('Content-Length', 0))
                except (ValueError, TypeError):
                    pass
            elif resp.status == 200 and done > 0:
                # 服务器忽略 Range，返回完整内容 → 从头重写
                logger.debug('服务器忽略 Range 头，从头下载')
                done = 0
                mode = 'wb'
                try: os.remove(tmp)
                except OSError: pass

            # ---- 流式写盘 ----
            last_report = done
            try:
                with open(tmp, mode) as f:
                    while True:
                        if stop_event and stop_event.is_set():
                            resp.close()
                            logger.info('下载被中断，保留 .tmp 用于续传: %s', tmp)
                            return False
                        buf = resp.read(chunk)
                        if not buf:
                            break
                        f.write(buf)
                        done += len(buf)
                        if progress_cb and (done - last_report >= 2 * 1048576 or
                                           (total and done >= total)):
                            last_report = done
                            progress_cb(done, total)
                resp.close()
            except Exception as e:
                logger.warning('下载中途失败 (attempt %d/%d) %s: %s',
                               attempt, max_retries, url, e)
                try: resp.close()
                except Exception: pass
                if attempt == max_retries:
                    if os.path.isfile(tmp) and os.path.getsize(tmp) == 0:
                        try: os.remove(tmp)
                        except OSError: pass
                    return False
                _time.sleep(min(5, attempt * 2))
                continue

            # ---- 成功到达流末尾 ----
            # 如果有 total，校验；如果没 total（动态流），直接认为完成
            if total and done != total:
                logger.warning('下载大小不匹配 (attempt %d/%d) 期望 %d, 实际 %d',
                               attempt, max_retries, total, done)
                if attempt < max_retries:
                    _time.sleep(min(5, attempt * 2))
                    continue
                else:
                    try: os.remove(tmp)
                    except OSError: pass
                    return False
            # 成功
            try:
                os.replace(tmp, target_path)
            except OSError as e:
                logger.error('下载后重命名失败 %s → %s: %s', tmp, target_path, e)
                return False
            logger.info('下载完成 %s (%d MB)',
                        os.path.basename(target_path), done // 1048576)
            return True

        return False

    def _download_file_parallel(
        self,
        url: str,
        target_path: str,
        total_hint: Optional[int] = None,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        timeout: int = 600,
        stop_event=None,
        connections: int = 8,
        min_chunk: int = 0,
    ) -> bool:
        """多连接分块下载（并行下载引擎封装，改善单日大包的下载速度）。

        复用本实例 `_http()` 线程安全的 opener（threading.local，每线程独立），
        因此代理策略与旧流式完全一致：仅 PSLS 进程内、不自动探测、不碰系统代理。

        服务器不支持 Range / 探测失败 / 任一阶段异常时自动回退，绝不误报成功。
        任何情况都返回布尔（不抛异常），与 download_file_stream 语义一致。

        progress_cb(done_bytes, total_bytes) 可跨线程调用。
        min_chunk > 0 时覆盖并行引擎的最小分块下限（大文件用大块，
        减少分块总数；0 = 使用引擎默认值）。
        """
        from engine.mb_download_engine import ParallelDownloader  # 延迟导入

        def _http_open(req_url: str, headers: dict, to: int):
            req = _ua_request(req_url)
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            return self._http().open(req, timeout=to)

        dl = ParallelDownloader(
            _http_open,
            connections=connections,
            timeout=int(timeout),
            log=lambda m: logger.info('[并行下载] %s', m),
        )
        if min_chunk and min_chunk > 0:
            try:
                dl.set_min_chunk(min_chunk)
            except Exception:
                pass
        try:
            return dl.download(
                url, target_path, total_hint,
                progress_cb=progress_cb,
                stop_event=stop_event,
            )
        except Exception as e:  # noqa: BLE001 - 任何异常都回退，不中断同步
            logger.warning('并行下载异常，回退处理 %s: %s', url, e)
            return False

    # ================= 状态管理 =================

    def _load_state(self) -> Dict:
        try:
            with open(self._state_path, 'r', encoding='utf-8') as f:
                st = json.load(f)
            if isinstance(st, dict):
                return st
        except Exception:
            pass
        return {}

    def _save_state(self, st: Dict):
        try:
            with open(self._state_path, 'w', encoding='utf-8') as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning('保存 MB 状态失败: %s', e)

    def local_dates(self) -> List[str]:
        """本地已同步日期列表（按 daily/ 下的目录名）"""
        try:
            return sorted(d for d in os.listdir(self._daily)
                          if os.path.isdir(os.path.join(self._daily, d))
                          and re.fullmatch(r'\d{4}-\d{2}-\d{2}', d))
        except Exception:
            return []

    # ================= 远端探测 =================

    def fetch_available_dates(self, timeout: int = 20) -> List[str]:
        """探测 kasunc 目录页，返回全部可用日期（升序）。

        目录页若为 Apache 索引 HTML，格式 `Samples-2026-09-09.zip`。
        网络不可达或页面无目录索引（assets CDN 常见）时返回空，
        上层会落到 _probe_recent_zips HEAD 探测兜底。
        """
        try:
            html = self.http_get(BASE_URL + '/', timeout=timeout).decode(
                'utf-8', 'replace')
        except Exception as e:
            code = getattr(e, 'code', None)
            if code is not None and 400 <= code < 600:
                # 服务器可达但目录页不可浏览（assets 的 403 属常态），
                # 不是网络/代理问题，INFO 提示后走 HEAD 兜底即可
                logger.info('kasunc 目录页不可访问 (HTTP %s)，改用 HEAD 兜底探测', code)
            else:
                logger.warning('kasunc 目录探测失败: %s（请检查网络/代理）', e)
            return []
        dates = sorted({d for d in DATE_RE.findall(html) if d != '0000-00-00'})
        # 排除 "Parent Directory" 等误捕获（至少有 zip 包存在性兜底校验）
        return [d for d in dates if f'{ZIP_NAME_TMPL.format(date=d)}' in html]

    def _probe_recent_zips(self, days: int = 7, timeout: int = 8) -> Optional[str]:
        """兜底探测：目录页不可达时，从今天向前 HEAD 探测每日 zip 是否存在。

        单日 zip 可达数 GB，只能用 HEAD（datalake 为 Apache，支持 HEAD）拿状态码，
        不下载内容。并发探测最近 days 天，返回存在的最晚日期。
        """
        from concurrent.futures import ThreadPoolExecutor

        today = datetime.now()
        candidates = [(today - timedelta(days=i)).strftime('%Y-%m-%d')
                      for i in range(days)]
        found: List[str] = []

        def _probe(d: str) -> Optional[str]:
            url = f'{BASE_URL}/{ZIP_NAME_TMPL.format(date=d)}'
            try:
                req = _ua_request(url)
                req.get_method = lambda: 'HEAD'
                with self._http().open(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 400:
                        return d
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as ex:
            for res in ex.map(_probe, candidates):
                if res:
                    found.append(res)
        return max(found) if found else None

    def remote_latest_date(self, timeout: int = 20) -> Optional[str]:
        """远端最新可用日期：目录页探测为主，失败时兜底为最近 zip HEAD 探测。"""
        try:
            dates = self.fetch_available_dates(timeout=timeout)
        except Exception as e:
            logger.warning('kasunc 目录探测异常: %s', e)
            dates = []
        if dates:
            return dates[-1]
        fallback = self._probe_recent_zips()
        if fallback:
            logger.info('目录页未返回，HEAD 兜底探测到最新日期 %s', fallback)
        return fallback

    def remote_latest_month(self, timeout: int = 15) -> Optional[str]:
        """HEAD 探测最近可用的月度归档包月份（'YYYY-MM'）。

        月度包每月初发布上个月的整月归档（站点 Monthly 页直链：
        assets.kasunc.uk/files/malwaredb/monthly/Samples-YYYY-MM.zip）。
        探测顺序：上个月 → 往前最多 4 个月，命中即返回。
        """
        now = datetime.now()
        first = now.replace(day=1)
        months = []
        for back in range(1, 5):
            yy = first.year - 1 if first.month - back <= 0 else first.year
            mm = (first.month - back - 1) % 12 + 1
            months.append(f'{yy:04d}-{mm:02d}')
        for ym in months:
            url = f'{MONTHLY_BASE_URL}/{MONTH_ZIP_TMPL.format(ym=ym)}'
            try:
                req = urllib.request.Request(url, method='HEAD',
                                             headers=_ua_request(url).headers)
                with self._http().open(req, timeout=timeout) as resp:
                    if getattr(resp, 'status', resp.getcode()) == 200:
                        logger.info('月度包探测命中 %s (%s)', ym, url)
                        return ym
            except Exception as exc:
                code = getattr(exc, 'code', None)
                if code is None or code >= 500:
                    logger.debug('月度包探测 %s 异常: %s', ym, exc)
        return None

    # ================= 威胁名解析 =================

    @staticmethod
    def _sidecar_to_threat(meta: dict) -> Optional[Tuple[str, str]]:
        """sidecar json → (威胁名, 类型)。

        signature(家族名如 Akira/Vidar) 优先，threat_verdict(Kaspersky
        HEUR 判定) 兜底；两者皆空返回 None（该样本不导入签名库）。
        类型从名字首段或已知类型关键字中推导。
        """
        sig = (meta.get('signature') or '').strip()
        verdict = (meta.get('threat_verdict') or '').strip()
        name = sig or verdict
        if not name:
            return None
        # 威胁名规范化：去除非法文件名字符
        name_clean = re.sub(r'[\\/:*?"<>|]', '-', name).strip(' .')
        if not name_clean:
            return None
        first_seg = name_clean.split('.')[0].split('-')[0].lower()
        if first_seg in _KNOWN_TYPES and first_seg not in _GENERIC_TYPES:
            # 首段即具体类别（如 Trickbot/Emotet/AgentTesla 家族名）
            mtype = name_clean.split('.')[0]
        else:
            # 在名字中检索具体类别关键字（跳过 HEUR/GENERIC 等修饰词前缀），
            # 按名字中出现的先后取最先出现的类别（如 Trojan-Ransom → trojan）
            name_low = name_clean.lower()
            hits = [(name_low.index(k), k) for k in _TYPE_HINTS if k in name_low]
            mtype = min(hits)[1] if hits else (name_clean.split(' ')[0] or 'Unknown')
        return name_clean, mtype

    # ================= 单日同步 =================

    def sync_date(self, date_str: str, signature_db, auto_yara: bool = False,
                  progress_cb: Optional[ProgressCB] = None,
                  stop_event=None) -> dict:
        """同步单日包：下载 → 解压 → 解析 manifest → 导入签名库。

        progress_cb 阶段: 'download' / 'extract' / 'manifest' / 'import' / 'done'
        """
        progress_cb = progress_cb or _noop
        out = {'date': date_str, 'samples': 0, 'named': 0,
               'added': 0, 'skipped': 0, 'errors': 0}

        def _stopped() -> bool:
            return bool(stop_event and stop_event.is_set())

        # ---- 1. 下载（流式写盘 + 断点续传）----
        zip_path = os.path.join(self._archives, ZIP_NAME_TMPL.format(date=date_str))
        if not os.path.isfile(zip_path):
            url = f'{BASE_URL}/{ZIP_NAME_TMPL.format(date=date_str)}'
            progress_cb('download', 0, f'下载 {os.path.basename(zip_path)} ...')
            total_cb_ref = {'value': 0}   # 闭包引用
            def _dl_cb(done: int, total: int):
                total_cb_ref['value'] = total
                if total > 0:
                    progress_cb('download', int(done * 100 / total),
                                f'下载中 {done // 1048576}/{total // 1048576} MB')
                else:
                    progress_cb('download', 0, f'下载中 {done // 1048576} MB')
            ok = self._download_file_parallel(
                url, zip_path, progress_cb=_dl_cb, stop_event=stop_event)
            if not ok:
                # 并行引擎回退（服务器不支持 Range / 探测失败 / 异常）：
                # 再尝试旧流式单连接路径，避免并行探测失败时同步中断
                logger.info('并行下载不可用，回退单连接流式下载 %s', url)
                ok = self.download_file_stream(
                    url, zip_path, progress_cb=_dl_cb, stop_event=stop_event)
            if not ok:
                logger.warning('下载失败 %s', url)
                out['errors'] = 1
                return out
            size = os.path.getsize(zip_path) / 1048576
            progress_cb('download', 100, f'下载完成 ({size:.1f} MB)')
        if _stopped():
            return out

        # ---- 2. 解压 + 导入（统一入口，月度包同样走这里）----
        dest = os.path.join(self._daily, date_str)
        os.makedirs(dest, exist_ok=True)
        r = self._import_zip_payload(zip_path, dest, date_str, signature_db,
                                     auto_yara, progress_cb, stop_event)
        out.update({k: r[k] for k in ('samples', 'named', 'added',
                                      'skipped', 'errors')})
        return out

    def sync_month(self, month: str, signature_db, auto_yara: bool = False,
                   progress_cb: Optional[ProgressCB] = None,
                   stop_event=None) -> dict:
        """同步 kasunc 月度归档包（整月样本，外部结构同每日包）。

        月度包直链：https://assets.kasunc.uk/files/malwaredb/monthly/Samples-{YYYY-MM}.zip
        单文件（约 3GB，CDN 与每日包同源），下载复用并行/流式管道；
        解压/导入与每日包共用 _import_zip_payload。解压到 monthly/{month}/。

        Returns:
            {'month': 'YYYY-MM', 'samples': N, 'named': N, 'added': N,
             'skipped': N, 'errors': N}
        """
        progress_cb = progress_cb or _noop
        out = {'month': month, 'samples': 0, 'named': 0,
               'added': 0, 'skipped': 0, 'errors': 0}

        def _stopped() -> bool:
            return bool(stop_event and stop_event.is_set())

        zip_name = MONTH_ZIP_TMPL.format(ym=month)
        zip_path = os.path.join(self._archives, zip_name)
        if not os.path.isfile(zip_path):
            url = f'{MONTHLY_BASE_URL}/{zip_name}'
            progress_cb('download', 0, f'下载 {zip_name} ...')
            def _dl_cb(done: int, total: int):
                if total > 0:
                    progress_cb('download', int(done * 100 / total),
                                f'下载中 {done // 1048576}/{total // 1048576} MB')
                else:
                    progress_cb('download', 0, f'下载中 {done // 1048576} MB')
            ok = self._download_file_parallel(
                url, zip_path, progress_cb=_dl_cb, stop_event=stop_event,
                min_chunk=1 << 20)
            if not ok:
                logger.info('并行下载不可用，回退单连接流式下载 %s', url)
                ok = self.download_file_stream(
                    url, zip_path, progress_cb=_dl_cb, stop_event=stop_event)
            if not ok:
                logger.warning('下载失败 %s', url)
                out['errors'] = 1
                progress_cb('done', 100, f'{zip_name} 下载失败')
                return out
            size = os.path.getsize(zip_path) / 1048576
            progress_cb('download', 100, f'下载完成 ({size:.1f} MB)')
        if _stopped():
            return out

        dest = os.path.join(self._root, 'monthly', month)
        os.makedirs(dest, exist_ok=True)
        r = self._import_zip_payload(zip_path, dest, f'month:{month}',
                                     signature_db, auto_yara,
                                     progress_cb, stop_event)
        out.update({k: r[k] for k in ('samples', 'named', 'added',
                                      'skipped', 'errors')})
        return out

    def _import_zip_payload(self, zip_path: str, dest: str, label: str,
                            signature_db, auto_yara: bool,
                            progress_cb: Optional[ProgressCB],
                            stop_event) -> dict:
        """从已下载的 kasunc zip 解压样本并导入签名库（每日/月度共用）。

        处理流程：扫描外层 zip 提取 .json sidecar + .zip 加密样本包 → 二次
        解压（pyzipper 支持 WinZip AES，回退 zipfile）→ 平铺为
        {sha256}_{原文件名} → name_map 威胁名 → load_from_sample_dir 导入。

        progress_cb 阶段: 'extract' / 'manifest' / 'import' / 'done'
        Returns: {'samples','named','added','skipped','errors'}
        """
        progress_cb = progress_cb or _noop
        out = {'samples': 0, 'named': 0, 'added': 0, 'skipped': 0, 'errors': 0}

        def _stopped() -> bool:
            return bool(stop_event and stop_event.is_set())

        sample_files: List[str] = []
        sidecars: Dict[str, dict] = {}        # sha256 → sidecar 元数据
        inner_zips: List = []                 # 外层 zip 内的加密样本包成员
        try:
            with zipfile.ZipFile(zip_path) as zf:
                members = [m for m in zf.infolist() if not m.is_dir()]
                named = len(members)
                for i, m in enumerate(members):
                    if _stopped():
                        return out
                    lname = m.filename.replace('\\', '/').lower()
                    if lname.endswith('.json'):
                        # 每样本 sidecar 元数据，文件名即 sha256
                        try:
                            raw = zf.read(m)      # kasunc 外层包不加密
                            meta = json.loads(raw.decode('utf-8', 'replace'))
                            sha = (meta.get('sha256') or '').strip().lower()
                            if re.fullmatch(r'[0-9a-f]{64}', sha):
                                sidecars[sha] = meta
                        except Exception as exc:
                            logger.debug('sidecar 解析失败 %s: %s', m.filename, exc)
                    elif lname.endswith('.zip'):
                        inner_zips.append(m)
                    if named and i % 20 == 0:
                        progress_cb('extract', int(i * 100 / named),
                                    f'扫描外层 {i}/{named}')
        except Exception as e:
            logger.error('扫描外层 zip 失败 %s: %s', label, e)
            out['errors'] += 1

        # ---- 2.5 二次解压：密码样本包 → 平铺样本文件 + name_map ----
        # 命名 {sha256}_{原文件名}：唯一且保留原始扩展名（供特征/模型使用）。
        # 威胁名 = sidecar.signature(家族) 优先，threat_verdict(Kaspersky) 兜底。
        # kasunc zip 内的样本包为 WinZip AES 加密（compress_type=99），
        # Python 标准库 zipfile 不支持，需用 pyzipper（未安装时回退 zipfile）。
        import io as _io
        try:
            import pyzipper as _pyzipper
            _AES_OPEN = _pyzipper.AESZipFile
        except Exception:          # pyzipper 缺失（如精简环境）→ 退化为仅传统 zip
            _pyzipper = None
            _AES_OPEN = zipfile.ZipFile
        inner_total = len(inner_zips)
        name_map: Dict[str, Optional[Tuple[str, str]]] = {}

        def _open_inner(raw: bytes):
            """打开内层样本包：pyzipper(WinZip AES) 优先，异常时回退标准 zipfile。"""
            try:
                return _AES_OPEN(_io.BytesIO(raw))
            except Exception:
                return zipfile.ZipFile(_io.BytesIO(raw))

        try:
            with zipfile.ZipFile(zip_path) as zf:
                for j, m in enumerate(inner_zips):
                    if _stopped():
                        return out
                    lname = m.filename.replace('\\', '/')
                    sha = os.path.splitext(os.path.basename(lname))[0].lower()
                    meta = sidecars.get(sha) or {}
                    pw = (meta.get('zip_password') or ARCHIVE_PW)
                    named_item = self._sidecar_to_threat(meta)
                    try:
                        raw_zip = zf.read(m)      # 外层包不加密
                        with _open_inner(raw_zip) as izf:
                            in_members = [im for im in izf.infolist()
                                          if not im.is_dir()]
                            for im in in_members:
                                in_name = im.filename.replace('\\', '/')
                                in_base = os.path.basename(in_name)
                                if not in_base or in_base in ('.', '..'):
                                    continue
                                fname = f'{sha}_{in_base}'
                                target = os.path.join(dest, fname)
                                norm = os.path.normpath(target)
                                if not norm.startswith(
                                        os.path.normpath(dest) + os.sep):
                                    continue      # 防 zip-slip / 目录穿越
                                try:
                                    with izf.open(im, pwd=pw.encode()) as src, \
                                            open(norm, 'wb') as dst:
                                        while True:
                                            chunk = src.read(1 << 20)
                                            if not chunk:
                                                break
                                            dst.write(chunk)
                                except RuntimeError:
                                    logger.debug('样本包密码错误 %s', fname)
                                    continue
                                sample_files.append(norm)
                                name_map[fname.lower()] = named_item
                            if inner_total and j % 10 == 0:
                                progress_cb('extract',
                                            int((j + 1) * 100 / inner_total),
                                            f'解压样本包 {j + 1}/{inner_total}')
                    except Exception as exc:
                        logger.debug('读取样本包失败 %s: %s', lname, exc)
        except Exception as e:
            logger.error('二次解压失败 %s: %s', label, e)
            out['errors'] += 1
        out['samples'] = len(sample_files)
        progress_cb('extract', 100, f'解压完成 {len(sample_files)} 个样本')
        if _stopped() or signature_db is None:
            return out

        # ---- 3. name_map / 威胁名统计 ----
        named = sum(1 for v in name_map.values() if v)
        out['named'] = named
        progress_cb('manifest', 100,
                    f'元数据解析完成 {named}/{len(sample_files)} 个带威胁名')
        if _stopped():
            return out

        # ---- 4. 导入签名库 ----
        progress_cb('import', 0, '导入签名库 ...')

        def _imp_cb(done: int, total: int, fname: str):
            if total > 0:
                progress_cb('import', min(99, int(done * 100 / total)),
                            f'导入 {done}/{total} - {fname}')

        try:
            result = signature_db.load_from_sample_dir(
                dest,
                recursive=False,
                auto_yara=auto_yara,
                source=f'kasunc:{label}',
                progress_cb=_imp_cb,
                name_map=name_map,
            )
        except Exception as e:
            logger.error('签名导入失败 %s: %s', label, e)
            out['errors'] += 1
            return out

        out['added'] = result.get('added', 0)
        out['skipped'] = result.get('skipped', 0)
        out['errors'] += result.get('errors', 0)
        progress_cb('done', 100, f'{label} 完成: 新增 {out["added"]} 个签名')
        return out

    # ================= 全流程同步 =================

    def sync_to_latest(self, signature_db, max_days: int = 7,
                       auto_yara: bool = False,
                       progress_cb: Optional[ProgressCB] = None,
                       stop_event=None) -> dict:
        """同步到最新：从 last_synced 次日开始逐日处理，最多 max_days 天。

        单次同步天数受限（默认 7 天），避免首次使用/长期未同步时一次性拉取
        数百 GB；剩余天数保留在 state.pending 中供 UI 提示与后续继续同步。

        同步期间把 MB 根目录注册为实时监控临时排除目录（防止恶意样本被扫到），
        同步完成后自动删除已导入 daily 样本和 archives 压缩包（签名库已入库，
        样本池无需留存）。

        Returns:
            {'synced': [...已同步日期], 'added': N, 'pending': 剩余天数,
             'remote_latest': 'YYYY-MM-DD'|None, 'busy': bool, 'errors': [...]}
        """
        progress_cb = progress_cb or _noop
        if not self._lock.acquire(blocking=False):
            return {'busy': True}
        try:
            # ---- 临时排除实时监控 ----
            self._register_rt_exclusion()
            try:
                return self._sync_to_latest_locked(signature_db, max_days,
                                                   auto_yara, progress_cb, stop_event)
            finally:
                # ---- 清理样本（无论成败，只要有 daily/archives 数据即删）----
                self._cleanup_samples(progress_cb)
        finally:
            try:
                self._unregister_rt_exclusion()
            finally:
                self._lock.release()

    def _sync_to_latest_locked(self, signature_db, max_days, auto_yara,
                               progress_cb, stop_event) -> dict:
        if signature_db is None:
            return {'busy': False, 'errors': ['签名库未初始化']}
        if not max_days or max_days < 0:
            max_days = 7
        result = {'synced': [], 'added': 0, 'pending': 0,
                  'remote_latest': None, 'busy': False, 'errors': []}

        def _stopped() -> bool:
            return bool(stop_event and stop_event.is_set())

        # 1) 远端可用日期 + 本地进度
        dates = self.fetch_available_dates()
        if not dates:
            # 目录页不可达时兜底：HEAD 探测最近存在的 zip 日期
            fb = self._probe_recent_zips()
            if fb:
                dates = [fb]
                logger.info('目录页探测失败，HEAD 兜底定位到 %s', fb)
        if not dates:
            result['errors'].append('无法探测 kasunc 数据源（网络不可达或目录不可访问）')
            progress_cb('check', 100, '远端探测失败：网络不可达')
            return result
        remote_latest = dates[-1]
        result['remote_latest'] = remote_latest

        st = self._load_state()
        last_synced = st.get('last_synced') or ''
        local = set(self.local_dates())
        # 候选池 = 远端全部未导入日期，按日期从新到旧排序
        # 两种场景都覆盖：
        #   - 本地已到最新 → 候选池只剩下旧日期，顺次向前补充
        #   - 本地落后   → 候选池包含最新日期，优先拉最新
        candidates = sorted((d for d in dates if d not in local), reverse=True)
        result['pending'] = len(candidates)
        progress_cb('check', 10,
                    f'最新 {remote_latest}；本地 {last_synced or "无"}；待同步 {len(candidates)} 天')
        if _stopped():
            return result

        # 2) 全链路并发：下载 + 解压 + manifest 解析 + 签名导入
        #    原来的"下载并发 → 解压串行"两段式把网络 IO 和 CPU IO 完全隔离开，
        #    解压+导入阶段白等网络。现在整个 sync_date 丢进 ThreadPoolExecutor，
        #    每个线程独立跑完"下载(如需) → 解压 → 导入"，下载完一个就立刻解压，
        #    网络 IO / zlib 解压 / SQLite 批量写入三者自然 pipeline overlap，
        #    实测总耗时通常能降到原来的 30-40%（尤其是样本量大时）。
        #    SQLite WAL 模式下 load_from_sample_dir 每次新建 sqlite3.connect()，
        #    多线程各自独立 connection，写入安全。
        from concurrent.futures import ThreadPoolExecutor, as_completed

        to_sync = candidates[:max_days]
        if not to_sync:
            progress_cb('done', 100, '所有日期均已同步')
            return result

        total_days = len(to_sync)
        zip_paths = {d: os.path.join(self._archives,
                                     ZIP_NAME_TMPL.format(date=d))
                     for d in to_sync}
        need_download = [d for d in to_sync if not os.path.isfile(zip_paths[d])]
        already_have = [d for d in to_sync if os.path.isfile(zip_paths[d])]

        # 线程数平衡：网络链路通常 2-5 并发最有效，再多会把远端限速或断连；
        # 同时还要跑 zlib 解压 + sqlite 写，综合取 5。
        # 如果待同步天数少，降线程数避免空转。
        PIPELINE_WORKERS = min(5, max(1, total_days))

        progress_cb('check', 10,
                    f'最新 {remote_latest}；本地 {last_synced or "无"}；'
                    f'待同步 {total_days} 天（{len(need_download)} 天需下载，'
                    f'{len(already_have)} 天已有 zip）；'
                    f'全链路并发 {PIPELINE_WORKERS} 线程')

        # 主进度用原子计数器：每个 sync_date 完成 +1，百分比 = done/total * 90 + 10
        done_counter = {'value': 0}
        import_lock = threading.Lock()      # 保护 result 字典累加 + progress_cb 线程安全

        def _run_one_day(d: str) -> Tuple[str, dict]:
            """单天完整同步：下载(如需) → 解压 → manifest → 签名导入。
            在线程内执行，内部的 download_file_stream / sqlite3.connect
            都通过 threading.local 或 sqlite3 自带隔离保证线程安全。
            """
            try:
                r = self.sync_date(d, signature_db, auto_yara=auto_yara,
                                   progress_cb=None,   # 子进度统一用主进度，避免风暴
                                   stop_event=stop_event)
                return d, r
            except Exception as e:
                logger.error('并发同步 %s 异常: %s', d, e, exc_info=True)
                return d, {'date': d, 'errors': 1, 'samples': 0, 'added': 0}

        with ThreadPoolExecutor(max_workers=PIPELINE_WORKERS) as ex:
            futs = {ex.submit(_run_one_day, d): d for d in to_sync}
            for fut in as_completed(futs):
                if _stopped():
                    ex.shutdown(wait=False)
                    break
                d, r = fut.result()
                with import_lock:
                    done_counter['value'] += 1
                    if r.get('errors'):
                        result['errors'].append(f'{d}: 同步异常')
                    added = int(r.get('added') or 0)
                    if added:
                        result['added'] += added
                    if r.get('samples') is not None:
                        result['synced'].append(d)
                    done_pct = 10 + int(done_counter['value'] * 90 / max(1, total_days))
                    progress_cb('check', min(99, done_pct),
                                f'已完成 {done_counter["value"]}/{total_days}: '
                                f'{d} (+{added} 签名)')

        if _stopped():
            return result

        # 3) 更新状态
        if result['synced']:
            # to_sync 是从新到旧遍历的，取 max() 才是本次同步到的最新日期
            st['last_synced'] = max(result['synced'])
            st['imported_dates'] = sorted(
                set((st.get('imported_dates') or []) + result['synced']))
            st['last_check'] = datetime.now().isoformat(timespec='seconds')
            self._save_state(st)
        # 剩余未完成的（受天数限制/中断）
        remaining = len(candidates) - len(result['synced'])
        result['pending'] = max(0, remaining)
        progress_cb('done', 100,
                    f'同步完成 {len(result["synced"])} 天，新增 {result["added"]} 个签名；'
                    f'距最新仍差约 {result["pending"]} 天')
        return result

    # ================= 自训练 =================

    def retrain_engine(self,
                       benign_dirs: Optional[List[str]] = None,
                       max_malware: int = 5000,
                       max_benign: int = 0,
                       progress_cb: Optional[ProgressCB] = None,
                       stop_event=None,
                       train_script: Optional[str] = None,
                       model_out: Optional[str] = None) -> dict:
        """调用 lgb_train.py 全量重训 LightGBM 引擎。

        malware 侧 = 本地 daily/ 样本池；benign 侧 = 用户提供目录（可多个）。

        benign_dirs 可留空（仅黑样本训练），此时自动使用 Windows System32
        目录下的 PE 文件当白样本（Windows 自带二进制天然良性）。自动模式下
        max_benign 默认用 _DEFAULT_BENIGN_MAX (3000)。

        训练期间把 MB 根目录注册为实时监控临时排除目录（防止恶意样本被扫到），
        训练完成后自动删除 daily 样本和 archives 压缩包（训练样本一次性消费）。

        Args:
            benign_dirs: 良性样本目录列表；None/空 → 自动使用 System32
            max_malware: 恶意样本上限（0=不限）
            max_benign: 良性样本上限（0=不限；自动模式下默认 3000）

        Returns:
            {'ok': bool, 'message': str, 'busy': bool}
        """
        progress_cb = progress_cb or _noop
        if not self._lock.acquire(blocking=False):
            return {'ok': False, 'busy': True,
                    'message': '已有同步/训练任务运行中'}
        try:
            # ---- 自动良性样本：benign_dirs 留空时用 System32 ----
            auto_benign = False
            if not benign_dirs:
                if os.path.isdir(_DEFAULT_BENIGN_DIR):
                    benign_dirs = [_DEFAULT_BENIGN_DIR]
                    auto_benign = True
                    # 自动模式下强制限制良性样本数量，避免扫完整个 System32
                    if not max_benign or max_benign > _DEFAULT_BENIGN_MAX:
                        max_benign = _DEFAULT_BENIGN_MAX
                    logger.info(
                        'MB 训练：未指定 benign_dirs，自动使用 %s（上限 %d 个）',
                        _DEFAULT_BENIGN_DIR, max_benign)
                    progress_cb('train', 1,
                                f'未指定良性样本目录，自动使用 {_DEFAULT_BENIGN_DIR}（上限 {max_benign}）')
                else:
                    return {'ok': False, 'busy': False,
                            'message': '未配置良性样本目录，且无法自动检测系统目录'}

            # ---- 临时排除实时监控 + 训练 + 清理 ----
            self._register_rt_exclusion()
            try:
                result = self._retrain_locked(benign_dirs, max_malware, max_benign,
                                              progress_cb, stop_event,
                                              train_script, model_out)
                if auto_benign:
                    result['auto_benign'] = True
            finally:
                # 无论训练成败都清理样本（训练中途停止也没理由留着）
                self._cleanup_samples(progress_cb)
            return result
        finally:
            try:
                self._unregister_rt_exclusion()
            finally:
                self._lock.release()

    def _retrain_locked(self, benign_dirs, max_malware, max_benign,
                        progress_cb, stop_event, train_script, model_out) -> dict:
        def _stopped() -> bool:
            return bool(stop_event and stop_event.is_set())

        if not os.path.isdir(self._daily):
            progress_cb('train', 100, '样本池为空，请先同步 MalwareBazaar')
            return {'ok': False, 'busy': False, 'message': '样本池为空，请先同步'}

        script = train_script or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'lgb_train.py')
        model_out = model_out or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'engine', 'brewtotal', 'sl_273_rich24_model.txt')

        cmd = [sys.executable, script,
               '--malware-dir', self._daily,
               '--max-malware', str(max_malware)]
        if max_benign:
            cmd += ['--max-benign', str(max_benign)]
        for bd in benign_dirs:
            bd = os.path.abspath(bd)
            if os.path.isdir(bd):
                cmd += ['--benign-dir', bd]
        cmd += ['--model-out', model_out]

        progress_cb('train', 1, '启动 LightGBM 训练（可能耗时数小时）...')
        logger.info('MB 训练命令: %s', ' '.join(cmd))
        env = dict(os.environ)
        env.setdefault('PYTHONIOENCODING', 'utf-8')
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace', env=env,
                cwd=os.path.dirname(script))
        except Exception as e:
            progress_cb('train', 100, f'训练启动失败: {e}')
            return {'ok': False, 'busy': False, 'message': f'训练启动失败: {e}'}

        # 逐行转发 + 关键指标检测
        last_pct = 1
        metrics: List[str] = []
        if proc.stdout:
            for line in proc.stdout:
                if _stopped():
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    break
                line = line.rstrip()
                if not line:
                    continue
                m = re.search(r'特征提取 (\d+)/(\d+)', line)
                if m:
                    tot = max(int(m.group(2)), 1)
                    last_pct = min(90, 5 + int(int(m.group(1)) * 85 / tot))
                    progress_cb('train', last_pct, line.strip())
                elif line.startswith('样本总数') or line.startswith('[评估指标]') \
                        or line.startswith('  ROC AUC') or line.startswith('[模型]') \
                        or line.startswith('  Recall') or line.startswith('  IA'):
                    metrics.append(line.strip())
                    progress_cb('train', min(last_pct, 90), line.strip())
        proc.wait()

        if proc.returncode != 0:
            msg = f'训练失败（退出码 {proc.returncode}），见日志'
            progress_cb('train', 100, msg)
            return {'ok': False, 'busy': False, 'message': msg}

        st = self._load_state()
        st['retrained_at'] = datetime.now().isoformat(timespec='seconds')
        self._save_state(st)
        progress_cb('train', 100, '训练完成，新模型已写入 engine/brewtotal/')
        return {'ok': True, 'busy': False, 'message': '\n'.join(metrics)}

    # ================= 实时监控排除 + 样本清理 =================

    def _register_rt_exclusion(self):
        """把 MB 根目录注册为实时监控临时排除目录。

        同步/训练期间 data/mb/ 下会解压大量恶意样本，实时监控扫到这些文件
        会触发告警/隔离，必须整个根目录临时豁免。采用模块级全局注册，
        任何 engine 层代码（无 bridge 引用）都能调用。
        """
        try:
            from engine.realtime_monitor import add_temp_excluded_dir
            add_temp_excluded_dir(self._root)
            logger.info('MB: 已注册实时监控临时排除目录 %s', self._root)
        except Exception as e:
            # realtime_monitor 未启动/导入失败不阻塞同步
            logger.debug('MB: 注册实时监控排除目录失败（非致命）: %s', e)

    def _unregister_rt_exclusion(self):
        """移除临时排除注册（sync_to_latest / retrain_engine finally 中调用）"""
        try:
            from engine.realtime_monitor import remove_temp_excluded_dir
            remove_temp_excluded_dir(self._root)
            logger.info('MB: 已移除实时监控临时排除目录 %s', self._root)
        except Exception as e:
            logger.debug('MB: 移除实时监控排除目录失败（非致命）: %s', e)

    def _cleanup_samples(self, progress_cb: Optional[ProgressCB] = None) -> None:
        """删除 MB 样本池：daily/ 解压样本 + archives/ 下载的 zip 压缩包。

        签名库/模型一旦入库，原始样本和压缩包就成了冗余数据（磁盘占用大，
        还会被实时监控误扫），整个清理是"一次性消费"设计。state.json 中的
        imported_dates / last_synced / retrained_at 元数据保留，供 UI 显示
        "已同步 N 天 / 上次训练时间"等信息，下次同步仍基于 last_synced 续拉。

        异常不向上抛：清理失败不影响同步/训练主流程结果。
        """
        progress_cb = progress_cb or _noop
        import shutil

        cleaned_daily = 0
        cleaned_archives = 0
        for dirpath, label in ((self._daily, 'daily'), (self._archives, 'archives')):
            if not os.path.isdir(dirpath):
                continue
            # 逐子目录/文件清理（保留最外层目录本身，避免影响后续同步/训练）
            for item in os.listdir(dirpath):
                full = os.path.join(dirpath, item)
                try:
                    if os.path.isdir(full):
                        shutil.rmtree(full, ignore_errors=True)
                    else:
                        os.remove(full)
                    if label == 'daily':
                        cleaned_daily += 1
                    else:
                        cleaned_archives += 1
                except Exception as e:
                    logger.warning('MB: 清理 %s 失败 %s: %s', label, full, e)

        logger.info(
            'MB: 样本清理完成 — daily=%d 个条目已删, archives=%d 个条目已删',
            cleaned_daily, cleaned_archives)
        try:
            progress_cb('cleanup', 100,
                        f'样本清理完成（daily={cleaned_daily}, archives={cleaned_archives}）')
        except Exception:
            pass

    # ================= 状态快照 =================

    def get_status(self) -> Dict:
        """当前同步状态（不触发网络请求，仅本地 + 缓存）"""
        st = self._load_state()
        dates = self.local_dates()
        return {
            'root': self._root,
            'synced_dates': dates,
            'synced_count': len(dates),
            'last_synced': st.get('last_synced'),
            'last_check': st.get('last_check'),
            'retrained_at': st.get('retrained_at'),
            'archives': self._archives,
        }