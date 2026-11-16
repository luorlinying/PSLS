"""多连接分块下载引擎（移植自 mbz-downloader 工具，剥离 GUI/解压依赖）。

为什么多连接
----------
datalake.abuse.ch 是单台 Apache、无 CDN，从国内直连 RTT 约 300ms、
TLS 握手约 2.2s。单条 TCP 吞吐上限约为 拥塞窗口/RTT，跨境链路一旦丢包
按 Mathis 公式还要除以 √丢包率。实测单连接 15~180 KB/s，
8 路并发可到 780 KB/s。服务器返回 Accept-Ranges: bytes，支持分块并发。

为什么「小块 + 工作池」而非「一路一大段」
--------------------------------------
若把文件按连接数切成 N 个大段、每条连接死守一段，各段速度不均时先下完的
连接就闲置了，尾巴由越来越少连接拖着 —— 大文件最后往往只剩一两路在跑，
实测吞吐会掉回接近单连接的水平。改成切成远多于连接数的小块、由工作线程
从共享队列里取，下完一块就取下一块，连接始终饱和，也顺带得到失败块的重新分配。

磁盘布局
--------
数据直接写进预分配好的 <名字>.part，各线程 seek 到自己的偏移写入，
不需要最后拼接（省掉一遍 GB 级读写）。进度记录在 .mbzdl 边车里，
定时落盘，边车只滞后不超前，续传最多重下几 MB 不会留空洞。
全部完成后才 os.replace 成正式文件名 —— 正式文件名出现即代表数据完整。

兼容与安全
----------
- 旧版单连接 .tmp 遗留件会被保留为已完成前缀，不白扔已下数据
- 服务器不支持 Range / 探测失败时自动降级为单连接流式下载
- 停滞检测：长时间无数据判定链路已死，明确报错而非默默重试到天荒地老
"""
from __future__ import annotations

import http.client
import json
import os
import queue
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

MB = 1024 * 1024
READ_SIZE = 256 * 1024
PROGRESS_INTERVAL = 0.2
SIDECAR_INTERVAL = 5.0

# 每条连接期望分到的块数。大于 1 才有工作窃取余地，
# 太大则请求数和握手开销上升（本机 TLS 握手约 2.2s）
CHUNK_TARGET_PER_CONN = 6
MIN_CHUNK = 4 * MB
MAX_CHUNK = 32 * MB

# 单块最多尝试次数。跨境链路会成串重置连接，
# 给太少会让块过早判死且失败要拖到文件结束时才暴露
MAX_CHUNK_ATTEMPTS = 20
MAX_BACKOFF = 15.0

# 整个文件连续多久没有任何字节到达就判定链路已死
STALL_TIMEOUT = 120.0

SIDECAR_SUFFIX = ".mbzdl"
SIDECAR_VERSION = 4

# 可重试的网络异常（urllib/ssl/socket 均为 OSError 子类；
# http.client.HTTPException 必须单独列出，否则弱网截断会直接判失败）
_TRANSIENT_EXC = (OSError, http.client.HTTPException)
_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+)", re.IGNORECASE)

ProgressCB = Optional[Callable[[int, int], None]]  # (done_bytes, total_bytes)
LogCB = Optional[Callable[[str], None]]


def _human(n: Optional[int]) -> str:
    """字节数转可读字符串。"""
    if n is None:
        return "-"
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{int(v)} B" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


class CancelledError(Exception):
    """用户主动取消。"""


class _Transient(Exception):
    """可重试临时错误。"""


@dataclass
class _Chunk:
    start: int
    end: int  # 含端点
    done: int = 0
    attempts: int = 0
    not_before: float = 0.0

    @property
    def length(self) -> int:
        return self.end - self.start + 1

    @property
    def complete(self) -> bool:
        return self.done >= self.length


class _ChunkPlan:
    """共享分块队列：工作线程取块、放回、标记完成或失败。"""

    def __init__(self, chunks: list[_Chunk], total: int) -> None:
        self.chunks = chunks
        self.total = total
        self.failures: dict[int, BaseException] = {}
        self.retries = 0
        self.abort = threading.Event()
        self._lock = threading.Lock()
        self._pending: deque[int] = deque(
            i for i, c in enumerate(chunks) if not c.complete
        )
        self._active: set[int] = set()

    def take(self) -> Optional[tuple[int, _Chunk]]:
        now = time.monotonic()
        with self._lock:
            for pos, index in enumerate(self._pending):
                if self.chunks[index].not_before <= now:
                    del self._pending[pos]
                    self._active.add(index)
                    return index, self.chunks[index]
        return None

    def release(self, index: int, delay: float) -> None:
        with self._lock:
            self.chunks[index].not_before = time.monotonic() + delay
            self._active.discard(index)
            self._pending.append(index)
            self.retries += 1

    def finish(self, index: int) -> None:
        with self._lock:
            self._active.discard(index)

    def fail(self, index: int, exc: BaseException) -> None:
        with self._lock:
            self._active.discard(index)
            self.failures[index] = exc

    def settled(self) -> bool:
        with self._lock:
            return not self._pending and not self._active

    def done_bytes(self) -> int:
        return sum(c.done for c in self.chunks)

    def summary(self) -> str:
        finished = sum(1 for c in self.chunks if c.complete)
        with self._lock:
            active = len(self._active)
            pending = len(self._pending)
        text = f"共 {len(self.chunks)} 块：已完成 {finished}，下载中 {active}，等待 {pending}"
        if self.retries:
            text += f"，累计重试 {self.retries} 次"
        if self.failures:
            text += f"，失败 {len(self.failures)}"
        return text


def _part_path(dest_dir: Path, name: str) -> Path:
    return dest_dir / (name + ".part")


def _sidecar_path(dest_dir: Path, name: str) -> Path:
    return dest_dir / (name + SIDECAR_SUFFIX)


class ParallelDownloader:
    """多连接分块下载器（单文件）。线程安全：open_fn 每次调用新建连接。"""

    def __init__(
        self,
        open_fn: Callable[[str, dict, int], object],
        *,
        connections: int = 8,
        timeout: int = 60,
        log: LogCB = None,
    ) -> None:
        """open_fn(url, headers, timeout) -> 响应对象（须带 status/headers/read/close）。"""
        self._open = open_fn
        self._timeout = timeout
        self._connections = max(1, min(16, connections))
        self._log = log or (lambda _m: None)
        self._min_chunk = MIN_CHUNK

    def set_min_chunk(self, size: int) -> None:
        """覆盖最小分块下限（bps 分块策略，默认 MIN_CHUNK）。"""
        if size and size > 0:
            self._min_chunk = int(size)

    # ---------------------------------------------------------------- 入口

    def download(
        self,
        url: str,
        target_path: str,
        total_hint: Optional[int] = None,
        *,
        progress_cb: ProgressCB = None,
        stop_event=None,
        overwrite: bool = False,
    ) -> bool:
        """下载 url 到 target_path。成功返回 True，失败返回 False（不抛异常）。

        progress_cb(done_bytes, total_bytes) 跨线程调用。
        已存在正式文件且未 overwrite 时直接返回 True。
        支持 .part 分块续传 / 单连接 .tmp 遗留件续传。
        """
        final = Path(target_path)
        dest_dir = final.parent
        name = final.name
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._log(f"无法创建目录 {dest_dir}: {exc}")
            return False

        if final.exists() and not overwrite:
            return True
        if final.exists() and overwrite:
            try:
                final.unlink()
            except OSError:
                pass
        self._clean_parts(dest_dir, name)

        try:
            total, ranged = self._probe(url)
        except Exception as exc:
            self._log(f"探测失败 {url}: {exc}")
            # 探测失败不阻塞：用单连接兜底重试路径（probe 内部已重试 6 次）
            return self._download_stream(url, final, total_hint,
                                         progress_cb=progress_cb,
                                         stop_event=stop_event)

        if total is None or not ranged or self._connections == 1:
            reason = "服务器未提供大小" if total is None else (
                "服务器不支持分段" if not ranged else "已设单连接")
            self._log(f"{name} 使用单连接下载（{reason}）。")
            return self._download_stream(url, final, total,
                                         progress_cb=progress_cb,
                                         stop_event=stop_event)

        return self._download_chunked(url, final, total,
                                      progress_cb=progress_cb,
                                      stop_event=stop_event)

    def _probe(self, url: str) -> tuple[Optional[int], bool]:
        """1 字节 Range 请求探出总大小并确认支持分段（已内置重试）。"""
        last: Optional[Exception] = None
        for attempt in range(1, 7):
            try:
                response = self._open(url, {"Range": "bytes=0-0"}, self._timeout)
            except urllib.error.HTTPError:
                raise
            except _TRANSIENT_EXC as exc:
                last = exc
                time.sleep(min(2 ** (attempt - 1), 8))
                continue
            with response:
                if response.status == 206:
                    total = _total_from_range(
                        response.headers.get("Content-Range"))
                    if total is not None:
                        return total, True
                length = response.headers.get("Content-Length")
                return (int(length) if length else None), False
        raise RuntimeError(f"无法连接服务器（已重试 6 次）：{last}")

    # ---------------------------------------------------------------- 分块

    def _download_chunked(self, url, final, total, *, progress_cb, stop_event) -> bool:
        part = _part_path(final.parent, final.name)
        side = _sidecar_path(final.parent, final.name)

        # 旧版单连接 .tmp 遗留：rename 成 .part 作为完成前缀
        legacy_tmp = Path(str(final) + ".tmp")
        if legacy_tmp.exists() and not part.exists():
            try:
                legacy_tmp.rename(part)
            except OSError:
                pass

        chunks = self._plan(final, url, total, part, side)
        plan = _ChunkPlan(chunks, total)
        already = plan.done_bytes()

        if not self._check_disk_space(final.name, total, already):
            self._log(f"磁盘空间不足，放弃下载 {final.name}")
            return False

        if plan.settled():
            self._log(f"{final.name} 之前已下载完整，直接归档。")
            self._finalize(part, final, side)
            return True

        workers = min(self._connections, max(1, len(chunks)))
        if already:
            self._log(
                f"{final.name} 续传：已有 {_human(already)}/{_human(total)}，"
                f"剩余 {len(chunks)} 块 {workers} 路并发。")
        else:
            self._log(
                f"{final.name} 共 {_human(total)}，切成 {len(chunks)} 块，"
                f"{workers} 路并发下载。")

        threads = [
            threading.Thread(target=self._pool_worker,
                             args=(url, part, plan),
                             daemon=True, name=f"mbdl-{i}")
            for i in range(workers)
        ]
        for t in threads:
            t.start()
        self._watch(plan, total, side, threads, progress_cb, stop_event)
        for t in threads:
            t.join()
        self._save_sidecar(side, url, total, plan.chunks)

        if _is_stopped(stop_event):
            raise CancelledError
        done = plan.done_bytes()
        if plan.abort.is_set() and done < total:
            raise RuntimeError(
                f"连续 {int(STALL_TIMEOUT)}s 无数据，已停止重试。"
                f"已保存 {_human(done)}/{_human(total)}，可稍后续传。")
        if plan.failures:
            raise next(iter(plan.failures.values()))
        if done != total:
            raise RuntimeError(
                f"大小不符：已写 {_human(done)}，应为 {_human(total)}，进度已保留。")

        if progress_cb:
            progress_cb(total, total)
        self._finalize(part, final, side)
        return True

    def _pool_worker(self, url: str, part: Path, plan: _ChunkPlan) -> None:
        while not plan.abort.is_set():
            item = plan.take()
            if item is None:
                if plan.settled():
                    return
                time.sleep(0.4)
                continue
            index, chunk = item
            try:
                self._fetch_chunk(url, part, chunk)
                plan.finish(index)
            except CancelledError:
                plan.release(index, 0.0)
                return
            except _Transient as exc:
                self._retry_or_fail(plan, index, chunk, exc)
            except urllib.error.HTTPError as exc:
                if 500 <= exc.code < 600:
                    self._retry_or_fail(plan, index, chunk, exc)
                else:
                    plan.fail(index, exc)
            except Exception as exc:  # noqa: BLE001
                plan.fail(index, exc)

    def _retry_or_fail(self, plan, index, chunk, exc) -> None:
        chunk.attempts += 1
        if chunk.attempts >= MAX_CHUNK_ATTEMPTS:
            plan.fail(index, RuntimeError(
                f"块 {chunk.start}-{chunk.end} 尝试 {chunk.attempts} 次仍失败：{exc}"))
            return
        delay = min(2 ** min(chunk.attempts - 1, 4), MAX_BACKOFF)
        if chunk.attempts in (1, 3, 6, 10, 15):
            self._log(f"  块 {chunk.start}-{chunk.end} 第 {chunk.attempts} 次失败"
                      f"（{exc}），{delay:.0f}s 后重试")
        plan.release(index, delay)

    def _fetch_chunk(self, url: str, part: Path, chunk: _Chunk) -> None:
        start = chunk.start + chunk.done
        if start > chunk.end:
            return
        headers = {"Range": f"bytes={start}-{chunk.end}"}
        try:
            response = self._open(url, headers, self._timeout)
        except urllib.error.HTTPError:
            raise
        except _TRANSIENT_EXC as exc:
            raise _Transient(f"连接失败：{exc}") from exc
        with response:
            if response.status != 206:
                raise _Transient(f"期望 206，实际 {response.status}")
            try:
                with open(part, "r+b") as handle:
                    handle.seek(start)
                    while chunk.done < chunk.length:
                        try:
                            data = response.read(READ_SIZE)
                        except _TRANSIENT_EXC as exc:
                            handle.flush()
                            raise _Transient(f"读取中断：{exc}") from exc
                        if not data:
                            break
                        overflow = chunk.done + len(data) - chunk.length
                        if overflow > 0:
                            data = data[:-overflow]
                        handle.write(data)
                        chunk.done += len(data)
                    handle.flush()
            except OSError as exc:
                raise RuntimeError(f"写入失败：{exc}") from exc
        if chunk.done < chunk.length:
            raise _Transient(
                f"仅收到 {_human(chunk.done)}/{_human(chunk.length)}")

    def _watch(self, plan, total, side, threads, progress_cb, stop_event) -> None:
        start = time.monotonic()
        last_sidecar = start
        window_start = start
        window_done = plan.done_bytes()
        last_progress_at = start
        last_progress_bytes = window_done
        speed = 0.0
        stall_warned = False

        while any(t.is_alive() for t in threads):
            done = plan.done_bytes()
            now = time.monotonic()
            if now - window_start >= 1.0:
                speed = max(0.0, (done - window_done) / (now - window_start))
                window_start, window_done = now, done
            if done > last_progress_bytes:
                last_progress_bytes = done
                last_progress_at = now
                stall_warned = False
            stalled = now - last_progress_at

            hint_after = min(10.0, STALL_TIMEOUT / 4)
            warn_after = min(30.0, STALL_TIMEOUT / 2)
            detail = plan.summary()
            if stalled >= hint_after:
                detail += f"　·　已 {int(stalled)}s 无数据流入"
                if not stall_warned and stalled >= warn_after:
                    stall_warned = True
                    self._log(
                        f"  {detail_prefix(plan)}: 已 {int(stalled)}s 无数据，"
                        f"仍在重试（{int(STALL_TIMEOUT)}s 后放弃）。")

            if progress_cb:
                progress_cb(done, total)
            if now - last_sidecar >= SIDECAR_INTERVAL:
                last_sidecar = now
                self._save_sidecar(side, "", total, plan.chunks)
            if stalled >= STALL_TIMEOUT:
                plan.abort.set()
                self._log("  连续无数据，判定链路不可用，停止重试。")
                return
            if _is_stopped(stop_event):
                plan.abort.set()
                return
            time.sleep(PROGRESS_INTERVAL)

    # ---------------------------------------------------------------- 规划

    def _chunk_size(self, remaining: int) -> int:
        desired = max(1, self._connections * CHUNK_TARGET_PER_CONN)
        size = remaining // desired
        return max(self._min_chunk, min(MAX_CHUNK, size or self._min_chunk))

    def _split(self, start: int, end: int) -> list[_Chunk]:
        if end < start:
            return []
        size = self._chunk_size(end - start + 1)
        chunks = []
        cursor = start
        while cursor <= end:
            stop = min(cursor + size - 1, end)
            chunks.append(_Chunk(start=cursor, end=stop))
            cursor = stop + 1
        return chunks

    def _plan(self, final: Path, url: str, total: int,
              part: Path, side: Path) -> list[_Chunk]:
        saved = self._load_sidecar(side)
        if (saved and saved.get("url") == url
                and saved.get("total") == total
                and part.exists()
                and part.stat().st_size == total):
            ranges = [(int(s[0]), int(s[1]), int(s[2]))
                      for s in saved.get("segments", [])]
            chunks = self._rechunk(ranges, total)
            if chunks is not None:
                return chunks
            self._log(f"{final.name} 进度记录不完整，重新划分。")

        prefix = 0
        if part.exists() and not side.exists():
            size = part.stat().st_size
            if 0 < size < total:
                prefix = size
                self._log(
                    f"{final.name} 发现单连接遗留 {_human(size)}，保留并继续。")
        self._allocate(part, total)
        chunks = []
        if prefix:
            chunks.append(_Chunk(start=0, end=prefix - 1, done=prefix))
        chunks.extend(self._split(prefix, total - 1))
        self._save_sidecar(side, url, total, chunks)
        return chunks

    def _rechunk(self, ranges, total: int) -> Optional[list[_Chunk]]:
        if not ranges:
            return None
        chunks = []
        cursor = 0
        for start, end, done in ranges:
            if start != cursor or end < start:
                return None
            length = end - start + 1
            if not (0 <= done <= length):
                return None
            if done > 0:
                chunks.append(_Chunk(start=start, end=start + done - 1,
                                     done=done))
            if done < length:
                chunks.extend(self._split(start + done, end))
            cursor = end + 1
        if cursor != total:
            return None
        return chunks

    def _allocate(self, part: Path, total: int) -> None:
        try:
            mode = "r+b" if part.exists() else "wb"
            with open(part, mode) as handle:
                handle.truncate(total)
        except OSError as exc:
            raise RuntimeError(f"无法预分配 {part.name}: {exc}") from exc

    @staticmethod
    def _load_sidecar(side: Path) -> Optional[dict]:
        try:
            data = json.loads(side.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("version") != SIDECAR_VERSION:
            return None
        return data

    @staticmethod
    def _save_sidecar(side: Path, url: str, total: int,
                      chunks: list[_Chunk]) -> None:
        payload = {"version": SIDECAR_VERSION, "url": url, "total": total,
                   "segments": [[c.start, c.end, c.done] for c in chunks]}
        try:
            tmp = side.with_suffix(side.suffix + ".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, side)
        except OSError:
            pass

    # ---------------------------------------------------------------- 兜底单连接

    def _download_stream(self, url: str, final: Path, total: Optional[int],
                         *, progress_cb, stop_event) -> bool:
        part = _part_path(final.parent, final.name)
        side = _sidecar_path(final.parent, final.name)
        # 分块边车/预分配 .part 语义不同，不能混用流式
        if side.exists():
            side.unlink(missing_ok=True)
            part.unlink(missing_ok=True)
        resume_from = part.stat().st_size if part.exists() else 0
        headers = {"Range": f"bytes={resume_from}-"} if resume_from else {}
        try:
            response = self._open(url, headers, self._timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and resume_from > 0:
                exc.close()
                self._finalize(part, final, side)
                return True
            self._log(f"下载请求失败 HTTP {exc.code}")
            return False
        except _TRANSIENT_EXC as exc:
            self._log(f"下载失败：{exc}")
            return False
        with response:
            content_length = response.headers.get("Content-Length")
            remaining = int(content_length) if content_length is not None else None
            if resume_from > 0 and response.status == 206:
                stream_total = _total_from_range(
                    response.headers.get("Content-Range"))
                if stream_total is None and remaining is not None:
                    stream_total = resume_from + remaining
                self._log(f"{final.name} 从 {_human(resume_from)} 处续传。")
                mode = "ab"
            else:
                if resume_from > 0:
                    self._log(f"{final.name} 服务器未接受续传，从头开始。")
                mode = "wb"
                resume_from = 0
                stream_total = remaining if remaining is not None else total
            done = resume_from
            try:
                with open(part, mode) as handle:
                    while True:
                        if _is_stopped(stop_event):
                            handle.flush()
                            os.fsync(handle.fileno())
                            raise CancelledError
                        data = response.read(READ_SIZE)
                        if not data:
                            break
                        handle.write(data)
                        done += len(data)
                        if progress_cb:
                            progress_cb(done, stream_total or done)
            except OSError as exc:
                self._log(f"写入失败：{exc}")
                return False
        if stream_total is not None and done != stream_total:
            self._log(f"大小不符：收到 {_human(done)}，应为 {_human(stream_total)}"
                      f"，已保留 .part 可续传。")
            return False
        if progress_cb:
            progress_cb(done, stream_total or done)
        self._finalize(part, final, side)
        return True

    # ---------------------------------------------------------------- 收尾

    def _finalize(self, part: Path, final: Path, side: Path) -> None:
        try:
            os.replace(part, final)
        except OSError as exc:
            raise RuntimeError(
                f"归档失败：{exc}。杀毒软件可能锁定/隔离该文件——"
                f"这是样本包正常反应，可为保存目录添加排除项后重试。") from exc
        side.unlink(missing_ok=True)

    def _check_disk_space(self, name: str, total: int, already: int) -> bool:
        need = total - already
        if need <= 0:
            return True
        try:
            free = shutil.disk_usage(Path(name).resolve().anchor).free
        except OSError:
            return True
        if free < need + 64 * MB:
            self._log(f"磁盘空间不足：{name} 仍需 {_human(need)}，"
                      f"磁盘剩余 {_human(free)}。")
            return False
        return True

    @staticmethod
    def _clean_parts(dest_dir: Path, name: str) -> None:
        for suffix in (".part", SIDECAR_SUFFIX):
            try:
                Path(dest_dir / (name + suffix)).unlink(missing_ok=True)
            except OSError:
                pass


def _total_from_range(content_range: Optional[str]) -> Optional[int]:
    if not content_range:
        return None
    match = _CONTENT_RANGE_RE.search(content_range)
    return int(match.group(3)) if match else None


def _is_stopped(stop_event) -> bool:
    return bool(stop_event and stop_event.is_set())


def detail_prefix(plan: _ChunkPlan) -> str:
    finished = sum(1 for c in plan.chunks if c.complete)
    return f"{finished}块完成"