#!/usr/bin/env python3
"""
音效管理器 - 检测到威胁/可疑时播放提示音

根据检测结果严重程度播放不同提示音：
- 威胁（malware）：播放 error.mp3（高优先级警报）
- 可疑（suspicious）：播放 warn.mp3（中优先级警告）

优先播放 MP3（PyQt5 QMediaPlayer 原生支持 MP3），
降级使用合成 WAV 播放，最终降级为蜂鸣器。
"""

import os
import sys
import wave
import struct
import tempfile
from typing import Optional

from utils.logger import get_logger

logger = get_logger('sound_manager')

# 提示音文件名（6 级，按严重程度区分）
# - info：无通知的实时监测发现可疑 / 无通知的启动监测发现可疑
# - info2：通知询问是否重启（沙箱放行）
# - warn：沙箱拦截分析 / 无通知的检测到威胁
# - error：通知隔离可疑对象
# - error2：通知隔离恶意对象
# - critical：MBR/引导扇区被修改 / 勒索行为（文件被修改）/ 注册表被篡改
_INFO_SOUND_FILE = 'info.mp3'
_INFO2_SOUND_FILE = 'info2.mp3'
_WARN_SOUND_FILE = 'warn.mp3'
_ERROR_SOUND_FILE = 'error.mp3'
_ERROR2_SOUND_FILE = 'error2.mp3'
_CRITICAL_SOUND_FILE = 'critical.mp3'

# 向后兼容（旧命名）
_THREAT_SOUND_FILE = _ERROR_SOUND_FILE   # 威胁（malware）
_SUSPICIOUS_SOUND_FILE = _WARN_SOUND_FILE  # 可疑（suspicious）
_DEFAULT_SOUND_FILE = _INFO_SOUND_FILE

# 合成 WAV 频率（按严重程度区分）
# 威胁：高频急促（970Hz/660Hz 交替，3次重复）
# 可疑：中频平缓（660Hz/440Hz 交替，2次重复）
_THREAT_HIGH_FREQ = 970
_THREAT_LOW_FREQ = 660
_THREAT_REPEAT = 3

_SUSPICIOUS_HIGH_FREQ = 660
_SUSPICIOUS_LOW_FREQ = 440
_SUSPICIOUS_REPEAT = 2

_TONE_DURATION_MS = 500
_TONE_GAP_MS = 80

_sound_enabled = True

# 诊断开关：临时禁用全部提示音播放（验证"沙箱分析播放 info2.mp3 后闪退"
# 是否由 QMediaPlayer/COM 触发）。置 True 时 _play_alert 直接跳过，
# 不创建 QMediaPlayer、不访问 QtMultimedia 任何接口。
# 2026-08-31 闪退根因已确定为"自我沙箱误判"，与音频无关，已恢复 False。
_DIAG_DISABLE_SOUND = False

_qmedia_player = None
# QMediaPlayer 最近一次播放是否成功：
# None=未尝试, True=上次成功, False=上次失败
# 失败后下一次仍会重试（不永久禁用），避免单次偶发错误导致永久降级
_qmedia_last_ok: Optional[bool] = None

# 音效文件路径缓存（init_sound_engine 启动预热时填充，避免每次播放重复搜索磁盘）
_sound_path_cache: dict = {}

# 当前正在播放的音效文件名（仅用于 info2 中断逻辑：
# 沙箱放行询问音播放期间若触发新音效，须先中断旧音效再播新的）
_current_sound_name = None


def set_sound_enabled(enabled: bool):
    global _sound_enabled
    _sound_enabled = enabled


def init_sound_engine():
    """PSLS 启动时预热音效播放组件（主线程调用）。

    作用：
      1. 预创建并缓存 QMediaPlayer 实例，避免首次播放时才创建
      2. 预探测 6 级音效文件路径并缓存，避免逐次播放时重复磁盘搜索

    Win10 兼容性策略（简化版）：
      - 不再在预热阶段做复杂的后端探测（容易误判）
      - 采用"乐观假设"策略：假设 QMediaPlayer 可用
      - 只有在实际播放失败时才降级，且下一次仍会重试
      - 日志中记录初始化结果，便于排查问题

    幂等/复用铁律（2026-09-10 修复启动 0x8001010d 崩溃）：
      - 若已存在实例（_qmedia_player 非 None，如 critical 事件在 initRequested
        之前到达、由 _play_via_qmedia 现场创建），**绝不二次创建** QMediaPlayer。
        Qt5 的 WMF 后端在同一 STA 上顺序创建第二个 QMediaPlayer 时，会抛出
        原生 fatal 异常 0x8001010d (RPC_E_DISCONNECTED)——进程直接被 CRT 终止，
        Python try/except 拦不住（Windows fatal exception 直接结束进程），
        表现为"启动未响应"（GUI 冻结后进程被终结）。
      - 预热失败允许降级（winsound/ctypes/Beep 链），下次仍会重试。
    """
    global _qmedia_player, _qmedia_last_ok

    # 诊断模式：跳过 QMediaPlayer 预热，完全不触碰 QtMultimedia
    if _DIAG_DISABLE_SOUND:
        logger.info('音效引擎预热：诊断模式已跳过（QMediaPlayer 不创建）')
        return True

    # 1. 预探测并缓存全部音效文件路径
    for name in (_INFO_SOUND_FILE, _INFO2_SOUND_FILE, _WARN_SOUND_FILE,
                 _ERROR_SOUND_FILE, _ERROR2_SOUND_FILE, _CRITICAL_SOUND_FILE):
        if name not in _sound_path_cache:
            path = _get_sound_file_path(name)
            if path:
                _sound_path_cache[name] = path

    # 1.5 幂等：已有实例直接复用（同一 STA 上禁止双 QMediaPlayer）
    if _qmedia_player is not None:
        logger.debug('音效引擎预热：复用已存在的 QMediaPlayer 实例（不二次创建）')
        return True

    # 2. 预创建 QMediaPlayer 实例（仅创建，不播放）
    try:
        from PyQt5.QtMultimedia import QMediaPlayer
        _qmedia_player = QMediaPlayer()
        try:
            _qmedia_player.setVolume(80)
        except Exception:
            pass
        _qmedia_last_ok = None  # 重置为未尝试状态
        logger.info('音效引擎已预热（QMediaPlayer 实例就绪）')
        return True
    except ImportError as e:
        logger.info(f'音效引擎预热：PyQt5.QtMultimedia 不可用，'
                     f'将使用 winsound/ctypes 降级链: {e}')
        _qmedia_player = None
        _qmedia_last_ok = False
        return False
    except Exception as e:
        logger.warning(f'音效引擎预热异常: {e}')
        _qmedia_player = None
        _qmedia_last_ok = False
        return False


def is_sound_enabled() -> bool:
    return _sound_enabled


def _get_sound_file_path(sound_file: str) -> Optional[str]:
    """获取指定提示音文件的完整路径

    Args:
        sound_file: 提示音文件名（如 error.mp3 / warn.mp3 / info.mp3）
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, sound_file),
        os.path.join(base_dir, 'ui', 'webview', 'assets', sound_file),
    ]
    # 打包模式下额外检查 _MEIPASS
    if getattr(sys, 'frozen', False):
        try:
            meipass = sys._MEIPASS
            candidates.append(os.path.join(meipass, sound_file))
            candidates.append(os.path.join(meipass, '_internal', sound_file))
        except Exception:
            pass
    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)
    return None


def _play_via_qmedia(file_path: str) -> bool:
    """使用 QMediaPlayer 播放 MP3/WAV 文件

    必须在主线程调用。QMediaPlayer.play() 为异步操作，不会阻塞 UI。
    优先复用 init_sound_engine 预热的播放器实例（无则现场创建）。

    Win10 兼容性：
      - 即使上次播放失败（_qmedia_last_ok=False），这次仍会重试
      - 只有在实际的 ImportError 时才跳过（QMediaPlayer 完全不可用）
      - 单次播放失败不影响后续重试
    """
    global _qmedia_player, _qmedia_last_ok

    try:
        from PyQt5.QtCore import QUrl
        from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
    except ImportError:
        # QMediaPlayer 模块完全不可用，直接返回
        if _qmedia_last_ok is not False:
            logger.info('QMediaPlayer 模块不可用（ImportError），将使用降级链')
            _qmedia_last_ok = False
        return False

    try:
        # 如果没有预热的播放器实例，现场创建一个
        if _qmedia_player is None:
            _qmedia_player = QMediaPlayer()
            try:
                _qmedia_player.setVolume(80)
            except Exception:
                pass
            logger.debug('现场创建 QMediaPlayer 实例')
        else:
            # 停止当前播放（避免叠加）
            try:
                _qmedia_player.stop()
            except Exception:
                pass

        # 设置媒体并播放
        media = QMediaContent(QUrl.fromLocalFile(file_path))
        _qmedia_player.setMedia(media)
        _qmedia_player.play()

        # 短暂等待让 Qt 处理事件（10ms 足够）
        import time as _time
        _time.sleep(0.01)

        # 检查错误状态
        err = _qmedia_player.error()
        if err != QMediaPlayer.NoError:
            err_str = _qmedia_player.errorString()
            logger.warning(
                f'QMediaPlayer 播放失败: {os.path.basename(file_path)} '
                f'(error={err}): {err_str}')
            # 重置播放器实例（清理可能的内部状态）
            try:
                _qmedia_player = QMediaPlayer()
                _qmedia_player.setVolume(80)
            except Exception:
                _qmedia_player = None
            _qmedia_last_ok = False
            return False

        _qmedia_last_ok = True
        logger.info(f'QMediaPlayer 播放: {os.path.basename(file_path)}')
        return True

    except Exception as e:
        logger.warning(f'QMediaPlayer 播放异常: {e}')
        # 清理可能损坏的实例
        _qmedia_player = None
        _qmedia_last_ok = False
        return False


def _play_via_winsound(file_path: str) -> bool:
    """使用 winsound.PlaySound 播放 WAV 文件（异步，不阻塞）

    某些精简系统/虚拟机上 winsound 模块本身可能因 SxS 并行配置错误
    无法导入（DLL load failed）。这种情况直接返回 False 让上层走
    ctypes winmm 降级通道。
    """
    try:
        import winsound
        winsound.PlaySound(file_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        logger.info(f'winsound 播放: {os.path.basename(file_path)}')
        return True
    except Exception as e:
        logger.debug(f'winsound 播放失败（将走 ctypes 降级）: {e}')
        return False


def _play_via_winmm_ctypes(file_path: str) -> bool:
    """使用 ctypes 直接调用 winmm.PlaySoundW 播放 WAV 文件

    这是关键降级方案：
    - 不依赖 winsound 模块（某些 Win10 精简系统因 SxS 并行配置错误无法导入）
    - 不依赖 QtMultimedia（某些 Win10 系统可能缺少后端插件）
    - winmm.dll 属于 Windows 系统核心组件，任何版本均可通过 ctypes 加载
    - PlaySoundW 支持异步播放（SND_ASYNC），不阻塞主线程

    注意：PlaySoundW 只支持 WAV 格式，不支持 MP3。
    """
    try:
        import ctypes
        from ctypes import wintypes

        winmm = ctypes.WinDLL('winmm', use_last_error=True)
        winmm.PlaySoundW.argtypes = [wintypes.LPCWSTR, wintypes.HMODULE, wintypes.DWORD]
        winmm.PlaySoundW.restype = wintypes.BOOL

        # SND_FILENAME = 0x00020000, SND_ASYNC = 0x00000001
        flags = 0x00020000 | 0x00000001

        # 确保路径是 Unicode 字符串（ctypes 会自动转换，但显式转换更安全）
        if isinstance(file_path, bytes):
            file_path = file_path.decode('utf-8', errors='ignore')

        ok = winmm.PlaySoundW(file_path, None, flags)
        if ok:
            logger.debug(f'winmm.PlaySoundW 播放: {os.path.basename(file_path)}')
            return True
        else:
            err = ctypes.get_last_error()
            logger.debug(
                f'winmm.PlaySoundW 返回 False (err={err}): '
                f'{os.path.basename(file_path)}')
            return False
    except Exception as e:
        logger.debug(f'winmm.PlaySoundW 播放异常: {e}')
        return False


def _play_via_kernel32_beep(high_freq: int, low_freq: int, repeat: int) -> bool:
    """使用 ctypes 调用 kernel32.Beep 蜂鸣（最终兜底，无需音频文件）

    kernel32.Beep 在任何 Windows 版本上均可用，甚至无音频驱动时也能工作
    （主板蜂鸣器）。虚拟机中若音频服务关闭，这是唯一可闻的提示方式。
    """
    try:
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.Beep.argtypes = [ctypes.c_uint, ctypes.c_uint]
        kernel32.Beep.restype = ctypes.c_bool
        import time
        for i in range(repeat):
            kernel32.Beep(high_freq, _TONE_DURATION_MS)
            if _TONE_GAP_MS > 0:
                time.sleep(_TONE_GAP_MS / 1000.0)
            kernel32.Beep(low_freq, _TONE_DURATION_MS)
            if i < repeat - 1:
                time.sleep(_TONE_GAP_MS / 1000.0)
        logger.info('kernel32.Beep 蜂鸣播放完成')
        return True
    except Exception as e:
        logger.debug(f'kernel32.Beep 播放失败: {e}')
        return False


def _play_via_user32_messagebeep() -> bool:
    """使用 ctypes 调用 user32.MessageBeep 播放系统默认提示音

    如果 kernel32.Beep 也失败，最后尝试系统级默认提示音。
    MB_ICONEXCLAMATION = 0x30
    """
    try:
        import ctypes
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        user32.MessageBeep.argtypes = [ctypes.c_uint]
        user32.MessageBeep.restype = ctypes.c_bool
        ok = user32.MessageBeep(0x30)
        logger.info('user32.MessageBeep 播放完成')
        return bool(ok)
    except Exception as e:
        logger.debug(f'user32.MessageBeep 失败: {e}')
        return False


def _play_beep_sequence(high_freq: int, low_freq: int, repeat: int):
    """蜂鸣器降级方案（阻塞式，仅作为最后兜底）

    Args:
        high_freq: 高频音频率（Hz）
        low_freq: 低频音频率（Hz）
        repeat: 重复次数
    """
    try:
        import winsound
        for i in range(repeat):
            winsound.Beep(high_freq, _TONE_DURATION_MS)
            if _TONE_GAP_MS > 0:
                import time
                time.sleep(_TONE_GAP_MS / 1000.0)
            winsound.Beep(low_freq, _TONE_DURATION_MS)
            if i < repeat - 1:
                import time
                time.sleep(_TONE_GAP_MS / 1000.0)
    except Exception as e:
        logger.warning(f'蜂鸣器播放失败: {e}')
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass


def _generate_wav_file(high_freq: int, low_freq: int, repeat: int) -> Optional[str]:
    """生成指定频率和重复次数的 WAV 临时文件

    Args:
        high_freq: 高频音频率（Hz）
        low_freq: 低频音频率（Hz）
        repeat: 重复次数
    """
    try:
        import math
        sample_rate = 22050
        total_tones = repeat * 2
        tone_samples = int(sample_rate * _TONE_DURATION_MS / 1000)
        gap_samples = int(sample_rate * _TONE_GAP_MS / 1000)
        total_samples = total_tones * tone_samples + (total_tones - 1) * gap_samples

        samples = []
        amp = 0.4
        for rep in range(repeat):
            for i in range(tone_samples):
                t = i / sample_rate
                env = min(1.0, i / 200) * min(1.0, (tone_samples - i) / 200)
                val = amp * env * math.sin(2 * math.pi * high_freq * t)
                samples.append(val)
            for _ in range(gap_samples):
                samples.append(0.0)
            for i in range(tone_samples):
                t = i / sample_rate
                env = min(1.0, i / 200) * min(1.0, (tone_samples - i) / 200)
                val = amp * env * math.sin(2 * math.pi * low_freq * t)
                samples.append(val)
            if rep < repeat - 1:
                for _ in range(gap_samples):
                    samples.append(0.0)

        tmp_path = os.path.join(tempfile.gettempdir(), 'psls_alert.wav')
        with wave.open(tmp_path, 'w') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            frames = b''.join(
                struct.pack('<h', int(max(-1.0, min(1.0, s)) * 32767))
                for s in samples
            )
            wf.writeframes(frames)
        return tmp_path
    except Exception as e:
        logger.warning(f'生成 WAV 文件失败: {e}')
        return None


def _stop_current_sound():
    """强制中断当前正在播放的音效（仅用于 info2 被打断的场景）"""
    global _qmedia_player, _current_sound_name
    try:
        if _qmedia_player is not None:
            _qmedia_player.stop()
    except Exception:
        pass
    _current_sound_name = None


def _play_alert(sound_file: str, high_freq: int, low_freq: int, repeat: int):
    """播放提示音的内部实现（按优先级降级）

    优先级（每层都会尝试，成功即返回）：
    1. QMediaPlayer 播放指定 MP3 文件（PyQt5 正常环境）
       - 失败后不永久禁用，下次仍会重试
    2. ctypes 直接调用 winmm.PlaySoundW 播放合成 WAV
       —— 关键降级通道：不依赖 winsound 模块或 QtMultimedia
       —— 在 Win10 精简系统上比 winsound 更可靠
    3. winsound.PlaySound 播放合成 WAV（备选）
    4. ctypes 调用 kernel32.Beep 蜂鸣（主板蜂鸣器，最可靠兜底）
    5. ctypes 调用 user32.MessageBeep 系统默认提示音

    Args:
        sound_file: MP3 文件名（如 error.mp3 / warn.mp3）
        high_freq: 蜂鸣器降级时的高频
        low_freq: 蜂鸣器降级时的低频
        repeat: 蜂鸣器降级时的重复次数
    """
    global _current_sound_name
    if not _sound_enabled:
        logger.debug('声音已禁用，跳过播放')
        return

    # 诊断模式：跳过全部播放路径（QMediaPlayer/winmm/winsound/Beep 均不触发），
    # 用于验证"沙箱分析播放提示音后闪退"是否与音频 COM 组件相关。
    if _DIAG_DISABLE_SOUND:
        logger.info(f'[诊断模式] 跳过提示音播放: {sound_file}')
        return

    # info2 中断逻辑：若前一段音效为 info2（沙箱放行询问音）且尚未播放完毕，
    # 需先中断当前音效，再播新的更高优先级音效，避免两段声音叠加/相互淹没。
    if _current_sound_name == _INFO2_SOUND_FILE:
        _stop_current_sound()
    _current_sound_name = sound_file

    # 1. 尝试 QMediaPlayer 播放指定 MP3（优先使用缓存路径）
    sound_path = _sound_path_cache.get(sound_file)
    if not sound_path:
        sound_path = _get_sound_file_path(sound_file)
        if sound_path:
            _sound_path_cache[sound_file] = sound_path
    if sound_path:
        if _play_via_qmedia(sound_path):
            return
    else:
        logger.debug(f'未找到 {sound_file}，尝试降级方案')

    # 2. 生成 WAV 文件并尝试降级播放
    wav_path = None
    try:
        wav_path = _generate_wav_file(high_freq, low_freq, repeat)
        if wav_path and os.path.exists(wav_path):
            # 优先使用 ctypes winmm（比 winsound 更可靠，不依赖 SxS 并行配置）
            if _play_via_winmm_ctypes(wav_path):
                return
            # winsound 作为备选
            if _play_via_winsound(wav_path):
                return
        else:
            logger.warning('生成 WAV 文件失败或文件不存在')
    except Exception as e:
        logger.warning(f'WAV 降级播放异常: {e}')
    finally:
        # 清理临时 WAV 文件（留到下次可能有用，但节省磁盘空间）
        # 注意：不清理，因为 winsound 异步播放需要文件存在
        pass

    # 3. 最终降级：kernel32.Beep 蜂鸣（ctypes 直接调用，任何系统均可用）
    #    【卡死修复】蜂鸣兜底是**阻塞式**的：`Beep(500ms)` + `time.sleep` × repeat。
    #    实测 play_critical_alert(repeat=4) 会给 GUI 线程带来 ≈4.5s 阻塞 —— 而本函数
    #    由 Qt 信号槽（playCriticalRequested → play_critical_alert）在**主线程**执行，
    #    于是"提示音响了但界面卡死"（VM 上 MP3/WAV 路径常失败，正好落到这里）。
    #    因此把阻塞兜底搬到 **daemon 线程**：不阻塞调用方，声音照旧。
    #    注意：仅兜底搬线程；上面的 QMediaPlayer 路径保持原线程（Qt 多媒体需线程亲和）。
    def _blocking_fallback():
        try:
            logger.info('使用 ctypes kernel32.Beep 蜂鸣降级方案（后台线程）')
            if _play_via_kernel32_beep(high_freq, low_freq, repeat):
                return
            _play_via_user32_messagebeep()
        except Exception as e:
            logger.debug(f'蜂鸣兜底异常: {e}')

    try:
        import threading as _th
        _th.Thread(target=_blocking_fallback, daemon=True,
                   name='PslsSoundFallback').start()
    except Exception as e:
        logger.debug(f'启动蜂鸣兜底线程失败（改为同步执行）: {e}')
        _blocking_fallback()


def play_threat_alert():
    """播放威胁检测警报音（malware 级别，在主线程调用）

    播放 error.mp3，降级为高频急促蜂鸣（970Hz/660Hz，3次重复）。
    QMediaPlayer.play() 和 winsound.SND_ASYNC 均为异步操作，
    不会阻塞主线程，无需额外线程。
    """
    _play_alert(_THREAT_SOUND_FILE, _THREAT_HIGH_FREQ, _THREAT_LOW_FREQ, _THREAT_REPEAT)


def play_suspicious_alert():
    """播放可疑检测警告音（suspicious 级别，在主线程调用）

    播放 warn.mp3，降级为中频平缓蜂鸣（660Hz/440Hz，2次重复）。
    QMediaPlayer.play() 和 winsound.SND_ASYNC 均为异步操作，
    不会阻塞主线程，无需额外线程。
    """
    _play_alert(_SUSPICIOUS_SOUND_FILE, _SUSPICIOUS_HIGH_FREQ, _SUSPICIOUS_LOW_FREQ, _SUSPICIOUS_REPEAT)


def play_info_alert():
    """播放 info.mp3：无通知的实时监测/启动监测发现可疑（最轻提示）"""
    _play_alert(_INFO_SOUND_FILE, 440, 330, 1)


def play_info2_alert():
    """播放 info2.mp3：通知询问是否重启（沙箱放行）

    该音效在播放期间若触发新的更高优先级音效，会先中断本音效再播放新音效。
    """
    _play_alert(_INFO2_SOUND_FILE, 520, 390, 1)


def play_warn_alert():
    """播放 warn.mp3：沙箱拦截分析、无通知的检测到威胁"""
    _play_alert(_WARN_SOUND_FILE, _SUSPICIOUS_HIGH_FREQ, _SUSPICIOUS_LOW_FREQ, _SUSPICIOUS_REPEAT)


def play_error_alert():
    """播放 error.mp3：通知隔离可疑对象"""
    _play_alert(_ERROR_SOUND_FILE, _THREAT_HIGH_FREQ, _THREAT_LOW_FREQ, _THREAT_REPEAT)


def play_error2_alert():
    """播放 error2.mp3：通知隔离恶意对象（最高级警报音）"""
    _play_alert(_ERROR2_SOUND_FILE, _THREAT_HIGH_FREQ, _THREAT_LOW_FREQ, _THREAT_REPEAT)


def play_critical_alert():
    """播放 critical.mp3：MBR/引导扇区被修改、勒索行为（文件被修改）、注册表被篡改

    紧急提示音（最严重级别），蜂鸣降级使用更高频率、更多重复次数。
    """
    _play_alert(_CRITICAL_SOUND_FILE, 1220, 880, 4)


# 保留向后兼容的别名
play_threat_alert_async = play_threat_alert
