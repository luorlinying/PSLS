# -*- coding: utf-8 -*-
"""
通知提醒管理器
管理桌面通知、提示音、通知历史记录和通知偏好设置。

功能：
1. 通知历史记录：记录所有已发送的通知（时间、类型、内容、状态）
2. 通知偏好设置：是否启用桌面通知、是否启用声音、通知弹窗持续时间
3. 通知节流：防止短时间内大量通知轰炸
4. 通知分类：信息/警告/威胁/成功 四类
5. 声音提示：与 sound_manager 联动，确保声音与通知设置一致
"""
import os
import sys
import time
import threading
import json
from typing import Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger('notification_manager')


# 通知级别常量
class NotificationLevel:
    INFO = 'info'
    SUCCESS = 'success'
    WARNING = 'warning'
    THREAT = 'threat'


# 通知级别显示名称
LEVEL_NAMES = {
    NotificationLevel.INFO: '信息',
    NotificationLevel.SUCCESS: '成功',
    NotificationLevel.WARNING: '警告',
    NotificationLevel.THREAT: '威胁',
}

# 通知级别图标
LEVEL_ICONS = {
    NotificationLevel.INFO: 'ℹ',
    NotificationLevel.SUCCESS: '✓',
    NotificationLevel.WARNING: '⚠',
    NotificationLevel.THREAT: '✗',
}

# 通知级别颜色
LEVEL_COLORS = {
    NotificationLevel.INFO: '#3b82f6',
    NotificationLevel.SUCCESS: '#10b981',
    NotificationLevel.WARNING: '#f59e0b',
    NotificationLevel.THREAT: '#ef4444',
}

# 默认设置
DEFAULT_SETTINGS = {
    'desktop_enabled': True,       # 桌面通知开关
    'sound_enabled': True,         # 声音提醒开关
    'popup_duration': 2,           # 弹窗持续时间（秒）
    'threat_popup_duration': 30,   # 威胁弹窗持续时间（秒）
    'max_history': 200,            # 最大历史记录数
    'throttle_seconds': 1,         # 同一类型通知最小间隔（秒）
    'show_success': True,          # 是否显示成功通知
    'show_info': True,             # 是否显示信息通知
    'show_warning': True,          # 是否显示警告通知
    'show_threat': True,           # 是否显示威胁通知
}


class NotificationManager:
    """通知提醒管理器

    负责：
    - 通知偏好设置的读取和保存（持久化到 JSON 文件）
    - 通知历史记录的维护
    - 通知发送的节流和过滤
    - 与 sound_manager 的联动
    """

    def __init__(self, config_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._running = False

        # 设置
        self._settings = dict(DEFAULT_SETTINGS)
        self._config_path = config_path or self._get_default_config_path()
        self._load_settings()

        # 通知历史
        self._history: List[dict] = []
        self._history_lock = threading.Lock()

        # 节流：每种级别最后一次通知时间
        self._last_notify_time: Dict[str, float] = {}

        # 统计
        self._stats = {
            'total_sent': 0,
            'info_sent': 0,
            'success_sent': 0,
            'warning_sent': 0,
            'threat_sent': 0,
            'blocked': 0,
            'started_at': 0,
        }
        self._stats_lock = threading.Lock()

        # 回调：通知发送时触发（用于 bridge 转发到前端）
        self._on_notification: Optional[Callable[[dict], None]] = None

        logger.info('通知管理器已初始化')

    # ---- 配置路径 ----

    @staticmethod
    def _get_default_config_path() -> str:
        """获取默认配置文件路径

        打包模式下使用 %APPDATA%\PSLS\config 避免只读临时目录。
        """
        if getattr(sys, 'frozen', False):
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            else:
                appdata = os.path.expanduser('~/.config')
            config_dir = os.path.join(appdata, 'PSLS', 'config')
        else:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_dir = os.path.join(project_root, 'config')
        if not os.path.isdir(config_dir):
            try:
                os.makedirs(config_dir, exist_ok=True)
            except Exception:
                pass
        return os.path.join(config_dir, 'notification_settings.json')

    # ---- 属性 ----

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def settings(self) -> dict:
        with self._lock:
            return dict(self._settings)

    @property
    def history(self) -> list:
        with self._history_lock:
            return list(self._history)

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    # ---- 回调设置 ----

    def set_notification_callback(self, callback: Callable[[dict], None]):
        """设置通知发送回调（由 bridge 设置，用于将通知转发到前端）"""
        self._on_notification = callback

    # ---- 启动/停止 ----

    def start(self) -> bool:
        if self._running:
            return True
        self._running = True
        with self._stats_lock:
            self._stats['started_at'] = time.time()
        logger.info('通知管理器已启动')
        return True

    def stop(self) -> bool:
        if not self._running:
            return True
        self._running = False
        self._save_settings()
        logger.info('通知管理器已停止')
        return True

    # ---- 设置管理 ----

    def update_settings(self, new_settings: dict) -> dict:
        """更新通知设置，返回更新后的完整设置"""
        with self._lock:
            for key, value in new_settings.items():
                if key in self._settings:
                    self._settings[key] = value
            self._save_settings()
            return dict(self._settings)

    def get_settings(self) -> dict:
        """获取当前通知设置"""
        with self._lock:
            return dict(self._settings)

    def is_desktop_enabled(self) -> bool:
        """桌面通知是否启用"""
        with self._lock:
            return self._settings.get('desktop_enabled', True)

    def is_sound_enabled(self) -> bool:
        """声音提醒是否启用"""
        with self._lock:
            return self._settings.get('sound_enabled', True)

    def set_desktop_enabled(self, enabled: bool):
        """设置桌面通知开关"""
        with self._lock:
            self._settings['desktopEnabled'] = enabled
            settings_to_save = dict(self._settings)
        # 保存到文件（在锁外执行，避免死锁）
        try:
            config_dir = os.path.dirname(self._config_path)
            if config_dir and not os.path.isdir(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            with open(self._config_path, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f'保存通知设置失败: {e}')

    def set_sound_enabled(self, enabled: bool):
        """设置声音开关"""
        with self._lock:
            self._settings['sound_enabled'] = enabled
            settings_to_save = dict(self._settings)
        # 保存到文件（在锁外执行，避免与 _save_settings 重复获取锁导致死锁）
        try:
            config_dir = os.path.dirname(self._config_path)
            if config_dir and not os.path.isdir(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            with open(self._config_path, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f'保存通知设置失败: {e}')
        # 同步到 sound_manager
        try:
            from utils import sound_manager
            sound_manager.set_sound_enabled(enabled)
        except Exception:
            pass

    # ---- 历史记录管理 ----

    def get_history(self, limit: int = 50, level: Optional[str] = None) -> list:
        """获取通知历史记录"""
        with self._history_lock:
            history = self._history[:]
        if level:
            history = [h for h in history if h.get('level') == level]
        return history[:limit]

    def clear_history(self):
        """清空历史记录"""
        with self._history_lock:
            self._history.clear()
        logger.info('通知历史已清空')

    def get_history_stats(self) -> dict:
        """获取历史统计"""
        with self._history_lock:
            total = len(self._history)
            by_level = {}
            for h in self._history:
                lvl = h.get('level', 'unknown')
                by_level[lvl] = by_level.get(lvl, 0) + 1
        return {'total': total, 'by_level': by_level}

    # ---- 通知发送 ----

    def notify(self, title: str, message: str,
               level: str = NotificationLevel.INFO,
               category: str = 'general',
               play_sound: Optional[bool] = None) -> dict:
        """发送一条通知

        Args:
            title: 通知标题
            message: 通知内容
            level: 通知级别 (info/success/warning/threat)
            category: 通知分类（用于过滤和节流）
            play_sound: 是否播放声音（None=自动，根据设置决定）

        Returns:
            通知数据字典（包含 id、时间、状态等）
        """
        # 检查是否运行
        if not self._running:
            return {'status': 'skipped', 'reason': 'not_running'}

        # 检查该级别是否启用
        show_key = f'show_{level}'
        with self._lock:
            if not self._settings.get(show_key, True):
                return {'status': 'skipped', 'reason': f'{level}_disabled'}

        # 检查桌面通知是否启用
        with self._lock:
            if not self._settings.get('desktop_enabled', True):
                return {'status': 'skipped', 'reason': 'desktop_disabled'}

        # 节流检查
        now = time.time()
        with self._lock:
            throttle_secs = self._settings.get('throttle_seconds', 1)
        last_time = self._last_notify_time.get(category, 0)
        if now - last_time < throttle_secs:
            with self._stats_lock:
                self._stats['blocked'] += 1
            return {'status': 'throttled', 'reason': 'too_frequent'}

        # 构建通知数据
        notification = {
            'id': f'{int(now * 1000)}',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'title': title,
            'message': message,
            'level': level,
            'level_name': LEVEL_NAMES.get(level, '未知'),
            'level_icon': LEVEL_ICONS.get(level, ''),
            'level_color': LEVEL_COLORS.get(level, '#6b7280'),
            'category': category,
            'status': 'sent',
        }

        # 更新节流时间
        self._last_notify_time[category] = now

        # 更新统计
        with self._stats_lock:
            self._stats['total_sent'] += 1
            stat_key = f'{level}_sent'
            if stat_key in self._stats:
                self._stats[stat_key] += 1

        # 添加到历史
        with self._history_lock:
            self._history.insert(0, notification)
            max_history = self._settings.get('max_history', 200)
            if len(self._history) > max_history:
                self._history = self._history[:max_history]

        # 触发回调（转发到 bridge，由 bridge emit 信号到前端）
        if self._on_notification:
            try:
                self._on_notification(notification)
            except Exception as e:
                logger.error(f'通知回调异常: {e}')

        # 播放声音（如果启用）
        should_play_sound = play_sound
        if should_play_sound is None:
            with self._lock:
                should_play_sound = self._settings.get('sound_enabled', True)

        if should_play_sound:
            try:
                from utils import sound_manager
                if level == NotificationLevel.THREAT:
                    sound_manager.play_threat_alert()
                elif level == NotificationLevel.WARNING:
                    sound_manager.play_threat_alert()
            except Exception as e:
                logger.debug(f'播放通知声音失败: {e}')

        logger.info(f'[{LEVEL_NAMES.get(level, level)}] {title}: {message[:80]}')
        return notification

    def notify_info(self, title: str, message: str, **kwargs) -> dict:
        """发送信息通知"""
        return self.notify(title, message, level=NotificationLevel.INFO, **kwargs)

    def notify_success(self, title: str, message: str, **kwargs) -> dict:
        """发送成功通知"""
        return self.notify(title, message, level=NotificationLevel.SUCCESS, **kwargs)

    def notify_warning(self, title: str, message: str, **kwargs) -> dict:
        """发送警告通知"""
        return self.notify(title, message, level=NotificationLevel.WARNING, **kwargs)

    def notify_threat(self, title: str, message: str, **kwargs) -> dict:
        """发送威胁通知"""
        return self.notify(title, message, level=NotificationLevel.THREAT, **kwargs)

    # ---- 批量通知 ----

    def notify_batch(self, notifications: List[dict]) -> List[dict]:
        """批量发送通知

        Args:
            notifications: 通知列表，每项包含 title, message, level 等字段

        Returns:
            发送结果列表
        """
        results = []
        for n in notifications:
            result = self.notify(
                title=n.get('title', ''),
                message=n.get('message', ''),
                level=n.get('level', NotificationLevel.INFO),
                category=n.get('category', 'general'),
            )
            results.append(result)
        return results

    # ---- 持久化 ----

    def _load_settings(self):
        """从文件加载设置"""
        try:
            if os.path.isfile(self._config_path):
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                with self._lock:
                    self._settings.update(saved)
                logger.info(f'通知设置已从 {self._config_path} 加载')
        except Exception as e:
            logger.warning(f'加载通知设置失败: {e}')

    def _save_settings(self):
        """保存设置到文件"""
        try:
            config_dir = os.path.dirname(self._config_path)
            if config_dir and not os.path.isdir(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            with self._lock:
                settings_to_save = dict(self._settings)
            with open(self._config_path, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f'保存通知设置失败: {e}')

    # ---- 导出 ----

    def export_history(self, file_path: str) -> bool:
        """导出通知历史到文件"""
        try:
            with self._history_lock:
                history_copy = list(self._history)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('PSLS 通知历史记录\n')
                f.write(f'导出时间: {time.strftime("%Y-%m-%d %H:%M:%S")}\n')
                f.write(f'记录条数: {len(history_copy)}\n')
                f.write('=' * 60 + '\n\n')
                for h in history_copy:
                    f.write(f"[{h.get('timestamp', '')}] [{h.get('level_name', '')}] ")
                    f.write(f"{h.get('title', '')} - {h.get('message', '')}\n")
            logger.info(f'通知历史已导出到 {file_path}')
            return True
        except Exception as e:
            logger.error(f'导出通知历史失败: {e}')
            return False

    def reset_stats(self):
        """重置统计数据"""
        with self._stats_lock:
            self._stats = {
                'total_sent': 0,
                'info_sent': 0,
                'success_sent': 0,
                'warning_sent': 0,
                'threat_sent': 0,
                'blocked': 0,
                'started_at': time.time(),
            }
