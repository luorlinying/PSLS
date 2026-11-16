#!/usr/bin/env python3
"""
统一日志系统
替代散落在各模块中的 print 语句，支持日志级别和文件记录
"""

import logging
import os
import sys
from datetime import datetime

# 日志级别常量
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

# 单例日志器
_logger = None
_configured = False


def get_logger(name: str = 'antivirus') -> logging.Logger:
    """
    获取日志器实例（单例模式）
    
    Args:
        name: 日志器名称
        
    Returns:
        logging.Logger 实例
    """
    global _logger, _configured
    
    if _logger is not None and _configured:
        return _logger
    
    _logger = logging.getLogger(name)
    _logger.setLevel(logging.DEBUG)
    
    # 避免重复添加handler
    if not _logger.handlers:
        # 获取日志目录
        # 打包模式下 __file__ 指向只读临时目录 _MEIxxxxx，使用 %APPDATA%\PSLS\logs
        if getattr(sys, 'frozen', False):
            if sys.platform == 'win32':
                appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            else:
                appdata = os.path.expanduser('~/.config')
            log_dir = os.path.join(appdata, 'PSLS', 'logs')
        else:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            # 回退到用户主目录
            log_dir = os.path.join(os.path.expanduser('~'), 'PSLS_logs')
            os.makedirs(log_dir, exist_ok=True)
        
        # 日志文件名（按日期）
        log_file = os.path.join(log_dir, f'antivirus_{datetime.now().strftime("%Y%m%d")}.log')
        
        # 文件handler（记录所有级别）
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)
        
        # 控制台handler（仅显示WARNING及以上）
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING)
        console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        console_handler.setFormatter(console_formatter)
        _logger.addHandler(console_handler)
    
    _configured = True
    return _logger


def debug(msg: str, *args, **kwargs):
    """记录DEBUG级别日志"""
    get_logger().debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """记录INFO级别日志"""
    get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """记录WARNING级别日志"""
    get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """记录ERROR级别日志"""
    get_logger().error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """记录CRITICAL级别日志"""
    get_logger().critical(msg, *args, **kwargs)


def set_console_level(level: int):
    """
    设置控制台输出级别
    
    Args:
        level: 日志级别（DEBUG/INFO/WARNING/ERROR/CRITICAL）
    """
    logger = get_logger()
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(level)


if __name__ == '__main__':
    # 测试日志系统
    print("测试日志系统...")
    debug("这是一条DEBUG消息（仅写入文件）")
    info("这是一条INFO消息（仅写入文件）")
    warning("这是一条WARNING消息（控制台+文件）")
    error("这是一条ERROR消息（控制台+文件）")
    print("日志测试完成，请检查 logs/ 目录")
