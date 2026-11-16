# -*- mode: python ; coding: utf-8 -*-
"""PSLS 主程序 PyInstaller Spec（onedir 模式）

包含 PyQt5 + QtWebEngine + 扫描引擎 + YARA。
开源构建不包含私有 ML 引擎（Dantrolene V1）与签名数据库：
如需打包完整版，请自行补回 models/、db/signatures.db 与对应 hiddenimports。
"""

import os


a = Analysis(
    ['gui_entry.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    datas=[
        ('icon.ico', '.'),
        ('logo.png', '.'),
        ('logo_small.png', '.'),
        ('error.mp3', '.'),
        ('warn.mp3', '.'),
        ('info.mp3', '.'),
        ('info2.mp3', '.'),
        ('error2.mp3', '.'),
        ('critical.mp3', '.'),
        ('rules/yara', 'rules/yara/'),
        ('ui/webview', 'ui/webview/'),
        # 内核驱动定义（可选；二进制需自行构建并签名）
        ('driver/PSLS.inf', 'driver/'),
    ],
    hiddenimports=[
        'pyzipper', 'py7zr', 'rarfile', 'sqlite3', 'hashlib',
        'multiprocessing', 'concurrent.futures',
        'multiprocessing.spawn', 'multiprocessing.forkserver', 'multiprocessing.popen_spawn_win32',
        'pystray', 'watchdog', 'watchdog.observers', 'watchdog.events',
        'plyer', 'plyer.platforms.win.notification',
        'PIL', 'PIL.Image', 'PIL.ImageDraw', 'PIL.ImageGrab',
        # frida（沙箱 API hook，可选；缺失时自动降级为仅 psutil 监控）
        'frida',
        # engine 模块
        'engine.rule_engine', 'engine.pe_analyzer', 'engine.quarantine_manager',
        'engine.scan_engine', 'engine.ml_detector', 'engine.yara_portable',
        'engine.yara_worker', 'engine.realtime_monitor', 'engine.virus_identifier',
        'engine.etw_monitor', 'engine.engine_server', 'engine.self_protection',
        'engine.file_protection', 'engine.process_protection', 'engine.system_protection',
        'engine.mbr_protector',
        'engine.threat_intel', 'engine.notification_manager', 'engine.sandbox_analyzer',
        # Sandboxie 沙盘增量取证（在函数内动态导入，需显式声明）
        'engine.sandboxie_delta',
        'engine.visual_prank_detector', 'engine.aggressive_prank_detector',
        # db / utils 模块
        'db.signature_db',
        'utils.file_walker', 'utils.hash_utils', 'utils.archive_scanner',
        'utils.logger', 'utils.sound_manager', 'utils.autostart_manager',
        'utils.signature_verifier', 'utils.driver_manager',
        # 内核驱动桥接层（动态导入，需显式声明）
        'driver.bridge.psls_driver_bridge',
        # UI 桥接
        'ui.webview.bridge',
        # PyQt5 WebEngine
        'PyQt5.QtWebEngineWidgets', 'PyQt5.QtWebChannel',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PSLS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='PSLS',
)
