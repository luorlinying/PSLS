#!/usr/bin/env python3
"""
PyInstaller打包脚本 - 构建 PSLS + MLWorker
- PSLS: 主程序（含 PyQt5、WebView、YARA 等）
- MLWorker: 独立 ML 推理引擎（仅含 onnxruntime，无 PyQt5，避免 DLL 冲突）
"""

import subprocess
import os
import shutil
import sys

APP_NAME = "Project Sertraline Lab Offline Security"
APP_NAME_SHORT = "PSLS"
ICON_PATH = "icon.ico"
PSLS_SPEC = "PSLS.spec"
MLWORKER_SPEC = "MLWorker.spec"
OUTPUT_DIR = "dist"
BUILD_DIR = "build"
# PSLS 输出目录（当 dist\PSLS 被系统进程锁定时，使用 dist_new 绕过）
PSLS_OUTPUT_DIR = "dist_new"

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_command(cmd, cwd=None):
    print(f"执行命令: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=cwd or PROJECT_DIR, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"STDERR: {result.stderr}")
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        print(f"命令执行失败: {e}")
        return False, "", str(e)

def verify_package():
    """验证打包产物的完整性"""
    print("\n[验证] 检查打包产物...")
    app_dir = os.path.join(PSLS_OUTPUT_DIR, APP_NAME_SHORT)
    internal_dir = os.path.join(app_dir, "_internal")
    
    checks = [
        ("主程序 EXE", os.path.join(app_dir, f"{APP_NAME_SHORT}.exe")),
        ("ML Worker EXE", os.path.join(app_dir, "MLWorker.exe")),
        ("签名库", os.path.join(internal_dir, "db", "signatures.db")),
        ("ML模型", os.path.join(internal_dir, "models", "malware_detector.onnx")),
        ("onnxruntime DLL", os.path.join(internal_dir, "onnxruntime", "capi", "onnxruntime.dll")),
        ("LightGBM DLL", os.path.join(internal_dir, "engine", "brewtotal_sorel", "lib_lightgbm.dll")),
        ("SOREL EMBER v2 模型", os.path.join(internal_dir, "engine", "brewtotal_sorel", "sorel20m_ember_v2.model")),
        ("SOREL 模型清单", os.path.join(internal_dir, "engine", "brewtotal_sorel", "manifest.json")),
        ("SOREL 阈值清单", os.path.join(internal_dir, "engine", "brewtotal_sorel", "thresholds.json")),
        ("PyQt5", os.path.join(internal_dir, "PyQt5")),
        ("QtWebEngineProcess", os.path.join(internal_dir, "PyQt5", "Qt5", "bin", "QtWebEngineProcess.exe")),
        ("QtWebEngine resources.pak", os.path.join(internal_dir, "PyQt5", "Qt5", "Resources", "resources.pak")),
        ("QtWebEngine locales", os.path.join(internal_dir, "PyQt5", "Qt5", "translations", "qtwebengine_locales")),
        ("yara", os.path.join(internal_dir, "yara.cp310-win_amd64.pyd")),
        ("图标", os.path.join(internal_dir, "icon.ico")),
        ("内核驱动 PSLS.sys", os.path.join(internal_dir, "driver", "PSLS.sys")),
        ("驱动 INF", os.path.join(internal_dir, "driver", "PSLS.inf")),
        ("音效error", os.path.join(internal_dir, "error.mp3")),
        ("音效warn", os.path.join(internal_dir, "warn.mp3")),
        ("音效info", os.path.join(internal_dir, "info.mp3")),
        ("音效info2", os.path.join(internal_dir, "info2.mp3")),
        ("音效error2", os.path.join(internal_dir, "error2.mp3")),
        ("音效critical", os.path.join(internal_dir, "critical.mp3")),
        ("Tailwind CSS", os.path.join(internal_dir, "ui", "webview", "tailwind.global.js")),
        ("Lucide图标", os.path.join(internal_dir, "ui", "webview", "lucide.min.js")),
        ("主页HTML", os.path.join(internal_dir, "ui", "webview", "index.html")),
        ("启动页HTML", os.path.join(internal_dir, "ui", "webview", "splash.html")),
    ]
    
    all_ok = True
    for name, path in checks:
        exists = os.path.exists(path)
        size = os.path.getsize(path) if exists and os.path.isfile(path) else 0
        status = "✓" if exists else "✗"
        size_info = f" ({size:,} bytes)" if size > 0 else ""
        if not exists:
            all_ok = False
        print(f"  {status} {name}: {path}{size_info}")
    
    return all_ok

def main():
    print(f"========== 开始打包 {APP_NAME} ==========")
    
    # 清理旧的构建文件
    print("\n[1/8] 清理旧的构建文件...")
    for d in [BUILD_DIR, os.path.join(OUTPUT_DIR, APP_NAME_SHORT), os.path.join(OUTPUT_DIR, "MLWorker"),
              os.path.join(PSLS_OUTPUT_DIR, APP_NAME_SHORT)]:
        if os.path.exists(d):
            try:
                shutil.rmtree(d)
                print(f"  已删除: {d}")
            except Exception as e:
                print(f"  [警告] 删除失败(可能被占用,PyInstaller将覆盖): {d} - {e}")
    
    # 检查必要源文件
    print("\n[2/8] 检查源文件...")
    source_checks = [
        ("PSLS入口", "gui_entry.py"),
        ("ML Worker入口", "ml_worker_entry.py"),
        ("PSLS Spec", PSLS_SPEC),
        ("ML Worker Spec", MLWORKER_SPEC),
        ("签名库", os.path.join("db", "signatures.db")),
        ("ML模型", os.path.join("models", "malware_detector.onnx")),
        ("SOREL 模型清单", os.path.join("engine", "brewtotal_sorel", "manifest.json")),
        ("图标", ICON_PATH),
        ("UI资源", os.path.join("ui", "webview", "index.html")),
    ]
    for name, path in source_checks:
        full_path = os.path.join(PROJECT_DIR, path)
        if os.path.exists(full_path):
            size = os.path.getsize(full_path) if os.path.isfile(full_path) else 0
            print(f"  ✓ {name}: {path} ({size:,} bytes)")
        else:
            print(f"  ✗ {name}: {path} [缺失!]")
    
    pyinstaller_path = os.path.join(os.path.dirname(sys.executable), "Scripts", "pyinstaller.exe")
    if not os.path.exists(pyinstaller_path):
        pyinstaller_path = "pyinstaller"
    
    # Step 1: 构建 MLWorker
    print("\n[3/8] 构建 MLWorker（独立 ML 推理引擎）...")
    success, stdout, stderr = run_command([
        pyinstaller_path, "--clean", "--noconfirm", MLWORKER_SPEC
    ])
    if not success:
        print("MLWorker 构建失败!")
        return
    print("  MLWorker 构建成功!")
    
    # Step 2: 构建 PSLS（输出到 dist_new 目录，避免 dist\PSLS 被锁定时失败）
    print("\n[4/8] 构建 PSLS（主程序）...")
    success, stdout, stderr = run_command([
        pyinstaller_path, "--clean", "--noconfirm", "--distpath", PSLS_OUTPUT_DIR, PSLS_SPEC
    ])
    if not success:
        print("PSLS 构建失败!")
        if stderr:
            for line in stderr.split('\n'):
                if any(kw in line.lower() for kw in ['error', 'fail', 'exception', 'traceback']):
                    print(f"  {line.strip()}")
        return
    print("  PSLS 构建成功!")
    
    # Step 3: 复制 MLWorker.exe 到 PSLS 输出目录
    print("\n[5/8] 集成 MLWorker 到 PSLS...")
    mlworker_dir = os.path.join(OUTPUT_DIR, "MLWorker")
    psls_dir = os.path.join(PSLS_OUTPUT_DIR, APP_NAME_SHORT)
    
    if os.path.exists(mlworker_dir) and os.path.exists(psls_dir):
        # 复制 MLWorker.exe
        mlworker_exe = os.path.join(mlworker_dir, "MLWorker.exe")
        if os.path.exists(mlworker_exe):
            dest = os.path.join(psls_dir, "MLWorker.exe")
            shutil.copy2(mlworker_exe, dest)
            print(f"  已复制 MLWorker.exe -> {dest}")
        
        # 复制 MLWorker 的 _internal 目录（如果有）
        mlworker_internal = os.path.join(mlworker_dir, "_internal")
        psls_internal = os.path.join(psls_dir, "_internal")
        if os.path.exists(mlworker_internal):
            # 将 MLWorker 的 _internal 内容合并到 PSLS 的 _internal
            for item in os.listdir(mlworker_internal):
                src = os.path.join(mlworker_internal, item)
                dst = os.path.join(psls_internal, item)
                if os.path.isfile(src):
                    if not os.path.exists(dst):
                        shutil.copy2(src, dst)
                elif os.path.isdir(src):
                    if not os.path.exists(dst):
                        shutil.copytree(src, dst)
            print(f"  已合并 MLWorker _internal 到 PSLS _internal")
    else:
        print("  ⚠ MLWorker 或 PSLS 输出目录不存在")
    
    # Step 4: 复制 LightGBM (EMBER v2) 引擎文件
    print("\n[6/9] 集成 LightGBM EMBER v2 引擎...")
    psls_internal = os.path.join(psls_dir, "_internal")
    for sub in ("brewtotal_sorel",):
        bt_src_dir = os.path.join(PROJECT_DIR, "engine", sub)
        bt_dst_dir = os.path.join(psls_internal, "engine", sub)
        if os.path.isdir(bt_src_dir):
            os.makedirs(bt_dst_dir, exist_ok=True)
            for item in os.listdir(bt_src_dir):
                s = os.path.join(bt_src_dir, item)
                d = os.path.join(bt_dst_dir, item)
                if os.path.isfile(s):
                    shutil.copy2(s, d)
                    print(f"  已复制: engine/{sub}/{item}")
            print(f"  {sub} 集成完成 -> {bt_dst_dir}")
        else:
            print(f"  ⚠ 源目录不存在 (engine/{sub})")
    
    # 修复 QtWebEngine 资源命名（PyQt5 在打包后需要 resources.pak）
    print("\n[7/9] 修复 QtWebEngine 资源...")
    resources_dir = os.path.join(psls_dir, "_internal", "PyQt5", "Qt5", "Resources")
    if os.path.isdir(resources_dir):
        rename_map = {
            'qtwebengine_resources.pak': 'resources.pak',
            'qtwebengine_resources_100p.pak': 'resources_100p.pak',
            'qtwebengine_resources_200p.pak': 'resources_200p.pak',
            'qtwebengine_devtools_resources.pak': 'devtools_resources.pak',
        }
        for src_name, dst_name in rename_map.items():
            src = os.path.join(resources_dir, src_name)
            dst = os.path.join(resources_dir, dst_name)
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
                print(f"  已复制: {src_name} -> {dst_name}")
        print("  QtWebEngine 资源修复完成")
    else:
        print("  ⚠ Resources 目录不存在")
    
    # 验证打包产物
    print("\n[8/10] 验证打包产物...")
    if not verify_package():
        print("\n  ⚠ 部分资源缺失，可能影响功能")
    
    # 创建版本信息
    print("\n[9/10] 创建版本信息...")
    version_info = f"""# PSLS 版本信息
版本: V26.2.0beta
打包时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Python版本: {sys.version.split()[0]}
PyInstaller模式: onedir (开箱即用)

## V26.2.0beta 更新日志
◆ 优化了沙箱，使用sandboxie同捆。
◆ 增加了一键终止所有进程的紧急按钮。
◆ 修复了隔离区逃逸文件无法再次隔离的问题
◆ 添加了勒索回滚功能。
◆ 开机自启动现在设置为默认。
◆ 提升了Emergency Kill的优先级，现在能够更快地结束可疑进程。
◆ 提高了视觉特效检测的敏感性。
◆ 持久化激进视觉特效检测。
◆ 添加了拦截非法修改用户开机密钥的功能。
◆ 修复了签名库可能无法加载的问题。
◆ 添加了VirusIdentifier开关，现在可以自行启用该7维度启发式引擎（误报高，谨慎启用）
◆ 勘误了ML错误的训练说明。
◆ 引入了一部分Elastic Security技术，目前仍处于试验阶段。

## V26.1.7 更新日志
◆ 新增了一种GUI风格：CRT琥珀终端
◆ 重置了ML机器学习引擎，大幅降低了误报率
◆ 在询问隔离操作时添加了信任按钮。

## V26.1.6 更新日志
◆ 修复了自我保护有可能误报进程的问题
◆ 修复了自身进程被误报为"非 DLL 模块注入"的问题（.pyd 为 Python 扩展，不再误判）
◆ 修复了打包版启动后签名库未正确更新、签名数量显示异常的问题
◆ 修复了退出时窗口未响应、无法立即关闭的问题（清理改后台执行，超时强制退出）
◆ 更新了安装向导的GUI
◆ 沙箱判定安全的项目，下一次再启动将不会再进入沙箱
◆ 修复了实时防护无视白名单的问题
　　（警告：白名单内的文件按照精确哈希匹配，如果您不确定该文件是否为安全，请谨慎添加白名单！）

## V26.1.5 更新日志
◆ 修复了可能隔离webview导致PSLS自身卡死的问题
◆ 修复了对关键目录保护的大量误报的问题
◆ 将沙箱进程剥离，减小了卡死的几率
◆ 新增进程行为启发式检测
◆ 对驱动签名进行了灰名单分层
◆ 加强了内核驱动防护

## V26.1.4 更新日志
◆ 更改了联网更新样本库的数据库来源，现在不需要VPN
◆ 开机自启动将PSLS进程升级为了最高优先级
◆ 重新训练了ML引擎，增强查杀能力
◆ 新增6维度上下文信任评估
◆ 学习了蛋包饭的做法

## V26.1.3 更新日志
◆ 修复了沙箱无法监控释放子进程的恶意程序的问题
◆ 新增了非管理员启动自动提权的功能
◆ 修复了内核驱动未加载导致MBR保护失败的问题
◆ MBR保护升级为关键目录全保护，更加全面覆盖系统关键部分
◆ 做了一份叉烧饭

## V26.1.2 更新日志
◆ 新增了非可信签名可执行文件一律监测的功能
◆ 加强了内核驱动拦截能力
◆ 新增了对银狐木马的针对性防御
◆ 优化了资源占用

## V26.1.1 更新日志
◆ 修复了沙箱导致PSLS进程卡死的问题
◆ 优化了PSLS的性能占用
◆ 增加了MB样本下载的功能（须要VPN）

## V26.1.0 更新日志
◆ 更新了沙箱的GUI，使分析过程可见
◆ 优化了对bat等脚本的处理逻辑
◆ 修复了沙箱启动失败的问题
◆ 修复了PSLS驱动残留导致软件无法使用的恶性漏洞
◆ 优化了隔离区恢复逻辑，在文档文件夹可以找到恢复路径错误的文件

## V26.0.13 更新日志
◆ MBR/引导扇区防护升级为内核级实时拦截（diskmon驱动），在写入落盘前直接拦截，不再依赖轮询回滚
◆ 修复了沙箱分析偶发启动失败的问题（脚本类文件按对应解释器运行）

## V26.0.12 更新日志
◆ 按照优先级修改了PSLS的提示音效：
         info:无通知的实时监测发现可疑、无通知的启动监测发现可疑
         info2:通知询问是否重启（沙箱放行）
         warn:沙箱拦截分析、无通知的检测到威胁
         error:通知隔离可疑对象
         error2:通知隔离恶意对象
         critical：MBR、引导扇区被修改，检测到勒索行为（文件被修改），注册表被篡改
◆ 添加了更多恶意软件签名
◆ 添加了MBR防修改功能
◆ 优化了启动监测的处理逻辑

## V26.0.11c 更新日志
◆ 增强了引擎检测能力，拦截外联

## V26.0.11b 更新日志
◆ 修复了主动防御监测遗漏的问题
◆ 修复了隔离区逃逸的问题
◆ 修复了内存泄漏问题

## V26.0.11a 更新日志
◆ 修复了PSLS扫描时导致某些文件启动的问题
◆ 增强了沙箱隔离与放行机制
◆ 优化了针对银狐病毒的查杀能力

## V26.0.11 更新日志
◆ 修复了驱动可能导致蓝屏的问题
◆ 加强了沙箱反逃逸能力
◆ 优先进行文件锁定，防止恶意文件启动

## V26.0.10 更新日志
◆ 新增了LightGBM引擎
◆ 优化了ML引擎查杀能力
◆ 实时防护支持并行处理可疑文件
◆ 加强了针对银狐木马的防护

## V26.0.9 更新日志
◆ 启用了内核驱动防护功能

## V26.0.8f 更新日志
◆ 升级了查杀引擎。

## V26.0.8e 更新日志
◆ 修复了系统保护监视进程终止不及时的问题

## V26.0.8d 更新日志
◆ 为驱动防护做了充分准备
◆ 增强了进程拦截功能

## V26.0.8c 更新日志
◆ 加强了沙箱隔离机制，降低了逃逸的概率
◆ 修复了实时防护子进程扫描路径未应用排除目录的问题
◆ 增加了大量恶意样本和白名单
◆ 添加了启动项监控功能

## V26.0.8b 更新日志
◆ 测试过渡版本，修复了一些问题

## V26.0.8a 更新日志
◆ 写入了内核级驱动防护（beta）
◆ 加强了自我保护机制（beta）

## V26.0.8 更新日志
◆ 优化了扫描策略，提升了扫描速度
◆ 改善了误报问题
◆ 加强了实时防护模块

## V26.0.7h 更新日志
◆ 降低了误报率
◆ 增加了一些签名
◆ 增加了模糊哈希的功能
◆ 增加了YARA引擎规则

## V26.0.7g 更新日志
◆ 修复了对系统默认项目的扫描排除
◆ 支持自定义扫描排除路径

## V26.0.7f 更新日志
◆ 加快了扫描速度
◆ 提升了隔离区文件处理速度
◆ 移除了GUI自动重置的功能

## V26.0.7e 更新日志
◆ 优化了扫描速度
◆ 优化了隔离区批量操作卡顿的问题
◆ 修复了WMI Powershell监控问题

## 包含组件
- 主程序: PSLS.exe (UI + 扫描引擎)
- ML Worker: MLWorker.exe (独立 ML 推理引擎，避免 DLL 冲突)
- 签名库: db/signatures.db (1.6MB+)
- ML引擎: ONNX Runtime + 预训练模型
- YARA: 规则引擎
- 杀毒扫描: 全文件扫描 + 压缩包深度扫描
- 实时防护: 文件监控 + 进程保护 + 应用启动拦截
- 沙箱分析: 本地隔离行为分析
- 自我保护: 反调试 + 完整性校验

## 首次运行
1. 双击 PSLS.exe 启动
2. 签名库和ML模型会自动复制到 %APPDATA%\\PSLS\\
3. ML Worker 会在首次使用时自动启动
4. 无需手动配置，开箱即用
"""
    readme_path = os.path.join(psls_dir, "README.txt")
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(version_info)
    print(f"  已创建: {readme_path}")
    
    # 清理临时文件
    print("\n[10/10] 清理临时文件...")
    for d in [BUILD_DIR]:
        if os.path.exists(d):
            try:
                shutil.rmtree(d)
            except Exception as e:
                print(f"  [警告] 删除 {d} 失败: {e}")

    generated_spec = f"{APP_NAME_SHORT}.spec"
    if os.path.exists(generated_spec) and generated_spec != PSLS_SPEC:
        os.remove(generated_spec)

    # 如果 PSLS 输出在 dist_new 目录，尝试移动到 dist\PSLS
    if PSLS_OUTPUT_DIR != OUTPUT_DIR:
        target_dir = os.path.join(OUTPUT_DIR, APP_NAME_SHORT)
        if os.path.exists(psls_dir):
            # 先尝试删除旧的 dist\PSLS（可能被锁定）
            if os.path.exists(target_dir):
                try:
                    shutil.rmtree(target_dir)
                    print(f"  已删除旧目录: {target_dir}")
                except Exception as e:
                    print(f"  [警告] 无法删除旧目录 {target_dir}: {e}")
                    print(f"  PSLS 保留在: {os.path.abspath(psls_dir)}")
                    # 保留在 dist_new 目录，更新路径引用
                    target_dir = psls_dir
            # 移动 dist_new\PSLS → dist\PSLS
            if not os.path.exists(target_dir) or target_dir == psls_dir:
                if target_dir != psls_dir:
                    try:
                        shutil.move(psls_dir, target_dir)
                        print(f"  已移动: {psls_dir} -> {target_dir}")
                        psls_dir = target_dir
                    except Exception as e:
                        print(f"  [警告] 无法移动到 {target_dir}: {e}")
                        print(f"  PSLS 保留在: {os.path.abspath(psls_dir)}")
        # 清理空的 dist_new 目录
        if os.path.exists(PSLS_OUTPUT_DIR):
            try:
                # 只在目录为空时删除
                if not os.listdir(PSLS_OUTPUT_DIR):
                    os.rmdir(PSLS_OUTPUT_DIR)
            except Exception:
                pass
    
    # 需求 3：在 PSLS 自身目录内落一份签名库备份（db_backup\signatures.db）。
    # 位置选 {app}\db_backup（**不是桌面/用户目录**）；用的是"随包一次性分发"策略：
    # 从打包产物自带的 _internal\db\signatures.db 复制一份，安装器 `dist\PSLS\*`
    # 递归打包会自然带上（无需改 .iss）。运行时主库缺失/损坏会自动回退到它。
    try:
        _db_src = os.path.join(psls_dir, '_internal', 'db', 'signatures.db')
        if not os.path.isfile(_db_src):
            _db_src = os.path.join(psls_dir, 'db', 'signatures.db')
        if os.path.isfile(_db_src):
            _db_bak_dir = os.path.join(psls_dir, 'db_backup')
            os.makedirs(_db_bak_dir, exist_ok=True)
            _db_dst = os.path.join(_db_bak_dir, 'signatures.db')
            shutil.copy2(_db_src, _db_dst)
            print(f"  [签名库备份] {_db_src} -> {_db_dst} "
                  f"({os.path.getsize(_db_dst) / 1024 / 1024:.1f} MB)")
        else:
            print(f"  [警告] 未找到内置签名库，跳过 db_backup 复制: {_db_src}")
    except Exception as e:
        print(f"  [警告] 生成 db_backup 失败（不影响打包）: {e}")

    print("\n" + "=" * 60)
    print(f"打包完成!")
    print(f"输出目录: {os.path.abspath(psls_dir)}")
    print(f"主程序: {os.path.abspath(os.path.join(psls_dir, f'{APP_NAME_SHORT}.exe'))}")
    print(f"ML Worker: {os.path.abspath(os.path.join(psls_dir, 'MLWorker.exe'))}")
    print(f"\n运行方式:")
    print(f"  - 直接双击 PSLS.exe 启动")
    print(f"  - ML Worker 会按需自动启动")
    print(f"\n注意: 整个 PSLS 文件夹可以独立运行，无需安装!")
    print("=" * 60)

if __name__ == '__main__':
    main()
