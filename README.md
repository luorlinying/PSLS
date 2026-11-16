# PSLS / 璱鸲计划实验室离线安全软件

Project Sertraline Lab Offline Security —— 一套完全离线的 Windows 终端安全软件。
判定全部在本机完成：不联网、不上传、不收集任何信息。

> **开源构建说明**：本仓库不包含私有机器学习引擎 **Dantrolene V1**（模型权重、
> 特征管线与推理实现）。ML 层为接口空实现，扫描由 PE 解析、YARA、模糊哈希与
> 签名库完成。上游完整构建的内部指标（检出率 >80%、误报率 <1%）**不适用于**
> 本仓库构建，请勿据此评估本项目。

## 发布说明

- **GitHub Releases 提供的是 Rust 版本**（主线实现）的安装包：
  [下载最新版本](https://github.com/luorlinying/PSLS/releases)。
- **Python 版本源码继续在本仓库开放**，但不再提供官方安装包；如需运行，请按
  下方“快速开始”从源码启动。
- 当前为**早期测试版**，功能和检测结果可能变化，请勿用于关键环境。

## 功能

| 模块 | 说明 |
| --- | --- |
| 多引擎判定 | PE 文件解析、YARA 规则、模糊哈希（CTPH）、SHA-256 签名库；ML 层为可选扩展 |
| 实时防护 | 监控下载/桌面/文档/启动项，文件落地即扫描，命中可阻断或隔离 |
| 隔离区 | 隔离样本、元数据记录与恢复 |
| 勒索回滚 | 关键目录快照与按世代回滚 |
| 自我保护 | 进程/文件/注册表/启动项/服务等多面防护 |
| 完全离线 | 无遥测、无账号、无云端查询，断网可完整运行 |

## 目录结构

```
engine/       检测与防护核心（扫描瀑布、规则、行为、隔离、回滚等）
utils/        日志、声音与通用工具
ui/webview/   PyQt5 + Qt WebEngine 界面与 JS 桥接
db/           签名库访问层与内置规则（数据库在运行时生成）
rules/yara/   通用 YARA 规则（第三方规则需自行获取并遵守其许可）
driver/       可选内核驱动源码与用户态桥接（需测试签名）
tests/        开发自测脚本（部分依赖完整版组件）
scripts/      规则同步等维护脚本
docs/         设计与规则评估文档
```

## 环境要求

- Windows 10/11 x64
- Python 3.13（完整版使用嵌入式 Python 运行时）
- PyQt5 / PyQtWebEngine、psutil、watchdog、numpy、pefile、yara-python、Pillow
- 可选：onnxruntime（仅当你自行接入 ML 引擎时）

## 快速开始

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python gui_entry.py
```

首次启动会在 `db/` 下创建空签名库并写入内置条目；`rules/yara/Rules_General_A1.yar`
为默认规则集。

打包（可选）：

```powershell
pyinstaller PSLS.spec
```

> 完整版的 `build.py` 与 `MLWorker.spec` 依赖私有 ML 组件，未包含在本仓库；
> 开源构建请直接使用 `PSLS.spec`，并按需删减其中的资源条目。

## 未包含的内容

以下内容因产权、许可或体积原因不随本仓库分发：

- Dantrolene V1 私有引擎（`engine/ml_detector.py` 的完整实现、`lightgbm_engine.py`、
  `ember_features.py`、`models/`、`engine/brewtotal_sorel/`、MLWorker）
- `db/signatures.db` 与白名单数据库（运行时生成）
- Elastic 规则子集（Elastic License 2.0，请用 `scripts/fetch_elastic_yara.py`
  自行获取并遵守上游许可）
- 已编译的 YARA 缓存、安装包、便携运行时、日志、隔离区与回滚快照
- 已签名的内核驱动二进制（仅保留源码；测试请使用测试签名）

## 安全须知

- 仅扫描你拥有或已获授权处理的文件。
- 本仓库不包含真实恶意样本；测试请使用 EICAR 标准测试文件。
- `driver/` 下的内核驱动仅供研究与测试，必须使用测试签名并开启测试模式；
  不要在未评估的生产环境加载未签名驱动。
- 发现安全问题请通过 GitHub Security Advisories 私下报告，不要公开提交可复现样本。

## 第三方组件

详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。本项目使用 PyQt5
（GPL-3.0），因此整体以 GPL-3.0 发布。

## 许可证

Copyright (C) 2026 璱鸲计划实验室 / Project Sertraline Lab

本项目以 **GNU General Public License v3.0** 发布，全文见 [LICENSE](LICENSE)。
你可以再分发和修改，但衍生作品必须同样以 GPL-3.0 开源。

## 免责声明

本软件按“现状”提供，不附带任何明示或暗示担保。作者不对因使用本软件造成的
数据丢失、系统损坏或法律风险承担责任。
