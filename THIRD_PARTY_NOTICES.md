# 第三方组件与许可

本项目以 GPL-3.0 发布。以下组件随项目使用或曾被用于完整构建，列明出处与许可，
以便再分发时保留必要声明。

## 随本仓库分发

| 组件 | 许可 | 说明 |
| --- | --- | --- |
| PyQt5 / PyQtWebEngine | GPL-3.0（Riverbank Computing） | 界面绑定；本项目因此整体采用 GPL-3.0 |
| Qt 5 / Qt WebEngine | LGPL-3.0 / GPL-3.0（Qt Company） | PyQt5 的运行时依赖 |
| Lucide | ISC | `ui/webview/lucide.min.js` 图标库 |
| Tailwind CSS | MIT | `ui/webview/tailwind.global.js` |
| psutil | BSD-3-Clause | 进程与系统信息 |
| watchdog | Apache-2.0 | 文件系统事件监控 |
| NumPy | BSD-3-Clause | 数值计算 |
| pefile | MIT | PE 结构解析 |
| Pillow | MIT-CMU | 屏幕截图相关检测 |
| YARA / yara-python | BSD-3-Clause（YARA）；绑定见上游 | 规则引擎 |
| SQLite | Public Domain | 签名库存储 |

## 不随本仓库分发

| 组件 | 许可 | 说明 |
| --- | --- | --- |
| Dantrolene V1 | 私有 | 与 PYAS 共同研发；模型、特征管线与推理实现未包含 |
| Sorel-20M 衍生模型 | 见数据集上游条款 | 未包含 |
| Elastic protections-artifacts | Elastic License 2.0 | 未包含；可用 `scripts/fetch_elastic_yara.py` 自行获取，须遵守上游许可（含限制条款） |
| Sandboxie-Plus | GPL-3.0 | 可选外部沙箱组件，未包含 |
| Microsoft VC++ Redistributable / WebView2 | Microsoft 再分发条款 | 仅安装包使用，未包含 |

## 备注

- 若你重新引入上述“不随仓库分发”的组件，请自行确认许可兼容性，并在发布物中
  附带对应许可全文与来源说明。
- 本项目名称、图标与“璱鸲计划实验室 / Project Sertraline Lab”标识不随 GPL
  授权授予商标使用权。
