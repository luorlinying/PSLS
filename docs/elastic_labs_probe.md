# Elastic Security Labs 工具链探测（labs-releases / nightMARE / SWAT）

> 本文档记录对 Elastic Security Labs 三个候选资源的**结构 / 依赖 / 许可 / 接入点**
> 探测结论。数据来源为 GitHub 官方 API 与各仓库 README/pyproject（**本机未实际
> 安装依赖、未运行 extractor**，见文末"未验证项"）。日期：2026-10-09。

## 0. 结论速览

| 资源 | 定位 | 许可 | 是否接入 PSLS |
|---|---|---|---|
| `elastic/labs-releases`（`extractors/`） | 恶意软件**配置提取器**（按家族） | Elastic License 2.0 | **不接入**（用户已决定） |
| `elastic/nightMARE` | 逆向/分析**库**（extractor 的底层依赖） | Elastic License 2.0 | 不接入（依赖原生 Rizin） |
| `elastic/SWAT` | Google Workspace **红队模拟**工具 | Apache-2.0 | 不接入（与端点防护无关） |

---

## 1. `elastic/labs-releases`

- 结构（GitHub API，`main`）：
  - `extractors/`：按家族组织，实测含 `lobshot` / `remcos` / `redlinestealer` /
    `strelastealer`；每个目录含 `README.md` + `<family>_config_extractor.py`
    （部分含 `requirements.txt`）。
  - `indicators/`：研究型原子指标，`ecs-indicators.ndjson` + `stix-bundle.json`
    （家族/编号目录，如 `bitsloth`、`guloader`、`ref6138`…）。
  - `tools/`：社区工具（如 `icedid`、`alcatraz`、`guloader`、`lobshot`、
    `latrodectus`、`ghostpulse`、`shellter`、`stix-to-ecs`…），多含
    `README.md` 与脚本。
  - `README.md` 明示 `nightMARE/` 指向**独立仓库** `https://github.com/elastic/nightMARE`。
- 元数据：语言 Python；stars 91；创建 2023-02-22；最近 push 2026-09-11；
  仓库许可 `LICENSE.md` = **Elastic License 2.0**（README 亦声明）。
- extractor 运行方式（`extractors/README.md`）：需 Python 3.10+，并
  `pip install <labs-releases>/nightMARE` 作为依赖，再对单文件/目录运行
  `<family>_config_extractor.py -f FILE | -d DIR`。

## 2. `elastic/nightMARE`

- 定位：night**MARE** = Malware Analysis & Reverse Engineering 库（分析/逆向通用
  构件），供 labs-releases 的 extractor 复用。
- 元数据：语言 Python；stars 80；创建 2025-03-04；最近 push 2026-09-14；
  许可（README）= **Elastic License 2.0**；发布包名 `nightmare-lib`（PyPI）。
- **硬依赖**（README，"Requirements"）：
  - Python **>= 3.10**；
  - **Rizin v0.8.1** 必须安装并在系统 `PATH`（**原生二进制依赖**，非纯 Python）。
- 模块（README，节选）：`blister`、`ghostpulse`、`latrodectus`、`lobshot`、
  `lumma`、`netwire`、`redlinestealer`、`revstealer`、`remcos`、`smokeloader`、
  `stealc`、`telepuz`、`vidar`、`warmcookie`、`xorddos`、`deprecated.icedid`。
- 测试需下载含恶意样本的语料并置于 `tests/`（README 提示须在隔离 VM 中执行）。

## 3. `elastic/SWAT`

- 全名：**SWAT（Simple Workspace ATT&CK Tool）** —— 面向 **Google Workspace** 的
  红队模拟工具，用于验证检测规则（由 Elastic TRaDE 团队构想）。
- 元数据：语言 Python；stars 169；创建 2023-04-11；最近 push 2026-08-17；
  许可 = **Apache-2.0**（`pyproject.toml: license = "Apache-2.0"`）。
- 依赖（`pyproject.toml`，poetry）：`python = "^3.10"`、`colorama`、
  `google-auth`、`google-auth-oauthlib`、`google-auth-httplib2`、
  `google-api-python-client`、`PyYAML`、`requests`、`semver`、`tabulate`、
  `selenium`、`sphinx`、`pytest`，可选 `pandas`（`audit_support`）。
  入口脚本：`swat = 'swat.main:main'`。
- 自述处于 pre-alpha 阶段；需 Google Workspace 凭据/会话。

---

## 4. 接入点分析（若将来接入）

- PSLS 现有相关通道：`engine/rule_engine.py`（YARA 文件/DB 规则）、
  `engine/file_protection.py` / `engine/scan_engine.py`（扫描判定）。
- labs-releases extractor 产物是"**配置/指标**"（IOC），与 PSLS 的"检测/回滚"
  目标不同：更贴近**威胁情报**（可对接 `engine/threat_intel.py` 的 IP/域名黑名单
  或 `rules/yara/` 的家族规则），而非直接判定样本是否为勒索。
- 落地点若是"按家族提取配置字符串"，本质是**样本分析**能力，应放在沙箱分析
  （`engine/sandbox_analyzer.py`）之后的离线分析路径，**不得**写入扫描/沙箱
  协议通道，不得阻塞 Qt 主线程。
- nightMARE 作为库依赖 Rizin 原生二进制，与"**不引入新依赖**"的硬约束冲突。

## 5. 推荐子集与分步清单

推荐子集 = **不接入运行时依赖，仅选择性参考与其对应的 YARA/情报资产**：

1. **不接入 `labs-releases/extractors/`**（用户已决定）：其运行依赖 nightMARE + Rizin，
   且产物为 IOC，非端点判定所需。
2. **可选：参考 `indicators/` 的 STIX/ECS 指标**，抽取可静态化的域名/IP/哈希，
   合并进已有威胁情报库（`engine/threat_intel.py`），纯数据、无新依赖、无协议写入。
3. **可选：将工具中出现的家族 YARA 片段**（如 labs-releases `tools/*/**.yar`）
   经 `scripts/fetch_elastic_yara.py` 同款启发式预筛后再评估，谨慎放量。
4. **不接入 `nightMARE` / `SWAT`**：前者引入原生依赖，后者面向 Google Workspace，
   与 Windows 端点防护无交集。
5. 任何接入都必须：不写协议通道、不阻塞主线程、异常安全、中文注释、不引入新依赖。

## 6. 未验证项（明确声明，未编造）

- **未实际安装/运行** labs-releases 任一 extractor（未 `pip install nightMARE`）；
- **未安装 Rizin v0.8.1**，故 nightMARE 的"可跑性"未在真实环境验证；
- **未运行 SWAT**（无 Google Workspace 凭据），其命令/模拟行为未实测；
- 未逐条核对 `indicators/` 各家族的完整指标数量与字段质量；
- 未验证在 PSLS 打包（PyInstaller）环境下引入上述任一依赖的可行性与体积影响；
- 上述"依赖列表/许可/结构"来自官方 README 与 GitHub API 的**静态读取**，
  未在本机构建验证。

## 7. 许可小结

- labs-releases 与 nightMARE：**Elastic License 2.0**（非 OSI；含"不得作为托管服务
  提供"等限制）。
- SWAT：**Apache-2.0**（宽松，但本项目用途不相关）。