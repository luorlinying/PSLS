# Elastic YARA 规则引入评估（protections-artifacts）

> 本文档为 PSLS 引入 Elastic `protections-artifacts` YARA 子集的评估与落地记录。
> 所有数字均为**本机实测**（Windows 10，Python 3.10.11，yara-python 4.5.4，
> 上游 tar 包缓存于 `%TEMP%\elastic_pa_main.tar.gz`，离线可复现），未编造。

## 1. 上游结构

- 仓库：`https://github.com/elastic/protections-artifacts`（分支 `main`）。
- 规则目录：`yara/rules/`，单文件一族（`Windows_*` / `Multi_*`），每条规则内联
  `meta`（`threat_name` / `severity`（数值）/ `scan_context` / `os` / `license` 等）。
- 许可：仓库根 `LICENSE.txt` = **Elastic License 2.0**；已随子集落盘到
  `rules/yara/elastic/LICENSE.txt`，每条规则的 `meta.license` 原样保留。

## 2. 规模（实测，`scripts/fetch_elastic_yara.py --dry-run`）

| 指标 | 数值 |
|---|---|
| 上游 `.yar` 文件数 | 1056 |
| 上游规则条数 | 3069 |
| 平台淘汰（非 windows/multi） | 997 |
| 上下文淘汰（`scan_context` 缺 file） | 4 |
| `any of them` 淘汰 | 57 |
| 噪声类别淘汰（AttackSimulation/Joke/Prank/Debug） | 2 |
| 低熵 `any/1 of them`（串数 ≤2）淘汰 | 3 |
| 全短串（≤6B）淘汰 | 2 |
| **误报高风险剔除合计** | **7（修正后）** |
| **入选规则条数** | **2004** |
| **落盘文件数** | **741** |
| 落盘字节数 | 2,512,895 |

> 历史基线（Hacktool 放回前）：入选 1902 条 / 686 文件 / 剔除 109 条。
> 本次按"决定 1"放回 Hacktool 102 条（不再按类别剔除，改为强制降权），
> 故入选 = 1902 + 102 = **2004**，剔除 = 109 − 102 = **7**。

## 3. 兼容性实测

- 子集单独编译：`yara.compile(filepaths={elastic_<file>: path})` 成功（无重名冲突）。
- 与基线规则合并编译（`rule_engine` 的 `namespace = 相对路径下划线化` 方案）成功：
  `rules/yara/Rules_General_A1.yar` + 741 个 elastic 文件 = **742 个规则文件** 一次编译通过。
- 编译缓存 `rules/yara/compiled.yc` 可被 `yara.load()` 读取（见测试
  `test_elastic_yara_subset.py::TestElasticSubsetCompiles`）。
- 误报抽样：System32 采样（≤150 个 dll/exe）命中文件数阈值 ≤3（实测 0，见
  `TestSystem32FalsePositives`）。

## 4. severity 归一化（`engine/rule_engine.py::normalize_severity`）

Elastic `meta.severity` 为数值（100/90/50…），PSLS 计分按字符串
（`severity == 'high'`）比较，故在 `_match_rules_obj` 入口统一归一化：

- `>=90 → high`、`>=50 → medium`、`<50 → low`；
- **非数值字符串原样返回**（`'high'/'medium'/'low'/'info'` 行为不变）。

落盘子集（归一化后）分布：
`high=629`、`medium=1269`、`low=106`（其中 **Hacktool 强制 low = 102**），合计 2004。

## 5. 本次落地结果与剔除依据

### 5.1 Hacktool 放回且强制降权（决定 1）

- `_NOISE_CATEGORIES` 移除 `Hacktool` → 不再按类别剔除；
- 新增 `_FORCE_LOW_CATEGORIES = {'Hacktool'}`：保留规则块，但把其
  `meta.severity` **改写为字符串 `"low"`**（`_force_low_severity()`，
  仅改 severity 一行，不动其它 meta / strings / condition）；
- 归一化逻辑对该字符串原样透传为 `low` → "保留但降权"落地，且不影响其它规则；
- `any of them` / `one_of_them_few` / `short_strings` 三条启发式剔除**继续保留**。
- 放回条目：**102 条**，落盘为 55 个 `*Hacktool*.yar` 文件。

### 5.2 落盘后 `EXCLUDED.txt`（7 条，可复现）

| 规则 | reason |
|---|---|
| Multi_AttackSimulation_Blindspot_d93f54c5 | noise_category |
| Windows_AttackSimulation_Hovercraft_f5c7178f | noise_category |
| Windows_Trojan_BruteRatel_ade6c9d5 | short_strings |
| Windows_Trojan_Generic_0e135d58 | one_of_them_few |
| Windows_Trojan_Generic_2993e5a5 | one_of_them_few |
| Windows_Trojan_Generic_9997489c | short_strings |
| Windows_Trojan_HiddenCli_a9aa62d1 | one_of_them_few |

`scripts/fetch_elastic_yara.py --verify` 结果：
`文件数=741 规则数=2004 EXCLUDED=7 问题数=0 ✅ 全部符合筛选条件`。

### 5.3 编译缓存

`rules/yara/compiled.yc` 已重生成（6,062,800 字节）；同时写出规则文件集合指纹
`rules/yara/compiled.yc.fp`（`engine/rule_engine.py::_yara_files_fingerprint`：
排序后的 `(namespace, size, mtime_ns)` + 文件数 → SHA-256）。指纹不匹配即
自动重编译，避免"改规则后仍用旧缓存"。

## 6. 风险

- **误报**：Elastic 规则面向狩猎/扫描，直接在端点常驻扫描仍有误报可能；用
  启发式剔除 + System32 抽样控制，但非同于零误报。
- **许可**：Elastic License 2.0 非 OSI 许可，禁止"把软件作为托管/管理服务提供给
  第三方"等；作为本机安全产品的组成部分分发需遵守其条款。
- **性能**：2004 条规则（含 pe/正则/hex）编译与扫描耗时可观，故走后台懒加载 +
  编译缓存（见 `_start_yara_async_load`）。
- **DB 规则耦合**：有 DB 自动规则时不使用文件规则磁盘缓存（避免旧缓存不含新
  DB 规则），此时每次启动都重新编译文件规则。

## 7. 复现命令

```powershell
python scripts/fetch_elastic_yara.py            # 下载(tar 缓存优先)→筛选→落盘→自校验
python scripts/fetch_elastic_yara.py --dry-run  # 只统计不写盘
python scripts/fetch_elastic_yara.py --verify   # 校验已落盘子集
```

（脚本仅用标准库；离线时读 `%TEMP%\elastic_pa_main.tar.gz`。）