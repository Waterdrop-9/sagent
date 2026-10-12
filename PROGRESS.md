# Sagent 进度记录

状态：2026-10-11 更新。本文记录项目当前进度和下一步计划，随进展持续更新。

## 项目目标

面向 C/C++ ELF 和固件样本的防御性静态二进制分析系统。结果服务于人工审计：证据、风险判断、验证建议和审计 PoC 报告。首期分析 CWE-78、CWE-134、CWE-190、CWE-606。Ghidra 作为独立分析引擎，Agent 底座通过适配器接入。

约束见 `GUIDELINE.md`（开发风格）、`设计总纲.md`（总体设计）、`术语表.md`（领域词汇）。模块文档统一放 `docs/`。

## 已完成

- 设计与规范：`GUIDELINE.md`、`设计总纲.md`、`术语表.md` 已建立（讨论稿 v0）。
- 模块文档：`docs/01` 领域模型、`docs/02` 单 ELF 联合分析组、`docs/03` 依赖检索与分析组构建、`docs/04` Agent 接入与本地配置、`docs/05` Agent 底座和 CWE 插件 MVP。
- 实验规范：`EXPERIMENT.md`，实验目录格式 `tests/YYYYMMDD_序号_目的_rXX`，数据来自 `data/`。
- 实验数据：`data/01_simple_demo/`（client、server 两个可执行程序，libs/libauth.so、libs/liblog.so）。
- 实现：`src/elf.py`（约 550 行），包含：
  - `read_elf()`：纯标准库解析 ELF 头、程序头、`PT_INTERP`、动态段 `DT_NEEDED/DT_SONAME/DT_RPATH/DT_RUNPATH`、动态字符串表，输出 `ElfInfo`（含 sha256）。
  - `_CandidateIndex`：递归扫描工作根目录，按文件名/SONAME 建候选索引；按 ELF 魔数识别，不依赖后缀。
  - 依赖解析：架构/位数/端序兼容检查；同内容候选去重；多候选冲突不擅自选择；常见库白名单（`COMMON_LIBRARY_NAMES`）转通用库知识引用。
  - `build_analysis_groups()`：单 ELF 模式（不扫父目录，仅显式依赖根）和目录模式（可执行 ELF 各自建组，`ET_DYN` 带 interpreter 视为 PIE）。
- 实验：`tests/20261010_01_elf依赖检索_r01/` 三个用例全部通过（目录模式分组、单 ELF 不扫父目录、显式依赖根）。
- Agent 原型：`src/agent/` 提供 Claude Code/OpenCode adapter、CWE 插件接口、GhidraMCP 配置和 CWE-78 dry-run/真实调用入口；CWE prompt 位于 `prompts/cwe-78/`。
- Ghidra 接入：使用外部 GhidraMCP 提供反编译、函数、导入、导出、字符串、调用和交叉引用 MCP 工具；headless 启动链路已在本机验证。
- 配置与工作流：根目录 `config.toml.example` 提供 Agent 配置模板，真实 `config.toml` 被忽略；`部署与使用手册.md` 和 `docs/06-工作流.md` 已建立；静态污点工具比较记录在 `docs/07-静态污点工具调研.md`。
- Prompt 与覆盖账本：`docs/08-Prompt与覆盖账本设计.md` 已定义攻击面、source/sink 自定义模型、sink 驱动查询、覆盖结束条件和不同 CWE 的阶段化 prompt 组织。
- 产物规模约束：账本只保存摘要和引用，候选、查询和证据使用紧凑 JSONL，原始工具结果独立保存，避免单个 JSON 或 prompt 无限增长。
- 大型分析组策略：默认采用紧凑 JSONL 和稀疏证据；只保留高价值候选、被引用证据和 unresolved 项，设置候选、查询、路径和证据预算，避免函数数量导致 Agent lost in the middle。
- 开发推进计划：`docs/09-开发推进计划.md` 已确定阶段一至阶段六的实现、验收、真实 ELF 实验和回滚顺序。
- 阶段一实验：`docs/10-阶段一真实ELF实验.md` 记录 `server` 的真实 OpenCode + DeepSeek + GhidraMCP 攻击面侦查；发现 `remoteExec → doSystem → popen` 候选路径，并区分了固定常量 `system` 调用。
- 路径后端试跑：真实 `server` ELF 上 angr CFGFast 成功识别 147 个函数，RDA 对 `doSystem`/`remoteExec` 成功建立 485/952 节点依赖图；Mango 被本地 cmake/unicorn 依赖阻塞，CTADL 尚未完成部署，参数级适配器仍待实现。
- 参数路径联调：启用 `paths` MCP server 后，真实 Agent 对 `popen@0x401be7` 和 `system@0x4022ef` 均返回 `path_found`；Agent 将前者保留为 candidate，将常量路径后者判为 rejected，实验记录在 `docs/10-阶段一真实ELF实验.md`。
- 报告门禁联调：真实 Agent 输出经 `AgentReport` 校验通过，保留 3 条 finding、3 条 unresolved 和 coverage 摘要；`remoteExec` 为 candidate，固定常量路径为 rejected。

## 实现与 docs/03 的差距

按 `docs/03` 设计稿，实现尚未覆盖：

1. `RPATH`/`RUNPATH`/`$ORIGIN` 路径信息缩小候选范围——已按可解析的 `$ORIGIN` 和绝对路径过滤候选；完整动态加载器优先级仍未模拟。
2. 符号链接别名与断链/循环链接的记录（索引里部分处理，无原因记录）。
3. 无法明确分类的 ELF 保留为“不确定组件”（当前只有可执行/非可执行二分）。
4. sysroot 目标系统绝对路径映射。
5. 导入符号和版本信息辅助检查候选。

## 下一步计划

1. 完成真实 ELF 正反例和大型分析组实验，重点验证 backend 的 unknown/unsupported、预算和恢复行为。
2. 按 `docs/03` 验证场景补充依赖检索实验：同名库冲突、断链和同内容库共享身份。
3. 在覆盖门禁和证据产物稳定后，按同一插件契约增加 CWE-134，再评估 CWE-190、CWE-606 所需的数值状态。

## 2026-10-12 恢复后进展

- 暂缓 PoC：CWE-78 运行时不再加载 `poc.md`，流程截止 finding、覆盖账本和人工复核。
- 报告门禁已接入本地产物：Agent 原文、Ghidra/paths 原始 JSONL、候选、查询、稀疏 evidence 和 `coverage-ledger.json` 分开保存；工具响应通过代理获得 `evidenceID`。
- 覆盖账本现在逐项检查攻击面、函数模型、confirmed sink 的每个敏感参数、工具查询状态、预算和 unresolved；Agent 自述的 `pathToolResult` 不会被视为实际查询记录。
- `server` 真实联调返回 3 个 finding、11 个函数模型和 3 个实际 paths 查询；本地核验结果为 `inconclusive`，原因包括未知攻击面、未加载依赖、跨函数路径缺失和部分模型无证据。这是预期门禁行为。
- 真实联调产物已归档到 `tests/20261012_01_覆盖门禁_r01/产物/真实server联调_r01/`，不再只留在 `/private/tmp`。
- 新增 `tests/20261012_01_覆盖门禁_r01/`，验证参数级覆盖、地址别名、报告契约、证据代理、产物恢复和 PoC prompt 排除。
- PoC 阶段接好：新建仓库内专用模板 `prompts/poc-stage.md`（弃用外部模板；报告叙事结构借鉴 vulnhunter 的 PoC prompt 思想，契约由 Sagent 自己定义），`config.toml(.example)` 的 `[poc].prompt_file` 改为相对路径；模板契约测试更新后通过。
- 新增 `tests/20261012_02_PoC阶段_r01/`：fake OpenCode 端到端验证 PoC 落盘、manifest 结构、cwd 与 skipped 分支；confirmed fixture（真实 evidenceID）通过证据门禁；真实 OpenCode PoC 请求成功生成静态审计材料，`executed: false`。
- 修复运行时缺陷：`_CliRuntime.run` 把过期的 `PWD` 环境变量修正为实际 cwd（opencode 项目发现依赖 `PWD`，不一致会报 `Model unavailable`），并加回归测试。
- PoC 产物布局收紧：request/response/manifest 移到 run 目录顶层（`poc-request.md`/`poc-response.md`/`poc-manifest.json`），`poc/` 里只保留模型生成的 PoC 报告和验证脚本；`OpenCodeRuntime` 运行后清理空的 `.opencode/` 目录；真实请求按新布局复跑成功。
- PoC 阶段借鉴 vulnhunter 产出验证脚本：每个 confirmed finding 除 8 小节报告外再生成可运行的 `<functionID>.CWE-78.py`（命令行参数、证据出处注释、默认无害命令、超时与异常处理、仅供授权隔离环境人工执行）；真实请求已验证，`executed: false`。
- PoC 命名与产物索引：交付物命名去掉 `.poc`（`<functionID>.CWE-78.md`/`.py`）；CLI 在 PoC 阶段结束后自动清点 `poc/` 文件写入 `poc-manifest.json` 的 `files` 字段，作为交付物索引；真实请求按最终命名复跑成功（`run-5e3cec028963`，旧轮次归档到 `历史轮次/`）。
- 使用手册更新：`部署与使用手册.md` §5 补完整产物目录树（run 级账目与 `poc/` 交付物）和"如何查看结果"四步顺序（report.json 结论 → 覆盖账本 → 原始证据 → PoC 交付物），并修正已过时的 PoC 段落。
- code review 清理技术债：PoC 外部调用补全开始/结束/失败日志；`poc-manifest.json` 成功/失败形态统一（`files` 恒存在、失败为空列表 + `error`）；术语统一为"独立的 PoC 阶段"（去掉"外部"）；`{created_at}` 占位符改填真实时间戳；模板交付物命名参数化 `<functionID>.<CWE编号>.md/.py`（`{cwe_id}` 跟随 `--cwe`）；`docs/11` 列入 `docs/文档索引.md`；PWD 回归测试移植进版本库（tracked `tests/20261012_01_覆盖门禁_r01/test_workflow.py` 的 `RuntimeEnvTests`）。清理后真实 PoC 复跑成功（`run-d4832cfc3a71`）。
- `--cwe` 默认跑全部 CWE：默认值改为 `all`，一次运行依次执行全部支持的 CWE（每个 CWE 一个独立 `run-<id>`，`report.json` 记录 `cwe` 字段）；只想跑单个类型时显式传 `--cwe CWE-78`。顺带修复 `MarkdownCwePlugin.build_user_prompt` 用 `str.format` 填充导致模板里 C 代码字面花括号报 `KeyError` 的问题（改为字面替换 `{target}`/`{goal}`）。r02 新增"无 `--cwe` 默认跑全部 CWE"端到端测试。
- TaintSage 论文精读与三份方案落档：用户提供 ICSE 2027 论文 PDF，精读卡入 `docs/12`（paper card 全 16 节，audit 通过：22 PASS、0 ERROR）；`docs/13` TaintSage 接入方案（P0 source 识别增强与四类证据标注 → P1 结构化状态抽象与缓存 → P2 Juliet 基准 → P3 RDC 物化；docs/09「不引入 TaintSage state cache」边界按用户要求更新）；`docs/14` 攻击面侦查阶段方案（现状核实：攻击面分析已存在但折叠在各 CWE 任务内，缺独立阶段/持久化产物/跨 CWE 复用/无攻击面门禁；补齐=阶段 0 独立侦查 + state/attack-surface.json + 网络攻击面门禁 skipped_no_attack_surface）；`docs/15` 真实固件测试方案（KARONTE 同源样本 + CVE 对照评测，六步技术路径与三个实验目录）。`docs/文档索引.md` 同步。

## 暂缓项

- 固件解包（binwalk 适配器）、压缩包输入。
- 缓冲区溢出/UAF/Double Free 等内存生命周期问题。
- 更多 CWE 插件、完整跨函数污点状态扩展和动态验证。
