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
- TaintSage 论文精读与三份方案落档：用户提供 ICSE 2027 论文 PDF，精读卡入 `docs/12`（paper card 全 16 节，audit 通过：22 PASS、0 ERROR）；`docs/13` TaintSage 接入方案 v1（P0 source 识别增强与四类证据标注 → P1 Juliet 基准评测（CWE-78/134/190/606 各 50 对，数据放 `data/juliet/`）→ P2 RDC 物化；结构化状态抽象按用户决定本轮不做）；`docs/14` 攻击面侦查阶段方案（现状核实：攻击面分析已存在但折叠在各 CWE 任务内，缺独立阶段/持久化产物/跨 CWE 复用/无攻击面门禁；补齐=阶段 0 独立侦查 + state/attack-surface.json + 网络攻击面门禁 skipped_no_attack_surface）；`docs/15` 真实固件测试方案 v1（样本改为用户提供的 `data/02_two_firmwares` 两个已解包 Tenda rootfs——AC18/FH1203，路径第 1 步为 unzip+架构确认，binwalk 适配器退回暂缓项）。`docs/文档索引.md` 同步。
- 运行开销观测与日志监视：CLI 日志加时间戳、每轮日志追加写入 `run-<id>/analysis.log`、`report.json` 增加 `elapsedSeconds`（分析+PoC 墙钟时间）与 `usage`（OpenCode 从本地会话库 `$XDG_DATA_HOME/opencode/opencode.db` 按运行目录+时间窗匹配本次会话，读出 6 列 token/cost；读不到为 null 不影响分析）；`poc-manifest.json` 恒带 `usage` 字段；结束日志带耗时与 tokens_in/out，末尾输出"运行全部结束"汇总；手册新增 §5.2 日志与开销监视。GhidaMCP 环境重建：本机 ghidra 12.0.4 + 遗留扩展 jar 兼容可用，基线 env 记录在 docs/11。
- 运行开销基线实验（`tests/20261013_01_运行开销基线_r01/`）：`--cwe all --poc` 完整运行 6 个 CWE。第 1 轮总耗时 1415.4s、5/6 失败，暴露三类 schema 硬化问题并修复：① `findings[].limitations` 允许空字符串项 → `prompts/common/report-schema.md` 强化非空与篇幅控制；② 模型发明 `allocator` 角色被拒 → `models.py` 角色集合/映射扩充 `allocator`/`deallocator`，`source-sink-model.md` 明确角色词汇表；③ CWE-78 报告 JSON 被截断 → report-schema 增加"报告必须完整闭合"要求。第 2 轮（硬化后）**6/6 全部通过**，总耗时 1378.3s、token 合计 in 708,657 / out 84,655、成本约 $0.29；单 CWE 耗时 104–369s。分析请求 cwd 从仓库根改为 run 目录（模型写的文件与 `.opencode` 落进 run 目录，不污染仓库根）；`.gitignore` 增加 `/.opencode` 与 `/data/02_two_firmwares`。已知环境抖动：GhidraMCP 会话时连时不连（未连上时 agent 降级为 objdump+paths 并照常产出有效报告），根因待查。
- 日志信息密度与进度监视：每条日志带 `[当前完成组数/总组数]` 进度前缀（按分析组×CWE 任务计数，多进程 worker 各自维护）；`分析结束` 行在耗时/token 后追加 `findings/confirmed/rejected/unresolved/poc_status/poc_files` 全量结论；新增 `Agent 底座`（MCP 服务器清单）、`运行命令`/`进程退出`、`工具证据 ghidra=N paths=M`（`ghidra=0` 即时暴露 GhidraMCP 未连上的降级）等关键动作日志；`runtime.py` 记录真实命令行与退出码/输出字节数。
- 产物瘦身：证据代理不再为每个会话写 `{ghidra,paths}-version.json`（MCP 会话版本改为一行进 `analysis.log`），并在会话收尾把证据条数与字节量一行入账；run 目录 `raw/` 只剩 `agent.txt` 与 `{ghidra,paths}.jsonl` 证据记录（预算耗尽时才有 `budget-*.json`）。
- 结果正确性分析（`docs/16`）：对照 demo ground truth 逐项核对两轮 11 个 run 的全部 findings——0 误报（100 个被引用 evidenceID 全部能在 raw 证据中找到，`scripts/check_evidence_integrity.py` 自动化审计），candidate 链（remoteExec→doSystem→popen、authLogin→auth_log→system）被完整捕获且诚实标注证据边界；漏报风险集中在 GhidraMCP 会话抖动（已加 `ghidra=0` 告警）与跨二进制路径无工具覆盖（docs/13 P2 路线）。
- 证据门禁缺口修复：并发第 3 轮审计发现 run-80e26d98d2d7（CWE-416）的函数模型/攻击面/propagationMap 引用了代理从未签发的幻觉 ID（`ev-7cc5a1964e66c4c1303a`）——此前门禁只对 finding 的坏引用生效。修复（`artifacts.py` finalize）：函数模型/攻击面剔除坏引用保留对象、propagationMap 含坏引用的条目整体剔除，均记 unresolved；审计脚本改为只统计结构性引用位置（findings/模型/攻击面/pathQueries/propagationMap 的 `evidenceIDs` 数组），诊断文本不计。r01 新增回归测试 `test_model_and_surface_hallucinated_evidence_is_stripped`；存档 run 重新 finalize 复核后 6/6 通过。
- 并发执行：`--workers N` 把 (分析组×CWE) 任务分发到 N 个独立子进程（`ProcessPoolExecutor`，每个任务独立 run 目录/日志/临时 MCP 配置，产物语义与串行一致，`executor.map` 保持产物聚合顺序）；r02 新增 workers=2 端到端测试（6 任务全部落盘、每任务日志带进度前缀）。真实并发验证三轮（`tests/20261013_02_并发验证_r01/`）：workers=2 总墙钟 708.5s vs 串行 1378.3s（约 1.95×），三轮结论与串行一致（6 CWE 全 inconclusive、0 confirmed、0 误报）。并发暴露并修复三个鲁棒性缺陷：① opencode standalone 会话同时启动的竞态（`Standalone server exited before reporting readiness`）→ OpenCodeRuntime 退避重试（2s/4s 两次）；② 模型 propagationMap 键名漂移（from/to）→ 解析层容忍别名 + report-schema 明确固定键名；③ 模型 JSON 输出方差（未转义引号/截断）→ 报告级重试一次（`报告无效（…），重试分析会话`）。修复后 6/6 一次通过、零重试触发。
- 断点续跑：`--resume <run目录>` 原地续跑、按阶段跳过——report.json 存在直接复用报告（跳过分析阶段）、raw/agent.txt 存在重新 finalize（不重复调用 Agent）、再否则从上下文摘要续跑；PoC 阶段按 `poc-manifest.json` 复用交付物（仅 failed 重跑）；`report.json` 改为无条件落盘作为断点检查点。任务级断点：同 `--output` 重跑按 `completed-<CWE编号>.json` 跳过已完成任务（goal 与 PoC 开关一致才复用），`--force` 全量重跑；汇总行加 `复用=N`。r02 新增 4 个续跑端到端测试；手册 §5.4 断点续跑。
- 确认门禁保守性分析与漏报优先策略（`docs/17`）：12 个有效 run 全 0 confirmed 的逐层根因——① 提示词规则层禁止函数内路径证据下输出 confirmed（模型把两条真实命令注入链自我降级为 candidate→unresolved）；② 证据核验层要求 evidenceID 本地可核验、跨二进制对象整条移出；③ 覆盖账本把"覆盖充分"定义得高于工具能力上限（unresolved 项即 canFinish=False）；④ PoC 阶段只接受 confirmed 且禁止执行样本，无运行时验证通道。与 vulnhuntr 对比（输入源码+PoC 运行即证据+无覆盖账本）确认三重叠加必然 0 confirmed。策略实现：`--confirmation {recall,precision}`（默认 recall 漏报优先）——confirmed 增加 `confirmationBasis` 字段（taint-path | reference-chain）；新增 `prompts/common/confirmation-policy.md` 按模式注入系统提示词；precision 模式由运行时硬门禁把引用链级 finding 降级为 unresolved；recall 模式新增"调用方写入即外部来源"规则（禁把 recv/memcpy 缓冲判为常量）。r01 +2、r02 +3 回归测试全绿；手册 §5.5。
- 漏报优先验证 + 跨二进制证据核验修复（`tests/20261014_01_漏报优先验证_r01/`，docs/17 §3.1 vh 实测对照）：用户本地 docker vulnhunter task 5 对同一 server 二进制报 8 vulns（VULN-001 未认证 RCE = 我们的链 A、VULN-002 auth_log 命令注入 = 链 B），确认差距在门禁不在目标（我们每轮 manifest 根都是 server，client 无 vulns 与 vh 一致）。recall 首轮（run-656dc86af251）模型正确输出 2 条 confirmed reference-chain finding，却被证据核验错杀——Ghidra 只加载 root binary、全部记录 binaryID=server，而链 B finding 归属 libauth，binaryID 强相等判定 6 条证据"无法核验"，且 invalid_references 全局连坐把共享 get_program_info/list_imports 证据的链 A 一并踢出。修复：核验只查"evidenceID 存在、属于本分析组、工具未报错"，不要求 binaryID 相等（r01 回归测试 `test_cross_binary_evidence_attributed_to_root_binary_is_kept`）；修复后同轮 raw 事后 finalize 2 confirmed（unresolved 13→5）。真实重跑（run-3c27fd0aa510，--force）：链 A doSystem@0x401ba2 **confirmed（reference-chain）并产出 PoC**（`0x401ba2.CWE-78.md/.py`），链 B 由模型如实写 unresolved（分析组内无 auth_log 调用点证据）；证据完整性 2/2 OK。顺带修复汇总行计数 bug（`成功=len(reports)-failures`）。遗留：CWE 模板继承 vh 提示词的 clues/notes/decompile 目录引用（我们的运行时一个都不产出，模型会浪费探索找它们），待模板去 vh 化。
- 搜索范围扩大验证（`tests/20261014_02_搜索范围扩大验证_r01/`）：把「前期扩大搜索范围、后期 agent 判断降 FP」落成两阶段提示词——`prompts/common/attack-surface.md` 重写（第一阶段全组危险 sink 枚举宁滥勿缺：root 用 GhidraMCP、依赖库用 nm -D/objdump/strings 且候选记 unresolved；第二阶段按 CWE 判定规则+confirmation-policy 收紧），6 个 CWE 模板「起点」节去 vh 化（改指 Sagent 工具，不再引用 clues/notes/decompile 等不存在的线索文件）。验证两轮（第 1 轮 provider 超时中断，第 2 轮 run-3939894a5123 成功）：链 A doSystem→popen confirmed（reference-chain）+ PoC；搜索范围扩大直接可见——unresolved 新增链 B 完整候选（auth_verify→auth_log echo→system 的 ELF 级证据）、硬编码 token "SGC2023_SECRET" 候选（=vh VULN-005，注明 CWE-798 超范围）、server 命令类 sink 覆盖清单；main mkdir system 仍 rejected（具体反证）。遗留：依赖库侧候选无 evidenceID 无法 confirmed（待 Ghidra 加载依赖库）；provider 超时成为真实运行主要不稳定源（5 次真实运行 2 次 `Timed out waiting for response data`，重试均成功），待加会话级重试。

## 暂缓项

- 固件解包（binwalk 适配器）、压缩包输入。
- 缓冲区溢出/UAF/Double Free 等内存生命周期问题。
- 更多 CWE 插件、完整跨函数污点状态扩展和动态验证。
