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

## 实现与 docs/03 的差距

按 `docs/03` 设计稿，实现尚未覆盖：

1. `RPATH`/`RUNPATH`/`$ORIGIN` 路径信息缩小候选范围——已读取字段但 `resolve()` 只按名称匹配。
2. 符号链接别名与断链/循环链接的记录（索引里部分处理，无原因记录）。
3. 无法明确分类的 ELF 保留为“不确定组件”（当前只有可执行/非可执行二分）。
4. sysroot 目标系统绝对路径映射。
5. 导入符号和版本信息辅助检查候选。

## 下一步计划

1. 接入参数级路径查询后端，向 `query_sink_paths` 提供真实证据。
2. 验证 CWE-78 的真实 sink 发现、路径查询和证据报告。
3. 按同一插件契约增加 CWE-134，再评估 CWE-190、CWE-606 所需的数值状态。
4. 按 `docs/03` 验证场景补充依赖检索实验：同名库冲突、断链和同内容库共享身份。

## 暂缓项

- 固件解包（binwalk 适配器）、压缩包输入。
- 缓冲区溢出/UAF/Double Free 等内存生命周期问题。
- Ghidra 接入、真实静态路径查询、更多 CWE 插件、污点状态扩展和报告生成。
