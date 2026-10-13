# 实验规范

实验用于验证模块设计和实现，不替代正式测试。

## 目录和命名

实验目录统一放在 `tests/` 下，格式为：

```text
YYYYMMDD_前两位序号_实验目的_rxx
```

规则如下：

- 日期放在最前，使用八位数字 `YYYYMMDD`。
- 实验数据必须来自 `data/`。
- 目录名只取实验数据目录序号的前两位。
- 实验目的使用简短中文名称。
- 尝试轮数从 `r01` 开始，之后按 `r02`、`r03` 递增。
- 每次改变实验思路或验证目标时，新建下一轮目录，不覆盖旧实验。
- 实验目录应保留说明、命令、输入数据和观察结果。
- Agent、Ghidra 和路径后端的运行产物统一放在对应实验目录的 `产物/` 下；临时目录只用于中间运行，不作为实验记录位置。
- 不修改 `data/` 中的原始实验数据。

当前实验：

- `tests/20261010_01_elf依赖检索_r01/`：使用 `data/01_simple_demo/` 验证 ELF 发现、根目标识别和依赖分组。
- `tests/20261012_01_覆盖门禁_r01/`：使用真实 `server` 联调产物和最小结构化输入验证覆盖门禁、证据引用、预算和恢复；不执行样本、不生成 PoC。
- `tests/20261012_02_PoC阶段_r01/`：fake OpenCode 端到端验证 PoC 阶段（run 级 poc-request/response/manifest、干净 poc/、cwd、skipped 分支、manifest `files` 交付物索引）；confirmed fixture（真实 evidenceID）通过证据门禁后做真实 OpenCode PoC 请求（vulnhunter 风格 8 小节报告 + 可运行验证脚本，命名参数化 `<functionID>.<CWE编号>.md`/`.py`）；最终产物在 `产物/group-6aeb5375a9c368ad/run-d4832cfc3a71/`，此前轮次归档在同级 `历史轮次/`；不执行样本。另验证 `--cwe` 缺省时默认依次运行全部支持的 CWE（每个 CWE 独立 run 目录、report 带 `cwe` 字段）。
- `tests/20261013_01_运行开销基线_r01/`：用 `data/01_simple_demo/server` 以 `--cwe all --poc` 做一次完整运行，记录时间与 token 开销基线（`report.json` 的 `elapsedSeconds`/`usage`、每轮 `analysis.log`）；配套验证日志监视能力。
- `tests/20261013_02_并发验证_r01/`：`--cwe all --poc --workers 2` 验证并发执行的时间收益与结果一致性（对比串行基线 1378.3s）；第 1 轮暴露两个缺陷并修复：opencode standalone 会话同时启动的竞态（`Standalone server exited before reporting readiness`，加退避重试）、模型 propagationMap 键名漂移（`from`/`to` 别名容忍 + report-schema 明确键名契约）；修复后复跑核对逐 CWE 结果。
- `tests/20261014_01_漏报优先验证_r01/`：`--cwe CWE-78 --poc --confirmation recall` 验证漏报优先策略下 demo server 的 ground-truth 命令注入链（remoteExec→doSystem→popen）能否产出 confirmed finding 并进入 PoC 阶段（对照此前 12 个 run 全 0 confirmed）。结果：根因定位为证据核验层 binaryID 强相等错杀（Ghidra 只加载 root binary，跨二进制 finding 证据全带 server 的 binaryID）叠加 invalid_references 全局连坐；修复后真实重跑 run-3c27fd0aa510 链 A doSystem@0x401ba2 confirmed（reference-chain）并首次端到端产出 PoC 交付物；对照用户本地 docker vulnhuntr 报告（server 8 vulns，VULN-001/002=链 A/B）确认差距在门禁不在目标。
- `tests/20261014_02_搜索范围扩大验证_r01/`：验证「前期扩大搜索范围、后期 agent 判断降 FP」的两阶段提示词——`attack-surface.md` 重写为两阶段（全组危险 sink 枚举宁滥勿缺 → 按 CWE 规则收紧），6 个 CWE 模板「起点」节去 vh 化。结果（run-3939894a5123）：链 A doSystem→popen confirmed（reference-chain）+ PoC 不回退；unresolved 从 5 项扩出依赖库侧候选（链 B auth_verify→auth_log echo→system 完整 ELF 证据、硬编码 token "SGC2023_SECRET"=vh VULN-005、server 命令类 sink 覆盖清单），main mkdir system 仍 rejected（反证不变）。第 1 轮 provider 超时中断（run-d50f0edc4b76 失败前已产出高质量依赖库枚举）；重试成功。
- `tests/20261014_03_阶段M逐链判定验证_r01/`：验证 docs/18 执行者分层（阶段 M 机械物化候选链 → 阶段 J 逐链判定+驳斥清单）的真实运行效果，对比基线 run-3939894a5123。结果（run-6950c30b7959，一次通过）：阶段 M 4 条候选链（4.3s）注入提示词后全部被模型逐条判定并写进 finding 的 chainIDs——链 A doSystem→popen confirmed+PoC 不回退；main mkdir system 被驳斥清单 R1/R4 rejected（反证：常量 './files/recv' + 启动阶段先于 accept）；链 B auth_log system 首次真实运行 confirmed（medium，reference-chain）+PoC，limitations 按先验条款披露依赖库先验依据与未验证跨库跳。findings 2→3、证据完整性 OK、总耗时 315s。
- `tests/20261014_04_CWE召回验证_r01/`：补齐 CWE-134/190/415/416/606 的召回验证——手工反汇编确认 demo（data/01_simple_demo）不含这五类真洞后，为每类建含真洞的 socket 服务器夹具（`data/03_cwe_fixtures/`，源码即 ground truth，容器 gcc 编译 x86-64 PIE + DWARF）。结果：5/5 夹具洞全部 confirmed（reference-chain）+ PoC，夹具中非洞调用点被正确 rejected；三轮跑出三个真实缺陷并修复——①任务 D 多二进制改造的 paths KeyError（r01 PluginMcpTests 回归）②模型 sourceParams/sinkParams 对象数组写法连错两轮（`_coerce_params` 容错 + 模板契约明确）③GhidraMCP 会话波动（evidence-rules 韧性条款兜底）。逐 CWE 结果与 run 号见该目录 说明.md。
- `tests/20261014_05_多二进制Ghidra验证_r01/`：任务 D（多二进制 GhidraMCP 会话）在 demo 上的端到端验证。结果（run-722dbd194d9d）：mcp_servers = ghidra + ghidra-368d7931 + ghidra-ee2406a4 + paths 四会话；链 B（libauth auth_log→system@0x1014a3）以 libauth 会话 7 条机械证据 + 2 条 paths confirmed（此前依赖基模先验），链 A 不回退、main mkdir rejected；证据引用完整性 OK。跑出并修复一个审计脚本缺陷：check_evidence_integrity.py 漏 glob 多会话 ghidra-*.jsonl 日志。PoC 阶段因 api.deepseek.com DNS 故障（ENOTFOUND）失败，已 --resume 重跑 PoC。详见该目录 说明.md。
