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
- `tests/20261012_02_PoC阶段_r01/`：fake OpenCode 端到端验证 PoC 阶段（run 级 poc-request/response/manifest、干净 poc/、cwd、skipped 分支、manifest `files` 交付物索引）；confirmed fixture（真实 evidenceID）通过证据门禁后做真实 OpenCode PoC 请求（vulnhunter 风格 8 小节报告 + 可运行验证脚本，命名参数化 `<functionID>.<CWE编号>.md`/`.py`）；最终产物在 `产物/group-6aeb5375a9c368ad/run-d4832cfc3a71/`，此前轮次归档在同级 `历史轮次/`；不执行样本。
