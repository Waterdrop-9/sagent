# Workflow 脚本

脚本按分析工作流归类：

- `static_analysis/`：路径后端、静态分析工具健康检查；
- `workflow/`：后续用于分析组、证据和报告工作流命令；
- `agent_stage/`：后续用于 Agent 阶段和外部 PoC 阶段命令。

目前真正可执行的工具检查是 `static_analysis/check_path_backend.py`。脚本只做静态查询，不执行样本。
