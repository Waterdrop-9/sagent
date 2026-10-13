#!/bin/sh
# sagent 容器入口：只设置运行时环境，其余全部交给 agent.cli。
# 用户通过 -v 挂载 /work（内含 config.toml 与待分析数据），
# 本地模型把 base_url 指向宿主机（如 http://host.docker.internal:11434/v1）。
set -eu

export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC
export GHIDRA_MCP_COMMAND="/opt/sagent-venv/bin/ghidra-mcp"
export GHIDRA_MCP_EXTENSION_JAR=/opt/sagent/GhidraMCP.jar
# paths 后端需要 angr：基础镜像的 /usr/bin/python3 自带 angr 9.3.2
export AGENT_PATH_BACKEND_PYTHON=/usr/bin/python3
export PYTHONPATH=/opt/sagent/src

cd /work
exec /opt/sagent-venv/bin/python -m agent.cli "$@"
