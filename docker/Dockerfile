# sagent 运行时镜像：Ghidra 12.0.4 + GhidraMCP 扩展 jar + 离线 venv + opencode。
# 基础镜像 vulnhunter:v2.0.2 自带 opencode/node/gcc 与 angr 9.3.2（paths 后端）；
# 其余全部离线注入。Ghidra/扩展 jar/venv 与宿主实测环境同版本。
FROM vulnhunter:v2.0.2

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC \
    GHIDRA_MCP_COMMAND="/opt/sagent-venv/bin/ghidra-mcp" \
    GHIDRA_MCP_EXTENSION_JAR=/opt/sagent/GhidraMCP.jar \
    AGENT_PATH_BACKEND_PYTHON=/usr/bin/python3 \
    PYTHONPATH=/opt/sagent/src

# Ghidra 12.0.4（与宿主实测版本一致）
COPY ghidra_12.0.4_PUBLIC /opt/ghidra_12.0.4_PUBLIC

# GhidraMCP 扩展 jar（com.lauriewired.ghidramcp，headless 后端入口）
COPY GhidraMCP.jar /opt/sagent/GhidraMCP.jar

# 离线 Python 环境（mcp/pyghidra/ghidra_mcp/Jpype1）与运行时源码
COPY sagent-venv /opt/sagent-venv
COPY src /opt/sagent/src
COPY prompts /opt/sagent/prompts

COPY entrypoint.sh /opt/sagent/entrypoint.sh
RUN chmod +x /opt/sagent/entrypoint.sh

WORKDIR /work
ENTRYPOINT ["/opt/sagent/entrypoint.sh"]
