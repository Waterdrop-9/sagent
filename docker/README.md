# Sagent Docker 镜像构建

镜像内容只含运行时最小集合（用户约束 m05985）：Ghidra 12.0.4、GhidraMCP 扩展 jar、
离线 Python venv（mcp/pyghidra/ghidra_mcp/Jpype1）、src/、prompts/、entrypoint。
不含 docs/tests/scripts 等开发文件。

## 前置条件（仅构建机需要，部署机只需要 docker）

- 基础镜像 `vulnhunter:v2.0.2`（本地已有，含 opencode/node/gcc 与 angr 9.3.2）
- Ghidra 12.0.4 安装目录（与 pyghidra 3.1.0 匹配；11.x 不兼容）
- `GhidraMCP.jar`（GhidraMCP 扩展 jar，构建方式见 部署与使用手册 §3，
  或复用已验证的 jar：含 `com.lauriewired.ghidramcp.headless.HeadlessBackend`）
- 离线 wheel 集合（一次打包，见下）

## 构建步骤

```bash
# 1. 准备离线 wheelhouse（有网的机器执行一次）：
python3 -m pip download --dest wheelhouse \
  --platform manylinux2014_x86_64 --python-version 312 --only-binary=:all: \
  "mcp>=1.30,<2" requests pyghidra
# 另需 ghidra_mcp 的 wheel（不在 PyPI）：从 uv 缓存
# ~/.cache/uv/sdists-v9/**/ghidra_mcp-2.0.0-py3-none-any.whl 复制进 wheelhouse

# 2. 组装构建上下文：
mkdir buildctx && cd buildctx
cp -R /path/to/ghidra_12.0.4_PUBLIC .
cp /path/to/GhidraMCP.jar .
python3 -m venv sagent-venv && ./sagent-venv/bin/pip install \
  --no-index --find-links wheelhouse -r <(echo -e 'mcp>=1.30,<2\nrequests\npyghidra\nghidra_mcp')
cp -R ../src ../prompts ../docker/Dockerfile ../docker/entrypoint.sh .

# 3. 构建（amd64 平台警告可忽略——本机即为 arm64 宿主上的模拟运行基线）：
docker build -t sagent:r1 .

# 4.（可选）导出给部署机：
docker save sagent:r1 | gzip > sagent-r1.tar.gz
```

## 部署与运行

```bash
docker load < sagent-r1.tar.gz
docker run --rm -v "$PWD:/work" sagent:r1 \
  --target data/xxx/server --dependency-root data/xxx \
  --goal "..." --cwe CWE-78 --poc --output /work/out
```

`/work` 即宿主机工作目录：config.toml 放 `/work/config.toml`，产物目录也挂在其下。

## 本地模型

镜像内 opencode provider 的 `base_url` 取自 config.toml，直接指向宿主机上的
OpenAI-compatible 服务即可（macOS 用 `http://host.docker.internal:11434/v1`，
Linux 用 `--network host` + `http://127.0.0.1:11434/v1`），无需改动镜像。

## 环境变量（entrypoint.sh 已预设）

| 变量 | 值 | 说明 |
| --- | --- | --- |
| GHIDRA_INSTALL_DIR | /opt/ghidra_12.0.4_PUBLIC | Ghidra 安装目录 |
| GHIDRA_MCP_COMMAND | /opt/sagent-venv/bin/ghidra-mcp | MCP 直启命令（跳过 uvx 联网解析） |
| GHIDRA_MCP_EXTENSION_JAR | /opt/sagent/GhidraMCP.jar | 扩展 jar（headless 必需） |
| AGENT_PATH_BACKEND_PYTHON | /usr/bin/python3 | paths 后端（基础镜像自带 angr） |
