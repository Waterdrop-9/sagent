# Sagent Docker 镜像构建与部署

镜像内容 = 反编译分析所需的最小运行集合：Ghidra 12.0.4、GhidraMCP 扩展 jar、
python venv（ghidra-mcp）、系统 python + angr（paths 后端）、node 26 + opencode 2.0.26、
src/、prompts/、entrypoint。不含编译器、调试器、文档等无关内容。

**部署机只需要 docker**（`docker load` + `docker run`，全程离线）。

## 两条构建路线

### 路线 A（本机已验证）：删减 + 扁平化，`docker/slim.sh`

从「已含 sagent 运行时的重型基础镜像」裁出最小镜像，**全程不需要网络**：

```bash
SRC_IMAGE=sagent:r1 OUT_IMAGE=sagent:minimal bash docker/slim.sh
docker save sagent:minimal | gzip > sagent-minimal.tar.gz
```

关键点（踩过的坑，勿改）：

1. **分层镜像里 `rm` 不会减小 `docker save` 体积**——被删文件仍留在底层里。
   必须 `docker export` → `docker import` 扁平化成单层，tar 才真正变小
   （实测 10.7G → 6.27G 镜像、3.9G → 2.2G tar.gz）。
2. **`docker import` 必须带 `--platform linux/amd64`**：不带会把镜像标成宿主架构
   （Apple Silicon 上是 arm64），之后按 amd64 运行会报「找不到镜像」。
3. import 会丢失镜像配置，脚本已用 `--change` 逐条恢复
   ENV/ENTRYPOINT/WORKDIR/VOLUME/EXPOSE。
4. 维护容器必须 `--entrypoint bash`：镜像自带 ENTRYPOINT，直接 `docker run … sleep infinity`
   会被当成 agent 参数并以 exit 2 退出。

### 路线 B（理想态，未在本机验证）：纯净基座 `docker/Dockerfile`

`FROM ubuntu:24.04` 白手起家，产物更纯（不含 vh 层）。前置条件：构建机可稳定出网
（apt 拉 JRE/python 约 50MB，再拉 nodejs.org + npm registry）。

```bash
bash scripts/build_wheelhouse.sh wheels    # 离线 wheelhouse（angr 依赖链需版本钉扎）
mkdir buildctx && cd buildctx
cp -R /path/to/ghidra_12.0.4_PUBLIC /path/to/GhidraMCP.jar . && mv /path/to/wheels wheels
cp -R <repo>/src <repo>/prompts <repo>/docker/entrypoint.sh <repo>/docker/Dockerfile .
docker build --platform linux/amd64 -t sagent:minimal .
```

本机失败原因记录：apt 出口只有 ~44 kB/s 且频繁 `502 Bad Gateway`
（`security.ubuntu.com` 的 openjdk 包），换阿里云 HTTP 源后 apt 更新虽快，
容器仍异常退出。故本机交付走路线 A。

Dockerfile 中的两个必要修正（纯净基座必需）：`libatomic1`
（node 26 x64 二进制依赖，缺失时报 `cannot open shared object file: libatomic.so.1`）、
opencode 装完后的 `/usr/local/bin/opencode` 软链（npm 全局 bin 在
`/usr/local/lib/nodejs/bin`，不在 PATH 上）。

## 网络与代理（重要）

镜像运行需要容器能访问 LLM API（或本地模型）。macOS Docker Desktop 的代理模式若指向
已失效的本地代理（如 `manual → 127.0.0.1:7890`），容器内全部 HTTPS 会 TLS 失败
（`SSL_ERROR_SYSCALL`）。修复：Docker Desktop 设置 → Resources → Proxies 改为
`System proxy`（跟随 macOS 系统代理，实测可用），或改 `Manual` 指向可用的代理。

## 部署与运行

一键脚本（推荐）：仓库根目录 `deploy.sh`，交互式或环境变量全自动，自动完成
加载镜像→生成 config.toml→定位目标→跑分析→打印结论。分平台手把手教程见
仓库根 [部署教程.md](../部署教程.md)。

手动等价命令：

```bash
docker load < sagent-minimal.tar.gz
docker run --rm -v "$PWD:/work" sagent:minimal \
  --target data/xxx/server --dependency-root data/xxx \
  --goal "..." --cwe CWE-78 --poc --output /work/out
```

`/work` 即宿主机工作目录：config.toml 放 `/work/config.toml`，产物目录也挂在其下。

## 本地模型

镜像内 opencode provider 的 `base_url` 取自 config.toml，直接指向宿主机上的
OpenAI-compatible 服务即可（macOS 用 `http://host.docker.internal:11434/v1`，
Linux 用 `--network host` + `http://127.0.0.1:11434/v1`），无需改动镜像。

## 环境变量（镜像内已预设）

| 变量 | 值 | 说明 |
| --- | --- | --- |
| GHIDRA_INSTALL_DIR | /opt/ghidra_12.0.4_PUBLIC | Ghidra 安装目录 |
| GHIDRA_MCP_COMMAND | /opt/sagent-venv/bin/ghidra-mcp | MCP 直启命令（跳过 uvx 联网解析） |
| GHIDRA_MCP_EXTENSION_JAR | /opt/sagent/GhidraMCP.jar | 扩展 jar（headless 必需） |
| AGENT_PATH_BACKEND_PYTHON | /usr/bin/python3 | paths 后端（系统 python 自带 angr 9.3.2） |

## 体积参考（实测）

| 产物 | 体积 |
| --- | --- |
| `sagent:r1`（vh 系基础镜像派生，分层） | 10.7G |
| `sagent:minimal`（删减 + 扁平化） | 6.27G |
| `sagent-minimal.tar.gz`（离线交付件） | 2.2G |

剩余大头都是不可再删的运行时：Ghidra 12.0.4 ~850M、angr site-packages ~1.1G、
opencode(node 包) 821M、node 225M、JRE 与 glibc 等系统库。
若要更小，只能接受功能裁剪（例如去掉 angr 则失去 paths 后端）。

## 验证记录

`tests/20261014_09_docker最小镜像验证_r01/`：`sagent:minimal` 容器内端到端实跑
（本地 config.toml + DeepSeek API + Ghidra 三会话 + 阶段 M/J + PoC），
`run-11113690007d`：confirmed 2（`0x401380`、`0x1010b0`，各 8/9 条证据）、
rejected 1、PoC 4 文件、159.2s、$0.0437——与 vh 系镜像（`sagent:r1`）结果一致。
