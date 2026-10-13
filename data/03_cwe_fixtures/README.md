# 03_cwe_fixtures — CWE 召回 ground-truth 夹具

每个 `src/*.c` 是一个独立的小型 socket 服务器，**源码即 ground truth**：每份恰好内置一个
对应 CWE 的真实漏洞，用于验证 Sagent 五个已支持 CWE 插件的召回能力
（阶段 M 候选链物化 → 阶段 J 逐链判定 → confirmed + PoC）。

## 构建

宿主为 arm64 mac，使用本地 `vulnhunter:v2.0.2` 镜像（内含 Linux x86-64 gcc 工具链）编译：

```bash
cd data/03_cwe_fixtures
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
    vulnhunter:v2.0.2 gcc -g -O0 -o bin/fixture_134 src/fixture_134.c
# 其余四个同理（fixture_190 / fixture_415 / fixture_416 / fixture_606）
```

产物为带 DWARF 调试信息的 Linux x86-64 ELF，可用 `readelf/objdump` 反汇编。

## Ground truth 表

| 夹具 | CWE | 漏洞 | sink | 监听端口 | 触发方式 | 期望判定 |
|---|---|---|---|---|---|---|
| fixture_134.c | CWE-134 | 未校验格式字符串 | `printf(buf)` | 13400 | 发送含 `%x/%n` 的字符串 | confirmed |
| fixture_190.c | CWE-190 | 整数溢出（len+4 回绕） | `malloc(len+4)` 后按 len 写入 | 19000 | 发送 4 字节 `0xFFFFFFFC` 长度 | confirmed |
| fixture_415.c | CWE-415 | Double Free（错误路径+无条件） | 同路径两次 `free(p)` | 41500 | 发送以 `'x'` 开头的数据 | confirmed |
| fixture_416.c | CWE-416 | Use-After-Free | `free(p)` 后 `send(...,p,...)` | 41600 | 发送任意数据 | confirmed |
| fixture_606.c | CWE-606 | 未校验输入控制循环 | `for (i=0; i<count; i++) data[i]=...` | 60600 | 发送 4 字节 count（>16） | confirmed |

## 使用

每个 CWE 用对应夹具串行验证（避开 Ghidra MCP 并发端口冲突）：

```bash
PYTHONPATH=src python3 -m agent.cli \
    --target data/03_cwe_fixtures/bin/fixture_134 \
    --cwe CWE-134 --poc --confirmation recall \
    --goal "分析 fixture_134 二进制，确认 CWE-134 漏洞并给出证据" \
    --output tests/<轮次>/产物
```

验证标准：对应 CWE 至少 1 条 confirmed finding 且 PoC 生成。
