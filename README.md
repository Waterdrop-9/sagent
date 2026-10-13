# Sagent

面向 C/C++ 编译产生的 ELF 与固件样本的防御性静态二进制分析工具：以证据为中心，
对 CWE-78（命令注入）、CWE-134（格式串）、CWE-190（整数回绕）、CWE-415（Double
Free）、CWE-416（Use-After-Free）、CWE-606（循环条件不检）六个漏洞类别产出可追溯的
风险链、确认/拒绝判定与审计 PoC 材料。结果服务人工审计，不自动执行样本。

## 快速开始

环境准备、配置、运行方式见 [部署与使用手册](部署与使用手册.md)。三步概览：

```bash
# 1. 准备配置（config.toml：API key / base_url / 模型）
cp config.toml.example config.toml

# 2. 单样本分析（Ghidra + 路径查询 + Agent 阶段 M/J）
PYTHONPATH=src python3 -m agent.cli --target <ELF路径> --cwe CWE-78 \
    --goal "分析该二进制中的 CWE-78 漏洞" --output tests/<轮次>/产物

# 3. 回归测试
PYTHONPATH=src python3 -m pytest tests/ -q
```

也可以全程用 Docker 部署。**部署机只需 Docker + 离线镜像包**，一键脚本
`deploy.sh` 自动完成加载镜像→生成配置→跑分析→打印结论：

```bash
bash deploy.sh /path/to/sagent-minimal.tar.gz   # 交互式
# 或环境变量全自动：SAGENT_MODEL=deepseek DEEPSEEK_API_KEY=sk-xxx \
#   SAGENT_TARGET=/path/to/server SAGENT_MODE=all bash deploy.sh
```

完整的分平台手把手教程见 [部署教程](部署教程.md)（macOS/Linux/Windows、云端 DeepSeek
与本地 ollama 两种模型接入、批量运行、排错手册）。

## 文档导航

- [部署教程](部署教程.md)：**从镜像包到批量运行的分平台手把手教程**（含一键脚本 deploy.sh）。
- [设计总纲](设计总纲.md)：目标、当前范围、分析对象、静态分析能力、安全边界与后续方向（含未来可改动方向清单）。
- [部署与使用手册](部署与使用手册.md)：安装、配置、Ghidra MCP、多二进制会话、目录布局、断点续跑。
- [术语表](术语表.md)：样本、分析组、证据、发现项等领域概念。
- [GUIDELINE](GUIDELINE.md)：工程规约（最简实现、接口设计、注释、日志、错误处理、测试）。
- [PROGRESS](PROGRESS.md)：改造进度账目；[EXPERIMENT](EXPERIMENT.md)：实验轮次账目。
- `docs/`：各模块设计与逐轮实验复盘（`docs/文档索引.md` 提供完整目录）。
- `data/03_cwe_fixtures/`：五个内置真洞的 ground-truth 夹具（源码即标准答案），用于召回验证。

## 仓库布局

```text
src/agent/     Agent 阶段（M 风险链 / J 判定 / PoC）、报告与证据核验、运行时适配
src/elf.py     ELF 解析与依赖闭包、分析组构建（纯 Python，无外部依赖）
prompts/       六个 CWE 模板与公共规则（攻击面、确认门禁、证据规则、报告 schema）
scripts/       路径后端健康检查、证据完整性核验
data/          demo 样本与 ground-truth 夹具
docs/          模块设计文档与实验复盘
tests/         回归测试与实验产物（不入库）
```
