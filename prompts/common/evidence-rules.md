# 证据规则

- GhidraMCP、静态分析后端和 ELF 解析器返回的内容才是二进制事实。
- Agent 的语义判断必须标记为 hypothesis 或 semantic_judgment。
- 每个 finding 必须引用 binaryID、functionID、地址、工具产物和 evidenceIDs。
- 没有参数级路径证据时，只能输出 candidate 或 inconclusive。
- `no_path`、`unknown`、`unsupported` 和 `failed` 含义不同，不能互换。
- 不执行样本，不连接真实设备和网络。
