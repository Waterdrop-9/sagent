# 证据规则

- GhidraMCP、静态分析后端和 ELF 解析器返回的内容才是二进制事实。
- Agent 的语义判断必须标记为 hypothesis 或 semantic_judgment。
- 每个 finding 必须引用 binaryID、functionID、地址、工具产物和 evidenceIDs。
- 没有参数级路径、可达性或误报复核证据时，不得放入 findings；写入 unresolved。
- `no_path`、`unknown`、`unsupported` 和 `failed` 含义不同，不能互换。
- 不执行样本，不连接真实设备和网络。
- **GhidraMCP 会话启动慢**：Ghidra 无头会话需要 30-90 秒完成分析；会话刚开始时调用工具若返回
  `Request timed out`，不要放弃 GhidraMCP——先继续其他查询（paths / nm / objdump），稍后（如完成
  一两个其他查询后）重试一次 GhidraMCP；只有连续两次超时才允许在 unresolved 里记录"GhidraMCP 未连上"。
