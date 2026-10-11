# 报告结构

最终输出只包含 JSON：

```json
{
  "findings": [],
  "unresolved": [],
  "coverage": {}
}
```

finding 至少包含 `cwe`、`binaryID`、`functionID`、`source`、`sink`、`path`、`evidenceIDs`、`status`、`confidence` 和 `limitations`。
