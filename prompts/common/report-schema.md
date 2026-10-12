# 报告结构

最终只输出一个 JSON 对象，不要复制完整工具结果：

```json
{
  "findings": [],
  "unresolved": [],
  "coverage": {
    "attackSurfaces": [],
    "functionModels": []
  }
}
```

finding 至少包含 cwe、binaryID、functionID、source、sink、sinkParams、path（紧凑地址/边摘要）、evidenceIDs、status、confidence、limitations。最终 finding 的 status 只能是 confirmed 或 rejected；证据不足的候选不能放入 findings，必须写入 unresolved。confidence 是 low/medium/high。当前路径后端仅返回函数内定义依赖时，不能输出 confirmed finding。

attackSurfaces 每项包含 surfaceID、category、functionID、status（open/checked/rejected/unknown）、evidenceIDs、reason。无法检查的攻击面必须写 unknown 和原因；不能用空数组表示全部覆盖。

functionModels 每项使用函数模型规则中的字段；source/sink 角色与 finding 状态分别记录。sinkParams 是从 0 开始的参数编号。外部 sink 的 functionID 使用路径工具返回的 sink.functionID；无法确定时保留内部模型状态并写入 unresolved，不生成最终 finding。同一函数只记录一个模型，可有多个 roles。

unresolved 每项是原因字符串，或包含 reason 的对象。每类数组最多 128 项，报告最多 512 KiB。达到预算时保留高价值候选，并在 unresolved 写 budget_exhausted 和遗漏范围。

工具响应末尾提供本地 evidenceID 时，直接引用该 ID；不要自行编造工具证据 ID。pathToolResult 和 coverage 自述不代替实际工具执行记录。本地程序计算最终 coverageLedger 和 analysisStatus；不要生成这些字段。`analysisStatus` 是整轮分析状态，不是 finding.status。
