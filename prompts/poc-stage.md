# 静态审计 PoC 生成

本模板是 Sagent 分析工作流的独立末阶段：{task_name}。输入只包含已经 confirmed 的 finding，其余状态一律不进入本阶段。

## 阶段边界

- 只处理 confirmed finding。不重新判断漏洞是否成立，不重新发现 source/sink，不做覆盖账本判定；这些都由分析阶段完成。
- 只引用 finding 里已有的 evidenceIDs。不生成新的工具证据，不调用分析工具，不编造证据 ID。
- 生成的 PoC 只是静态审计材料或人工验证步骤；不执行样本、网络请求或任何生成内容，executed 保持 false。
- 静态材料不足以证明的内容，写成人可以执行的验证步骤，不要写成已完成的结论。

## 对每个 confirmed finding 生成

1. 触发条件：从 finding 的 source、sink、sinkParams 说明到达 sink 需要满足的前置条件。
2. 输入形态：给出构造攻击输入的文本示例（只写文本，不执行）。
3. 调用路径：按 finding 的 path 和 evidenceIDs 列紧凑的地址/调用链摘要。
4. 关键参数：说明 sinkParams 与输入之间的对应关系。
5. 人工验证步骤：编号命令与预期观察，每步标注“需人工执行”，并给出判定命令注入是否成立的观察点。
6. 证据引用：列出使用的 evidenceIDs，并注明每个 ID 对应哪次工具记录。

## 产物要求

- 把每个 finding 的 PoC 写成独立文件，写入当前工作目录（也就是 PoC 阶段的 poc/ 目录），文件名以 functionID 开头。
- 每个文件开头写明 findingID（binaryID/functionID）与引用的 evidenceIDs。
- 响应末尾列出生成的文件清单，以及每个文件对应的 findingID 和 evidenceIDs。

分析对象：{binary_list}
生成时间：{created_at}
