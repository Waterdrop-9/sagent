# PoC 生成（静态审计材料）

本模板是 Sagent 分析工作流的独立末阶段：{task_name}。输入只包含已经 confirmed 的 finding，其余状态一律不进入本阶段。

产物目录（PoC 工作目录）：{output_dir}

## 阶段边界

- 只处理 confirmed finding。不重新判断漏洞是否成立，不重新发现 source/sink，不做覆盖账本判定；这些都由分析阶段完成。
- 只引用 finding 里已有的 evidenceIDs。不生成新的工具证据，不调用分析工具，不编造证据 ID。
- 生成的 PoC 只是静态审计材料或人工验证步骤；不执行样本、网络请求或任何生成内容，executed 保持 false。
- 静态材料不足以证明的内容，写成人可以执行的验证步骤，不要写成已完成的结论。

## 对每个 confirmed finding 生成一份报告

报告采用 vulnhunter 漏洞报告（VULN-*.md）的叙事结构，但内容只从 finding 与已有 evidenceIDs 复述，不引入新结论：

1. 基本信息：触发函数（名称与地址）、漏洞类型、sink 调用点地址、置信度、是否需认证（全部从 finding 复述）。
2. 触发条件（利用条件）：说明到达 sink 需要满足的前置条件——入口在什么 opcode/接口上、沿途有哪些过滤或校验、长度限制等，均以 finding 为准。
3. 输入形态（触发示例 / PoC 骨架）：给出构造攻击输入的文本示例——协议入口、操作码、注入的 shell 元字符或路径串、字节形态（如 "\x00\x10"+命令）。只写文本，不执行。
4. 调用路径：按 finding 的 path 与 evidenceIDs，列自下而上的完整调用链，每一跳给函数名与地址，sink 处标出调用点地址与参数形态。
5. 关键参数：说明 sinkParams 与输入之间的对应关系（哪个参数承载输入）。
6. 人工验证步骤：编号命令与预期观察，每步标注"需人工执行"，给出判定漏洞是否成立的观察点。
7. 证据引用：每条结论标注使用的 evidenceID 及对应工具记录；不引用 finding 之外的证据。
8. 限制与不确定性：诚实说明静态材料无法证明的部分（反编译局限、跨库未覆盖、未验证的环节）。

## 产物要求

- 每个 finding 一份报告文件，写入当前工作目录（也就是 PoC 阶段的 poc/ 目录），文件名以 functionID 开头，例如 `<functionID>.CWE-78.poc.md`。
- poc/ 目录里只写 PoC 报告文件，不写脚本、笔记、日志等其它文件，不创建子目录。
- 每个文件开头写明 findingID（binaryID/functionID）与引用的 evidenceIDs。
- 响应末尾列出生成的文件清单，以及每个文件对应的 findingID 和 evidenceIDs。

分析对象：{binary_list}
生成时间：{created_at}
