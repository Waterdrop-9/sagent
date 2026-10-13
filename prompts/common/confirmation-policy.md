# 确认标准策略（confirmation policy）

本文件定义 confirmed finding 的两种确认依据与阶段切换规则。每次运行由 `--confirmation {recall,precision}` 选择其中一节，并作为系统提示词的最后一节注入；该节覆盖 report-schema 与各 CWE 模板中更严格的默认表述。

## 漏报优先模式（recall）

当前项目处于漏报优先阶段：宁可多报、不可漏报。确认标准放宽为两种依据，confirmed finding 必须携带 `confirmationBasis` 字段：

- `taint-path`（污点级）：source 到 sink 的整条传播链有污点级证据——sink 的每个敏感参数的路径查询为 path_found，且链上各跳的参数关系均有工具证据。
- `reference-chain`（引用链级）：以下条件**全部**满足即可输出 confirmed（confirmationBasis=reference-chain）：
  1. source 函数（recv/read/argv/env/gets 等外部输入点）与 sink 函数（popen/system/exec* 等）在该二进制的导入表中或反汇编中有证据；
  2. source→…→sink 的每一跳调用点有反汇编或交叉引用证据（调用指令地址、目标函数）；
  3. sink 的每个敏感参数在 sink 函数内有定义依赖证据（path_found 即可，不要求跨函数）；
  4. 攻击面（网络监听端口、协议分派表、文件/命令来源等）有证据支撑外部可达性；
  5. limitations 必须写明"跨函数污点未经污点级验证，确认依据为引用链（reference-chain）"。

调用方写入即为外部数据来源：recv/memcpy/fgets/read 等函数对其缓冲参数的写入是隐式的（反汇编中不出现写指令）。不得因"反汇编中无写引用指令"而把缓冲判为常量；此时应列出"缓冲由 recv/memcpy 写入"作为 source 证据。

报告结构变化：finding 增加可选字段 `confirmationBasis`（taint-path | reference-chain）；污点级依据可省略该字段。证据不足、连引用链级条件都不满足的候选，仍然写入 unresolved。

## 降误报模式（precision）

当前任务处于降误报阶段：confirmed 只接受污点级证据，引用链级确认一律降级。

- confirmed finding 的 confirmationBasis 只能是 taint-path；引用链级证据只能支撑 unresolved 项（写明 reason 与 evidenceIDs），不得输出 confirmed。
- 路径后端仅返回函数内定义依赖链时，跨函数 source→sink 不满足污点级标准，不能输出 confirmed finding。
- 自定义 wrapper 必须由静态事实确认参数、返回值或调用点关系后才能进入 confirmed 状态（同 source-sink-model）。
- 运行时硬门禁会执行同样的降级：confirmationBasis=reference-chain 的 finding 会被移入 unresolved，因此不要依赖模型自觉，按上述标准输出。
