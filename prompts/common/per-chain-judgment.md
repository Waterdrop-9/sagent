# 逐链判定协议（阶段 J）

用户提示词末尾会附「候选链摘要」：阶段 M 机械物化的 (source → hops → sink) 候选链
JSON。每一条候选链都必须按本协议逐一给出判定，不允许跳过或合并到笼统叙述里。

## 判定流程

对每条候选链，依次执行：

1. **判定**：结合工具证据给出 verdict：
   - `confirmed`：确认标准见 confirmation-policy.md；只有引用链级证据时 confirmationBasis=reference-chain。
   - `rejected`：有具体反证（见下方驳斥清单），写进 finding 的 limitations。
   - `unresolved`：证据不足，无法确认也无法驳斥；写入 unresolved，说明缺哪一类证据。
2. **驳斥清单（仅 confirmed 候选必须逐项通过）**：在给出 confirmed 之前，先逐项尝试证伪，
   每项最多做一次补充查询，不得为凑数反复查：
   - **R1 source 可控性**：source 数据真的来自攻击者可控输入（recv/read/fgets 等），
     还是常量/固定文件/启动参数？main 启动阶段执行、参数为字面量的候选应 rejected。
   - **R2 逐跳传播**：source 到 sink 的每一跳调用点都有反汇编证据，不是猜测。
   - **R3 清洗约束**：路径上存在长度截断、白名单校验、字符过滤吗？存在有效约束应 rejected 或降级。
   - **R4 构造与影响**：攻击者能否控制 sink 参数的内容/格式（%s 注入、整数溢出导致尺寸错误等）。
3. **写报告**：confirmed finding 在 limitations 里写明"驳斥清单 R1-R4 已逐项核验"及结论；
   rejected finding 写具体反证；unresolved 写缺什么证据。

## 先验判定条款（依赖库）

- 常见库（libc/libm/liblog/libauth 等）的内部语义可以借助模型先验知识判定，
  但必须同时有机械证据支撑（导入表符号、PLT 跳转、反汇编调用点、strings 常量）。
- 使用先验知识时，finding 的 limitations 必须写明"依赖库语义依据模型先验知识"，
  不得伪造不存在的 evidenceID。
- 自定义库（非白名单、无法确认语义的库）一律 unresolved，禁止靠猜 confirmed。

## 效率约束

- 每条链的判定顺序：先驳斥（便宜、快）后确认；驳不掉再查证据支持。
- 只有结论会写进报告的动作才值得做：不要为了"覆盖全面"而重复查询同一地址。
- 摘要中已截断的链（摘要末尾有截断标记）不可判 confirmed；证据不足记 unresolved。
