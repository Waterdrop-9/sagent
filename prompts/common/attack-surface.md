# 攻击面侦查规则（两阶段：先扩大搜索，再判断降误报）

先确认程序、架构和分析组，再按风险查询导入、导出、函数、字符串、调用关系和交叉引用。

至少检查：网络服务、IPC、命令行、环境变量、配置和设备节点、动态加载、认证和权限边界。危险 API 只能形成候选攻击面；需要调用点、参数和可达性证据才能确认。

## 第一阶段：全组危险 sink 枚举（静态搜索，宁滥勿缺）

分析组 = root 二进制 + 全部依赖库。本阶段目标是把可疑面**全部列出来**，不允许以"与本 CWE 无关"或"证据不足"为由跳过枚举：

1. **root 二进制用 GhidraMCP**：枚举所有危险调用点——命令执行（`system`/`popen`/`exec*`）、文件操作（`fopen`/`fwrite`/`unlink`）、字符串/内存（`strcpy`/`strcat`/`sprintf`/`memcpy`）、认证与凭据（硬编码常量、token 比较）等，逐项记录地址与所在函数，引用 evidenceIDs。
2. **依赖库**：有专属 GhidraMCP 会话的组件（见「Ghidra MCP 会话映射」，会话名 `ghidra-<binaryID前8位>`）用该会话枚举危险调用点并引用 evidenceIDs；没有专属会话的库用 bash 里的 ELF 工具枚举：`nm -D` 查导出符号、`objdump -d` 查危险调用点、`strings` 查硬编码串。这些命令不产生 evidenceID——候选记入 `unresolved`（注明证据来源为本地 ELF 解析与地址），不得写进 findings。
3. 每个候选给出：binaryID/文件名、函数与地址、sink 类型、初步可达性线索（谁调用、是否在网络链路上）。全组枚举结果进入 `coverage.functionModels`（有 evidenceID 的）与 `unresolved`（lib 侧/无 evidenceID 的），**不允许漏列**。

## 第二阶段：agent 判断（收紧降误报）

按本 CWE 插件的判定规则对第一阶段候选逐项确认/拒绝：

- 确认需要真实工具证据，标准见 confirmation-policy（taint-path 或 reference-chain）；
- lib 侧仅 nm/objdump 的候选没有 evidenceID，只能留在 `unresolved` 等待人工复审；
- 被常量、白名单、不可达阻断的候选写 rejected 并给反证。

一阶段扩大搜索、二阶段收紧判断——漏报靠一阶段兜底，误报靠二阶段控制。
