# CWE-190 整数溢出和截断

目标文件：{target}
分析目标：{goal}

检查 {target} 的 CWE-190。结合 Ghidra 和路径证据分析整数状态、约束和安全影响，最终只输出 confirmed/rejected findings；证据不足放入 unresolved，不执行 PoC。

最终 JSON 必须包含 findings、unresolved、coverage；finding status 只能是 confirmed/rejected。