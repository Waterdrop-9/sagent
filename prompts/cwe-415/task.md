# CWE-415 Double Free

目标文件：{target}
分析目标：{goal}

检查 {target} 的 CWE-415。追踪分配实例和所有释放路径，最终只输出 confirmed/rejected findings；证据不足放入 unresolved，不执行 PoC。

最终 JSON 必须包含 findings、unresolved、coverage；finding status 只能是 confirmed/rejected。