# CWE-606 非受控循环

目标文件：{target}
分析目标：{goal}

检查 {target} 的 CWE-606。分析循环/递归的外部可控性、终止性和资源上界，最终只输出 confirmed/rejected findings；证据不足放入 unresolved，不执行 PoC。

最终 JSON 必须包含 findings、unresolved、coverage；finding status 只能是 confirmed/rejected。