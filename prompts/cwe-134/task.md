# CWE-134 外部可控格式字符串

目标文件：{target}
分析目标：{goal}

检查 {target} 的 CWE-134。按工具事实建立攻击面和格式化 sink，查询高价值格式参数路径，最终只输出 confirmed/rejected findings；证据不足放入 unresolved，不执行 PoC。

最终 JSON 必须包含 findings、unresolved、coverage；finding status 只能是 confirmed/rejected。