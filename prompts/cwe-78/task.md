# CWE-78 命令注入

目标文件：{target}
分析目标：{goal}

确认攻击面、命令执行 sink 和自定义 wrapper，查询敏感参数路径并复核常量、过滤和可达性。最终只输出 confirmed/rejected findings；证据不足写入 unresolved，不生成或执行 PoC。