# CWE-134 外部可控格式字符串：攻击面

优先检查 printf、fprintf、sprintf、snprintf、syslog、日志 wrapper 和自定义格式化函数。区分格式参数与普通数据参数；函数名不能单独证明漏洞。
