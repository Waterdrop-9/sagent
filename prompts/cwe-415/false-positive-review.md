# CWE-415 Double Free：误报复核

释放后置空且后续路径不可达、引用计数正确、分支互斥、每次循环重新分配或释放的是不同实例时 rejected。对象身份无法确定时写入 unresolved。
