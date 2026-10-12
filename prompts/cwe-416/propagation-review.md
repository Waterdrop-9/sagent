# CWE-416 Use-After-Free：传播或生命周期复核

对每个分配实例建立生命周期：allocate → aliases → free/delete → later use。检查控制流顺序、别名、重分配、置空、引用计数和线程同步；函数调用本身不能证明对象仍存活。
