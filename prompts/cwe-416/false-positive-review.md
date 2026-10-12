# CWE-416 Use-After-Free：误报复核

使用前必然重新分配、所有别名同步失效、引用计数/锁保证生命周期或路径不可达时 rejected。C++ 析构和别名无法确认时写入 unresolved。
