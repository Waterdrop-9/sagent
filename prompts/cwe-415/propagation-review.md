# CWE-415 Double Free：传播或生命周期复核

按分配实例追踪 malloc/calloc/realloc/new 到每个 free/delete，沿控制流和别名传播检查两条可同时到达的释放边；仅出现两个 free 调用点不构成 Double Free。
