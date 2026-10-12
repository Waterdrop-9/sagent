# source/sink 函数模型规则

固定库函数表只用于生成候选。自定义 wrapper 可以由 Agent 提出，但必须由静态事实确认参数、返回值或调用点关系后才能进入 confirmed 状态。

函数模型状态：`candidate`、`confirmed`、`rejected`、`unknown`。

模型应使用 `binaryID`、`functionID`、`functionAddress`、`roles`、`cweTypes`、`sourceParams`、`sinkParams`、`propagationMap` 和 `evidenceIDs`。

roles 只能是：`source`、`sink`、`sanitizer`、`wrapper`、`parser`、`auth_boundary`、`allocator`、`deallocator`。内存生命周期类 CWE（415 重复释放 / 416 释放后使用）用 `allocator`（malloc、fopen、popen 等分配函数）和 `deallocator`（free、fclose、pclose 等释放函数）标注；除此之外不要发明新角色。
