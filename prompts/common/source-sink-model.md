# source/sink 函数模型规则

固定库函数表只用于生成候选。自定义 wrapper 可以由 Agent 提出，但必须由静态事实确认参数、返回值或调用点关系后才能进入 confirmed 状态。

函数模型状态：`candidate`、`confirmed`、`rejected`、`unknown`。

模型应使用 `binaryID`、`functionID`、`functionAddress`、`roles`、`cweTypes`、`sourceParams`、`sinkParams`、`propagationMap` 和 `evidenceIDs`。
