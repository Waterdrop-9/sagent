# 覆盖账本规则

结束前检查所有高优先级攻击面、confirmed sink 的敏感参数和 candidate source/sink。

账本存在 `unknown`、`unsupported`、`failed` 或预算耗尽时，报告必须保留原因并保持整轮 `analysisStatus=inconclusive`；不能把未完成项伪装成 rejected，也不能输出确定性的“未发现漏洞”。
