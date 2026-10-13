# 脚本目录

开发与运维用的辅助脚本，全部只做静态查询，不执行样本：

- `static_analysis/check_path_backend.py`：路径查询后端健康检查。spawn
  `path_server` 子进程、走 JSON-RPC 发一次查询并校验响应形状；
- `check_evidence_integrity.py`：证据完整性核验。按 run 目录里的 `raw/*.jsonl`
  （Ghidra 多会话日志 + paths 日志）逐条检查 report.json 引用的 evidenceID
  是否真实可查、是否属于本分析组。

未来方向：把「finding 的 evidenceID → raw 日志文件+行号」映射检查并入
`check_evidence_integrity.py`（当前只核验存在性，不核验逐条映射）。
