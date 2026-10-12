"""PoC 阶段适配器：把 confirmed finding 组装成独立 PoC 阶段的提示词；只生成结果，不执行生成的代码。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class PocStageError(ValueError):
    """PoC 阶段模板缺失或输入不满足门槛。"""


class PocStageAdapter:
    """把 confirmed finding 适配为 PoC 阶段模板。"""

    def __init__(self, prompt_file: str | Path) -> None:
        self.prompt_file = Path(prompt_file).expanduser().resolve()
        if not self.prompt_file.is_file():
            raise PocStageError(f"PoC 阶段模板不存在: {self.prompt_file}")
        self.stage_template = self._read()

    def build_prompt(
        self,
        target: Path,
        cwe_id: str,
        findings: list[dict[str, Any]],
        artifact_directory: Path,
    ) -> str:
        if not findings or any(item.get("status") != "confirmed" for item in findings):
            raise PocStageError("没有 confirmed finding，跳过 PoC 阶段")
        context = json.dumps({
            "target": str(target), "cwe": cwe_id,
            "artifactDirectory": str(artifact_directory), "findings": findings,
        }, ensure_ascii=False, indent=2)
        template = self.stage_template
        for key, value in {
            "{task_name}": f"sagent-{cwe_id.lower()}-poc",
            "{output_dir}": str(artifact_directory),
            "{created_at}": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "{binary_list}": str(target),
            "{cwe_id}": cwe_id,
        }.items():
            template = template.replace(key, value)
        # 包装语只补模板没法表达的部分：阶段边界的一句话兜底、
        # finding 上下文 JSON，以及交付物写入位置的澄清（cwd 就是 poc/）。
        return f"""你正在执行独立的 PoC 生成阶段。只处理已确认（confirmed）的 finding。

阶段工作约束：
{template}

Sagent 已确认的 finding：
```json
{context}
```

把报告和验证脚本直接写入当前工作目录（也就是 PoC 阶段的 poc/ 目录）。"""

    def _read(self) -> str:
        path = self.prompt_file
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise PocStageError(f"读取 PoC 阶段模板失败: {path}") from exc
        if not content:
            raise PocStageError(f"PoC 阶段模板为空: {path}")
        return content
