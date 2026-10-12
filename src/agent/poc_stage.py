"""接入外部分析引擎的 PoC 阶段；只生成结果，不执行生成的代码。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PocStageError(ValueError):
    """外部 PoC 阶段模板缺失或输入不满足门槛。"""


class PocStageAdapter:
    """把 confirmed finding 适配为外部引擎的 PoC 阶段模板。"""

    def __init__(self, prompt_file: str | Path) -> None:
        self.prompt_file = Path(prompt_file).expanduser().resolve()
        if not self.prompt_file.is_file():
            raise PocStageError(f"外部 PoC 阶段模板不存在: {self.prompt_file}")
        self.stage_template = self._read()

    def build_prompt(
        self,
        target: Path,
        cwe_id: str,
        findings: list[dict[str, Any]],
        artifact_directory: Path,
    ) -> str:
        if not findings or any(item.get("status") != "confirmed" for item in findings):
            raise PocStageError("没有 confirmed finding，跳过外部 PoC 阶段")
        context = json.dumps({
            "target": str(target), "cwe": cwe_id,
            "artifactDirectory": str(artifact_directory), "findings": findings,
        }, ensure_ascii=False, indent=2)
        template = self.stage_template
        for key, value in {
            "{task_name}": f"sagent-{cwe_id.lower()}-poc",
            "{output_dir}": str(artifact_directory),
            "{created_at}": "current-run",
            "{binary_list}": str(target),
        }.items():
            template = template.replace(key, value)
        return f"""你正在执行独立的外部 PoC 生成阶段。只处理已经 confirmed 的 finding，不重新判断漏洞，不处理 rejected 或 unresolved 项。

外部阶段工作约束：
{template}

Sagent 已确认的 finding：
```json
{context}
```

请只生成静态审计 PoC 或人工验证步骤，输出或写入当前产物目录的 poc/；不要执行样本、网络请求或生成的 PoC。响应中列出生成文件及其对应的 findingID/evidenceIDs。"""

    def _read(self) -> str:
        path = self.prompt_file
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise PocStageError(f"读取外部 PoC 阶段模板失败: {path}") from exc
        if not content:
            raise PocStageError(f"外部 PoC 阶段模板为空: {path}")
        return content
