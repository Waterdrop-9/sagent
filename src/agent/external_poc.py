"""接入外部 foolish PoC 阶段；只生成结果，不执行生成的代码。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ExternalPocError(ValueError):
    """外部 PoC prompt 缺失或输入不满足阶段门槛。"""


_PROMPTS = {
    "CWE-78": "03-cmd-injection.md",
    "CWE-134": "11-format-string.md",
    "CWE-190": "10-integer-issues.md",
    "CWE-606": "18-dos.md",
    "CWE-415": "16-uaf.md",
    "CWE-416": "16-uaf.md",
}


class ExternalPocAdapter:
    """把 confirmed finding 适配为外部 prompt 阶段的输入。"""

    def __init__(self, prompt_dir: str | Path) -> None:
        self.prompt_dir = Path(prompt_dir).expanduser().resolve()
        if not self.prompt_dir.is_dir():
            raise ExternalPocError(f"外部 PoC prompt 目录不存在: {self.prompt_dir}")
        self.summary_prompt = self._read("20-summary.md")

    def build_prompt(
        self,
        target: Path,
        cwe_id: str,
        findings: list[dict[str, Any]],
        artifact_directory: Path,
    ) -> str:
        if not findings:
            raise ExternalPocError("没有 confirmed finding，跳过外部 PoC 阶段")
        try:
            stage = self._read(_PROMPTS[cwe_id.upper()])
        except KeyError as exc:
            raise ExternalPocError(f"没有为 {cwe_id} 配置外部 PoC prompt") from exc
        context = json.dumps({
            "target": str(target), "cwe": cwe_id,
            "artifactDirectory": str(artifact_directory), "findings": findings,
        }, ensure_ascii=False, indent=2)
        return f"""你正在执行外部 PoC 阶段。只处理已经 confirmed 的 finding，不重新判断漏洞，不处理 rejected 或 unresolved 项。

外部阶段规则：
{stage}

最终汇总约定（只作为产物组织参考）：
{self.summary_prompt}

Sagent 已确认的 finding：
```json
{context}
```

请只生成静态审计 PoC 或人工验证步骤，写入当前产物目录的 poc/；不要执行样本、网络请求或生成的 PoC。响应中列出生成文件及其对应的 findingID/evidenceIDs。"""

    def _read(self, name: str) -> str:
        path = self.prompt_dir / name
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ExternalPocError(f"读取外部 PoC prompt 失败: {path}") from exc
        if not content:
            raise ExternalPocError(f"外部 PoC prompt 为空: {path}")
        return content
