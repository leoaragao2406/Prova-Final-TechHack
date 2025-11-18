import json
from pathlib import Path
from typing import List

from .config import HISTORY_FILE
from .models import AnalysisResult


def load_history(limit: int | None = None) -> List[AnalysisResult]:
    if not HISTORY_FILE.exists():
        return []
    raw = json.loads(HISTORY_FILE.read_text())
    results = [AnalysisResult(**item) for item in raw]
    return results[-limit:] if limit else results


def append_history(result: AnalysisResult) -> None:
    history = load_history()
    history.append(result)
    HISTORY_FILE.write_text(
        json.dumps([item.model_dump(mode="json") for item in history], ensure_ascii=False, indent=2)
    )

