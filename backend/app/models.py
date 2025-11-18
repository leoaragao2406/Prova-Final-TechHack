from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, HttpUrl


class UrlRequest(BaseModel):
    url: HttpUrl


class HeuristicResult(BaseModel):
    name: str
    passed: bool
    details: str
    score_impact: int


class AnalysisResult(BaseModel):
    url: HttpUrl
    domain: str
    timestamp: datetime
    overall_score: int
    risk_level: str
    heuristics: List[HeuristicResult]
    metadata: dict


class HistoryResponse(BaseModel):
    items: List[AnalysisResult]

