from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import analyze_url
from .history import append_history, load_history
from .models import AnalysisResult, HistoryResponse, UrlRequest

app = FastAPI(title="Phishing Guard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow()}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: UrlRequest):
    try:
        result = await analyze_url(request.url)
        append_history(result)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/history", response_model=HistoryResponse)
async def history():
    return HistoryResponse(items=load_history())


@app.get("/history/export")
async def export_history():
    history = load_history()
    lines = ["url,domain,risk_level,score,timestamp"]
    for entry in history:
        lines.append(
            f"{entry.url},{entry.domain},{entry.risk_level},{entry.overall_score},{entry.timestamp.isoformat()}"
        )
    csv_data = "\n".join(lines)
    return JSONResponse(
        content={"filename": "history.csv", "data": csv_data},
    )

