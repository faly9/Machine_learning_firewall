from fastapi import FastAPI
from storage.db import recent_events

app = FastAPI(title="Intelligent Firewall API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/events")
def events(limit: int = 50):
    limit = max(1, min(limit, 500))
    rows = recent_events(limit)
    keys = ["id","timestamp","src_ip","decision","rf_label","anomaly_score","packets","bytes","detail"]
    return [dict(zip(keys, row)) for row in rows]
