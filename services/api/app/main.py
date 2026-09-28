from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import alerts, dashboard, health, ingestion

app = FastAPI(title="SentinelAI API", version="0.1.0", description="Log anomaly detection and incident triage API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(ingestion.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(health.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
