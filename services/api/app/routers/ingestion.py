from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.detection_service import run_detection, simulate_events
from app.ingestion import parse_line
from app.models import LogEvent
from app.schemas import IngestionResult, SimulationResult

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


@router.post("/upload", response_model=IngestionResult)
async def upload_logs(
    file: UploadFile = File(...),
    format: Literal["auto", "nginx", "ssh"] = Form("auto"),
    db: Session = Depends(get_db),
) -> IngestionResult:
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Log file exceeds the 10 MB upload limit.")
    lines = content.decode("utf-8", errors="replace").splitlines()
    parsed = [event for line in lines if (event := parse_line(line, format)) is not None]
    if parsed:
        db.add_all(parsed)
        db.commit()
    flagged = run_detection(db) if parsed else 0
    return IngestionResult(parsed=len(parsed), skipped=len(lines) - len(parsed), flagged=flagged)


@router.post("/simulate", response_model=SimulationResult)
def simulate(db: Session = Depends(get_db)) -> SimulationResult:
    generated = simulate_events()
    existing = {
        row[0] for row in db.query(LogEvent.raw_line)
        .filter(LogEvent.raw_line.in_([event.raw_line for event in generated]))
        .all()
    }
    events = [event for event in generated if event.raw_line not in existing]
    db.add_all(events)
    db.commit()
    flagged = run_detection(db)
    return SimulationResult(ingested=len(events), flagged=flagged)
