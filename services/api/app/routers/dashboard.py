from collections import defaultdict
from datetime import UTC

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AnomalyAlert, LogEvent
from app.schemas import Overview, TrafficPoint

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=Overview)
def overview(db: Session = Depends(get_db)) -> Overview:
    total_logs = db.query(func.count(LogEvent.id)).scalar() or 0
    active_alerts = db.query(func.count(AnomalyAlert.id)).filter(AnomalyAlert.status == "active").scalar() or 0
    http_count = db.query(func.count(LogEvent.id)).filter(LogEvent.event_type == "http").scalar() or 0
    error_count = db.query(func.count(LogEvent.id)).filter(LogEvent.event_type == "http", LogEvent.status_code >= 400).scalar() or 0
    latest = db.query(func.max(LogEvent.timestamp)).scalar()
    if latest and latest.tzinfo is None:
        latest = latest.replace(tzinfo=UTC)
    return Overview(total_logs=total_logs, active_alerts=active_alerts, error_rate=error_count / http_count * 100 if http_count else 0.0, latest_window=latest)


@router.get("/traffic", response_model=list[TrafficPoint])
def traffic(db: Session = Depends(get_db)) -> list[TrafficPoint]:
    events = db.query(LogEvent.timestamp, LogEvent.source_ip).order_by(LogEvent.timestamp.asc()).all()
    alert_rows = db.query(AnomalyAlert.source_ip, AnomalyAlert.window_start).filter(AnomalyAlert.status == "active").all()
    anomalous = {(ip, timestamp.replace(second=0, microsecond=0)) for ip, timestamp in alert_rows}
    buckets: dict[object, dict[str, int]] = defaultdict(lambda: {"normal": 0, "anomaly": 0})
    for timestamp, source_ip in events:
        minute = timestamp.replace(second=0, microsecond=0)
        bucket = buckets[minute]
        bucket["anomaly" if (source_ip, minute) in anomalous else "normal"] += 1
    output = []
    for timestamp in sorted(buckets):
        counts = buckets[timestamp]
        output.append(TrafficPoint(
            timestamp=timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp,
            normal_requests=counts["normal"] or None,
            anomaly_requests=counts["anomaly"] or None,
        ))
    return output[-180:]
