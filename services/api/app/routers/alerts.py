from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AnomalyAlert, LogEvent, TriageReport
from app.schemas import AlertDetail, AlertSummary, EvidenceEvent
from app.triage import run_triage

router = APIRouter(prefix="/alerts", tags=["alerts"])


def to_summary(alert: AnomalyAlert, report: TriageReport | None) -> dict:
    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "window_start": alert.window_start,
        "anomaly_score": alert.anomaly_score,
        "status": alert.status,
        "event_count": alert.event_count,
        "error_rate": alert.error_rate,
        "unique_endpoints": alert.unique_endpoints,
        "ssh_failures": alert.ssh_failures,
        "triage_status": report.status if report else "pending",
        "incident": report.incident if report and report.status == "complete" else None,
    }


@router.get("", response_model=list[AlertSummary])
def list_alerts(db: Session = Depends(get_db)) -> list[dict]:
    alerts = db.query(AnomalyAlert).order_by(AnomalyAlert.window_start.desc(), AnomalyAlert.id.desc()).limit(200).all()
    reports = {report.alert_id: report for report in db.query(TriageReport).filter(TriageReport.alert_id.in_([alert.id for alert in alerts])).all()} if alerts else {}
    return [to_summary(alert, reports.get(alert.id)) for alert in alerts]


@router.get("/{alert_id}", response_model=AlertDetail)
def alert_detail(alert_id: int, db: Session = Depends(get_db)) -> dict:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    start = alert.window_start.replace(second=0, microsecond=0)
    end = start + timedelta(minutes=1)
    events = db.query(LogEvent).filter(
        LogEvent.source_ip == alert.source_ip,
        LogEvent.timestamp >= start,
        LogEvent.timestamp < end,
    ).order_by(LogEvent.timestamp.desc()).limit(20).all()
    report = db.query(TriageReport).filter(TriageReport.alert_id == alert.id).one_or_none()
    return {
        **to_summary(alert, report),
        "evidence": [EvidenceEvent.model_validate(event).model_dump() for event in events],
    }


@router.post("/{alert_id}/triage", response_model=AlertSummary)
def triage_alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    report = run_triage(db, alert)
    return to_summary(alert, report)
