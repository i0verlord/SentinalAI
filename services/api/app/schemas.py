from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentAssessment(BaseModel):
    threat_category: str = Field(min_length=2, max_length=120)
    severity: Severity
    summary: str = Field(min_length=8, max_length=2000)
    remediation: str = Field(min_length=4, max_length=2000)


class AlertSummary(BaseModel):
    id: int
    source_ip: str
    window_start: datetime
    anomaly_score: float
    status: str
    event_count: int
    error_rate: float
    unique_endpoints: int
    ssh_failures: int
    triage_status: str
    incident: IncidentAssessment | None

    model_config = ConfigDict(from_attributes=True)


class EvidenceEvent(BaseModel):
    timestamp: datetime
    event_type: str
    source_ip: str
    http_method: str | None
    endpoint: str | None
    status_code: int | None
    raw_line: str


class AlertDetail(AlertSummary):
    evidence: list[EvidenceEvent]


class Overview(BaseModel):
    total_logs: int
    active_alerts: int
    error_rate: float
    latest_window: datetime | None


class TrafficPoint(BaseModel):
    timestamp: datetime
    normal_requests: int | None
    anomaly_requests: int | None


class IngestionResult(BaseModel):
    parsed: int
    skipped: int
    flagged: int


class SimulationResult(BaseModel):
    ingested: int
    flagged: int
