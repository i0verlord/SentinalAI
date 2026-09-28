from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LogEvent(Base):
    __tablename__ = "log_events"
    __table_args__ = (Index("ix_log_events_source_time", "source_ip", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(16), index=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ssh_outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw_line: Mapped[str] = mapped_column(Text)


class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"
    __table_args__ = (UniqueConstraint("source_ip", "window_start", name="uq_alert_ip_window"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    anomaly_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    event_count: Mapped[int] = mapped_column(Integer)
    error_rate: Mapped[float] = mapped_column(Float)
    unique_endpoints: Mapped[int] = mapped_column(Integer)
    ssh_failures: Mapped[int] = mapped_column(Integer)
    features: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class TriageReport(Base):
    __tablename__ = "triage_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("anomaly_alerts.id", ondelete="CASCADE"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    incident: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
