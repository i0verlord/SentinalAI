from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.detection import aggregate_events, score_windows
from app.models import AnomalyAlert, LogEvent


def run_detection(db: Session) -> int:
    events = db.query(LogEvent).all()
    features = aggregate_events(events)
    flagged = score_windows(features)
    for item, score in flagged:
        start = item.window_start.astimezone(UTC)
        alert = db.query(AnomalyAlert).filter(
            AnomalyAlert.source_ip == item.source_ip,
            AnomalyAlert.window_start == start,
        ).one_or_none()
        feature_data = {
            "requests_per_minute": item.requests_per_minute,
            "error_rate": round(item.error_rate, 2),
            "unique_endpoints": item.unique_endpoints,
            "ssh_failures": item.ssh_failures,
        }
        if alert is None:
            alert = AnomalyAlert(
                source_ip=item.source_ip,
                window_start=start,
                anomaly_score=score,
                event_count=item.event_count,
                error_rate=item.error_rate,
                unique_endpoints=item.unique_endpoints,
                ssh_failures=item.ssh_failures,
                features=feature_data,
            )
            db.add(alert)
        else:
            alert.anomaly_score = score
            alert.event_count = item.event_count
            alert.error_rate = item.error_rate
            alert.unique_endpoints = item.unique_endpoints
            alert.ssh_failures = item.ssh_failures
            alert.features = feature_data
            alert.status = "active"
    db.commit()
    return len(flagged)


def simulate_events(current_time: datetime | None = None) -> list[LogEvent]:
    now = (current_time or datetime.now(UTC)).astimezone(UTC).replace(second=0, microsecond=0)
    events: list[LogEvent] = []
    for minute_offset in range(14, 0, -1):
        window = now - timedelta(minutes=minute_offset)
        for host_index in range(8):
            source_ip = f"10.0.{host_index // 250}.{host_index + 10}"
            for request_index in range(2 + (host_index % 3)):
                status = 200 if request_index else (404 if host_index == 2 else 200)
                endpoint = ("/api/health", "/", "/assets/app.js")[request_index % 3]
                timestamp = window + timedelta(seconds=request_index * 9 + host_index % 7)
                raw = f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {status} 512 "-" "SentinelSim/1.0"'
                events.append(LogEvent(timestamp=timestamp, source_ip=source_ip, event_type="http", http_method="GET", endpoint=endpoint, status_code=status, response_time_ms=20.0 + request_index, raw_line=raw))

    attacker = "203.0.113.77"
    for request_index in range(32):
        timestamp = now + timedelta(seconds=request_index % 59)
        endpoint = f"/admin/.env?probe={request_index}"
        status = 401 if request_index < 24 else 404
        raw = f'{attacker} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {status} 128 "-" "SentinelSim/1.0"'
        events.append(LogEvent(timestamp=timestamp, source_ip=attacker, event_type="http", http_method="GET", endpoint=endpoint, status_code=status, response_time_ms=8.0, raw_line=raw))
    for failure_index in range(7):
        timestamp = now + timedelta(seconds=failure_index * 6)
        raw = f"Sep {now.day:2d} {timestamp.strftime('%H:%M:%S')} sentinel sshd[1337]: Failed password for invalid user admin from 198.51.100.42 port {41000 + failure_index} ssh2"
        events.append(LogEvent(timestamp=timestamp, source_ip="198.51.100.42", event_type="ssh", ssh_outcome="failure", raw_line=raw))
    return events
