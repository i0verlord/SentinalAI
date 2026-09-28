import re
from datetime import UTC, datetime

from app.models import LogEvent

NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<endpoint>\S+) HTTP/[\d.]+" (?P<status>\d{3}) (?P<size>\S+)(?: "[^"]*" "[^"]*")?(?: (?P<response_time>[\d.]+))?$'
)
SSH_PATTERN = re.compile(
    r'^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2}) .*?(?P<outcome>Failed|Accepted) (?:password|publickey) for (?:invalid user )?\S+ from (?P<ip>[\w:.]+) port \d+',
    re.IGNORECASE,
)
MONTHS = {name: index for index, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def parse_line(raw_line: str, log_format: str = "auto", now: datetime | None = None) -> LogEvent | None:
    line = raw_line.strip()
    if not line:
        return None
    current = now or datetime.now(UTC)
    if log_format in ("auto", "nginx"):
        match = NGINX_PATTERN.match(line)
        if match:
            values = match.groupdict()
            try:
                timestamp = datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
                status = int(values["status"])
                response_time = float(values["response_time"]) * 1000 if values["response_time"] else None
            except (ValueError, OverflowError):
                return None
            return LogEvent(
                timestamp=timestamp,
                source_ip=values["ip"],
                event_type="http",
                http_method=values["method"],
                endpoint=values["endpoint"],
                status_code=status,
                response_time_ms=response_time,
                raw_line=line,
            )
        if log_format == "nginx":
            return None
    if log_format in ("auto", "ssh"):
        match = SSH_PATTERN.match(line)
        if match:
            values = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    f"{current.year} {MONTHS[values['month']]} {int(values['day'])} {values['clock']}",
                    "%Y %m %d %H:%M:%S",
                ).replace(tzinfo=UTC)
            except ValueError:
                return None
            outcome = values["outcome"].lower()
            return LogEvent(
                timestamp=timestamp,
                source_ip=values["ip"],
                event_type="ssh",
                ssh_outcome="failure" if outcome == "failed" else "success",
                raw_line=line,
            )
    return None
