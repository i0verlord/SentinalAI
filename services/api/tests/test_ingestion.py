from datetime import UTC, datetime

from app.ingestion import parse_line


def test_parses_nginx_access_line() -> None:
    event = parse_line(
        '198.51.100.24 - - [28/Sep/2026:10:21:18 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.0"',
        now=datetime(2026, 9, 28, tzinfo=UTC),
    )

    assert event is not None
    assert event.event_type == "http"
    assert event.source_ip == "198.51.100.24"
    assert event.status_code == 404
    assert event.endpoint == "/admin"


def test_parses_ssh_failure_without_inventing_http_fields() -> None:
    event = parse_line(
        "Sep 28 10:21:18 host sshd[123]: Failed password for invalid user admin from 203.0.113.7 port 52122 ssh2",
        now=datetime(2026, 9, 28, tzinfo=UTC),
    )

    assert event is not None
    assert event.event_type == "ssh"
    assert event.ssh_outcome == "failure"
    assert event.http_method is None
    assert event.status_code is None


def test_rejects_malformed_lines() -> None:
    assert parse_line("not a supported log line") is None
