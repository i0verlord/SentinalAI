from datetime import UTC, datetime
from types import SimpleNamespace

from app.detection import aggregate_events, score_windows


def test_aggregates_http_errors_endpoints_and_ssh_failures() -> None:
    start = datetime(2026, 9, 28, 10, 21, tzinfo=UTC)
    events = [
        SimpleNamespace(timestamp=start, source_ip="192.0.2.1", event_type="http", status_code=200, endpoint="/", ssh_outcome=None),
        SimpleNamespace(timestamp=start.replace(second=22), source_ip="192.0.2.1", event_type="http", status_code=500, endpoint="/admin", ssh_outcome=None),
        SimpleNamespace(timestamp=start.replace(second=35), source_ip="192.0.2.1", event_type="ssh", status_code=None, endpoint=None, ssh_outcome="failure"),
    ]

    feature = aggregate_events(events)[0]

    assert feature.event_count == 3
    assert feature.error_rate == 50
    assert feature.unique_endpoints == 2
    assert feature.ssh_failures == 1


def test_sparse_traffic_flags_brute_force_window() -> None:
    start = datetime(2026, 9, 28, 10, 21, tzinfo=UTC)
    normal = [
        SimpleNamespace(source_ip=f"192.0.2.{index}", window_start=start, event_count=3, error_rate=0, unique_endpoints=2, ssh_failures=0, requests_per_minute=3)
        for index in range(5)
    ]
    attack = SimpleNamespace(source_ip="203.0.113.9", window_start=start, event_count=32, error_rate=100, unique_endpoints=28, ssh_failures=0, requests_per_minute=32)

    flagged = score_windows([*normal, attack])

    assert len(flagged) == 1
    assert flagged[0][0].source_ip == "203.0.113.9"
    assert flagged[0][1] > 0
