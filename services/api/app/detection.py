from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import median
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import settings


@dataclass
class WindowFeatures:
    source_ip: str
    window_start: datetime
    event_count: int
    error_rate: float
    unique_endpoints: int
    ssh_failures: int
    requests_per_minute: int

    def vector(self) -> list[float]:
        return [self.requests_per_minute, self.error_rate, self.unique_endpoints, self.ssh_failures]


def aggregate_events(events: list[Any]) -> list[WindowFeatures]:
    groups: dict[tuple[str, datetime], list[Any]] = defaultdict(list)
    for event in events:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        window = timestamp.astimezone(UTC).replace(second=0, microsecond=0)
        groups[(event.source_ip, window)].append(event)

    features = []
    for (source_ip, window), rows in groups.items():
        http_rows = [row for row in rows if row.event_type == "http"]
        errors = sum(1 for row in http_rows if row.status_code is not None and row.status_code >= 400)
        ssh_failures = sum(1 for row in rows if row.event_type == "ssh" and row.ssh_outcome == "failure")
        features.append(WindowFeatures(
            source_ip=source_ip,
            window_start=window,
            event_count=len(rows),
            error_rate=errors / len(http_rows) * 100 if http_rows else 0.0,
            unique_endpoints=len({row.endpoint for row in http_rows if row.endpoint}),
            ssh_failures=ssh_failures,
            requests_per_minute=len(rows),
        ))
    return sorted(features, key=lambda item: (item.window_start, item.source_ip))


def score_windows(features: list[WindowFeatures]) -> list[tuple[WindowFeatures, float]]:
    if not features:
        return []
    vectors = np.asarray([item.vector() for item in features], dtype=float)
    flagged: set[int] = set()
    scores = np.zeros(len(features), dtype=float)
    if len(features) >= 8 and len({tuple(row) for row in vectors}) > 1:
        contamination = min(max(settings.isolation_contamination, 0.01), 0.25)
        model = IsolationForest(n_estimators=120, contamination=contamination, random_state=42)
        predictions = model.fit_predict(vectors)
        decision_scores = model.decision_function(vectors)
        flagged.update(index for index, prediction in enumerate(predictions) if prediction == -1)
        scores = -decision_scores

    # Sparse datasets still need deterministic detection before the model has enough windows.
    req_values = [item.requests_per_minute for item in features]
    baseline = median(req_values)
    deviations = [abs(value - baseline) for value in req_values]
    mad = median(deviations) if deviations else 0
    threshold = max(20, baseline + 6 * mad)
    for index, item in enumerate(features):
        rule_flag = (
            item.requests_per_minute >= threshold
            or (item.requests_per_minute >= 8 and item.error_rate >= 80)
            or item.ssh_failures >= 5
        )
        if rule_flag:
            flagged.add(index)
            scores[index] = max(float(scores[index]), 0.5 + min(item.requests_per_minute / 200, 1.0))
    return [(features[index], float(scores[index])) for index in sorted(flagged)]
