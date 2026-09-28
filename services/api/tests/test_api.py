def test_simulation_populates_dashboard_and_alert_evidence(client) -> None:
    result = client.post("/api/ingestion/simulate")

    assert result.status_code == 200
    assert result.json()["ingested"] >= 30
    assert result.json()["flagged"] >= 1

    overview = client.get("/api/dashboard/overview").json()
    assert overview["total_logs"] == result.json()["ingested"]
    assert overview["active_alerts"] >= 1

    alerts = client.get("/api/alerts").json()
    assert alerts
    detail = client.get(f"/api/alerts/{alerts[0]['id']}")
    assert detail.status_code == 200
    assert detail.json()["evidence"]


def test_upload_reports_unparsed_lines(client) -> None:
    response = client.post(
        "/api/ingestion/upload",
        data={"format": "nginx"},
        files={"file": ("access.log", b'192.0.2.10 - - [28/Sep/2026:10:21:18 +0000] "GET / HTTP/1.1" 200 120 "-" "test"\nbad line', "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["parsed"] == 1
    assert response.json()["skipped"] == 1
