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


def test_simulation_does_not_insert_duplicate_sample_rows(client, monkeypatch) -> None:
    from datetime import UTC, datetime

    import app.routers.ingestion as ingestion_router
    from app.detection_service import simulate_events

    fixed_time = datetime(2026, 9, 28, 10, 21, tzinfo=UTC)
    monkeypatch.setattr(ingestion_router, "simulate_events", lambda: simulate_events(fixed_time))

    first = client.post("/api/ingestion/simulate").json()
    second = client.post("/api/ingestion/simulate").json()

    assert first["ingested"] > 0
    assert second["ingested"] == 0
    assert client.get("/api/dashboard/overview").json()["total_logs"] == first["ingested"]


def test_upload_reports_unparsed_lines(client) -> None:
    response = client.post(
        "/api/ingestion/upload",
        data={"format": "nginx"},
        files={"file": ("access.log", b'192.0.2.10 - - [28/Sep/2026:10:21:18 +0000] "GET / HTTP/1.1" 200 120 "-" "test"\nbad line', "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["parsed"] == 1
    assert response.json()["skipped"] == 1


def test_triage_remains_available_without_provider_configuration(client, monkeypatch) -> None:
    from app.triage import settings

    monkeypatch.setattr(settings, "llm_base_url", "")
    monkeypatch.setattr(settings, "llm_api_key", "")
    client.post("/api/ingestion/simulate")
    alert = client.get("/api/alerts").json()[0]

    response = client.post(f"/api/alerts/{alert['id']}/triage")

    assert response.status_code == 200
    assert response.json()["triage_status"] == "unavailable"


def test_triage_validates_provider_assessment(client, monkeypatch) -> None:
    import app.triage as triage_module

    monkeypatch.setattr(triage_module.settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(triage_module.settings, "llm_api_key", "test-key")

    class ProviderResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"choices": [{"message": {"content": '{"threat_category":"Credential Stuffing","severity":"High","summary":"Repeated failed SSH login attempts from one address.","remediation":"Block the source at the perimeter firewall and enforce key-based SSH authentication."}'}}]}

    monkeypatch.setattr(triage_module.httpx, "post", lambda *args, **kwargs: ProviderResponse())
    client.post("/api/ingestion/simulate")
    alert = client.get("/api/alerts").json()[0]

    response = client.post(f"/api/alerts/{alert['id']}/triage")

    assert response.status_code == 200
    assert response.json()["triage_status"] == "complete"
    assert response.json()["incident"]["severity"] == "High"


def test_triage_provider_failure_does_not_lose_alert(client, monkeypatch) -> None:
    import httpx
    import app.triage as triage_module

    monkeypatch.setattr(triage_module.settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(triage_module.settings, "llm_api_key", "test-key")

    def fail_request(*args, **kwargs):
        raise httpx.ConnectError("provider offline", request=httpx.Request("POST", "https://llm.example/v1/chat/completions"))

    monkeypatch.setattr(triage_module.httpx, "post", fail_request)
    client.post("/api/ingestion/simulate")
    alert = client.get("/api/alerts").json()[0]

    response = client.post(f"/api/alerts/{alert['id']}/triage")

    assert response.status_code == 200
    assert response.json()["triage_status"] == "failed"
    assert response.json()["incident"] is None
