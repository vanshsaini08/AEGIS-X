
import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import main


client = TestClient(main.app)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.db")
    main.init_db()


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["name"] == "VELTRIX"


def test_health_endpoint_returns_healthy_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "veltrix-api",
        "version": "0.3.0",
    }


def test_register_and_list_service() -> None:
    response = client.post(
        "/services",
        json={
            "name": "Demo Service",
            "url": "https://example.com",
            "timeout_seconds": 3,
        },
    )

    assert response.status_code == 201

    service = response.json()
    assert service["name"] == "Demo Service"
    assert service["timeout_seconds"] == 3

    listed = client.get("/services")

    assert listed.status_code == 200
    assert any(
        item["id"] == service["id"]
        for item in listed.json()
    )


def test_reject_service_with_invalid_scheme() -> None:
    response = client.post(
        "/services",
        json={
            "name": "Invalid Service",
            "url": "ftp://example.com",
        },
    )

    assert response.status_code == 422


def test_check_unknown_service_returns_404() -> None:
    response = client.post("/services/not-a-real-id/check")

    assert response.status_code == 404


def test_failed_check_creates_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        status_code = 503

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            pass

        def get(self, url: str) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(main.httpx, "Client", FakeClient)

    registered = client.post(
        "/services",
        json={
            "name": "Mock Failure Service",
            "url": "https://example.com",
        },
    )

    assert registered.status_code == 201
    service_id = registered.json()["id"]

    checked = client.post(f"/services/{service_id}/check")

    assert checked.status_code == 200
    assert checked.json()["status"] == "unhealthy"
    assert checked.json()["error"] == "http_error"

    incidents = client.get(
        "/incidents",
        params={"unresolved_only": True},
    )

    assert incidents.status_code == 200
    assert any(
        incident["service_id"] == service_id
        for incident in incidents.json()
    )


def test_successful_check_resolves_open_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        status_code = 200

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            pass

        def get(self, url: str) -> FakeResponse:
            return FakeResponse()

    class FailingResponse:
        status_code = 503

    class FailingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            pass

        def get(self, url: str) -> FailingResponse:
            return FailingResponse()

    registered = client.post(
        "/services",
        json={
            "name": "Mock Recovery Service",
            "url": "https://example.com",
        },
    )

    assert registered.status_code == 201
    service_id = registered.json()["id"]

    monkeypatch.setattr(main.httpx, "Client", FailingClient)

    failed = client.post(f"/services/{service_id}/check")

    assert failed.status_code == 200
    assert failed.json()["status"] == "unhealthy"

    monkeypatch.setattr(main.httpx, "Client", FakeClient)

    recovered = client.post(f"/services/{service_id}/check")

    assert recovered.status_code == 200
    assert recovered.json()["status"] == "healthy"

    incidents = client.get("/incidents")

    matching = [
        incident
        for incident in incidents.json()
        if incident["service_id"] == service_id
    ]

    assert matching
    assert matching[0]["status"] == "resolved"
    assert matching[0]["resolved_at"] is not None


def test_monitoring_cycle_checks_registered_services():
    registered = client.post(
        "/services",
        json={
            "name": "Failure Lab Test",
            "url": "https://example.com",
            "timeout_seconds": 5,
        },
    )

    assert registered.status_code == 201
    service_id = registered.json()["id"]

    with patch.object(
        main,
        "check_service",
        return_value=None,
    ) as mocked_check:
        asyncio.run(main.run_monitoring_cycle())

    mocked_check.assert_called_once_with(service_id)


def test_blocks_loopback_destination():
    with pytest.raises(ValueError, match="Non-public IP"):
        main.validate_public_destination("http://127.0.0.1")


def test_blocks_private_ip_destination():
    with pytest.raises(ValueError, match="Non-public IP"):
        main.validate_public_destination("http://192.168.1.10")


def test_blocks_credentials_in_url():
    with pytest.raises(ValueError, match="credentials"):
        main.validate_public_destination(
            "https://user:password@example.com"
        )


def test_blocks_hostname_resolving_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("10.0.0.5", 443))
        ],
    )

    with pytest.raises(ValueError, match="non-public IP"):
        main.validate_public_destination("https://example.com")


def test_unsafe_destination_never_makes_http_request(
    monkeypatch: pytest.MonkeyPatch,
):
    def fail_if_called(*args, **kwargs):
        pytest.fail("HTTP client must not be created for an unsafe URL")

    monkeypatch.setattr(main.httpx, "Client", fail_if_called)

    registered = client.post(
        "/services",
        json={
            "name": "Unsafe Destination Test",
            "url": "http://127.0.0.1",
        },
    )

    assert registered.status_code == 201
    service_id = registered.json()["id"]

    checked = client.post(f"/services/{service_id}/check")

    assert checked.status_code == 200
    assert checked.json()["status"] == "unhealthy"
    assert checked.json()["error"] == "unsafe_destination"


def test_unapproved_hostname_never_makes_http_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_client(*args, **kwargs):
        pytest.fail(
            "HTTP client must not be created for an unapproved host"
        )

    monkeypatch.setattr(main.httpx, "Client", unexpected_client)

    registered = client.post(
        "/services",
        json={
            "name": "Unapproved Host Test",
            "url": "https://not-allowlisted.invalid",
            "timeout_seconds": 3,
        },
    )

    assert registered.status_code == 201
    service_id = registered.json()["id"]

    checked = client.post(f"/services/{service_id}/check")

    assert checked.status_code == 200
    result = checked.json()
    assert result["status"] == "unhealthy"
    assert result["error"] == "unsafe_destination"


def test_security_audit_suppresses_duplicate_events():
    event = {
        "service_id": None,
        "event_type": "test_duplicate_event",
        "outcome": "blocked",
        "details": "Duplicate audit test",
    }

    main.write_security_audit(**event)
    main.write_security_audit(**event)

    with main.get_db() as db:
        rows = db.execute(
            """
            SELECT id
            FROM security_audit
            WHERE event_type = ?
              AND outcome = ?
              AND details = ?
            """,
            (
                event["event_type"],
                event["outcome"],
                event["details"],
            ),
        ).fetchall()

    assert len(rows) == 1


def test_security_audit_records_different_events():
    main.write_security_audit(
        service_id=None,
        event_type="test_event_one",
        outcome="blocked",
        details="First event",
    )

    main.write_security_audit(
        service_id=None,
        event_type="test_event_two",
        outcome="blocked",
        details="Second event",
    )

    with main.get_db() as db:
        rows = db.execute(
            """
            SELECT event_type
            FROM security_audit
            WHERE event_type IN (?, ?)
            """,
            ("test_event_one", "test_event_two"),
        ).fetchall()

    assert len(rows) == 2

def test_security_audit_records_event_again_after_ten_minutes(
    monkeypatch: pytest.MonkeyPatch,
):
    from datetime import datetime, timedelta, timezone

    fixed_now = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(main, "datetime", FakeDateTime)

    event = {
        "service_id": None,
        "event_type": "test_ten_minute_window",
        "outcome": "blocked",
        "details": "Ten minute boundary test",
    }

    main.write_security_audit(**event)

    # Simulate the same event after 11 minutes.
    monkeypatch.setattr(
        FakeDateTime,
        "now",
        classmethod(lambda cls, tz=None: fixed_now + timedelta(minutes=11)),
    )

    main.write_security_audit(**event)

    with main.get_db() as db:
        rows = db.execute(
            """
            SELECT id
            FROM security_audit
            WHERE event_type = ?
              AND outcome = ?
              AND details = ?
            """,
            (
                event["event_type"],
                event["outcome"],
                event["details"],
            ),
        ).fetchall()

    assert len(rows) == 2

def test_security_audit_concurrent_duplicate_events(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    event = {
        "service_id": None,
        "event_type": "test_concurrent_duplicate",
        "outcome": "blocked",
        "details": "Concurrent duplicate test",
    }

    def write_event(_):
        main.write_security_audit(**event)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_event, range(8)))

    with main.get_db() as db:
        rows = db.execute(
            """
            SELECT id
            FROM security_audit
            WHERE event_type = ?
              AND outcome = ?
              AND details = ?
            """,
            (
                event["event_type"],
                event["outcome"],
                event["details"],
            ),
        ).fetchall()

    assert len(rows) == 1
