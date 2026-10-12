
import httpx
import pytest
from fastapi.testclient import TestClient

from app import main

client = TestClient(main.app)


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["name"] == "AEGIS X"
    assert response.json()["version"] == "0.2.0"


def test_health_endpoint_returns_healthy_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "aegis-x-api",
        "version": "0.2.0",
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
    assert any(item["id"] == service["id"] for item in listed.json())


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


def test_failed_check_creates_incident(monkeypatch: pytest.MonkeyPatch) -> None:
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
    service_id = registered.json()["id"]

    checked = client.post(f"/services/{service_id}/check")
    assert checked.status_code == 200
    assert checked.json()["status"] == "unhealthy"
    assert checked.json()["error"] == "http_error"

    incidents = client.get("/incidents", params={"unresolved_only": True})
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

    monkeypatch.setattr(main.httpx, "Client", FakeClient)

    registered = client.post(
        "/services",
        json={
            "name": "Mock Recovery Service",
            "url": "https://example.com",
        },
    )
    service_id = registered.json()["id"]

    # First check fails and opens an incident.
    monkeypatch.setattr(
        main.httpx,
        "Client",
        type(
            "FailingClient",
            (),
            {
                "__init__": lambda self, *args, **kwargs: None,
                "__enter__": lambda self: self,
                "__exit__": lambda self, *args: None,
                "get": lambda self, url: type(
                    "Response", (), {"status_code": 503}
                )(),
            },
        ),
    )
    client.post(f"/services/{service_id}/check")

    # Next check succeeds, so the incident should be resolved.
    monkeypatch.setattr(main.httpx, "Client", FakeClient)
    checked = client.post(f"/services/{service_id}/check")

    assert checked.status_code == 200
    assert checked.json()["status"] == "healthy"

    incidents = client.get("/incidents")
    matching = [
        incident
        for incident in incidents.json()
        if incident["service_id"] == service_id
    ]
    assert matching
    assert matching[0]["status"] == "resolved"
