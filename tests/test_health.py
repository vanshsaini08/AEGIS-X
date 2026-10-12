from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint_returns_healthy_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "aegis-x-api",
        "version": "0.1.0",
    }


def test_root_endpoint_identifies_project() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["name"] == "AEGIS X"
    assert response.json()["docs"] == "/docs"
