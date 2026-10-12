
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl, field_validator

APP_VERSION = "0.2.0"

app = FastAPI(
    title="AEGIS X API",
    description="Safety-first reliability and recovery platform",
    version=APP_VERSION,
)

services: dict[str, dict] = {}
checks: list[dict] = []
incidents: dict[str, dict] = {}
data_lock = Lock()


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ServiceRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    timeout_seconds: float = Field(default=5.0, gt=0, le=15)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are allowed")
        if value.username or value.password:
            raise ValueError("URLs must not contain credentials")
        return value


class ServiceRecord(BaseModel):
    id: str
    name: str
    url: str
    timeout_seconds: float
    created_at: str


class CheckResult(BaseModel):
    id: str
    service_id: str
    service_name: str
    status: str
    http_status_code: int | None
    latency_ms: float | None
    error: str | None
    checked_at: str


class Incident(BaseModel):
    id: str
    service_id: str
    service_name: str
    reason: str
    status: str
    created_at: str
    resolved_at: str | None = None


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "name": "AEGIS X",
        "message": "Detect. Reason. Recover. Verify.",
        "docs": "/docs",
        "version": APP_VERSION,
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        service="aegis-x-api",
        version=APP_VERSION,
    )


@app.post("/services", response_model=ServiceRecord, status_code=201)
def register_service(payload: ServiceRegistration) -> ServiceRecord:
    """Register a trusted HTTP service for manual health checks."""
    service_id = str(uuid4())
    record = {
        "id": service_id,
        "name": payload.name,
        "url": str(payload.url),
        "timeout_seconds": payload.timeout_seconds,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with data_lock:
        services[service_id] = record

    return ServiceRecord(**record)


@app.get("/services", response_model=list[ServiceRecord])
def list_services() -> list[ServiceRecord]:
    with data_lock:
        records = list(services.values())
    return [ServiceRecord(**item) for item in records]


@app.post("/services/{service_id}/check", response_model=CheckResult)
def check_service(service_id: str) -> CheckResult:
    """Perform one bounded HTTP check; this does not execute recovery."""
    with data_lock:
        service = services.get(service_id)

    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    started = datetime.now(timezone.utc)
    start_clock = __import__("time").perf_counter()
    status_code = None
    error = None
    result_status = "healthy"

    try:
        # Redirects are disabled so a monitored URL cannot redirect this
        # request to a different destination.
        with httpx.Client(
            timeout=service["timeout_seconds"],
            follow_redirects=False,
        ) as client:
            response = client.get(service["url"])
            status_code = response.status_code

        if not 200 <= status_code < 300:
            result_status = "unhealthy"
            error = "http_error"

    except httpx.TimeoutException:
        result_status = "unhealthy"
        error = "timeout"

    except httpx.RequestError:
        result_status = "unhealthy"
        error = "connection_error"

    latency_ms = round(
        (__import__("time").perf_counter() - start_clock) * 1000,
        2,
    )

    checked_at = datetime.now(timezone.utc).isoformat()

    result = {
        "id": str(uuid4()),
        "service_id": service_id,
        "service_name": service["name"],
        "status": result_status,
        "http_status_code": status_code,
        "latency_ms": latency_ms,
        "error": error,
        "checked_at": checked_at,
    }

    with data_lock:
        checks.append(result)

        if result_status == "unhealthy":
            # Avoid creating a duplicate open incident for every failed check.
            existing = next(
                (
                    incident
                    for incident in incidents.values()
                    if incident["service_id"] == service_id
                    and incident["status"] == "open"
                ),
                None,
            )

            if existing is None:
                incident = {
                    "id": str(uuid4()),
                    "service_id": service_id,
                    "service_name": service["name"],
                    "reason": error or "unhealthy",
                    "status": "open",
                    "created_at": checked_at,
                    "resolved_at": None,
                }
                incidents[incident["id"]] = incident

        else:
            # A successful check resolves an open incident for this service.
            for incident in incidents.values():
                if (
                    incident["service_id"] == service_id
                    and incident["status"] == "open"
                ):
                    incident["status"] = "resolved"
                    incident["resolved_at"] = checked_at

    return CheckResult(**result)


@app.get("/checks", response_model=list[CheckResult])
def list_checks(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[CheckResult]:
    with data_lock:
        recent = list(reversed(checks[-limit:]))
    return [CheckResult(**item) for item in recent]


@app.get("/incidents", response_model=list[Incident])
def list_incidents(
    unresolved_only: bool = False,
) -> list[Incident]:
    with data_lock:
        records = list(incidents.values())

    if unresolved_only:
        records = [item for item in records if item["status"] == "open"]

    records.reverse()
    return [Incident(**item) for item in records]
