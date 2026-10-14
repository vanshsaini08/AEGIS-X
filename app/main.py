
import os
import ipaddress
import socket
import sqlite3
import time
import asyncio
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl, field_validator


APP_VERSION = "0.3.0"

ALLOWED_MONITOR_HOSTS = {
    host.strip().lower().rstrip(".")
    for host in os.getenv(
        "VELTRIX_ALLOWED_MONITOR_HOSTS",
        "example.com",
    ).split(",")
    if host.strip()
}

MONITOR_INTERVAL_SECONDS = max(
    5,
    int(os.getenv("VELTRIX_MONITOR_INTERVAL_SECONDS", "30")),
)

DB_PATH = Path(
    os.getenv(
        "VELTRIX_DB_PATH",
        str(Path(__file__).resolve().parent / "veltrix.db"),
    )
).resolve()

data_lock = Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_public_destination(url: str) -> None:
    """Allow only approved public hostnames for monitoring."""
    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname")

    if parsed.username or parsed.password:
        raise ValueError("URLs must not contain credentials")

    hostname = parsed.hostname.rstrip(".").lower()

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid destination port") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid destination port")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not literal_ip.is_global:
            raise ValueError("Non-public IP destinations are blocked")
        raise ValueError("IP-literal destinations are not allowed")

    if hostname not in ALLOWED_MONITOR_HOSTS:
        raise ValueError("Hostname is not in the monitoring allowlist")

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError) as exc:
        raise ValueError("Hostname could not be resolved") from exc

    if not addresses:
        raise ValueError("Hostname has no usable IP addresses")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("Hostname resolves to a non-public IP")


@contextmanager
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with get_db() as db:
        db.execute("PRAGMA journal_mode = WAL")

        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                timeout_seconds REAL NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checks (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                status TEXT NOT NULL,
                http_status_code INTEGER,
                latency_ms REAL,
                error TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY(service_id) REFERENCES services(id)
            );

            CREATE INDEX IF NOT EXISTS idx_checks_service_time
            ON checks(service_id, checked_at);

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(service_id) REFERENCES services(id)
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_service_status
            ON incidents(service_id, status);

            CREATE TABLE IF NOT EXISTS security_audit (
                id TEXT PRIMARY KEY,
                service_id TEXT,
                event_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_audit_created_at
            ON security_audit(created_at);
            """
        )



def write_security_audit(
    service_id: str | None,
    event_type: str,
    outcome: str,
    details: str,
) -> None:
    """Save security events, suppressing identical events for 10 minutes."""
    safe_details = details[:1000]
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=10)).isoformat()
    created_at = now.isoformat()

    with data_lock, get_db() as db:
        duplicate = db.execute(
            """
            SELECT 1
            FROM security_audit
            WHERE service_id IS ?
              AND event_type = ?
              AND outcome = ?
              AND details = ?
              AND created_at >= ?
            LIMIT 1
            """,
            (
                service_id,
                event_type,
                outcome,
                safe_details,
                cutoff,
            ),
        ).fetchone()

        if duplicate is not None:
            return

        db.execute(
            """
            INSERT INTO security_audit
            (id, service_id, event_type, outcome, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                service_id,
                event_type,
                outcome,
                safe_details,
                created_at,
            ),
        )



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


class SecurityAuditRecord(BaseModel):
    id: str
    service_id: str | None
    event_type: str
    outcome: str
    details: str
    created_at: str


async def run_monitoring_cycle() -> None:
    """Run one monitoring cycle for all registered services."""
    with get_db() as db:
        rows = db.execute(
            "SELECT id FROM services ORDER BY created_at"
        ).fetchall()

    for row in rows:
        try:
            await asyncio.to_thread(check_service, row["id"])
        except Exception as exc:
            print(
                "VELTRIX monitoring error for "
                f"{row['id']}: {type(exc).__name__}"
            )


async def monitoring_loop() -> None:
    while True:
        try:
            await run_monitoring_cycle()
        except Exception as exc:
            print(
                "VELTRIX monitoring loop error: "
                f"{type(exc).__name__}"
            )

        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    monitoring_task = asyncio.create_task(monitoring_loop())

    try:
        yield
    finally:
        monitoring_task.cancel()
        try:
            await monitoring_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="VELTRIX API",
    description="Safety-first reliability monitoring platform",
    version=APP_VERSION,
    lifespan=lifespan,
)

# Create missing tables without deleting existing data.
init_db()


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "name": "VELTRIX",
        "message": "Detect. Reason. Recover. Verify.",
        "docs": "/docs",
        "version": APP_VERSION,
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        service="veltrix-api",
        version=APP_VERSION,
    )


@app.post("/services", response_model=ServiceRecord, status_code=201)
def register_service(payload: ServiceRegistration) -> ServiceRecord:
    record = {
        "id": str(uuid4()),
        "name": payload.name,
        "url": str(payload.url),
        "timeout_seconds": payload.timeout_seconds,
        "created_at": utc_now(),
    }

    with data_lock, get_db() as db:
        db.execute(
            """
            INSERT INTO services
            (id, name, url, timeout_seconds, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            tuple(record.values()),
        )

    return ServiceRecord(**record)


@app.get("/services", response_model=list[ServiceRecord])
def list_services() -> list[ServiceRecord]:
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM services ORDER BY created_at"
        ).fetchall()

    return [ServiceRecord(**dict(row)) for row in rows]


@app.post(
    "/services/{service_id}/check",
    response_model=CheckResult,
    tags=["monitoring"],
)
def check_service(service_id: str) -> CheckResult:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM services WHERE id = ?",
            (service_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Service not found")

    service = dict(row)
    start_clock = time.perf_counter()
    status_code = None
    error = None
    result_status = "healthy"

    try:
        validate_public_destination(service["url"])

        with httpx.Client(
            timeout=service["timeout_seconds"],
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.get(service["url"])
            status_code = response.status_code

        if not 200 <= status_code < 300:
            result_status = "unhealthy"
            error = "http_error"

    except ValueError as exc:
        result_status = "unhealthy"
        error = "unsafe_destination"

        try:
            write_security_audit(
                service_id=service_id,
                event_type="outbound_request_blocked",
                outcome="blocked",
                details=str(exc),
            )
        except sqlite3.Error as audit_exc:
            print(
                "VELTRIX audit write failed: "
                f"{type(audit_exc).__name__}"
            )

    except httpx.TimeoutException:
        result_status = "unhealthy"
        error = "timeout"

    except httpx.RequestError:
        result_status = "unhealthy"
        error = "connection_error"

    result = {
        "id": str(uuid4()),
        "service_id": service_id,
        "service_name": service["name"],
        "status": result_status,
        "http_status_code": status_code,
        "latency_ms": round(
            (time.perf_counter() - start_clock) * 1000,
            2,
        ),
        "error": error,
        "checked_at": utc_now(),
    }

    with data_lock, get_db() as db:
        db.execute(
            """
            INSERT INTO checks
            (id, service_id, service_name, status,
             http_status_code, latency_ms, error, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(result.values()),
        )

        if result_status == "unhealthy":
            existing = db.execute(
                """
                SELECT id FROM incidents
                WHERE service_id = ? AND status = 'open'
                LIMIT 1
                """,
                (service_id,),
            ).fetchone()

            if existing is None:
                db.execute(
                    """
                    INSERT INTO incidents
                    (id, service_id, service_name, reason,
                     status, created_at, resolved_at)
                    VALUES (?, ?, ?, ?, 'open', ?, NULL)
                    """,
                    (
                        str(uuid4()),
                        service_id,
                        service["name"],
                        error or "unhealthy",
                        result["checked_at"],
                    ),
                )
        else:
            db.execute(
                """
                UPDATE incidents
                SET status = 'resolved', resolved_at = ?
                WHERE service_id = ? AND status = 'open'
                """,
                (result["checked_at"], service_id),
            )

    return CheckResult(**result)


@app.get("/checks", response_model=list[CheckResult], tags=["monitoring"])
def list_checks(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[CheckResult]:
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM checks ORDER BY checked_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [CheckResult(**dict(row)) for row in rows]


@app.get("/incidents", response_model=list[Incident], tags=["monitoring"])
def list_incidents(
    unresolved_only: bool = False,
) -> list[Incident]:
    query = "SELECT * FROM incidents"

    if unresolved_only:
        query += " WHERE status = 'open'"

    query += " ORDER BY created_at DESC"

    with get_db() as db:
        rows = db.execute(query).fetchall()

    return [Incident(**dict(row)) for row in rows]


@app.get(
    "/security-audit",
    response_model=list[SecurityAuditRecord],
    tags=["security"],
)
def list_security_audit(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[SecurityAuditRecord]:
    with get_db() as db:
        rows = db.execute(
            """
            SELECT id, service_id, event_type, outcome,
                   details, created_at
            FROM security_audit
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        SecurityAuditRecord(**dict(row))
        for row in rows
    ]
