from fastapi import FastAPI
from pydantic import BaseModel

APP_VERSION = "0.1.0"

app = FastAPI(
    title="AEGIS X API",
    description="Safety-first reliability and recovery platform",
    version=APP_VERSION,
)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    """Return basic service identity."""
    return {
        "name": "AEGIS X",
        "message": "Detect. Reason. Recover. Verify.",
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Return the API process health. This is not yet a full dependency check."""
    return HealthResponse(
        status="healthy",
        service="aegis-x-api",
        version=APP_VERSION,
    )
