# AEGIS X
**AI-Powered, Safety-First Autonomous Cloud Recovery and Verification Platform**

Tagline: **Detect. Reason. Recover. Verify.**

AEGIS X is a learning-focused reliability engineering project. Its first milestone provides a small FastAPI service with a health endpoint and automated tests. Recovery actions will be added later behind explicit safety policies and isolated testing.

## Day 1: Run the API

### Requirements
- Python 3.11+ recommended
- Git
- VS Code

### Windows PowerShell

```powershell
cd path\to\aegis-x
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

If PowerShell blocks activation, use this for the current terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Open:
- API health check: http://127.0.0.1:8000/health
- Interactive API docs: http://127.0.0.1:8000/docs

Expected `/health` response:

```json
{
  "status": "healthy",
  "service": "aegis-x-api",
  "version": "0.1.0"
}
```

### Run tests
In a second PowerShell terminal, activate the virtual environment and run:

```powershell
pytest -q
```

## Current scope
- Implemented: API health endpoint and automated tests.
- Not implemented yet: AI diagnosis, self-healing, cloud integrations, production deployment, and dashboard.
- Safety principle: an AI suggestion is not permission to execute an action. Any future recovery operation must pass deterministic policy checks and independent verification.

## Roadmap
1. Foundation and health checks
2. Structured logs and incident model
3. Failure simulation and detection
4. AI-assisted diagnosis interface
5. Safety policy engine
6. Isolated candidate-fix testing
7. Controlled recovery and rollback
8. Independent service and data verification
9. Dashboard and end-to-end demo
