# AEGIS X — Initial Architecture

## Day 1 component

```text
Developer / Browser
       |
       v
FastAPI API (:8000)
       |
       +--> GET /health
       +--> GET /
```

## Target architecture

```text
Monitored Demo Service
        |
        v
Health Checks + Logs
        |
        v
Incident Detection --> Incident Store
        |
        v
AI-Assisted Diagnosis --> Candidate Fix / Recovery Proposal
        |
        v
Deterministic Safety Policy
        |
        +--> Deny / Require Human Approval
        |
        v
Isolated Test Runner --> Regression Tests
        |
        v
Authorized Recovery Executor
        |
        v
Independent Verification --> Success / Rollback / Escalation
```

## Safety boundaries
- Never execute arbitrary AI-generated shell commands.
- Recovery actions must come from an allowlist.
- Test candidate fixes in an isolated environment.
- Apply timeouts and bounded retries.
- Verify service health and relevant data invariants after recovery.
- Record decisions, actions, test outcomes, and verification results.
