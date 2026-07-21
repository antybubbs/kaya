from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.high_availability import HAAgentActionResult, HAAgentEvents, HAAgentHeartbeat, HAAgentRegister
from app.services.ha_agents import HAAgentError, AuthenticatedAgent, authenticate_agent_request, desired_state, ingest_events, record_action_result, record_heartbeat, register_agent
from app.services.ha_agent_installer import agent_file
from app.services.ha_leases import HALeaseError, snapshot_for_agent


router = APIRouter(prefix="/api/ha/agent/v1", tags=["ha-agent"])
_registration_attempts: dict[str, list[datetime]] = {}


def registration_rate_limited(request: Request) -> bool:
    now = datetime.utcnow()
    key = request.client.host if request.client else "unknown"
    recent = [item for item in _registration_attempts.get(key, []) if item >= now - timedelta(minutes=10)]
    limited = len(recent) >= 10
    if not limited:
        recent.append(now)
    _registration_attempts[key] = recent
    return limited


async def require_agent(request: Request, db: Session = Depends(get_db)) -> AuthenticatedAgent:
    return await authenticate_agent_request(request, db)


@router.get("/install.sh", include_in_schema=False)
def install_script():
    return Response(agent_file("install.sh"), media_type="text/x-shellscript", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/files/{name}", include_in_schema=False)
def install_file(name: str):
    try:
        content = agent_file(name)
    except FileNotFoundError:
        raise HTTPException(404, "Agent installation file not found")
    return Response(content, media_type="application/octet-stream", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.post("/register", status_code=201)
def register(payload: HAAgentRegister, request: Request, db: Session = Depends(get_db)):
    if registration_rate_limited(request):
        raise HTTPException(429, "Agent registration rate limit exceeded")
    try:
        credential, node = register_agent(db, payload)
    except HAAgentError as exc:
        raise HTTPException(401, str(exc))
    return {
        "protocol_version": 1,
        "agent_id": credential.agent_id,
        "cluster_id": node.cluster.public_id,
        "node_id": node.public_id,
        "registered": True,
    }


@router.post("/heartbeat")
def heartbeat(payload: HAAgentHeartbeat, db: Session = Depends(get_db), agent: AuthenticatedAgent = Depends(require_agent)):
    node = record_heartbeat(db, agent.node, payload)
    return {"accepted": True, "received_generation": node.observed_generation, "desired": desired_state(node)}


@router.post("/events")
def events(payload: HAAgentEvents, db: Session = Depends(get_db), agent: AuthenticatedAgent = Depends(require_agent)):
    accepted, duplicates = ingest_events(db, agent.node, payload.events)
    return {"accepted": accepted, "duplicates": duplicates}


@router.get("/desired-state")
def get_desired_state(agent: AuthenticatedAgent = Depends(require_agent)):
    return desired_state(agent.node)


@router.get("/lease-snapshot/{generation}")
def lease_snapshot(generation: int, agent: AuthenticatedAgent = Depends(require_agent)):
    try:
        payload = snapshot_for_agent(agent.node, generation)
    except HALeaseError as exc:
        raise HTTPException(404, str(exc))
    return Response(
        content=__import__("json").dumps(payload, separators=(",", ":")),
        media_type="application/json",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.post("/action-result")
def action_result(payload: HAAgentActionResult, db: Session = Depends(get_db), agent: AuthenticatedAgent = Depends(require_agent)):
    try:
        row = record_action_result(db, agent.node, payload)
    except HAAgentError as exc:
        raise HTTPException(409, str(exc))
    return {"accepted": True, "action_id": row.action_id, "status": row.status}
