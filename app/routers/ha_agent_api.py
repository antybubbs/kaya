from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.high_availability import HAAgentEvents, HAAgentHeartbeat, HAAgentRegister
from app.services.ha_agents import HAAgentError, AuthenticatedAgent, authenticate_agent_request, desired_state, ingest_events, record_heartbeat, register_agent


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
