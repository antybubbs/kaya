import json
import secrets
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import encrypt_secret
from app.db.session import get_db
from app.models.models import ComputeEvent, ComputeHost, ComputeInventoryItem, ComputeMetric, ComputeWorkload
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit
from app.services.compute_monitor import compute_summary, sync_host
from datetime import datetime

router=APIRouter(prefix='/infrastructure/vm-docker-manager')
templates=Jinja2Templates(directory='app/templates')

def metadata(value):
    try: return json.loads(value or '{}')
    except json.JSONDecodeError: return {}

def bytes_label(value):
    if value is None: return '-'
    number=float(value)
    for unit in ('B','KB','MB','GB','TB','PB'):
        if abs(number)<1024: return f'{number:.1f} {unit}' if unit!='B' else f'{int(number)} B'
        number/=1024
    return f'{number:.1f} EB'

def pct(used,total): return round(used/total*100,1) if used is not None and total else None

def context(**extra): return {**extra,'metadata':metadata,'bytes_label':bytes_label,'pct':pct}

@router.get('')
def overview(request:Request,q:str=Query('',max_length=200),view:str=Query('overview',max_length=30),db:Session=Depends(get_db),user=Depends(require_user)):
    clean=q.strip(); query=db.query(ComputeWorkload).filter(ComputeWorkload.status!='missing')
    if clean: query=query.filter(or_(ComputeWorkload.name.ilike(f'%{clean}%'),ComputeWorkload.node.ilike(f'%{clean}%'),ComputeWorkload.owner.ilike(f'%{clean}%'),ComputeWorkload.tags.ilike(f'%{clean}%')))
    if view=='docker': query=query.filter(ComputeWorkload.kind=='container')
    elif view=='proxmox': query=query.filter(ComputeWorkload.kind.in_(['node','vm','lxc']))
    workloads=query.order_by(ComputeWorkload.status.asc(),ComputeWorkload.name.asc()).limit(500).all()
    hosts=db.query(ComputeHost).order_by(ComputeHost.name).all(); items=db.query(ComputeInventoryItem).order_by(ComputeInventoryItem.kind,ComputeInventoryItem.name).all(); events=db.query(ComputeEvent).order_by(ComputeEvent.created_at.desc()).limit(12).all()
    return templates.TemplateResponse(request,'compute_manager.html',context(user=user,hosts=hosts,workloads=workloads,items=items,events=events,summary=compute_summary(db),q=clean,view=view,**csrf_context(request)))

@router.get('/api/summary')
def summary_api(db:Session=Depends(get_db),user=Depends(require_user)):
    summary=compute_summary(db); summary['updated_at']=summary['updated_at'].isoformat() if summary['updated_at'] else None
    summary['hosts']=[{'id':h.id,'name':h.name,'platform':h.platform,'status':h.status,'cpu':h.cpu_percent,'memory':pct(h.memory_used,h.memory_total),'storage':pct(h.storage_used,h.storage_total),'updated_at':h.last_synced_at.isoformat() if h.last_synced_at else None,'error':h.last_error} for h in db.query(ComputeHost).order_by(ComputeHost.name)]
    summary['workloads']=[{'id':w.id,'name':w.name,'kind':w.kind,'host':w.host.name,'status':w.status,'cpu':w.cpu_percent,'memory':pct(w.memory_used,w.memory_total),'storage':pct(w.storage_used,w.storage_total),'owner':w.owner} for w in db.query(ComputeWorkload).filter(ComputeWorkload.status!='missing').order_by(ComputeWorkload.name)]
    return JSONResponse(summary)

@router.get('/hosts/new')
def new_host(request:Request,user=Depends(require_editor)):
    return templates.TemplateResponse(request,'compute_host_form.html',context(user=user,host=None,error=None,**csrf_context(request)))

@router.post('/hosts/new')
def create_host(request:Request,name:str=Form(...,max_length=255),platform:str=Form(...),base_url:str=Form("",max_length=500),token_id:str=Form('',max_length=255),token_secret:str=Form('',max_length=2000),verify_tls:str=Form(''),is_enabled:str=Form(''),poll_interval_seconds:int=Form(30),owner:str=Form('',max_length=255),notes:str=Form('',max_length=10000),csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); platform=platform.strip().lower(); clean_name=name.strip(); clean_url=base_url.strip()
    error=None
    if platform not in {'docker','docker_agent','proxmox'}:
        error='Choose Docker, Docker Agent or Proxmox.'
    elif not clean_name:
        error='Name is required.'
    elif platform != 'docker_agent' and not clean_url:
        error='Connection URL is required.'
    elif platform=='proxmox' and (not token_id.strip() or not token_secret.strip()): error='Proxmox requires an API token ID and secret.'
    elif db.query(ComputeHost).filter(ComputeHost.name==clean_name).first(): error='A host with that name already exists.'
    if error: return templates.TemplateResponse(request,'compute_host_form.html',context(user=user,host=None,error=error,**csrf_context(request)),status_code=400)
    row=ComputeHost(
        name=clean_name,
        platform=platform,
        base_url=clean_url if platform != 'docker_agent' else f'agent://{clean_name}',
        token_id=token_id.strip() or None,
        encrypted_token=encrypt_secret(token_secret.strip()) if token_secret.strip() else None,
        agent_token=secrets.token_urlsafe(32) if platform == 'docker_agent' else None,
        verify_tls=bool(verify_tls),
        is_enabled=bool(is_enabled),
        poll_interval_seconds=max(15,min(poll_interval_seconds,3600)),
        owner=owner.strip() or None,
        notes=notes.strip() or None,
    )
    db.add(row); db.commit(); write_audit(db,user,'create','compute_host',str(row.id),request.client.host if request.client else None,detail=row.name)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/hosts/{row.id}',status_code=303)

@router.get('/hosts/{host_id}')
def host_detail(request:Request,host_id:int,db:Session=Depends(get_db),user=Depends(require_user)):
    host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    workloads=db.query(ComputeWorkload).filter_by(host_id=host.id).order_by(ComputeWorkload.kind,ComputeWorkload.name).all(); items=db.query(ComputeInventoryItem).filter_by(host_id=host.id).order_by(ComputeInventoryItem.kind,ComputeInventoryItem.name).all(); metrics=db.query(ComputeMetric).filter(ComputeMetric.host_id==host.id,ComputeMetric.workload_id.is_(None)).order_by(ComputeMetric.recorded_at.desc()).limit(120).all()[::-1]
    return templates.TemplateResponse(request,'compute_host_detail.html',context(user=user,host=host,workloads=workloads,items=items,metrics=metrics,**csrf_context(request)))

@router.get('/hosts/{host_id}/edit')
def edit_host(request:Request,host_id:int,db:Session=Depends(get_db),user=Depends(require_editor)):
    host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    return templates.TemplateResponse(request,'compute_host_form.html',context(user=user,host=host,error=None,**csrf_context(request)))

@router.post('/hosts/{host_id}/edit')
def update_host(request:Request,host_id:int,name:str=Form(...),platform:str=Form(...),base_url:str=Form(""),token_id:str=Form(''),token_secret:str=Form(''),verify_tls:str=Form(''),is_enabled:str=Form(''),poll_interval_seconds:int=Form(30),owner:str=Form(''),notes:str=Form(''),csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    platform=platform.strip().lower()
    if platform not in {'docker','docker_agent','proxmox'}:
        raise HTTPException(400,'Invalid platform')
    host.name=name.strip(); host.platform=platform
    host.base_url=f'agent://{host.name}' if platform == 'docker_agent' else base_url.strip()
    host.token_id=token_id.strip() or None
    if token_secret.strip(): host.encrypted_token=encrypt_secret(token_secret.strip())
    if platform == 'docker_agent' and not host.agent_token: host.agent_token=secrets.token_urlsafe(32)
    host.verify_tls=bool(verify_tls); host.is_enabled=bool(is_enabled); host.poll_interval_seconds=max(15,min(poll_interval_seconds,3600)); host.owner=owner.strip() or None; host.notes=notes.strip() or None; db.commit(); write_audit(db,user,'update','compute_host',str(host.id),request.client.host if request.client else None,detail=host.name)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/hosts/{host.id}',status_code=303)

@router.post('/hosts/{host_id}/sync')
def sync_now(request:Request,host_id:int,csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    sync_host(db,host); write_audit(db,user,'sync','compute_host',str(host.id),request.client.host if request.client else None,detail=host.name)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/hosts/{host.id}',status_code=303)

@router.post('/hosts/{host_id}/delete')
def delete_host(request:Request,host_id:int,csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    name=host.name; workload_ids=[x.id for x in db.query(ComputeWorkload.id).filter_by(host_id=host.id)]
    if workload_ids: db.query(ComputeMetric).filter(ComputeMetric.workload_id.in_(workload_ids)).delete(synchronize_session=False)
    for model in (ComputeMetric,ComputeEvent,ComputeInventoryItem,ComputeWorkload): db.query(model).filter(model.host_id==host.id).delete(synchronize_session=False)
    db.delete(host); db.commit(); write_audit(db,user,'delete','compute_host',None,request.client.host if request.client else None,detail=name)
    return RedirectResponse('/infrastructure/vm-docker-manager',status_code=303)

@router.post('/api/agent/checkin')
async def agent_checkin(
    request: Request,
    db: Session = Depends(get_db),
):
    auth = request.headers.get('authorization', '')

    if not auth.lower().startswith('bearer '):
        raise HTTPException(
            status_code=401,
            detail='Missing agent token'
        )

    token = auth.split(' ', 1)[1].strip()

    host = (
        db.query(ComputeHost)
        .filter(
            ComputeHost.platform == 'docker_agent',
            ComputeHost.agent_token == token,
        )
        .first()
    )

    if not host:
        raise HTTPException(
            status_code=401,
            detail='Invalid agent token'
        )

    payload = await request.json()

    now = datetime.utcnow()

    host.status = 'online'
    host.last_synced_at = now
    host.agent_last_seen_at = now
    host.last_error = None

    if payload.get('version'):
        host.version = payload['version']

    db.commit()

    return JSONResponse({
        'ok': True,
        'host': host.name,
    })

@router.get('/workloads/{workload_id}')
def workload_detail(request:Request,workload_id:int,db:Session=Depends(get_db),user=Depends(require_user)):
    row=db.get(ComputeWorkload,workload_id)
    if not row: raise HTTPException(404,'Workload not found')
    metrics=db.query(ComputeMetric).filter_by(workload_id=row.id).order_by(ComputeMetric.recorded_at.desc()).limit(120).all()[::-1]; events=db.query(ComputeEvent).filter_by(workload_id=row.id).order_by(ComputeEvent.created_at.desc()).limit(50).all()
    return templates.TemplateResponse(request,'compute_workload_detail.html',context(user=user,row=row,metrics=metrics,events=events,**csrf_context(request)))

@router.post('/workloads/{workload_id}')
def update_workload(request:Request,workload_id:int,owner:str=Form(''),backup_policy:str=Form(''),csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); row=db.get(ComputeWorkload,workload_id)
    if not row: raise HTTPException(404,'Workload not found')
    row.owner=owner.strip() or None; row.backup_policy=backup_policy.strip() or None; db.commit(); write_audit(db,user,'update','compute_workload',str(row.id),request.client.host if request.client else None,detail=row.name)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/workloads/{row.id}',status_code=303)
