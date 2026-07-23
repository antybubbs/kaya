import json
import secrets
import hashlib
from ipaddress import ip_address
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import encrypt_secret
from app.db.session import get_db
from app.models.models import BackupJob, ComputeEvent, ComputeHost, ComputeInventoryItem, ComputeMetric, ComputeWorkload, IPAddress
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.compute_monitor import compute_summary, prune_missing_workloads, reconcile_workload, sync_host, workload_identity
from app.services.site_settings import get_site_setting
from datetime import datetime, timedelta


router=APIRouter(prefix='/infrastructure/vm-docker-manager', dependencies=[Depends(require_module_access("compute_manager"))])
agent_router=APIRouter(prefix='/infrastructure/vm-docker-manager')
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

def uptime_label(value):
    if value is None: return '-'
    seconds=max(0,int(value)); days,seconds=divmod(seconds,86400); hours,seconds=divmod(seconds,3600); minutes,_=divmod(seconds,60)
    if days: return f'{days}d {hours}h'
    if hours: return f'{hours}h {minutes}m'
    if minutes: return f'{minutes}m'
    return '<1m'

def normalize_address(value):
    try:
        parsed=ip_address(str(value).strip().split('/')[0].split('%')[0])
    except (TypeError,ValueError):
        return None
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    return str(parsed)

def workload_addresses(row):
    data=metadata(row.metadata_json); found=[]; seen=set()
    def add(value,label=None):
        address=normalize_address(value)
        if not address or address in seen: return
        seen.add(address); found.append({'address':address,'label':label})
    raw=data.get('ip_addresses') or []
    if isinstance(raw,(str,dict)): raw=[raw]
    for item in raw:
        if isinstance(item,dict): add(item.get('address') or item.get('ip_address') or item.get('ip-address'),item.get('network') or item.get('interface') or item.get('name'))
        else: add(item)
    networks=data.get('networks') or {}
    if isinstance(networks,dict):
        for name,network in networks.items():
            network=network or {}; values=network.get('addresses') or [network.get('IPAddress'),network.get('GlobalIPv6Address'),network.get('ip_address')]
            if isinstance(values,str): values=[values]
            for value in values: add(value,name)
    return found

def workload_network_context(db,rows):
    result={row.id:workload_addresses(row) for row in rows}; addresses={item['address'] for items in result.values() for item in items}
    records={}
    if addresses:
        for record in db.query(IPAddress).all():
            normalized=normalize_address(record.address)
            if normalized in addresses: records[normalized]=record
    for items in result.values():
        for item in items: item['record']=records.get(item['address'])
    return result

def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def context(**extra): return {**extra,'metadata':metadata,'bytes_label':bytes_label,'pct':pct,'uptime_label':uptime_label}

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
    if platform not in {'docker_agent','proxmox'}:
        error='Choose Docker Agent or Proxmox.'
    elif not clean_name:
        error='Name is required.'
    elif platform == 'proxmox' and not clean_url:
        error='Proxmox connection URL is required.'
    elif platform=='proxmox' and (not token_id.strip() or not token_secret.strip()): error='Proxmox requires an API token ID and secret.'
    elif db.query(ComputeHost).filter(ComputeHost.name==clean_name).first(): error='A host with that name already exists.'
    if error: return templates.TemplateResponse(request,'compute_host_form.html',context(user=user,host=None,error=error,**csrf_context(request)),status_code=400)
    agent_token = secrets.token_urlsafe(32) if platform == 'docker_agent' else None

    row=ComputeHost(
        name=clean_name,
        platform=platform,
        base_url=clean_url if platform != 'docker_agent' else f'agent://{clean_name}',
        token_id=token_id.strip() or None,
        encrypted_token=encrypt_secret(token_secret.strip()) if token_secret.strip() else None,
        agent_token_hash=hash_agent_token(agent_token) if agent_token else None,
        verify_tls=bool(verify_tls),
        is_enabled=bool(is_enabled),
        poll_interval_seconds=max(15,min(poll_interval_seconds,3600)),
        owner=owner.strip() or None,
        notes=notes.strip() or None,
    )
    db.add(row); db.commit(); write_audit(db,user,'create','compute_host',str(row.id),request.client.host if request.client else None,detail=row.name)
    if agent_token:
        return render_host_detail(request,row,db,user,agent_token=agent_token,status_code=201)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/hosts/{row.id}',status_code=303)

def render_host_detail(request:Request,host:ComputeHost,db:Session,user,agent_token:str|None=None,status_code:int=200):
    workloads=db.query(ComputeWorkload).filter_by(host_id=host.id).order_by(ComputeWorkload.kind,ComputeWorkload.name).all()
    items=db.query(ComputeInventoryItem).filter_by(host_id=host.id).order_by(ComputeInventoryItem.kind,ComputeInventoryItem.name).all()
    metrics=db.query(ComputeMetric).filter(ComputeMetric.host_id==host.id,ComputeMetric.workload_id.is_(None)).order_by(ComputeMetric.recorded_at.desc()).limit(120).all()[::-1]
    backup_storage_path=get_site_setting(db,'backup_storage_path') or '/mnt/backups'
    backup_storage_type=get_site_setting(db,'backup_storage_type') or 'local'
    return templates.TemplateResponse(request,'compute_host_detail.html',context(user=user,host=host,workloads=workloads,items=items,metrics=metrics,agent_token=agent_token,backup_storage_path=backup_storage_path,backup_storage_type=backup_storage_type,**csrf_context(request)),status_code=status_code)

@router.get('/hosts/{host_id}')
def host_detail(request:Request,host_id:int,db:Session=Depends(get_db),user=Depends(require_user)):
    host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    return render_host_detail(request,host,db,user)

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
    if platform not in {'docker_agent','proxmox'}:
        raise HTTPException(400,'Invalid platform')
    if not name.strip():
        raise HTTPException(400,'Name is required')
    if platform == 'proxmox' and not base_url.strip():
        raise HTTPException(400,'Proxmox connection URL is required')
    host.name=name.strip(); host.platform=platform
    host.base_url=f'agent://{host.name}' if platform == 'docker_agent' else base_url.strip()
    host.token_id=token_id.strip() or None
    if platform == 'docker_agent':
        host.encrypted_token=None
    elif token_secret.strip():
        host.encrypted_token=encrypt_secret(token_secret.strip())
    if platform == 'docker_agent' and not host.agent_token_hash:
        agent_token=secrets.token_urlsafe(32)
        host.agent_token_hash=hash_agent_token(agent_token)
        host.encrypted_agent_token=None
    else:
        agent_token=None
    host.verify_tls=bool(verify_tls); host.is_enabled=bool(is_enabled); host.poll_interval_seconds=max(15,min(poll_interval_seconds,3600)); host.owner=owner.strip() or None; host.notes=notes.strip() or None; db.commit(); write_audit(db,user,'update','compute_host',str(host.id),request.client.host if request.client else None,detail=host.name)
    if agent_token:
        return render_host_detail(request,host,db,user,agent_token=agent_token)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/hosts/{host.id}',status_code=303)

@router.post('/hosts/{host_id}/regenerate-agent-token')
def regenerate_agent_token(request:Request,host_id:int,csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); host=db.get(ComputeHost,host_id)
    if not host: raise HTTPException(404,'Host not found')
    if host.platform != 'docker_agent': raise HTTPException(400,'Host does not use a Docker agent')
    agent_token=secrets.token_urlsafe(32)
    host.agent_token_hash=hash_agent_token(agent_token)
    host.encrypted_agent_token=None
    db.commit()
    write_audit(db,user,'regenerate_agent_token','compute_host',str(host.id),request.client.host if request.client else None,detail=host.name)
    return render_host_detail(request,host,db,user,agent_token=agent_token)

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
    db.query(BackupJob).filter(BackupJob.host_id==host.id).delete(synchronize_session=False)
    if workload_ids: db.query(ComputeMetric).filter(ComputeMetric.workload_id.in_(workload_ids)).delete(synchronize_session=False)
    for model in (ComputeMetric,ComputeEvent,ComputeInventoryItem,ComputeWorkload): db.query(model).filter(model.host_id==host.id).delete(synchronize_session=False)
    db.delete(host); db.commit(); write_audit(db,user,'delete','compute_host',None,request.client.host if request.client else None,detail=name)
    return RedirectResponse('/infrastructure/vm-docker-manager',status_code=303)

@agent_router.post('/api/agent/checkin')
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

    token_hash = hash_agent_token(token)
    host = db.query(ComputeHost).filter(
        ComputeHost.platform == 'docker_agent',
        ComputeHost.agent_token_hash == token_hash,
    ).first()

    if not host:
        raise HTTPException(
            status_code=401,
            detail='Invalid agent token'
        )

    payload = await request.json()
    now = datetime.utcnow()

    host_data = payload.get('host') or {}

    host.status = 'online'
    host.last_synced_at = now
    host.agent_last_seen_at = now
    host.last_error = None
    host.version = payload.get('version') or host.version
    host.cpu_percent = host_data.get('cpu_percent')
    host.memory_used = host_data.get('memory_used')
    host.memory_total = host_data.get('memory_total')
    host.storage_used = host_data.get('storage_used')
    host.storage_total = host_data.get('storage_total')
    host.metadata_json = json.dumps(host_data.get('metadata') or {})

    seen = set()

    for data in payload.get('workloads') or []:
        kind = data.get('kind') or 'container'
        reported_id = str(data.get('external_id') or data.get('name'))
        name = data.get('name') or reported_id
        external_id = workload_identity(kind,reported_id,name)
        row,_ = reconcile_workload(db,host.id,kind,external_id,name)

        row.name = name
        row.node = host.name
        row.status = data.get('status') or 'unknown'
        row.cpu_percent = data.get('cpu_percent')
        row.cpu_total = data.get('cpu_total')
        row.memory_used = data.get('memory_used')
        row.memory_total = data.get('memory_total')
        row.storage_used = data.get('storage_used')
        row.storage_total = data.get('storage_total')
        row.uptime_seconds = data.get('uptime_seconds')
        row.tags = data.get('tags')
        workload_meta = dict(data.get('metadata') or {})
        for key in ('ip_addresses', 'networks'):
            if data.get(key) and not workload_meta.get(key):
                workload_meta[key] = data.get(key)
        row.metadata_json = json.dumps(workload_meta)
        row.last_seen_at = now
        row.updated_at = now

        seen.add((row.kind, row.external_id))

    for row in db.query(ComputeWorkload).filter_by(host_id=host.id).all():
        if (row.kind, row.external_id) not in seen and row.status != 'missing':
            row.status = 'missing'
            db.add(
                ComputeEvent(
                    host_id=host.id,
                    workload_id=row.id,
                    event_type='missing',
                    detail=f'{row.name} is no longer reported by the agent',
                )
            )
    prune_missing_workloads(db,host.id,now)

    db.query(ComputeInventoryItem).filter_by(host_id=host.id).delete(
        synchronize_session=False
    )

    inventory_seen = set()

    for data in payload.get('items') or []:
        external_id = str(data.get('external_id') or data.get('name'))
        kind = data.get('kind') or 'item'

        if (kind, external_id) in inventory_seen:
            continue

        inventory_seen.add((kind, external_id))

        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id=external_id,
                name=data.get('name') or external_id,
                kind=kind,
                status=data.get('status'),
                size_bytes=data.get('size_bytes'),
                metadata_json=json.dumps(data.get('metadata') or {}),
                last_seen_at=now,
            )
        )

    db.add(
        ComputeMetric(
            host_id=host.id,
            cpu_percent=host.cpu_percent,
            memory_used=host.memory_used,
            memory_total=host.memory_total,
            storage_used=host.storage_used,
            storage_total=host.storage_total,
            recorded_at=now,
        )
    )

    db.query(ComputeMetric).filter(
        ComputeMetric.recorded_at < now - timedelta(days=7)
    ).delete(synchronize_session=False)
    db.query(ComputeEvent).filter(
        ComputeEvent.created_at < now - timedelta(days=90)
    ).delete(synchronize_session=False)

    db.commit()

    return JSONResponse({
        'ok': True,
        'host': host.name,
        'workloads': len(payload.get('workloads') or []),
        'items': len(payload.get('items') or []),
    })

@router.get('/workloads/{workload_id}')
def workload_detail(request:Request,workload_id:int,db:Session=Depends(get_db),user=Depends(require_user)):
    row=db.get(ComputeWorkload,workload_id)
    if not row: raise HTTPException(404,'Workload not found')
    metrics=db.query(ComputeMetric).filter_by(workload_id=row.id).order_by(ComputeMetric.recorded_at.desc()).limit(120).all()[::-1]; events=db.query(ComputeEvent).filter_by(workload_id=row.id).order_by(ComputeEvent.created_at.desc()).limit(50).all()
    network=workload_network_context(db,[row]).get(row.id,[])
    return templates.TemplateResponse(request,'compute_workload_detail.html',context(user=user,row=row,network=network,metrics=metrics,events=events,**csrf_context(request)))

@router.post('/workloads/{workload_id}')
def update_workload(request:Request,workload_id:int,owner:str=Form(''),backup_policy:str=Form(''),csrf_token:str=Form(...),db:Session=Depends(get_db),user=Depends(require_editor)):
    validate_csrf_token(request,csrf_token); row=db.get(ComputeWorkload,workload_id)
    if not row: raise HTTPException(404,'Workload not found')
    row.owner=owner.strip() or None; row.backup_policy=backup_policy.strip() or None; db.commit(); write_audit(db,user,'update','compute_workload',str(row.id),request.client.host if request.client else None,detail=row.name)
    return RedirectResponse(f'/infrastructure/vm-docker-manager/workloads/{row.id}',status_code=303)
