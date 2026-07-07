import asyncio, http.client, json, socket, ssl
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from app.core.security import decrypt_secret
from app.db.session import SessionLocal
from app.models.models import ComputeEvent, ComputeHost, ComputeInventoryItem, ComputeMetric, ComputeWorkload

class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path): super().__init__('localhost', timeout=15); self.path=path
    def connect(self): self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.sock.settimeout(15); self.sock.connect(self.path)

def request_json(host,path):
    if host.platform=='docker' and host.base_url.startswith('unix://'):
        c=UnixConnection(host.base_url[7:]); c.request('GET',path); r=c.getresponse(); data=r.read()
        if r.status>=400: raise RuntimeError(f'Docker API HTTP {r.status}')
        return json.loads(data or b'null')
    headers={'Accept':'application/json','User-Agent':'Kaya/ComputeMonitor'}
    if host.platform=='proxmox':
        token=decrypt_secret(host.encrypted_token)
        if not host.token_id or not token or token=='[decryption failed]': raise RuntimeError('A valid Proxmox API token is required.')
        headers['Authorization']=f'PVEAPIToken={host.token_id}={token}'
    context=None
    if host.base_url.startswith('https://'): context=ssl.create_default_context() if host.verify_tls else ssl._create_unverified_context()
    with urlopen(Request(host.base_url.rstrip('/')+path,headers=headers),timeout=15,context=context) as r: return json.loads(r.read() or b'null')

def docker_cpu(stats):
    cur,prev=stats.get('cpu_stats') or {},stats.get('precpu_stats') or {}
    cpu=(cur.get('cpu_usage') or {}).get('total_usage',0)-(prev.get('cpu_usage') or {}).get('total_usage',0)
    system=cur.get('system_cpu_usage',0)-prev.get('system_cpu_usage',0); cpus=cur.get('online_cpus') or 1
    return round(cpu/system*cpus*100,2) if cpu>0 and system>0 else None

def docker_uptime(started_at):
    if not started_at or str(started_at).startswith('0001-01-01'):
        return None
    try:
        started=datetime.fromisoformat(str(started_at).replace('Z','+00:00'))
        now=datetime.now(started.tzinfo) if started.tzinfo else datetime.utcnow()
        return max(0,int((now-started).total_seconds()))
    except (TypeError,ValueError):
        return None

def docker_networks(container,inspect):
    networks=((inspect.get('NetworkSettings') or {}).get('Networks') or (container.get('NetworkSettings') or {}).get('Networks') or {})
    addresses=[]; compact={}
    for name,data in networks.items():
        data=data or {}; network_addresses=[]
        for key in ('IPAddress','GlobalIPv6Address'):
            value=data.get(key)
            if value and value not in network_addresses:
                network_addresses.append(value)
                addresses.append({'address':value,'network':name})
        compact[name]={'addresses':network_addresses,'mac_address':data.get('MacAddress')}
    return addresses,compact

def workload_identity(kind,external_id,name):
    if kind=='container' and name:
        return str(name)
    return str(external_id or name)

def reconcile_workload(db,host_id,kind,external_id,name):
    stable_id=workload_identity(kind,external_id,name)
    exact=db.query(ComputeWorkload).filter_by(host_id=host_id,kind=kind,external_id=stable_id).first()
    matches=db.query(ComputeWorkload).filter_by(host_id=host_id,kind=kind,name=name).all()
    row=exact
    if row is None and matches:
        row=max(matches,key=lambda item:(item.status!='missing',item.updated_at or item.created_at,item.id))
        row.external_id=stable_id
    created=row is None
    if created:
        row=ComputeWorkload(host_id=host_id,kind=kind,external_id=stable_id,name=name)
        db.add(row); db.flush()
    for duplicate in matches:
        if duplicate.id==row.id: continue
        if not row.owner and duplicate.owner: row.owner=duplicate.owner
        if not row.backup_policy and duplicate.backup_policy: row.backup_policy=duplicate.backup_policy
        db.query(ComputeMetric).filter_by(workload_id=duplicate.id).update({ComputeMetric.workload_id:row.id},synchronize_session=False)
        db.query(ComputeEvent).filter_by(workload_id=duplicate.id).update({ComputeEvent.workload_id:row.id},synchronize_session=False)
        db.delete(duplicate)
    db.flush()
    return row,created

def prune_missing_workloads(db,host_id,now,retention_days=30):
    cutoff=now-timedelta(days=retention_days)
    stale=db.query(ComputeWorkload).filter(ComputeWorkload.host_id==host_id,ComputeWorkload.status=='missing',ComputeWorkload.last_seen_at<cutoff).all()
    for row in stale:
        db.query(ComputeMetric).filter_by(workload_id=row.id).delete(synchronize_session=False)
        db.query(ComputeEvent).filter_by(workload_id=row.id).delete(synchronize_session=False)
        db.delete(row)

def collect_docker(host):
    version=request_json(host,'/version') or {}; info=request_json(host,'/info') or {}
    containers=request_json(host,'/containers/json?all=1&size=1') or []; workloads=[]; compose={}
    for c in containers:
        labels=c.get('Labels') or {}; project=labels.get('com.docker.compose.project')
        if project: compose[project]={'working_dir':labels.get('com.docker.compose.project.working_dir'),'config_files':labels.get('com.docker.compose.project.config_files')}
        stats={}; inspect={}
        try: inspect=request_json(host,f"/containers/{c.get('Id')}/json") or {}
        except Exception: pass
        if c.get('State')=='running':
            try: stats=request_json(host,f"/containers/{c.get('Id')}/stats?stream=false") or {}
            except Exception: pass
        mem=stats.get('memory_stats') or {}
        addresses,networks=docker_networks(c,inspect); state=inspect.get('State') or {}
        name=(c.get('Names') or [c.get('Id','')[:12]])[0].lstrip('/')
        workloads.append({'external_id':name,'name':name,'kind':'container','node':host.name,'status':c.get('State') or 'unknown','cpu_percent':docker_cpu(stats),'cpu_total':None,'memory_used':mem.get('usage'),'memory_total':mem.get('limit'),'storage_used':c.get('SizeRw'),'storage_total':None,'uptime_seconds':docker_uptime(state.get('StartedAt')) if state.get('Running') else None,'tags':project,'metadata':{'image':c.get('Image'),'ports':c.get('Ports') or [],'mounts':c.get('Mounts') or [],'summary':c.get('Status'),'ip_addresses':addresses,'networks':networks}})
    items=[]
    for x in request_json(host,'/images/json') or []: items.append({'external_id':x.get('Id'),'name':(x.get('RepoTags') or ['<untagged>'])[0],'kind':'image','status':None,'size_bytes':x.get('Size'),'metadata':{'tags':x.get('RepoTags') or []}})
    for x in request_json(host,'/networks') or []: items.append({'external_id':x.get('Id') or x.get('Name'),'name':x.get('Name'),'kind':'network','status':x.get('Scope'),'size_bytes':None,'metadata':{'driver':x.get('Driver'),'internal':x.get('Internal')}})
    for x in (request_json(host,'/volumes') or {}).get('Volumes') or []: items.append({'external_id':x.get('Name'),'name':x.get('Name'),'kind':'volume','status':x.get('Scope'),'size_bytes':(x.get('UsageData') or {}).get('Size'),'metadata':{'driver':x.get('Driver'),'mountpoint':x.get('Mountpoint')}})
    for name,meta in compose.items(): items.append({'external_id':name,'name':name,'kind':'compose','status':'active','size_bytes':None,'metadata':meta})
    running=[x for x in workloads if x['status']=='running']
    return {'version':version.get('Version'),'host':{'cpu_percent':sum(x.get('cpu_percent') or 0 for x in running),'memory_used':sum(x.get('memory_used') or 0 for x in running),'memory_total':info.get('MemTotal'),'storage_used':None,'storage_total':None,'metadata':{'os':info.get('OperatingSystem'),'kernel':info.get('KernelVersion'),'cpus':info.get('NCPU')}},'workloads':workloads,'items':items}

def pve(host,path):
    data=request_json(host,'/api2/json'+path); return data.get('data') if isinstance(data,dict) else data

def proxmox_guest_addresses(host,node_name,endpoint,guest):
    vmid=guest.get('vmid'); addresses=[]
    if not vmid or guest.get('status')!='running': return addresses
    try:
        if endpoint=='qemu':
            result=pve(host,f'/nodes/{node_name}/qemu/{vmid}/agent/network-get-interfaces') or {}
            interfaces=result.get('result') if isinstance(result,dict) else result
            for interface in interfaces or []:
                name=interface.get('name')
                for item in interface.get('ip-addresses') or []:
                    value=item.get('ip-address')
                    if value: addresses.append({'address':value,'interface':name})
        else:
            interfaces=pve(host,f'/nodes/{node_name}/lxc/{vmid}/interfaces') or []
            for interface in interfaces:
                name=interface.get('name')
                for key in ('inet','inet6'):
                    value=interface.get(key)
                    if value: addresses.append({'address':str(value).split('/')[0],'interface':name})
    except Exception:
        pass
    return addresses

def proxmox_backup_tasks(host):
    try:
        tasks=pve(host,'/cluster/tasks?typefilter=vzdump&limit=100') or []
    except Exception:
        return []
    return sorted(tasks,key=lambda item:item.get('starttime') or 0,reverse=True)

def proxmox_backup_task_status(task):
    if not task:
        return None
    status=str(task.get('status') or task.get('exitstatus') or '').strip()
    if not status:
        return 'running'
    return 'successful' if status.upper() == 'OK' else 'failed'

def proxmox_matching_backup_task(job,tasks):
    raw_vmids=str(job.get('vmid') or '').replace(';',',').replace(' ', ',')
    vmids={part for part in raw_vmids.split(',') if part}
    for task in tasks:
        task_id=str(task.get('id') or '')
        if not vmids or task_id in vmids:
            return task
    return None

def collect_proxmox(host):
    version=pve(host,'/version') or {}
    resources=pve(host,'/cluster/resources') or []
    node_names=sorted({x.get('node') for x in resources if x.get('type')=='node' and x.get('node')})
    seen={(x.get('type'),str(x.get('id') or x.get('vmid') or x.get('node') or x.get('storage'))) for x in resources}
    for node_name in node_names:
        try:
            node_status=pve(host,f'/nodes/{node_name}/status') or {}
            node_row=next((x for x in resources if x.get('type')=='node' and x.get('node')==node_name),None)
            if node_row is not None:
                memory=node_status.get('memory') or {}; rootfs=node_status.get('rootfs') or {}; cpuinfo=node_status.get('cpuinfo') or {}
                node_row.update({'cpu':node_status.get('cpu',node_row.get('cpu')),'maxcpu':cpuinfo.get('cpus') or node_status.get('cpuinfo',{}).get('cpus') or node_row.get('maxcpu'),'mem':memory.get('used',node_row.get('mem')),'maxmem':memory.get('total',node_row.get('maxmem')),'disk':rootfs.get('used',node_row.get('disk')),'maxdisk':rootfs.get('total',node_row.get('maxdisk')),'uptime':node_status.get('uptime',node_row.get('uptime'))})
        except Exception:
            pass
        for endpoint,kind in (('qemu','qemu'),('lxc','lxc')):
            try:
                for guest in pve(host,f'/nodes/{node_name}/{endpoint}') or []:
                    guest['_ip_addresses']=proxmox_guest_addresses(host,node_name,endpoint,guest)
                    key=(kind,str(kind)+'/'+str(guest.get('vmid')))
                    existing=next((item for item in resources if (item.get('type'),str(item.get('id') or item.get('vmid') or item.get('node') or item.get('storage')))==key),None)
                    if existing is not None:
                        existing.update(guest)
                    else:
                        guest.update({'type':kind,'node':node_name,'id':f'{kind}/{guest.get("vmid")}'})
                        if guest.get('maxcpu') is None: guest['maxcpu']=guest.get('cpus')
                        resources.append(guest); seen.add(key)
            except Exception:
                pass
        try:
            for storage in pve(host,f'/nodes/{node_name}/storage') or []:
                key=('storage','storage/'+str(node_name)+'/'+str(storage.get('storage')))
                if key not in seen:
                    storage.update({'type':'storage','node':node_name,'id':f'storage/{node_name}/{storage.get("storage")}','disk':storage.get('used'),'maxdisk':storage.get('total'),'plugintype':storage.get('type'),'status':'available' if storage.get('active',1) else 'offline'})
                    resources.append(storage); seen.add(key)
        except Exception:
            pass
    workloads=[]; items=[]; nodes=[]
    for x in resources:
        kind=x.get('type')
        if kind=='node': nodes.append(x)
        if kind in {'node','qemu','lxc'}:
            workloads.append({'external_id':str(x.get('vmid') or x.get('node') or x.get('id')),'name':x.get('name') or x.get('node') or x.get('id'),'kind':'vm' if kind=='qemu' else kind,'node':x.get('node'),'status':x.get('status') or 'unknown','cpu_percent':round(float(x.get('cpu') or 0)*100,2),'cpu_total':float(x.get('maxcpu') or x.get('cpus') or 0),'memory_used':x.get('mem'),'memory_total':x.get('maxmem'),'storage_used':x.get('disk'),'storage_total':x.get('maxdisk'),'uptime_seconds':x.get('uptime'),'tags':x.get('tags'),'metadata':{'id':x.get('id'),'pool':x.get('pool'),'template':x.get('template'),'ip_addresses':x.get('_ip_addresses') or []}})
        elif kind=='storage': items.append({'external_id':x.get('id'),'name':x.get('storage') or x.get('id'),'kind':'storage','status':x.get('status'),'size_bytes':x.get('maxdisk'),'metadata':{'node':x.get('node'),'used':x.get('disk'),'type':x.get('plugintype')}})
    try: jobs=pve(host,'/cluster/backup') or []
    except Exception: jobs=[]
    backup_tasks=proxmox_backup_tasks(host)
    for x in jobs:
        task=proxmox_matching_backup_task(x,backup_tasks)
        task_status=proxmox_backup_task_status(task)
        metadata={**x,'last_task':task,'last_status':task_status}
        eid=str(x.get('id') or f"{x.get('storage')}:{x.get('schedule')}:{x.get('vmid','all')}"); items.append({'external_id':eid,'name':x.get('id') or f"Backup to {x.get('storage','storage')}",'kind':'backup','status':'enabled' if x.get('enabled',1) else 'disabled','size_bytes':None,'metadata':metadata})
    cpu=sum(float(x.get('cpu') or 0)*100 for x in nodes)/len(nodes) if nodes else None
    limited=bool(nodes) and not any(x.get('maxmem') for x in nodes)
    warning='Connected, but the API token cannot read node capacity or guests. Assign PVEAuditor to the API token at / with Propagate enabled.' if limited else None
    return {'version':version.get('version'),'warning':warning,'host':{'cpu_percent':round(cpu,2) if cpu is not None else None,'memory_used':sum(x.get('mem') or 0 for x in nodes),'memory_total':sum(x.get('maxmem') or 0 for x in nodes),'storage_used':sum(x.get('disk') or 0 for x in nodes),'storage_total':sum(x.get('maxdisk') or 0 for x in nodes),'metadata':{'release':version.get('release'),'nodes':len(nodes)}},'workloads':workloads,'items':items}

def sync_host(db,host):
    if host.platform == 'docker_agent':
        return

    now=datetime.utcnow(); old_host_status=host.status
    try:
        result=collect_docker(host) if host.platform=='docker' else collect_proxmox(host); snap=result['host']; host.status='online'; host.version=result.get('version'); host.last_error=result.get('warning')
        for key in ('cpu_percent','memory_used','memory_total','storage_used','storage_total'): setattr(host,key,snap.get(key))
        host.metadata_json=json.dumps(snap.get('metadata') or {}); seen=set()
        for data in result['workloads']:
            row,created=reconcile_workload(db,host.id,data['kind'],data['external_id'],data['name'])
            if created: db.add(ComputeEvent(host_id=host.id,workload_id=row.id,event_type='discovered',detail=f"Discovered {data['kind']} {data['name']}"))
            elif row.status!=data['status']: db.add(ComputeEvent(host_id=host.id,workload_id=row.id,event_type='state_change',detail=f"{row.name}: {row.status} -> {data['status']}"))
            for key in ('name','node','status','cpu_percent','cpu_total','memory_used','memory_total','storage_used','storage_total','uptime_seconds','tags'): setattr(row,key,data.get(key))
            row.metadata_json=json.dumps(data.get('metadata') or {}); row.last_seen_at=now; row.updated_at=now; seen.add((row.kind,row.external_id))
        for row in db.query(ComputeWorkload).filter_by(host_id=host.id).all():
            if (row.kind,row.external_id) not in seen and row.status!='missing': row.status='missing'; db.add(ComputeEvent(host_id=host.id,workload_id=row.id,event_type='missing',detail=f'{row.name} is no longer reported'))
        prune_missing_workloads(db,host.id,now)
        db.query(ComputeInventoryItem).filter_by(host_id=host.id).delete(synchronize_session=False)
        inventory_seen=set()
        for data in result['items']:
            key=(data['kind'],data['external_id'])
            if key in inventory_seen: continue
            inventory_seen.add(key)
            db.add(ComputeInventoryItem(host_id=host.id,external_id=data['external_id'],name=data['name'],kind=data['kind'],status=data.get('status'),size_bytes=data.get('size_bytes'),metadata_json=json.dumps(data.get('metadata') or {}),last_seen_at=now))
        last=db.query(ComputeMetric).filter(ComputeMetric.host_id==host.id,ComputeMetric.workload_id.is_(None)).order_by(ComputeMetric.recorded_at.desc()).first()
        if not last or last.recorded_at<now-timedelta(seconds=60):
            db.add(ComputeMetric(host_id=host.id,cpu_percent=host.cpu_percent,memory_used=host.memory_used,memory_total=host.memory_total,storage_used=host.storage_used,storage_total=host.storage_total,recorded_at=now))
            for row in db.query(ComputeWorkload).filter_by(host_id=host.id).filter(ComputeWorkload.last_seen_at==now).all(): db.add(ComputeMetric(host_id=host.id,workload_id=row.id,cpu_percent=row.cpu_percent,memory_used=row.memory_used,memory_total=row.memory_total,storage_used=row.storage_used,storage_total=row.storage_total,recorded_at=now))
        if old_host_status!='online': db.add(ComputeEvent(host_id=host.id,event_type='host_online',detail=f'{host.name} is online'))
    except Exception as exc:
        host.status='offline'; host.last_error=str(exc)[:2000]
        if old_host_status!='offline': db.add(ComputeEvent(host_id=host.id,event_type='host_offline',detail=f'{host.name}: {str(exc)[:500]}'))
    host.last_synced_at=now; host.updated_at=now
    db.query(ComputeMetric).filter(ComputeMetric.recorded_at<now-timedelta(days=7)).delete(synchronize_session=False); db.query(ComputeEvent).filter(ComputeEvent.created_at<now-timedelta(days=90)).delete(synchronize_session=False); db.commit()

def sync_host_by_id(host_id):
    db=SessionLocal()
    try:
        host=db.get(ComputeHost,host_id)
        if host and host.is_enabled and host.platform != 'docker_agent':
            sync_host(db,host)
    except Exception:
        db.rollback()
    finally:
        db.close()

async def compute_monitor_loop():
    await asyncio.sleep(20)

    while True:
        db=SessionLocal(); now=datetime.utcnow()
        try:
            ids=[
                h.id for h in db.query(ComputeHost).filter_by(is_enabled=True).all()
                if h.platform != 'docker_agent'
                and (
                    not h.last_synced_at
                    or h.last_synced_at <= now - timedelta(seconds=max(15,min(h.poll_interval_seconds,3600)))
                )
            ]
        finally:
            db.close()

        if ids:
            await asyncio.gather(*(asyncio.to_thread(sync_host_by_id,i) for i in ids[:3]),return_exceptions=True)

        await asyncio.sleep(5)

def compute_summary(db):
    hosts=db.query(ComputeHost).all(); workloads=db.query(ComputeWorkload).filter(ComputeWorkload.kind.in_(['container','vm','lxc']),ComputeWorkload.status!='missing').all(); running={'running','up'}; stopped={'stopped','exited','down'}
    pct=lambda used,total: round(used/total*100,1) if used is not None and total else None
    cpu=[h.cpu_percent for h in hosts if h.cpu_percent is not None]; mu=sum(h.memory_used or 0 for h in hosts); mt=sum(h.memory_total or 0 for h in hosts); su=sum(h.storage_used or 0 for h in hosts); st=sum(h.storage_total or 0 for h in hosts)
    return {'hosts':len(hosts),'online_hosts':sum(h.status=='online' for h in hosts),'workloads':len(workloads),'running':sum(w.status.lower() in running for w in workloads),'stopped':sum(w.status.lower() in stopped for w in workloads),'warnings':sum(h.status=='offline' for h in hosts)+sum(w.status.lower() not in running|stopped for w in workloads),'cpu_percent':round(sum(cpu)/len(cpu),1) if cpu else None,'memory_percent':pct(mu,mt),'storage_percent':pct(su,st),'updated_at':max((h.last_synced_at for h in hosts if h.last_synced_at),default=None)}
