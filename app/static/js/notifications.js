(() => {
  const menu = document.querySelector("[data-notification-menu]");
  const csrf = menu?.dataset.csrfToken || document.querySelector("[data-notification-page],[data-notification-preferences],[data-notification-admin]")?.dataset.csrfToken || "";
  const channel = "BroadcastChannel" in window ? new BroadcastChannel("kaya-notifications") : null;
  const headers = () => ({"X-CSRF-Token": csrf});
  const jsonHeaders = () => ({...headers(), "Content-Type": "application/json"});
  const escapeTime = value => {
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 60) return "Just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
    return `${Math.floor(seconds / 86400)} days ago`;
  };
  async function mutate(url, method="POST", body) {
    const response = await fetch(url, {method, headers: body ? jsonHeaders() : headers(), body: body ? JSON.stringify(body) : undefined, cache:"no-store"});
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || "Request failed");
    channel?.postMessage("refresh");
    return response.json();
  }
  async function refreshBadge() {
    if (!menu || document.hidden) return;
    try {
      const data = await fetch("/api/notifications/unread-count", {cache:"no-store"}).then(r => r.json());
      const badge = menu.querySelector("[data-notification-badge]");
      badge.hidden = data.count === 0; badge.textContent = data.count > 99 ? "99+" : String(data.count);
      menu.classList.toggle("has-critical", data.critical); menu.querySelector("summary").setAttribute("aria-label", data.count ? `Notifications, ${data.count} unread` : "Notifications");
    } catch (_) { /* normal pages continue if the optional notification API is unavailable */ }
  }
  async function refreshMenu() {
    if (!menu?.open) return;
    const list = menu.querySelector("[data-notification-list]");
    try {
      const [items, count] = await Promise.all([fetch("/api/notifications?limit=10", {cache:"no-store"}).then(r=>r.json()), fetch("/api/notifications/unread-count", {cache:"no-store"}).then(r=>r.json())]);
      list.replaceChildren(); menu.querySelector("[data-notification-summary]").textContent = count.count ? `${count.count} unread` : "You're all caught up";
      if (!items.notifications.length) { const empty=document.createElement("p"); empty.className="notification-empty"; empty.textContent="No notifications yet."; list.append(empty); return; }
      items.notifications.forEach(item => {
        const entry=document.createElement(item.target_route ? "a" : "article"); entry.className=`notification-recent-item severity-${item.severity}${item.read ? "" : " unread"}`;
        if (item.target_route) { entry.href=item.target_route; entry.addEventListener("click", async event => { event.preventDefault(); try { await mutate(`/api/notifications/${item.id}/read`); } finally { location.assign(item.target_route); } }); }
        const marker=document.createElement("span"); marker.className="notification-severity"; marker.setAttribute("aria-label", item.severity);
        const body=document.createElement("div"), module=document.createElement("span"), title=document.createElement("strong"), message=document.createElement("p"), time=document.createElement("time");
        module.textContent=item.module.replaceAll("_"," "); title.textContent=item.title; message.textContent=item.message; time.textContent=escapeTime(item.created_at);
        body.append(module,title,message,time); entry.append(marker,body); list.append(entry);
      });
    } catch (_) { list.textContent="Notifications could not be loaded."; }
  }
  menu?.addEventListener("toggle", refreshMenu);
  menu?.querySelector("[data-notification-mark-all]")?.addEventListener("click", async () => { await mutate("/api/notifications/mark-all-read"); await Promise.all([refreshBadge(),refreshMenu()]); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshBadge(); });
  channel?.addEventListener("message", refreshBadge); window.addEventListener("storage", event => { if (event.key === "kaya-notifications") refreshBadge(); });
  refreshBadge(); setInterval(refreshBadge, 45000);

  const page=document.querySelector("[data-notification-page]");
  page?.addEventListener("click", async event => {
    const item=event.target.closest("[data-notification-id]"); if (!item) return; const id=item.dataset.notificationId;
    try {
      if (event.target.closest("[data-notification-dismiss]")) { await mutate(`/api/notifications/${id}/dismiss`); item.remove(); }
      else if (event.target.closest("[data-notification-acknowledge]")) { await mutate(`/api/notifications/${id}/acknowledge`); location.reload(); }
      else if (event.target.closest("[data-notification-toggle-read]")) { await mutate(`/api/notifications/${id}/${item.classList.contains("unread") ? "read" : "unread"}`); location.reload(); }
      else if (event.target.closest("[data-notification-open]")) await mutate(`/api/notifications/${id}/read`);
    } catch (_) { /* retain current state on failure */ }
  });
  document.querySelector("[data-notification-page-mark-all]")?.addEventListener("click", async()=>{await mutate("/api/notifications/mark-all-read");location.reload();});
  document.querySelector("[data-notification-clear-read]")?.addEventListener("click",async()=>{await mutate("/api/notifications/clear-read");location.reload();});

  const preferenceRoot=document.querySelector("[data-notification-preferences]"), preferenceDialog=preferenceRoot?.querySelector("[data-notification-dialog]"), preferenceForm=preferenceDialog?.querySelector("[data-notification-dialog-form]");
  preferenceRoot?.addEventListener("click",event=>{const button=event.target.closest("[data-edit-notification]");if(!button)return;const row=button.closest("[data-event-type]");preferenceForm.dataset.eventType=row.dataset.eventType;preferenceForm.querySelector("[data-dialog-title]").textContent=row.dataset.title;preferenceForm.in_app_enabled.checked=row.dataset.inApp==="1";preferenceForm.push_enabled.checked=row.dataset.push==="1";preferenceForm.email_enabled.checked=row.dataset.email==="1";preferenceForm.minimum_severity.value=row.dataset.severity;preferenceForm.in_app_enabled.disabled=row.dataset.mandatory==="1";preferenceForm.push_enabled.disabled=preferenceDialog.dataset.pushAvailable!=="1";preferenceForm.email_enabled.disabled=preferenceDialog.dataset.emailAvailable!=="1";preferenceForm.querySelector("[data-dialog-policy]").textContent=row.dataset.mandatory==="1"?"In-app delivery is mandatory for this event.":preferenceDialog.dataset.pushAvailable!=="1"?"Web Push is unavailable; in-app notifications continue to work.":"";preferenceForm.querySelector("[data-save-status]").textContent="";preferenceDialog.showModal();});
  preferenceDialog?.addEventListener("click",event=>{if(event.target.closest("[data-dialog-close]"))preferenceDialog.close();});
  preferenceForm?.addEventListener("submit",async event=>{event.preventDefault();const type=preferenceForm.dataset.eventType,status=preferenceForm.querySelector("[data-save-status]"),row=preferenceRoot.querySelector(`[data-event-type="${CSS.escape(type)}"]`);const body={event_type:type,in_app_enabled:preferenceForm.in_app_enabled.checked,push_enabled:preferenceForm.push_enabled.checked,email_enabled:preferenceForm.email_enabled.checked,minimum_severity:preferenceForm.minimum_severity.value,recovery_enabled:true,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC"};try{await mutate(`/api/notification-preferences/${encodeURIComponent(type)}`,"PUT",body);row.dataset.inApp=body.in_app_enabled?"1":"0";row.dataset.push=body.push_enabled?"1":"0";row.dataset.email=body.email_enabled?"1":"0";row.dataset.severity=body.minimum_severity;status.textContent="Saved";setTimeout(()=>location.reload(),350);}catch(error){status.textContent=error.message;}});
  document.querySelector("[data-device-list]")?.addEventListener("click",async event=>{const button=event.target.closest("[data-remove-device]");if(!button)return;await mutate(`/api/push-subscriptions/${button.dataset.removeDevice}`,"DELETE");button.closest("article").remove();});

  const pushRoot=document.querySelector("[data-push-settings]"), pushStatus=pushRoot?.querySelector("[data-push-status]");
  const b64=value=>{const pad="=".repeat((4-value.length%4)%4),raw=atob((value+pad).replace(/-/g,"+").replace(/_/g,"/"));return Uint8Array.from([...raw].map(c=>c.charCodeAt(0)));};
  pushRoot?.querySelector("[data-enable-push]")?.addEventListener("click",async()=>{
    if(pushRoot.dataset.pushAvailable!=="1"){pushStatus.textContent="Push is not available for this installation.";return;}
    if(!window.isSecureContext){pushStatus.textContent="Push requires HTTPS (localhost is allowed for development).";return;}
    if(!("serviceWorker" in navigator) || !("Notification" in window) || !("PushManager" in window)){pushStatus.textContent="This browser does not support Web Push.";return;}
    if(/iPad|iPhone|iPod/.test(navigator.userAgent)&&!matchMedia("(display-mode: standalone)").matches){pushStatus.textContent="On iPhone or iPad, install Kaya to the Home Screen before enabling notifications.";return;}
    try{const permission=await Notification.requestPermission();if(permission!=="granted"){pushStatus.textContent=permission==="denied"?"Permission was denied. Change it in browser settings to try again.":"Permission was not granted.";return;}
      const registration=await navigator.serviceWorker.ready,key=await fetch("/api/notifications/vapid-public-key").then(r=>r.json());
      const subscription=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64(key.public_key)}), raw=subscription.toJSON();
      await mutate("/api/push-subscriptions","POST",{endpoint:raw.endpoint,keys:raw.keys,device_label:`${navigator.userAgentData?.brands?.[0]?.brand||"Browser"} on this device`,browser_family:navigator.userAgentData?.brands?.[0]?.brand||null,operating_system:navigator.userAgentData?.platform||navigator.platform||null});
      pushStatus.textContent="Push notifications are enabled on this device.";
    }catch(_){pushStatus.textContent="Kaya could not enable push notifications on this device.";}
  });

  const admin=document.querySelector("[data-notification-admin]");
  admin?.querySelector("[data-notification-test]")?.addEventListener("click",async event=>{const button=event.currentTarget,result=admin.querySelector("[data-notification-test-result]");button.disabled=true;result.textContent="Sending…";try{const data=await mutate("/api/notifications/test");result.textContent=`In app: ${data.in_app}. Push: ${data.push}. Email: ${data.email}.`;}catch(error){result.textContent=error.message;}finally{button.disabled=false;}});
  const webPush=admin?.querySelector(".web-push-configuration"),webPushResult=webPush?.querySelector("[data-web-push-result]"),keyDialog=webPush?.querySelector('[data-web-push-dialog="keys"]'),keyForm=keyDialog?.querySelector("[data-web-push-key-form]");
  webPush?.addEventListener("click",async event=>{const opener=event.target.closest("[data-web-push-open]");if(opener){const mode=opener.dataset.webPushOpen;if(mode==="generate"||mode==="rotate"){keyForm.reset();keyForm.dataset.mode=mode;keyForm.querySelector("[data-web-push-dialog-title]").textContent=mode==="rotate"?"Rotate Web Push keys":"Generate Web Push keys";keyForm.querySelector("[data-web-push-warning]").textContent=mode==="rotate"?"Rotating Web Push keys invalidates existing browser subscriptions. Every affected user may need to enable Push again on each device.":"Kaya will generate a public and private P-256 VAPID key pair. The private key will be encrypted using this installation's ENCRYPTION_KEY.";keyForm.querySelector("[data-web-push-typed-confirm]").hidden=mode!=="rotate";keyForm.querySelector("[data-web-push-submit]").textContent=mode==="rotate"?"Rotate keys and revoke subscriptions":"Generate and enable Web Push";keyDialog.showModal();}else webPush.querySelector(`[data-web-push-dialog="${mode}"]`)?.showModal();return;}if(event.target.closest("[data-web-push-close]")){event.target.closest("dialog")?.close();return;}const action=event.target.closest("[data-web-push-action]");if(action){const name=action.dataset.webPushAction;action.disabled=true;try{await mutate(`/api/admin/web-push/${name}`,"POST",{confirmation:name.toUpperCase()});location.reload();}catch(error){webPushResult.textContent=error.message;action.disabled=false;}return;}const test=event.target.closest("[data-web-push-test]");if(test){test.disabled=true;webPushResult.textContent="Queueing push test…";try{const data=await mutate("/api/admin/web-push/test");webPushResult.textContent=`Push test queued for ${data.queued_devices} device(s).`;}catch(error){webPushResult.textContent=error.message;}finally{test.disabled=false;}}});
  keyForm?.addEventListener("submit",async event=>{event.preventDefault();const mode=keyForm.dataset.mode,body={contact_email:keyForm.contact_email.value||null,contact_url:keyForm.contact_url.value||null,installation_label:keyForm.installation_label.value||null,confirmation:mode==="rotate"?keyForm.confirmation.value:"GENERATE"},submit=keyForm.querySelector("[data-web-push-submit]");submit.disabled=true;try{await mutate(`/api/admin/web-push/${mode}`,"POST",body);location.reload();}catch(error){webPushResult.textContent=error.message;keyDialog.close();submit.disabled=false;}});
  webPush?.querySelectorAll("[data-web-push-confirm-form]").forEach(form=>form.addEventListener("submit",async event=>{event.preventDefault();if(form.confirmation.value!==form.dataset.confirmation){webPushResult.textContent=`Type ${form.dataset.confirmation} exactly to continue.`;return;}try{const data=await mutate(form.dataset.endpoint,form.dataset.method,{confirmation:form.confirmation.value});webPushResult.textContent=`Completed. ${data.affected_subscriptions??0} subscription(s) affected.`;location.reload();}catch(error){webPushResult.textContent=error.message;form.closest("dialog").close();}}));
  admin?.querySelector("[data-admin-settings]")?.addEventListener("submit",async event=>{event.preventDefault();const form=event.target,status=form.querySelector("[data-admin-status]");const body={enabled:form.enabled.checked,in_app_enabled:form.in_app_enabled.checked,email_enabled:form.email_enabled.checked,allow_customisation:form.allow_customisation.checked,read_retention_days:Number(form.read_retention_days.value),unread_retention_days:Number(form.unread_retention_days.value),maximum_per_event:Number(form.maximum_per_event.value),default_severity:form.default_severity.value};try{await mutate("/api/admin/notification-settings","PUT",body);status.textContent="Saved";}catch(error){status.textContent=error.message;}});
  admin?.querySelector(".notification-category-admin")?.addEventListener("submit",async event=>{event.preventDefault();const form=event.target.closest("[data-category]"),status=form.querySelector("[data-category-status]");const body={enabled:form.enabled.checked,in_app_allowed:true,push_allowed:form.push_allowed.checked,email_allowed:form.email_allowed.checked,minimum_severity:"info",user_can_opt_out:form.user_can_opt_out.checked,recovery_enabled:true,default_enabled:true,cooldown_seconds:Number(form.cooldown_seconds.value),repeat_interval_seconds:null,acknowledgement_required:form.acknowledgement_required.checked};try{await mutate(`/api/admin/notification-categories/${encodeURIComponent(form.dataset.category)}`,"PUT",body);status.textContent="Saved";}catch(error){status.textContent=error.message;}});
})();
