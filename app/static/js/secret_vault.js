(() => {
  "use strict";
  const viewStorageKey = "kaya.secret-vault.view";
  const viewButtons = Array.from(document.querySelectorAll("[data-vault-view-button]"));
  const views = Array.from(document.querySelectorAll("[data-vault-view]"));
  function setVaultView(view) {
    const nextView = view === "table" ? "table" : "tiles";
    views.forEach((item) => { item.hidden = item.dataset.vaultView !== nextView; });
    viewButtons.forEach((button) => {
      const active = button.dataset.vaultViewButton === nextView;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
    if (views.length) localStorage.setItem(viewStorageKey, nextView);
  }
  if (views.length && viewButtons.length) {
    setVaultView(localStorage.getItem(viewStorageKey) || "tiles");
    viewButtons.forEach((button) => button.addEventListener("click", () => setVaultView(button.dataset.vaultViewButton)));
  }
  const recovery = document.querySelector("[data-recovery-kit]");
  if (recovery) {
    recovery.querySelector("[data-print-recovery]")?.addEventListener("click", () => window.print());
    recovery.querySelector("[data-download-recovery]")?.addEventListener("click", () => {
      const key = recovery.querySelector("[data-recovery-key]").textContent.trim();
      const text = `Kaya Secret Vault Recovery Kit\n\nRecovery key: ${key}\n\nKeep this file outside Kaya. Anyone with this key and access to your Kaya account may reset your vault PIN.\n`;
      const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([text], {type:"text/plain"})); link.download = "kaya-vault-recovery-kit.txt"; link.click(); URL.revokeObjectURL(link.href);
    });
  }
  const search=document.querySelector("[data-vault-search]");
  if(search){const apply=()=>{const term=search.value.trim().toLowerCase();document.querySelectorAll("[data-vault-search-entry]").forEach(entry=>entry.hidden=Boolean(term)&&!entry.innerText.toLowerCase().includes(term));};search.addEventListener("input",apply);document.querySelector("[data-vault-search-button]")?.addEventListener("click",apply);}
  const form = document.querySelector("[data-vault-item-form]");
  if (form) {
    const list = form.querySelector("[data-vault-fields]"), output = form.querySelector("[data-vault-fields-json]");
    const sync = () => { output.value = JSON.stringify([...list.querySelectorAll(".vault-field-row")].map(row => ({label:row.querySelector("[data-field-label]").value,value:row.querySelector("[data-field-input]").value,sensitivity:row.querySelector("[data-field-sensitivity]").value}))); };
    const add = (initial={}) => { const row=document.createElement("div");row.className="vault-field-row";row.innerHTML='<label>Label<input data-field-label maxlength="120" placeholder="Recovery key"></label><label>Value<input data-field-input autocomplete="off"></label><label>Protection<select data-field-sensitivity><option value="normal">Normal</option><option value="masked">Masked</option><option value="highly_sensitive">Highly Sensitive</option></select></label><button class="button secondary small" type="button" data-remove-field>Remove</button>';row.querySelector("[data-field-label]").value=initial.label||"";row.querySelector("[data-field-input]").value=initial.value||"";row.querySelector("[data-field-sensitivity]").value=initial.sensitivity||"normal";list.append(row);if(!initial.label)row.querySelector("input").focus(); };
    try{JSON.parse(output.value||"[]").forEach(add);}catch(_error){} form.querySelector("[data-add-vault-field]")?.addEventListener("click",()=>add()); list.addEventListener("click",event=>{if(event.target.closest("[data-remove-field]")){event.target.closest(".vault-field-row").remove();sync();}}); form.addEventListener("submit",sync);
  }
  const detail = document.querySelector("[data-vault-detail]");
  if (detail) {
    const dialog=detail.querySelector("[data-vault-reauth]"); let target=null;
    async function reveal(button,pin="",totp="") { const body=new FormData();body.set("csrf_token",detail.dataset.csrfToken);body.set("pin",pin);body.set("totp_code",totp);const response=await fetch(`/security/secret-vault/items/${location.pathname.split('/').pop()}/reveal/${button.dataset.revealField}`,{method:"POST",body,cache:"no-store"});const data=await response.json();if(!response.ok)throw new Error(data.error||"Reveal failed");const field=button.parentElement.querySelector("[data-field-value]");field.textContent=data.value;button.textContent="Hide";button.dataset.revealed="1";setTimeout(()=>{field.textContent="••••••••••••";button.textContent="Reveal";delete button.dataset.revealed;},(data.hide_after_seconds||30)*1000);}
    detail.addEventListener("click",async event=>{const button=event.target.closest("[data-reveal-field]");if(!button)return;if(button.dataset.revealed){button.parentElement.querySelector("[data-field-value]").textContent="••••••••••••";button.textContent="Reveal";delete button.dataset.revealed;return;}if(button.dataset.sensitivity==="highly_sensitive"){target=button;dialog.showModal();return;}try{await reveal(button);}catch(_){button.textContent="Could not reveal";}});
    dialog?.addEventListener("close",async()=>{if(dialog.returnValue!=="confirm"||!target)return;const error=dialog.querySelector("[data-reauth-error]");try{await reveal(target,dialog.querySelector('[name="pin"]').value,dialog.querySelector('[name="totp_code"]').value);dialog.querySelector("form").reset();error.hidden=true;}catch(exc){error.textContent=exc.message;error.hidden=false;dialog.showModal();}finally{target=null;}});
  }
})();
