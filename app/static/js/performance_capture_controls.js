(() => {
  const root = document.querySelector("[data-performance-capture]");
  if (!root) return;
  const key = "kaya.performance.capture";
  const csrf = root.dataset.csrfToken || "";
  const status = root.querySelector("[data-capture-status]");
  const startButton = root.querySelector("[data-capture-start]");
  const stopButton = root.querySelector("[data-capture-stop]");
  const download = root.querySelector("[data-capture-download]");
  const discard = root.querySelector("[data-capture-discard]");
  const duration = root.querySelector("[data-capture-duration]");
  const boxes = [...root.querySelectorAll("[data-capture-collectors] input[type=checkbox]")];
  let timer = null;
  const setStatus = text => { status.textContent = text; };
  async function call(path, method, payload) {
    const response = await fetch(path, {method, cache: "no-store", headers: {"Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrf}, body: payload ? JSON.stringify({...payload, csrf_token: csrf}) : undefined});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Diagnostic capture request failed");
    return data;
  }
  function render(data) {
    const active = Boolean(data.active);
    startButton.hidden = active;
    stopButton.hidden = !active;
    download.hidden = (!data.capture_id && !data.completed_available) || (active && !data.completed_available);
    discard.hidden = (!data.capture_id && !data.completed_available) || (active && !data.completed_available);
    if (active) setStatus(`Capturing: ${data.remaining_seconds}s remaining · ${data.event_count} events${data.completed_available ? " · previous result retained" : ""}`);
    else if (data.status === "completed") setStatus(`Capture complete · ${data.event_count} events ready to download.`);
    else if (data.status === "stopped") setStatus(`Capture stopped · ${data.event_count} events ready to download.`);
    else setStatus(data.reason || "No completed capture is available.");
  }
  async function poll() {
    try {
      const data = await call("/api/system/about/performance/capture", "GET");
      render(data);
      if (!data.active && timer) { clearInterval(timer); timer = null; if (!["completed", "stopped"].includes(data.status)) sessionStorage.removeItem(key); }
    } catch (error) { setStatus(error.message); }
  }
  startButton.addEventListener("click", async () => {
    const collectors = boxes.filter(box => box.checked).map(box => box.value);
    if (!collectors.length) return setStatus("Select at least one collector.");
    startButton.disabled = true;
    try {
      const data = await call("/api/system/about/performance/capture/start", "POST", {duration_seconds: Number(duration.value), collectors});
      sessionStorage.setItem(key, JSON.stringify({captureId: data.capture_id, expiresAt: Date.now() + Number(data.duration_seconds) * 1000}));
      render(data);
      timer = setInterval(poll, 1000);
    } catch (error) { setStatus(error.message); }
    finally { startButton.disabled = false; }
  });
  stopButton.addEventListener("click", async () => {
    stopButton.disabled = true;
    try { render(await call("/api/system/about/performance/capture/stop", "POST", {})); sessionStorage.removeItem(key); if (timer) clearInterval(timer); timer = null; }
    catch (error) { setStatus(error.message); }
    finally { stopButton.disabled = false; }
  });
  discard.addEventListener("click", async () => {
    discard.disabled = true;
    try { render(await call("/api/system/about/performance/capture/discard", "POST", {})); sessionStorage.removeItem(key); }
    catch (error) { setStatus(error.message); }
    finally { discard.disabled = false; }
  });
  poll();
})();
