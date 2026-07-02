import Guacamole from "/static/vendor/guacamole/guacamole-common.min.js";

const RDP_RESIZE_SETTLE_MS = 600;

const root = document.querySelector("[data-rdp-session]");
if (root) {
  const form = root.querySelector(".rdp-credential-form");
  const log = root.querySelector("[data-rdp-log]");
  const button = form ? form.querySelector("button") : null;
  const shell = root.querySelector("[data-rdp-shell]");
  const displayTarget = root.querySelector("[data-rdp-display]");
  const placeholder = root.querySelector("[data-rdp-placeholder]");
  const statusPanel = root.querySelector("[data-rdp-status]");
  const logPanel = root.querySelector("[data-rdp-log-panel]");
  let client = null;
  let tunnel = null;
  let keyboard = null;
  let displayElement = null;
  let resizeTimer = null;
  let currentScale = 1;
  let manuallyStopped = false;
  let connected = false;
  let displayReady = false;
  let resizeObserver = null;
  let lastRequestedSize = "";
  let idleTimer = null;
  let disconnectReason = "";
  let activeToken = "";
  const recordingButton = document.querySelector("[data-recording-toggle]");
  const recordingStatus = document.querySelector("[data-recording-status]");
  const recordingEnabled = root.dataset.recordingEnabled === "1";
  const recordingAuto = root.dataset.recordingAuto === "1";
  let recorder = null;
  let recordingChunks = [];
  let recordingStartedAt = null;
  let recordingTrigger = "manual";

  const setRecordingStatus = (message) => {
    if (recordingStatus) recordingStatus.textContent = message;
  };

  const postRecordingState = () => {
    const active = Boolean(recorder && recorder.state === "recording");
    const available = Boolean(window.MediaRecorder) && recordingEnabled && connected && displayReady;
    const payload = {
      type: "kaya:remote-recording-state",
      enabled: recordingEnabled,
      available,
      active,
      label: active ? "Stop" : "Record",
      status: recordingStatus ? recordingStatus.textContent : "Ready",
    };
    if (window.parent && window.parent !== window) {
      window.parent.postMessage(payload, window.location.origin);
    }
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(payload, window.location.origin);
    }
  };

  const syncRecordingButton = () => {
    const available = Boolean(window.MediaRecorder) && recordingEnabled && connected && displayReady;
    if (recordingButton) {
      recordingButton.disabled = !available;
      recordingButton.textContent = recorder && recorder.state === "recording" ? "Stop" : "Record";
      recordingButton.classList.toggle("active", Boolean(recorder && recorder.state === "recording"));
    }
    postRecordingState();
  };

  const recorderMimeType = () => {
    if (!window.MediaRecorder) return "";
    for (const type of ["video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm"]) {
      if (MediaRecorder.isTypeSupported(type)) return type;
    }
    return "";
  };

  const uploadRecording = async (blob, startedAt, endedAt, trigger) => {
    const formData = new FormData();
    formData.append("csrf_token", root.dataset.recordingCsrfToken || "");
    formData.append("protocol", "rdp");
    formData.append("trigger", trigger);
    formData.append("started_at", startedAt.toISOString());
    formData.append("ended_at", endedAt.toISOString());
    formData.append("duration_seconds", String(Math.max(0, (endedAt - startedAt) / 1000)));
    formData.append("file", blob, "rdp-session.webm");
    const response = await fetch(root.dataset.recordingUploadUrl, { method: "POST", body: formData });
    if (!response.ok) throw new Error(`Upload failed (${response.status})`);
  };

  const startRecording = (trigger = "manual") => {
    if (!recordingEnabled || !connected || !displayReady || recorder) return;
    if (!window.MediaRecorder) {
      setRecordingStatus("Unavailable");
      syncRecordingButton();
      return;
    }
    const canvas = displayTarget.querySelector("canvas");
    if (!canvas || typeof canvas.captureStream !== "function") {
      setRecordingStatus("No display");
      syncRecordingButton();
      return;
    }
    const mimeType = recorderMimeType();
    if (!mimeType) {
      setRecordingStatus("Unavailable");
      syncRecordingButton();
      return;
    }
    recordingChunks = [];
    recordingTrigger = trigger;
    recordingStartedAt = new Date();
    const stream = canvas.captureStream(12);
    recorder = new MediaRecorder(stream, { mimeType });
    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) recordingChunks.push(event.data);
    };
    recorder.onstop = async () => {
      const startedAt = recordingStartedAt;
      const endedAt = new Date();
      const chunks = recordingChunks;
      const triggerName = recordingTrigger;
      stream.getTracks().forEach((track) => track.stop());
      recorder = null;
      recordingStartedAt = null;
      recordingChunks = [];
      syncRecordingButton();
      if (!startedAt || !chunks.length) {
        setRecordingStatus("Ready");
        return;
      }
      setRecordingStatus("Saving");
      try {
        await uploadRecording(new Blob(chunks, { type: "video/webm" }), startedAt, endedAt, triggerName);
        setRecordingStatus("Saved");
      } catch (_error) {
        setRecordingStatus("Save failed");
      }
    };
    recorder.start(1000);
    setRecordingStatus(trigger === "auto" ? "Recording automatically" : "Recording");
    syncRecordingButton();
  };

  const stopRecording = () => {
    if (recorder && recorder.state === "recording") recorder.stop();
  };

  const readInt = (value, fallback, min, max) => {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
  };

  const idleTimeoutMinutes = readInt(root.dataset.idleTimeoutMinutes, 0, 0, 1440);
  const idleTimeoutMs = idleTimeoutMinutes > 0 ? idleTimeoutMinutes * 60 * 1000 : 0;

  const writeLog = (lines) => {
    if (!log) return;
    const stamp = new Date().toLocaleTimeString();
    log.textContent = lines.map((line) => `[${stamp}] ${line}`).join("\n");
  };

  const setStatus = (title, message) => {
    if (!statusPanel) return;
    statusPanel.replaceChildren();
    const heading = document.createElement("h2");
    const detail = document.createElement("p");
    detail.className = "muted";
    heading.textContent = title;
    detail.textContent = message;
    statusPanel.append(heading, detail);
  };

  const setOverlayVisible = (visible) => {
    if (statusPanel) statusPanel.hidden = !visible;
    if (logPanel) logPanel.hidden = !visible;
  };

  const displaySize = () => {
    const rect = shell.getBoundingClientRect();
    const dpi = Math.max(96, Math.min(144, Math.round((window.devicePixelRatio || 1) * 96)));
    return {
      width: Math.max(640, Math.floor(rect.width || 1280)),
      height: Math.max(480, Math.floor(rect.height || 720)),
      dpi,
    };
  };

  const fitDisplay = () => {
    if (!client || !displayTarget) return;
    const display = client.getDisplay();
    const width = display.getWidth();
    const height = display.getHeight();
    if (!width || !height) return;
    const rect = displayTarget.getBoundingClientRect();
    const scale = Math.min(rect.width / width, rect.height / height);
    currentScale = Math.max(0.1, Math.min(scale, 1.5));
    display.scale(currentScale);
  };

  const refreshDisplay = () => {
    if (!client || !connected) return;
    const shellRect = shell.getBoundingClientRect();
    // A hidden workspace panel reports 0x0. Do not turn that into the
    // minimum 640x480 RDP size, as doing so causes two rapid remote display
    // changes when switching between split and single layouts.
    if (shellRect.width < 1 || shellRect.height < 1) return;
    fitDisplay();
    const size = displaySize();
    const requestedSize = `${size.width}x${size.height}`;
    if (requestedSize !== lastRequestedSize) {
      lastRequestedSize = requestedSize;
      client.sendSize(size.width, size.height);
    }
    client.getDisplay().flush(fitDisplay);
  };

  const scheduleResize = () => {
    // Scale the existing canvas immediately, but wait until the workspace
    // layout has settled before changing the remote desktop resolution.
    fitDisplay();
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(refreshDisplay, RDP_RESIZE_SETTLE_MS);
  };

  const disconnectCurrentSession = () => {
    stopRecording();
    window.clearTimeout(resizeTimer);
    if (idleTimer) {
      window.clearTimeout(idleTimer);
      idleTimer = null;
    }
    if (resizeObserver) {
      resizeObserver.disconnect();
      resizeObserver = null;
    }
    if (keyboard) {
      keyboard.onkeydown = null;
      keyboard.onkeyup = null;
      keyboard = null;
    }
    if (client) {
      client.disconnect();
      client = null;
    }
    displayElement = null;
    tunnel = null;
    currentScale = 1;
    lastRequestedSize = "";
    connected = false;
    displayReady = false;
    syncRecordingButton();
  };

  const stopSession = () => {
    manuallyStopped = true;
    disconnectCurrentSession();
  };

  const disconnectForIdle = () => {
    if (!connected) return;
    disconnectReason = `Disconnected after ${idleTimeoutMinutes} minute${idleTimeoutMinutes === 1 ? "" : "s"} of inactivity.`;
    manuallyStopped = true;
    setOverlayVisible(true);
    setStatus("Idle timeout", disconnectReason);
    writeLog([disconnectReason]);
    disconnectCurrentSession();
    form.hidden = false;
    button.disabled = false;
  };

  const markActivity = () => {
    if (!idleTimeoutMs || !connected) return;
    window.clearTimeout(idleTimer);
    idleTimer = window.setTimeout(disconnectForIdle, idleTimeoutMs);
  };

  const attachInput = () => {
    const displayEl = client.getDisplay().getElement();
    const mouse = new Guacamole.Mouse(displayEl);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (state) => {
      markActivity();
      displayEl.focus({ preventScroll: true });
      const adjustedState = new Guacamole.Mouse.State(
        Math.round(state.x / currentScale),
        Math.round(state.y / currentScale),
        state.left,
        state.middle,
        state.right,
        state.up,
        state.down,
      );
      client.sendMouseState(adjustedState);
    };
    keyboard = new Guacamole.Keyboard(displayEl);
    keyboard.onkeydown = (keysym) => {
      markActivity();
      client.sendKeyEvent(1, keysym);
      return false;
    };
    keyboard.onkeyup = (keysym) => {
      markActivity();
      client.sendKeyEvent(0, keysym);
      return false;
    };
  };

  const markDisplayReady = () => {
    if (displayReady) return;
    displayReady = true;
    setOverlayVisible(false);
    if (displayElement) displayElement.focus({ preventScroll: true });
    syncRecordingButton();
    if (recordingAuto) startRecording("auto");
  };

  const waitForLayout = () =>
    new Promise((resolve) => {
      window.requestAnimationFrame(() => window.requestAnimationFrame(resolve));
    });

  const connectDisplay = async (token, handoff = false) => {
    manuallyStopped = false;
    disconnectReason = "";
    activeToken = token;
    disconnectCurrentSession();
    window.clearTimeout(resizeTimer);
    displayTarget.replaceChildren();
    placeholder.hidden = true;
    displayReady = false;
    setOverlayVisible(true);
    setStatus("Connecting", "Opening browser display tunnel.");
    await waitForLayout();
    const size = displaySize();
    // The initial dimensions are already part of the connection request.
    // Avoid sending the same display-update again as soon as CONNECTED fires.
    lastRequestedSize = `${size.width}x${size.height}`;
    const params = new URLSearchParams({
      token,
      width: String(size.width),
      height: String(size.height),
    });
    if (handoff) params.set("handoff", "1");
    tunnel = new Guacamole.WebSocketTunnel(root.dataset.tunnelUrl);
    client = new Guacamole.Client(tunnel);
    const displayEl = client.getDisplay().getElement();
    displayEl.classList.add("rdp-guac-display");
    displayEl.setAttribute("tabindex", "0");
    displayEl.style.outline = "none";
    displayElement = displayEl;
    displayTarget.appendChild(displayEl);
    attachInput();
    client.onerror = (error) => {
      setOverlayVisible(true);
      writeLog([`RDP display error: ${error.message || "Unknown error"}`]);
      setStatus("Connection error", error.message || "The RDP session could not be opened.");
      connected = false;
      form.hidden = false;
      button.disabled = false;
    };
    client.onstatechange = (state) => {
      if (state === Guacamole.Client.State.CONNECTED) {
        setStatus("Connected", "RDP session is active.");
        connected = true;
        markActivity();
        syncRecordingButton();
        refreshDisplay();
        markDisplayReady();
        const hashParams = new URLSearchParams(window.location.hash.slice(1));
        const requestId = hashParams.get("requestId");
        if (requestId && window.opener && !window.opener.closed) {
          window.opener.postMessage({ type: "kaya:remote-popout-connected", requestId }, window.location.origin);
        }
      }
      if (state === Guacamole.Client.State.DISCONNECTED) {
        setOverlayVisible(true);
        connected = false;
        displayReady = false;
        stopRecording();
        syncRecordingButton();
        const disconnectTitle = disconnectReason === "Session moved to the pop-out window."
          ? "Popped out"
          : disconnectReason
            ? "Idle timeout"
            : "Disconnected";
        setStatus(disconnectTitle, disconnectReason || "The RDP session has ended.");
        form.hidden = false;
        button.disabled = false;
      }
    };
    client.getDisplay().onresize = () => {
      fitDisplay();
      markDisplayReady();
    };
    if (window.ResizeObserver) {
      resizeObserver = new ResizeObserver(scheduleResize);
      resizeObserver.observe(shell);
    }
    client.connect(params.toString());
  };

  window.addEventListener("resize", scheduleResize);
  window.addEventListener("focus", scheduleResize);
  root.addEventListener("pointerdown", markActivity, { passive: true });
  root.addEventListener("keydown", markActivity, true);
  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin) return;
    if (event.data && event.data.type === "kaya:remote-tab-active") {
      window.setTimeout(scheduleResize, 50);
      if (displayElement) displayElement.focus({ preventScroll: true });
    }
    if (event.data && event.data.type === "kaya:remote-display-refresh") {
      lastRequestedSize = "";
      scheduleResize();
    }
    if (event.data && event.data.type === "kaya:remote-recording-toggle") {
      if (recorder && recorder.state === "recording") {
        stopRecording();
      } else {
        startRecording("manual");
      }
      syncRecordingButton();
    }
    if (event.data && event.data.type === "kaya:remote-recording-query") {
      syncRecordingButton();
    }
    if (event.data && event.data.type === "kaya:remote-popout-request") {
      event.source?.postMessage({
        type: "kaya:remote-popout-state",
        requestId: event.data.requestId,
        ok: connected && Boolean(activeToken),
        token: activeToken,
      }, event.origin);
    }
    if (event.data && event.data.type === "kaya:remote-popout-detached") {
      if (!connected) return;
      disconnectReason = "Session moved to the pop-out window.";
      manuallyStopped = true;
      setOverlayVisible(true);
      setStatus("Popped out", disconnectReason);
      writeLog([disconnectReason]);
      disconnectCurrentSession();
      form.hidden = false;
      button.disabled = false;
    }
    if (event.data && event.data.type === "kaya:remote-popout-connect") {
      const hashParams = new URLSearchParams(window.location.hash.slice(1));
      if (event.data.requestId !== hashParams.get("requestId") || !event.data.token) return;
      form.hidden = true;
      setOverlayVisible(true);
      writeLog(["Opening popped-out RDP session."]);
      connectDisplay(event.data.token, true);
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && connected) {
      scheduleResize();
    }
  });
  window.addEventListener("beforeunload", stopSession);
  if (recordingButton) {
    recordingButton.addEventListener("click", () => {
      if (recorder && recorder.state === "recording") {
        stopRecording();
      } else {
        startRecording("manual");
      }
    });
    syncRecordingButton();
  }

  form.addEventListener("submit", (event) => event.preventDefault());
  button.addEventListener("click", async () => {
    button.disabled = true;
    setOverlayVisible(true);
    writeLog(["Creating RDP session. Password is not stored."]);
    const formData = new FormData(form);
    const size = displaySize();
    try {
      const response = await fetch(root.dataset.startUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csrf_token: formData.get("csrf_token"),
          username: formData.get("rdp_username"),
          password: formData.get("rdp_password"),
          width: size.width,
          height: size.height,
          dpi: size.dpi,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
        }),
      });
      const data = await response.json();
      writeLog(data.logs || [`Unexpected response: ${response.status}`]);
      if (!response.ok || !data.ok || !data.token) {
        button.disabled = false;
        return;
      }
      const passwordInput = form.querySelector("input[name='rdp_password']");
      if (passwordInput) passwordInput.value = "";
      form.hidden = true;
      connectDisplay(data.token);
    } catch (error) {
      writeLog([`Browser request failed: ${error}`]);
      button.disabled = false;
    }
  });

  const hashParams = new URLSearchParams(window.location.hash.slice(1));
  const handoffRequestId = hashParams.get("requestId");
  if (handoffRequestId && window.opener && !window.opener.closed) {
    form.hidden = true;
    setOverlayVisible(true);
    writeLog(["Waiting for secure RDP handoff."]);
    window.opener.postMessage({ type: "kaya:remote-popout-ready", requestId: handoffRequestId }, window.location.origin);
  }
}
