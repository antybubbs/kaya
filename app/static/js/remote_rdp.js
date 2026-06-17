import Guacamole from "/static/vendor/guacamole/guacamole-common.min.js";

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
    if (!client) return;
    fitDisplay();
    const size = displaySize();
    client.sendSize(size.width, size.height);
    client.getDisplay().flush(fitDisplay);
  };

  const scheduleResize = () => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(refreshDisplay, 150);
  };

  const disconnectCurrentSession = () => {
    window.clearTimeout(resizeTimer);
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
    connected = false;
    displayReady = false;
  };

  const stopSession = () => {
    manuallyStopped = true;
    disconnectCurrentSession();
  };

  const attachInput = () => {
    const displayEl = client.getDisplay().getElement();
    const mouse = new Guacamole.Mouse(displayEl);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (state) => {
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
      client.sendKeyEvent(1, keysym);
      return false;
    };
    keyboard.onkeyup = (keysym) => {
      client.sendKeyEvent(0, keysym);
      return false;
    };
  };

  const markDisplayReady = () => {
    if (displayReady) return;
    displayReady = true;
    setOverlayVisible(false);
    if (displayElement) displayElement.focus({ preventScroll: true });
  };

  const waitForLayout = () =>
    new Promise((resolve) => {
      window.requestAnimationFrame(() => window.requestAnimationFrame(resolve));
    });

  const connectDisplay = async (token) => {
    manuallyStopped = false;
    disconnectCurrentSession();
    window.clearTimeout(resizeTimer);
    displayTarget.replaceChildren();
    placeholder.hidden = true;
    displayReady = false;
    setOverlayVisible(true);
    setStatus("Connecting", "Opening browser display tunnel.");
    await waitForLayout();
    const size = displaySize();
    const params = new URLSearchParams({
      token,
      width: String(size.width),
      height: String(size.height),
    });
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
        refreshDisplay();
        markDisplayReady();
      }
      if (state === Guacamole.Client.State.DISCONNECTED) {
        setOverlayVisible(true);
        connected = false;
        displayReady = false;
        setStatus("Disconnected", "The RDP session has ended.");
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
  window.addEventListener("focus", refreshDisplay);
  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin) return;
    if (event.data && event.data.type === "homelab:remote-tab-active") {
      window.setTimeout(refreshDisplay, 50);
      if (displayElement) displayElement.focus({ preventScroll: true });
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && connected) {
      refreshDisplay();
    }
  });
  window.addEventListener("beforeunload", stopSession);

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
}
