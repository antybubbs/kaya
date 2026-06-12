(() => {
  const root = document.querySelector("[data-ssh-session]");
  if (!root) return;

  const terminalEl = root.querySelector("[data-ssh-terminal]");
  const passwordForm = root.querySelector("[data-ssh-password-form]");
  const passwordInput = root.querySelector("[data-ssh-password]");
  if (!terminalEl || !passwordForm || !passwordInput || !window.Terminal) return;

  const term = new window.Terminal({
    allowTransparency: false,
    convertEol: true,
    cursorBlink: true,
    cursorStyle: "block",
    fontFamily: "Cascadia Mono, Consolas, ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 15,
    fontWeight: 700,
    fontWeightBold: 800,
    lineHeight: 1.08,
    letterSpacing: 0,
    scrollback: 6000,
    theme: {
      background: "#080a08",
      foreground: "#f4f4f5",
      cursor: "#f8fafc",
      cursorAccent: "#080a08",
      selectionBackground: "#314158",
      black: "#0a0c0a",
      red: "#ff5f57",
      green: "#5af78e",
      yellow: "#f3f99d",
      blue: "#57c7ff",
      magenta: "#ff6ac1",
      cyan: "#9aedfe",
      white: "#f1f5f9",
      brightBlack: "#686f7a",
      brightRed: "#ff6e67",
      brightGreen: "#7cff9b",
      brightYellow: "#ffffa5",
      brightBlue: "#5cc8ff",
      brightMagenta: "#ff92d0",
      brightCyan: "#c2ffff",
      brightWhite: "#ffffff",
    },
  });
  const fitAddon = window.FitAddon ? new window.FitAddon.FitAddon() : null;
  if (fitAddon) term.loadAddon(fitAddon);
  term.open(terminalEl);
  if (fitAddon) fitAddon.fit();

  let socket = null;
  let connected = false;

  const fit = () => {
    if (!fitAddon) return;
    fitAddon.fit();
    if (connected && socket && socket.readyState === WebSocket.OPEN) {
      socket.send(`\x00resize:${term.cols}:${term.rows}`);
    }
  };

  window.addEventListener("resize", fit);

  term.onData((data) => {
    if (!connected || !socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(data);
  });

  passwordForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (socket && socket.readyState === WebSocket.OPEN) return;

    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${scheme}//${window.location.host}${root.dataset.wsUrl}`;
    term.reset();
    term.write("Connecting...\r\n");
    socket = new WebSocket(wsUrl);

    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({ password: passwordInput.value }));
      passwordInput.value = "";
      passwordForm.hidden = true;
      connected = true;
      fit();
      term.focus();
    });

    socket.addEventListener("message", (event) => term.write(event.data));
    socket.addEventListener("close", () => {
      connected = false;
      term.write("\r\nSession closed.\r\n");
    });
    socket.addEventListener("error", () => term.write("\r\nSession error.\r\n"));
  });
})();
