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
    cursorStyle: "bar",
    fontFamily: "Caskaydia Cove Nerd Font Mono, Cascadia Mono, Consolas, ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 14,
    fontWeight: 400,
    fontWeightBold: 700,
    lineHeight: 1.0,
    letterSpacing: 0,
    scrollback: 6000,
    theme: {
      background: "#0c0d0b",
      foreground: "#f7f7f7",
      cursor: "#f7f7f7",
      cursorAccent: "#0c0d0b",
      selectionBackground: "#3a3a3d",
      black: "#2e3436",
      red: "#cc0000",
      green: "#4e9a06",
      yellow: "#c4a000",
      blue: "#3465a4",
      magenta: "#75507b",
      cyan: "#06989a",
      white: "#d3d7cf",
      brightBlack: "#555753",
      brightRed: "#ef2929",
      brightGreen: "#8ae234",
      brightYellow: "#fce94f",
      brightBlue: "#729fcf",
      brightMagenta: "#ad7fa8",
      brightCyan: "#34e2e2",
      brightWhite: "#eeeeec",
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
