(() => {
  const root = document.querySelector("[data-ssh-session]");
  if (!root) return;

  const terminalEl = root.querySelector("[data-ssh-terminal]");
  const passwordForm = root.querySelector("[data-ssh-password-form]");
  const passwordInput = root.querySelector("[data-ssh-password]");
  if (!terminalEl || !passwordForm || !passwordInput || !window.Terminal) return;

  const readInt = (value, fallback, min, max) => {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
  };

  const readFloat = (value, fallback, min, max) => {
    const parsed = Number.parseFloat(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
  };

  const terminalThemes = {
    "night-owl": {
      background: "#011627",
      foreground: "#d6deeb",
      cursor: "#80a4c2",
      cursorAccent: "#011627",
      selectionBackground: "#1d3b53",
      black: "#011627",
      red: "#ef5350",
      green: "#22da6e",
      yellow: "#addb67",
      blue: "#82aaff",
      magenta: "#c792ea",
      cyan: "#21c7a8",
      white: "#ffffff",
      brightBlack: "#575656",
      brightRed: "#ef5350",
      brightGreen: "#22da6e",
      brightYellow: "#ffeb95",
      brightBlue: "#82aaff",
      brightMagenta: "#c792ea",
      brightCyan: "#7fdbca",
      brightWhite: "#ffffff",
    },
    dracula: {
      background: "#282a36",
      foreground: "#f8f8f2",
      cursor: "#f8f8f2",
      cursorAccent: "#282a36",
      selectionBackground: "#44475a",
      black: "#21222c",
      red: "#ff5555",
      green: "#50fa7b",
      yellow: "#f1fa8c",
      blue: "#bd93f9",
      magenta: "#ff79c6",
      cyan: "#8be9fd",
      white: "#f8f8f2",
      brightBlack: "#6272a4",
      brightRed: "#ff6e6e",
      brightGreen: "#69ff94",
      brightYellow: "#ffffa5",
      brightBlue: "#d6acff",
      brightMagenta: "#ff92df",
      brightCyan: "#a4ffff",
      brightWhite: "#ffffff",
    },
    nord: {
      background: "#2e3440",
      foreground: "#d8dee9",
      cursor: "#d8dee9",
      cursorAccent: "#2e3440",
      selectionBackground: "#434c5e",
      black: "#3b4252",
      red: "#bf616a",
      green: "#a3be8c",
      yellow: "#ebcb8b",
      blue: "#81a1c1",
      magenta: "#b48ead",
      cyan: "#88c0d0",
      white: "#e5e9f0",
      brightBlack: "#4c566a",
      brightRed: "#bf616a",
      brightGreen: "#a3be8c",
      brightYellow: "#ebcb8b",
      brightBlue: "#81a1c1",
      brightMagenta: "#b48ead",
      brightCyan: "#8fbcbb",
      brightWhite: "#eceff4",
    },
    "one-dark": {
      background: "#282c34",
      foreground: "#abb2bf",
      cursor: "#abb2bf",
      cursorAccent: "#282c34",
      selectionBackground: "#3e4451",
      black: "#282c34",
      red: "#e06c75",
      green: "#98c379",
      yellow: "#e5c07b",
      blue: "#61afef",
      magenta: "#c678dd",
      cyan: "#56b6c2",
      white: "#abb2bf",
      brightBlack: "#5c6370",
      brightRed: "#e06c75",
      brightGreen: "#98c379",
      brightYellow: "#e5c07b",
      brightBlue: "#61afef",
      brightMagenta: "#c678dd",
      brightCyan: "#56b6c2",
      brightWhite: "#ffffff",
    },
    gruvbox: {
      background: "#282828",
      foreground: "#ebdbb2",
      cursor: "#ebdbb2",
      cursorAccent: "#282828",
      selectionBackground: "#504945",
      black: "#282828",
      red: "#cc241d",
      green: "#98971a",
      yellow: "#d79921",
      blue: "#458588",
      magenta: "#b16286",
      cyan: "#689d6a",
      white: "#a89984",
      brightBlack: "#928374",
      brightRed: "#fb4934",
      brightGreen: "#b8bb26",
      brightYellow: "#fabd2f",
      brightBlue: "#83a598",
      brightMagenta: "#d3869b",
      brightCyan: "#8ec07c",
      brightWhite: "#ebdbb2",
    },
    "solarized-dark": {
      background: "#002b36",
      foreground: "#839496",
      cursor: "#93a1a1",
      cursorAccent: "#002b36",
      selectionBackground: "#073642",
      black: "#073642",
      red: "#dc322f",
      green: "#859900",
      yellow: "#b58900",
      blue: "#268bd2",
      magenta: "#d33682",
      cyan: "#2aa198",
      white: "#eee8d5",
      brightBlack: "#002b36",
      brightRed: "#cb4b16",
      brightGreen: "#586e75",
      brightYellow: "#657b83",
      brightBlue: "#839496",
      brightMagenta: "#6c71c4",
      brightCyan: "#93a1a1",
      brightWhite: "#fdf6e3",
    },
  };

  const terminalSettings = {
    theme: root.dataset.terminalTheme || "night-owl",
    fontFamily: root.dataset.terminalFontFamily || "Caskaydia Cove Nerd Font Mono, Cascadia Mono, Consolas, ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: readInt(root.dataset.terminalFontSize, 14, 8, 28),
    cursorStyle: root.dataset.terminalCursorStyle || "bar",
    letterSpacing: readInt(root.dataset.terminalLetterSpacing, 0, 0, 4),
    lineHeight: readFloat(root.dataset.terminalLineHeight, 1, 0.8, 2),
    bellStyle: root.dataset.terminalBellStyle || "none",
    backspaceMode: root.dataset.terminalBackspaceMode || "normal",
    cursorBlink: root.dataset.terminalCursorBlink !== "0",
    rightClickSelectsWord: root.dataset.terminalRightClickSelectsWord === "1",
    scrollback: readInt(root.dataset.terminalScrollback, 10000, 1000, 100000),
  };

  const registerWebLinks = () => {
    if (typeof term.registerLinkProvider !== "function") return;

    const urlPattern = /\bhttps?:\/\/[^\s<>"'`]+/gi;
    const trimUrl = (value) => value.replace(/[),.;:!?]+$/g, "");

    term.registerLinkProvider({
      provideLinks: (line, callback) => {
        const bufferLine = term.buffer && term.buffer.active.getLine(line - 1);
        if (!bufferLine) {
          callback([]);
          return;
        }

        const text = bufferLine.translateToString(true);
        const links = [];
        let match = urlPattern.exec(text);
        while (match) {
          const url = trimUrl(match[0]);
          const start = match.index + 1;
          const end = start + url.length - 1;
          links.push({
            text: url,
            range: {
              start: { x: start, y: line },
              end: { x: end, y: line },
            },
            activate: () => window.open(url, "_blank", "noopener,noreferrer"),
            hover: () => terminalEl.classList.add("is-link-hover"),
            leave: () => terminalEl.classList.remove("is-link-hover"),
            decorations: { pointerCursor: true, underline: true },
          });

          match = urlPattern.exec(text);
        }

        callback(links);
      },
    });
  };

  const term = new window.Terminal({
    allowTransparency: false,
    convertEol: true,
    cursorBlink: terminalSettings.cursorBlink,
    cursorInactiveStyle: "block",
    cursorStyle: terminalSettings.cursorStyle,
    drawBoldTextInBrightColors: true,
    fontFamily: terminalSettings.fontFamily,
    fontSize: terminalSettings.fontSize,
    fontWeight: 600,
    fontWeightBold: 700,
    lineHeight: terminalSettings.lineHeight,
    letterSpacing: terminalSettings.letterSpacing,
    scrollback: terminalSettings.scrollback,
    scrollOnUserInput: true,
    smoothScrollDuration: 0,
    termName: "xterm-256color",
    bellStyle: terminalSettings.bellStyle,
    rightClickSelectsWord: terminalSettings.rightClickSelectsWord,
    fastScrollModifier: "alt",
    fastScrollSensitivity: 5,
    minimumContrastRatio: 1,
    theme: terminalThemes[terminalSettings.theme] || terminalThemes["night-owl"],
  });
  const fitAddon = window.FitAddon ? new window.FitAddon.FitAddon() : null;
  if (fitAddon) term.loadAddon(fitAddon);
  term.open(terminalEl);
  registerWebLinks();
  if (fitAddon) fitAddon.fit();

  if (typeof term.attachCustomKeyEventHandler === "function") {
    term.attachCustomKeyEventHandler((event) => {
      if (event.type !== "keydown") return true;
      const key = event.key.toLowerCase();

      if (key === "backspace" && terminalSettings.backspaceMode === "bs") {
        if (connected && socket && socket.readyState === WebSocket.OPEN) {
          socket.send("\b");
        }
        return false;
      }

      if ((event.ctrlKey || event.metaKey) && key === "c" && term.hasSelection()) {
        const selection = term.getSelection();
        if (selection && navigator.clipboard) {
          navigator.clipboard.writeText(selection);
        }
        term.clearSelection();
        return false;
      }

      if ((event.ctrlKey || event.metaKey) && key === "v" && navigator.clipboard) {
        navigator.clipboard.readText().then((text) => {
          if (text && connected && socket && socket.readyState === WebSocket.OPEN) {
            socket.send(text);
          }
        });
        return false;
      }

      return true;
    });
  }

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
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      window.setTimeout(fit, 50);
      if (connected) term.focus();
    }
  });
  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin) return;
    if (event.data && event.data.type === "homelab:remote-tab-active") {
      window.setTimeout(fit, 50);
      if (connected) term.focus();
    }
  });
  terminalEl.addEventListener("click", () => term.focus());
  terminalEl.addEventListener("paste", (event) => {
    const text = event.clipboardData ? event.clipboardData.getData("text/plain") : "";
    if (!text || !connected || !socket || socket.readyState !== WebSocket.OPEN) return;
    event.preventDefault();
    socket.send(text);
  });

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
      socket.send(JSON.stringify({ password: passwordInput.value, cols: term.cols, rows: term.rows }));
      passwordInput.value = "";
      passwordForm.hidden = true;
      connected = true;
      fit();
      term.focus();
      term.options.cursorBlink = terminalSettings.cursorBlink;
      term.refresh(0, term.rows - 1);
    });

    socket.addEventListener("message", (event) => term.write(event.data));
    socket.addEventListener("close", () => {
      connected = false;
      term.write("\r\nSession closed.\r\n");
      passwordForm.hidden = false;
    });
    socket.addEventListener("error", () => term.write("\r\nSession error.\r\n"));
  });
})();
