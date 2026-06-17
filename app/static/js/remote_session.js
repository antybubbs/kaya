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
    homelab: {
      background: "#011627",
      foreground: "#d6deeb",
      cursor: "#d6deeb",
      cursorAccent: "#011627",
      selectionBackground: "#1d3b53",
      black: "#011627",
      red: "#ef5350",
      green: "#22da6e",
      yellow: "#addb67",
      blue: "#82aaff",
      magenta: "#c792ea",
      cyan: "#21c7a8",
      white: "#d6deeb",
      brightBlack: "#575656",
      brightRed: "#ef5350",
      brightGreen: "#22da6e",
      brightYellow: "#ffeb95",
      brightBlue: "#82aaff",
      brightMagenta: "#c792ea",
      brightCyan: "#7fdbca",
      brightWhite: "#ffffff",
    },
    homelabDark: {
      background: "#011627",
      foreground: "#d6deeb",
      cursor: "#d6deeb",
      cursorAccent: "#011627",
      selectionBackground: "#1d3b53",
      black: "#011627",
      red: "#ef5350",
      green: "#22da6e",
      yellow: "#addb67",
      blue: "#82aaff",
      magenta: "#c792ea",
      cyan: "#21c7a8",
      white: "#d6deeb",
      brightBlack: "#575656",
      brightRed: "#ef5350",
      brightGreen: "#22da6e",
      brightYellow: "#ffeb95",
      brightBlue: "#82aaff",
      brightMagenta: "#c792ea",
      brightCyan: "#7fdbca",
      brightWhite: "#ffffff",
    },
    homelabLight: {
      background: "#ffffff",
      foreground: "#18181b",
      cursor: "#18181b",
      cursorAccent: "#ffffff",
      selectionBackground: "#d1d5db",
      black: "#18181b",
      red: "#dc2626",
      green: "#16a34a",
      yellow: "#ca8a04",
      blue: "#2563eb",
      magenta: "#9333ea",
      cyan: "#0891b2",
      white: "#f4f4f5",
      brightBlack: "#71717a",
      brightRed: "#ef4444",
      brightGreen: "#22c55e",
      brightYellow: "#eab308",
      brightBlue: "#3b82f6",
      brightMagenta: "#a855f7",
      brightCyan: "#06b6d4",
      brightWhite: "#ffffff",
    },
    nightOwl: {
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
    monokai: {
      background: "#272822",
      foreground: "#f8f8f2",
      cursor: "#f8f8f0",
      cursorAccent: "#272822",
      selectionBackground: "#49483e",
      black: "#272822",
      red: "#f92672",
      green: "#a6e22e",
      yellow: "#f4bf75",
      blue: "#66d9ef",
      magenta: "#ae81ff",
      cyan: "#a1efe4",
      white: "#f8f8f2",
      brightBlack: "#75715e",
      brightRed: "#f92672",
      brightGreen: "#a6e22e",
      brightYellow: "#f4bf75",
      brightBlue: "#66d9ef",
      brightMagenta: "#ae81ff",
      brightCyan: "#a1efe4",
      brightWhite: "#f9f8f5",
    },
    oneDark: {
      background: "#282c34",
      foreground: "#abb2bf",
      cursor: "#528bff",
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
    gruvboxDark: {
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
    solarizedDark: {
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
    tokyoNight: {
      background: "#1a1b26",
      foreground: "#a9b1d6",
      cursor: "#a9b1d6",
      cursorAccent: "#1a1b26",
      selectionBackground: "#283457",
      black: "#15161e",
      red: "#f7768e",
      green: "#9ece6a",
      yellow: "#e0af68",
      blue: "#7aa2f7",
      magenta: "#bb9af7",
      cyan: "#7dcfff",
      white: "#a9b1d6",
      brightBlack: "#414868",
      brightRed: "#f7768e",
      brightGreen: "#9ece6a",
      brightYellow: "#e0af68",
      brightBlue: "#7aa2f7",
      brightMagenta: "#bb9af7",
      brightCyan: "#7dcfff",
      brightWhite: "#c0caf5",
    },
    catppuccinMocha: {
      background: "#1e1e2e",
      foreground: "#cdd6f4",
      cursor: "#f5e0dc",
      cursorAccent: "#1e1e2e",
      selectionBackground: "#585b70",
      black: "#45475a",
      red: "#f38ba8",
      green: "#a6e3a1",
      yellow: "#f9e2af",
      blue: "#89b4fa",
      magenta: "#f5c2e7",
      cyan: "#94e2d5",
      white: "#bac2de",
      brightBlack: "#585b70",
      brightRed: "#f38ba8",
      brightGreen: "#a6e3a1",
      brightYellow: "#f9e2af",
      brightBlue: "#89b4fa",
      brightMagenta: "#f5c2e7",
      brightCyan: "#94e2d5",
      brightWhite: "#a6adc8",
    },
  };

  const terminalFonts = {
    "Caskaydia Cove Nerd Font Mono": "\"Caskaydia Cove Nerd Font Mono\", \"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    "JetBrains Mono": "\"JetBrains Mono\", \"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    "Fira Code": "\"Fira Code\", \"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    "Cascadia Code": "\"Cascadia Code\", \"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    "Source Code Pro": "\"Source Code Pro\", \"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    "SF Mono": "\"SF Mono\", Consolas, \"Liberation Mono\", monospace",
    Consolas: "Consolas, \"Liberation Mono\", monospace",
    Monaco: "Monaco, \"Liberation Mono\", monospace",
  };

  const ansiCodes = {
    reset: "\x1b[0m",
    colors: {
      blue: "\x1b[34m",
      magenta: "\x1b[35m",
      brightBlack: "\x1b[90m",
      brightRed: "\x1b[91m",
      brightGreen: "\x1b[92m",
      brightYellow: "\x1b[93m",
      brightBlue: "\x1b[94m",
      brightWhite: "\x1b[97m",
    },
    styles: {
      underline: "\x1b[4m",
    },
  };

  const highlightPatterns = [
    {
      regex: /([a-zA-Z_][a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]+)(:)(~|\/[^\s#$]*)([$#])(?=\s|$)/g,
      ansiCode: (_match, userHost, colon, path, marker) =>
        `${ansiCodes.colors.brightGreen}${userHost}${ansiCodes.reset}${colon}${ansiCodes.colors.brightBlue}${path}${ansiCodes.reset}${marker}`,
      priority: 12,
    },
    {
      regex: /([a-zA-Z_][a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]+)([$#])(?=\s|$)/g,
      ansiCode: (_match, userHost, marker) =>
        `${ansiCodes.colors.brightGreen}${userHost}${ansiCodes.reset}${marker}`,
      priority: 12,
    },
    {
      regex: /(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?::\d{1,5})?/g,
      ansiCode: ansiCodes.colors.magenta,
      priority: 10,
    },
    {
      regex: /\b(ERROR|FATAL|CRITICAL|FAIL(?:ED)?|denied|invalid|DENIED)\b|\[ERROR\]/gi,
      ansiCode: ansiCodes.colors.brightRed,
      priority: 9,
    },
    {
      regex: /\b(WARN(?:ING)?|ALERT|restart required)\b|\[WARN(?:ING)?\]/gi,
      ansiCode: ansiCodes.colors.brightYellow,
      priority: 9,
    },
    {
      regex: /\b(SUCCESS|OK|PASS(?:ED)?|COMPLETE(?:D)?|connected|active|started|pulled|up|UP|FULL)\b|[\u2713\u2714]/gi,
      ansiCode: ansiCodes.colors.brightGreen,
      priority: 8,
    },
    {
      regex: /https?:\/\/[^\s\])}]+/g,
      ansiCode: `${ansiCodes.colors.brightBlue}${ansiCodes.styles.underline}`,
      priority: 8,
    },
    {
      regex: /(?:^|\s)(\/[a-zA-Z][a-zA-Z0-9_\-@.]*(?:\/[a-zA-Z0-9_\-@.]+)+)/g,
      ansiCode: (_match, path) => `${_match.slice(0, _match.length - path.length)}${ansiCodes.colors.brightBlue}${path}${ansiCodes.reset}`,
      priority: 7,
    },
    {
      regex: /(?:^|\s)(~\/[a-zA-Z0-9_\-@./]+)/g,
      ansiCode: (_match, path) => `${_match.slice(0, _match.length - path.length)}${ansiCodes.colors.brightBlue}${path}${ansiCodes.reset}`,
      priority: 7,
    },
    {
      regex: /\b(?:docker|compose|sudo|apt|apt-get|ls|cd|cat|nano|vim|systemctl|journalctl|ssh)\b/g,
      ansiCode: ansiCodes.colors.brightWhite,
      priority: 6,
    },
    {
      regex: /\bINFO\b|\[INFO\]/gi,
      ansiCode: ansiCodes.colors.blue,
      priority: 6,
    },
    {
      regex: /\b(?:DEBUG|TRACE)\b|\[(?:DEBUG|TRACE)\]/gi,
      ansiCode: ansiCodes.colors.brightBlack,
      priority: 6,
    },
  ];

  const hasIncompleteAnsiSequence = (text) => /\x1b(?:\[(?:[0-9;?>=!]*)?)?$/.test(text);

  const parseAnsiSegments = (text) => {
    const segments = [];
    const ansiRegex = /\x1b(?:[@-Z\\-_]|\[[0-9;?>=!]*[@-~])/g;
    let lastIndex = 0;
    let match = ansiRegex.exec(text);
    while (match) {
      if (match.index > lastIndex) {
        segments.push({ isAnsi: false, content: text.slice(lastIndex, match.index) });
      }
      segments.push({ isAnsi: true, content: match[0] });
      lastIndex = ansiRegex.lastIndex;
      match = ansiRegex.exec(text);
    }
    if (lastIndex < text.length) {
      segments.push({ isAnsi: false, content: text.slice(lastIndex) });
    }
    return segments;
  };

  const highlightPlainText = (text) => {
    if (text.length > 5000 || !text.trim()) return text;

    const matches = [];
    highlightPatterns.forEach((pattern) => {
      pattern.regex.lastIndex = 0;
      let match = pattern.regex.exec(text);
      while (match) {
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          match,
          pattern,
          priority: pattern.priority,
        });
        match = pattern.regex.exec(text);
      }
    });

    if (!matches.length) return text;

    matches.sort((a, b) => (a.priority === b.priority ? a.start - b.start : b.priority - a.priority));
    const appliedRanges = [];
    const finalMatches = matches.filter((match) => {
      const overlaps = appliedRanges.some(
        (range) =>
          (match.start >= range.start && match.start < range.end) ||
          (match.end > range.start && match.end <= range.end) ||
          (match.start <= range.start && match.end >= range.end),
      );
      if (overlaps) return false;
      appliedRanges.push({ start: match.start, end: match.end });
      return true;
    });

    let result = text;
    finalMatches.reverse().forEach((match) => {
      const before = result.slice(0, match.start);
      const matched = result.slice(match.start, match.end);
      const after = result.slice(match.end);
      const replacement =
        typeof match.pattern.ansiCode === "function"
          ? match.pattern.ansiCode(...match.match)
          : `${match.pattern.ansiCode}${matched}${ansiCodes.reset}`;
      result = before + replacement + after;
    });
    return result;
  };

  const highlightTerminalOutput = (text) => {
    if (!text || !text.trim() || hasIncompleteAnsiSequence(text)) return text;
    return parseAnsiSegments(text)
      .map((segment) => (segment.isAnsi ? segment.content : highlightPlainText(segment.content)))
      .join("");
  };

  const terminalSettings = {
    theme: root.dataset.terminalTheme || "homelab",
    fontFamily: terminalFonts[root.dataset.terminalFontFamily] || terminalFonts["Caskaydia Cove Nerd Font Mono"],
    fontSize: readInt(root.dataset.terminalFontSize, 14, 8, 28),
    cursorStyle: root.dataset.terminalCursorStyle || "bar",
    letterSpacing: readInt(root.dataset.terminalLetterSpacing, 0, 0, 4),
    lineHeight: readFloat(root.dataset.terminalLineHeight, 1, 0.8, 2),
    bellStyle: root.dataset.terminalBellStyle || "none",
    backspaceMode: root.dataset.terminalBackspaceMode || "normal",
    cursorBlink: true,
    rightClickSelectsWord: root.dataset.terminalRightClickSelectsWord === "1",
    syntaxHighlighting: true,
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

  const selectedTheme = terminalThemes.homelab;
  terminalEl.style.backgroundColor = selectedTheme.background;
  terminalEl.dataset.homelabSshRenderer = "rewrite-2";

  const term = new window.Terminal({
    allowTransparency: false,
    convertEol: true,
    cursorBlink: terminalSettings.cursorBlink,
    cursorInactiveStyle: "block",
    cursorStyle: terminalSettings.cursorStyle,
    cursorWidth: terminalSettings.cursorStyle === "bar" ? 3 : 1,
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
    theme: selectedTheme,
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
          sendTerminalMessage("input", "\b");
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
            sendTerminalMessage("input", text);
          }
        });
        return false;
      }

      return true;
    });
  }

  let socket = null;
  let connected = false;

  const writeTerminal = (data) => {
    const text = typeof data === "string" ? data : String(data || "");
    term.write(terminalSettings.syntaxHighlighting ? highlightTerminalOutput(text) : text);
  };

  const sendTerminalMessage = (type, data = {}) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type, data }));
  };

  const fit = () => {
    if (!fitAddon) return;
    fitAddon.fit();
    if (connected && socket && socket.readyState === WebSocket.OPEN) {
      sendTerminalMessage("resize", { cols: term.cols, rows: term.rows });
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
    sendTerminalMessage("input", text);
  });

  term.onData((data) => {
    if (!connected || !socket || socket.readyState !== WebSocket.OPEN) return;
    sendTerminalMessage("input", data);
  });

  window.addEventListener("beforeunload", () => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      sendTerminalMessage("disconnect");
    }
  });

  passwordForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (socket && socket.readyState === WebSocket.OPEN) return;

    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${scheme}//${window.location.host}${root.dataset.wsUrl}`;
    term.reset();
    writeTerminal("Connecting...\r\n");
    socket = new WebSocket(wsUrl);

    socket.addEventListener("open", () => {
      sendTerminalMessage("connectToHost", {
        password: passwordInput.value,
        cols: term.cols,
        rows: term.rows,
      });
      passwordInput.value = "";
      passwordForm.hidden = true;
      fit();
      term.focus();
      term.options.cursorBlink = true;
      term.options.cursorStyle = terminalSettings.cursorStyle;
      term.refresh(0, term.rows - 1);
    });

    socket.addEventListener("message", (event) => {
      let message = null;
      try {
        message = JSON.parse(event.data);
      } catch (_error) {
        writeTerminal(event.data);
        return;
      }

      if (message.type === "data") {
        writeTerminal(message.data || "");
      } else if (message.type === "connected") {
        connected = true;
        fit();
      } else if (message.type === "error") {
        writeTerminal(`\r\n${message.message || "SSH connection failed."}\r\n`);
      } else if (message.type === "sessionTakenOver" || message.type === "sessionExpired") {
        writeTerminal(`\r\n${message.message || "Session ended."}\r\n`);
      }

      if (connected && document.visibilityState === "visible") {
        window.setTimeout(() => {
          term.focus();
          term.refresh(0, term.rows - 1);
        }, 0);
      }
    });
    socket.addEventListener("close", () => {
      connected = false;
      writeTerminal("\r\nSession closed.\r\n");
      passwordForm.hidden = false;
    });
    socket.addEventListener("error", () => writeTerminal("\r\nSession error.\r\n"));
  });
})();
