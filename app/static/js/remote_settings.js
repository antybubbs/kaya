(() => {
  const preview = document.querySelector(".terminal-preview");
  const form = preview?.closest("form") || document.querySelector(".remote-settings-shell");
  if (!form || !preview) return;

  const themes = {
    kaya: { background: "#011627", foreground: "#d6deeb" },
    kayaDark: { background: "#011627", foreground: "#d6deeb" },
    kayaLight: { background: "#ffffff", foreground: "#18181b" },
    homelab: { background: "#011627", foreground: "#d6deeb" },
    homelabDark: { background: "#011627", foreground: "#d6deeb" },
    homelabLight: { background: "#ffffff", foreground: "#18181b" },
    nightOwl: { background: "#011627", foreground: "#d6deeb" },
    dracula: { background: "#282a36", foreground: "#f8f8f2" },
    monokai: { background: "#272822", foreground: "#f8f8f2" },
    nord: { background: "#2e3440", foreground: "#d8dee9" },
    oneDark: { background: "#282c34", foreground: "#abb2bf" },
    tokyoNight: { background: "#1a1b26", foreground: "#a9b1d6" },
    gruvboxDark: { background: "#282828", foreground: "#ebdbb2" },
    solarizedDark: { background: "#002b36", foreground: "#839496" },
    catppuccinMocha: { background: "#1e1e2e", foreground: "#cdd6f4" },
  };

  const fonts = {
    "Caskaydia Cove Nerd Font Mono": '"Caskaydia Cove Nerd Font Mono", "SF Mono", Consolas, monospace',
    "JetBrains Mono": '"JetBrains Mono", "SF Mono", Consolas, monospace',
    "Fira Code": '"Fira Code", "SF Mono", Consolas, monospace',
    "Cascadia Code": '"Cascadia Code", "SF Mono", Consolas, monospace',
    "Source Code Pro": '"Source Code Pro", "SF Mono", Consolas, monospace',
    "SF Mono": '"SF Mono", Consolas, monospace',
    Consolas: 'Consolas, monospace',
    Monaco: 'Monaco, monospace',
  };

  const updatePreview = () => {
    const themeValue = form.elements.terminal_theme?.value || "kaya";
    const fontValue = form.elements.terminal_font_family?.value || "Caskaydia Cove Nerd Font Mono";
    const fontSize = form.elements.terminal_font_size?.value || "14";
    const letterSpacing = form.elements.terminal_letter_spacing?.value || "0";
    const lineHeight = form.elements.terminal_line_height?.value || "1";

    const theme = themes[themeValue] || themes.kaya;

    preview.style.backgroundColor = theme.background;
    preview.style.color = theme.foreground;
    preview.style.fontFamily = fonts[fontValue] || fonts["Caskaydia Cove Nerd Font Mono"];
    preview.style.fontSize = `${fontSize}px`;
    preview.style.letterSpacing = `${letterSpacing}px`;
    preview.style.lineHeight = lineHeight;
  };

  form.addEventListener("input", updatePreview);
  form.addEventListener("change", updatePreview);
  updatePreview();
})();
