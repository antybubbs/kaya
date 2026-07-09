(function () {
  const viewStorageKey = "kaya.runbook.view";
  const viewButtons = Array.from(document.querySelectorAll("[data-runbook-view-button]"));
  const views = Array.from(document.querySelectorAll("[data-runbook-view]"));
  const codeLanguages = [
    ["", "Auto"],
    ["plaintext", "Plain text"],
    ["bash", "Bash"],
    ["powershell", "PowerShell"],
    ["dockerfile", "Dockerfile"],
    ["yaml", "YAML"],
    ["json", "JSON"],
    ["python", "Python"],
    ["javascript", "JavaScript"],
    ["typescript", "TypeScript"],
    ["html", "HTML"],
    ["css", "CSS"],
    ["sql", "SQL"],
    ["nginx", "Nginx"],
    ["ini", "INI"],
    ["markdown", "Markdown"],
    ["csharp", "C#"],
    ["java", "Java"],
    ["go", "Go"],
    ["rust", "Rust"],
  ];

  function setRunbookView(view) {
    const nextView = view === "table" ? "table" : "tiles";
    views.forEach((item) => {
      item.hidden = item.dataset.runbookView !== nextView;
    });
    viewButtons.forEach((button) => {
      const active = button.dataset.runbookViewButton === nextView;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
    if (views.length) localStorage.setItem(viewStorageKey, nextView);
  }

  if (views.length && viewButtons.length) {
    setRunbookView(localStorage.getItem(viewStorageKey) || "tiles");
    viewButtons.forEach((button) => {
      button.addEventListener("click", () => setRunbookView(button.dataset.runbookViewButton));
    });
  }

  const escapeHtml = (value) =>
    String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const cleanLanguage = (value) => String(value || "").trim().toLowerCase().replace(/[^a-z0-9_+#.-]/g, "").slice(0, 40);

  const inline = (value) => {
    const images = [];
    const links = [];
    let rendered = escapeHtml(value).replace(/!\[([^\]]*)\]\((https?:\/\/[^\s)]+|\/[^\s)]+)\)/g, (_match, alt, src) => {
      const token = `@@RUNBOOKIMAGE${images.length}@@`;
      images.push(`<img src="${src}" alt="${alt}" loading="lazy">`);
      return token;
    });
    rendered = rendered.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/[^\s)]+|#[^\s)]+)\)/g, (_match, label, href) => {
      const token = `@@RUNBOOKLINK${links.length}@@`;
      const external = href.startsWith("http");
      links.push(`<a href="${href}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`);
      return token;
    });
    rendered = rendered
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>")
      .replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
    images.forEach((image, index) => {
      rendered = rendered.replace(`@@RUNBOOKIMAGE${index}@@`, image);
    });
    links.forEach((link, index) => {
      rendered = rendered.replace(`@@RUNBOOKLINK${index}@@`, link);
    });
    return rendered;
  };

  function languageOptions(selected) {
    const current = cleanLanguage(selected);
    const known = codeLanguages.some(([value]) => value === current);
    const options = known || !current ? codeLanguages : [...codeLanguages, [current, current]];
    return options.map(([value, label]) => `<option value="${escapeHtml(value)}"${value === current ? " selected" : ""}>${escapeHtml(label)}</option>`).join("");
  }

  function codeBlock(code, language, index, editable) {
    const clean = cleanLanguage(language);
    const languageClass = clean ? ` class="language-${escapeHtml(clean)}"` : "";
    const languageControl = editable
      ? `<label class="runbook-code-language"><span class="sr-only">Code language</span><select data-runbook-code-block-language="${index}" aria-label="Code language">${languageOptions(clean)}</select></label>`
      : `<span class="runbook-code-language-label">${escapeHtml(clean || "auto")}</span>`;
    return `<div class="runbook-code-block" data-code-language="${escapeHtml(clean || "auto")}"><div class="runbook-code-header">${languageControl}<button class="runbook-code-copy" type="button" data-runbook-copy-code aria-label="Copy code">Copy</button></div><pre><code${languageClass}>${escapeHtml(code)}</code></pre></div>`;
  }

  function highlightCode(root = document) {
    if (!window.hljs) return;
    root.querySelectorAll(".runbook-code-block pre code:not([data-highlighted])").forEach((element) => {
      try {
        window.hljs.highlightElement(element);
      } catch (_error) {
        element.className = "language-plaintext";
        window.hljs.highlightElement(element);
      }
    });
  }

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-runbook-copy-code]");
    if (!button) return;
    const code = button.closest(".runbook-code-block")?.querySelector("code")?.textContent || "";
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(code);
      } else {
        const helper = document.createElement("textarea");
        helper.value = code;
        helper.style.position = "fixed";
        helper.style.opacity = "0";
        document.body.appendChild(helper);
        helper.select();
        document.execCommand("copy");
        helper.remove();
      }
      const previous = button.textContent;
      button.textContent = "Copied";
      button.classList.add("copied");
      window.setTimeout(() => {
        button.textContent = previous;
        button.classList.remove("copied");
      }, 1600);
    } catch (_error) {
      button.textContent = "Copy failed";
    }
  });

  const textarea = document.querySelector("[data-runbook-markdown]");
  const preview = document.querySelector("[data-runbook-preview]");
  if (!textarea || !preview) {
    highlightCode();
    return;
  }
  const toolbar = document.querySelector("[data-runbook-image-upload-url]");
  const pasteStatus = document.querySelector("[data-runbook-paste-status]");
  const uploadImageUrl = toolbar?.dataset.runbookImageUploadUrl || "";
  const csrfToken = textarea.form?.querySelector('input[name="csrf_token"]')?.value || "";

  function setPasteStatus(message, tone = "") {
    if (!pasteStatus) return;
    pasteStatus.textContent = message || "";
    pasteStatus.dataset.tone = tone;
  }

  function render(markdown) {
    const lines = markdown.replace(/\r\n/g, "\n").split("\n");
    const output = [];
    let paragraph = [];
    let listType = "";
    let codeOpen = false;
    let code = [];
    let codeLanguage = "";
    let codeIndex = 0;

    const flushParagraph = () => {
      if (!paragraph.length) return;
      output.push(`<p>${paragraph.map((line) => inline(line)).join("<br>")}</p>`);
      paragraph = [];
    };

    const closeList = () => {
      if (!listType) return;
      output.push(`</${listType}>`);
      listType = "";
    };

    const flushCode = () => {
      output.push(codeBlock(code.join("\n"), codeLanguage, codeIndex, true));
      code = [];
      codeLanguage = "";
      codeIndex += 1;
    };

    lines.forEach((line) => {
      const stripped = line.trim();
      const fence = stripped.match(/^```([A-Za-z0-9_+#.-]*)\s*$/);
      if (fence) {
        if (codeOpen) {
          flushCode();
          codeOpen = false;
        } else {
          flushParagraph();
          closeList();
          codeOpen = true;
          codeLanguage = cleanLanguage(fence[1]);
        }
        return;
      }

      if (codeOpen) {
        code.push(line);
        return;
      }

      if (!stripped) {
        flushParagraph();
        closeList();
        return;
      }

      const heading = stripped.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        flushParagraph();
        closeList();
        const level = heading[1].length + 1;
        output.push(`<h${level}>${inline(heading[2])}</h${level}>`);
        return;
      }

      const listItem = stripped.match(/^([-*]|\d+\.)\s+(.+)$/);
      if (listItem) {
        flushParagraph();
        const nextType = /^\d/.test(listItem[1]) ? "ol" : "ul";
        if (listType && listType !== nextType) closeList();
        if (!listType) {
          const start = nextType === "ol" ? Number.parseInt(listItem[1], 10) : 1;
          output.push(nextType === "ol" && start > 1 ? `<ol start="${start}">` : `<${nextType}>`);
          listType = nextType;
        }
        output.push(`<li>${inline(listItem[2])}</li>`);
        return;
      }

      paragraph.push(stripped);
    });

    if (codeOpen) flushCode();
    flushParagraph();
    closeList();
    return output.join("\n") || '<p class="muted">Preview appears here as you write.</p>';
  }

  const update = () => {
    preview.innerHTML = render(textarea.value);
    highlightCode(preview);
  };

  function replaceSelection(before, after, placeholder) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.slice(start, end) || placeholder;
    textarea.setRangeText(`${before}${selected}${after}`, start, end, "end");
    const selectionStart = start + before.length;
    textarea.setSelectionRange(selectionStart, selectionStart + selected.length);
    textarea.focus();
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function replaceSelectedLines(transform, placeholder = "List item") {
    const value = textarea.value;
    const selectionStart = textarea.selectionStart;
    const selectionEnd = textarea.selectionEnd;
    const lineStart = value.lastIndexOf("\n", Math.max(0, selectionStart - 1)) + 1;
    const nextBreak = value.indexOf("\n", selectionEnd);
    const lineEnd = nextBreak === -1 ? value.length : nextBreak;
    const selected = value.slice(lineStart, lineEnd) || placeholder;
    const replacement = transform(selected.split("\n")).join("\n");
    textarea.setRangeText(replacement, lineStart, lineEnd, "select");
    textarea.focus();
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function insertCodeBlock() {
    const picker = document.querySelector("[data-runbook-code-language]");
    const language = cleanLanguage(picker?.value);
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.slice(start, end) || "command here";
    const prefix = start > 0 && textarea.value[start - 1] !== "\n" ? "\n\n" : "";
    const suffix = end < textarea.value.length && textarea.value[end] !== "\n" ? "\n\n" : "\n";
    const opening = `\`\`\`${language}`;
    const replacement = `${prefix}${opening}\n${selected}\n\`\`\`${suffix}`;
    textarea.setRangeText(replacement, start, end, "end");
    const codeStart = start + prefix.length + opening.length + 1;
    textarea.setSelectionRange(codeStart, codeStart + selected.length);
    textarea.focus();
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function runAction(action) {
    if (action === "heading") replaceSelectedLines((lines) => lines.map((line) => `# ${line.replace(/^#{1,3}\s+/, "")}`), "Section heading");
    if (action === "bold") replaceSelection("**", "**", "bold text");
    if (action === "italic") replaceSelection("*", "*", "italic text");
    if (action === "link") replaceSelection("[", "](https://example.com)", "link text");
    if (action === "inline-code") replaceSelection("`", "`", "code");
    if (action === "bullet-list") replaceSelectedLines((lines) => lines.map((line) => `- ${line.replace(/^[-*]\s+/, "")}`));
    if (action === "numbered-list") replaceSelectedLines((lines) => lines.map((line, index) => `${index + 1}. ${line.replace(/^\d+\.\s+/, "")}`));
    if (action === "code-block") insertCodeBlock();
  }

  document.querySelectorAll("[data-markdown-action]").forEach((button) => {
    button.addEventListener("click", () => runAction(button.dataset.markdownAction));
  });

  preview.addEventListener("change", (event) => {
    const select = event.target.closest("[data-runbook-code-block-language]");
    if (!select) return;
    const targetIndex = Number.parseInt(select.dataset.runbookCodeBlockLanguage, 10);
    const language = cleanLanguage(select.value);
    const lines = textarea.value.replace(/\r\n/g, "\n").split("\n");
    let open = false;
    let index = 0;
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      if (!/^```[A-Za-z0-9_+#.-]*\s*$/.test(lines[lineIndex].trim())) continue;
      if (!open) {
        if (index === targetIndex) {
          const indentation = lines[lineIndex].match(/^\s*/)?.[0] || "";
          lines[lineIndex] = `${indentation}\`\`\`${language}`;
          break;
        }
        index += 1;
      }
      open = !open;
    }
    textarea.value = lines.join("\n");
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const languageAliases = {
    sh: "bash",
    shell: "bash",
    console: "bash",
    terminal: "bash",
    ps1: "powershell",
    pwsh: "powershell",
    yml: "yaml",
    js: "javascript",
    jsx: "javascript",
    ts: "typescript",
    tsx: "typescript",
    py: "python",
    cs: "csharp",
    c: "c",
    cpp: "cpp",
    html: "html",
    xml: "html",
  };

  function inferCodeLanguage(element) {
    const candidates = [];
    let current = element;
    for (let depth = 0; current && depth < 3; depth += 1, current = current.parentElement) {
      candidates.push(current.dataset?.language, current.dataset?.lang, current.getAttribute?.("data-code-language"));
      candidates.push(current.className);
    }
    const combined = candidates.filter(Boolean).join(" ");
    const match = combined.match(/(?:language|lang|highlight-source)-([A-Za-z0-9_+#.-]+)/i);
    const raw = cleanLanguage(match?.[1] || candidates.find((value) => value && !String(value).includes(" ")) || "");
    return languageAliases[raw] || raw;
  }

  function fencedCode(code, language) {
    const normalized = code.replace(/\r\n?/g, "\n").replace(/^\n/, "").replace(/\n\s*$/, "");
    const longestRun = Math.max(0, ...(normalized.match(/`+/g) || []).map((run) => run.length));
    const fence = "`".repeat(Math.max(3, longestRun + 1));
    return `${fence}${cleanLanguage(language)}\n${normalized}\n${fence}`;
  }

  function inlineHtmlToMarkdown(node) {
    if (node.nodeType === Node.TEXT_NODE) return (node.nodeValue || "").replace(/[\t\r\n ]+/g, " ");
    if (node.nodeType !== Node.ELEMENT_NODE) return "";
    const tag = node.tagName.toLowerCase();
    const content = Array.from(node.childNodes).map(inlineHtmlToMarkdown).join("");
    if (tag === "br") return "\n";
    if (tag === "strong" || tag === "b") return `**${content.trim()}**`;
    if (tag === "em" || tag === "i") return `*${content.trim()}*`;
    if (tag === "code" && node.parentElement?.tagName.toLowerCase() !== "pre") return `\`${content.trim()}\``;
    if (tag === "a") {
      const href = node.getAttribute("href") || "";
      if (/^(https?:\/\/|\/|#)/i.test(href)) return `[${content.trim() || href}](${href})`;
    }
    if (tag === "img") return node.getAttribute("alt") || "";
    return content;
  }

  function isStandaloneCode(element) {
    if (element.tagName.toLowerCase() === "pre") return true;
    if (element.tagName.toLowerCase() !== "code" || element.closest("pre")) return false;
    const classes = `${element.className || ""} ${element.parentElement?.className || ""}`;
    return element.textContent.includes("\n") || /(?:code-block|highlight|source-code|language-|lang-)/i.test(classes);
  }

  function blockHtmlToMarkdown(node) {
    if (node.nodeType === Node.TEXT_NODE) return (node.nodeValue || "").trim();
    if (node.nodeType !== Node.ELEMENT_NODE) return "";
    const tag = node.tagName.toLowerCase();

    if (tag === "pre") {
      const code = node.querySelector("code") || node;
      return fencedCode(code.textContent || "", inferCodeLanguage(code));
    }
    if (tag === "code" && isStandaloneCode(node)) {
      return fencedCode(node.textContent || "", inferCodeLanguage(node));
    }
    if (/^h[1-6]$/.test(tag)) {
      const sourceLevel = Number.parseInt(tag.slice(1), 10);
      const level = Math.min(3, Math.max(1, sourceLevel - 1));
      return `${"#".repeat(level)} ${inlineHtmlToMarkdown(node).trim()}`;
    }
    if (tag === "p") return inlineHtmlToMarkdown(node).trim();
    if (tag === "ul" || tag === "ol") {
      return Array.from(node.children)
        .filter((child) => child.tagName.toLowerCase() === "li")
        .map((item, index) => {
          const contentClone = item.cloneNode(true);
          contentClone.querySelectorAll("ul, ol").forEach((nested) => nested.remove());
          Array.from(contentClone.querySelectorAll("pre, code")).filter(isStandaloneCode).forEach((code) => code.remove());
          const content = inlineHtmlToMarkdown(contentClone).trim();
          const blocks = Array.from(item.querySelectorAll("pre, code"))
            .filter(isStandaloneCode)
            .map((code) => code.tagName.toLowerCase() === "pre"
              ? fencedCode((code.querySelector("code") || code).textContent || "", inferCodeLanguage(code.querySelector("code") || code))
              : fencedCode(code.textContent || "", inferCodeLanguage(code)));
          const itemLine = `${tag === "ol" ? `${index + 1}.` : "-"} ${content}`.trimEnd();
          return blocks.length ? `${itemLine}\n\n${blocks.join("\n\n")}` : itemLine;
        })
        .join("\n");
    }
    if (tag === "li") return `- ${inlineHtmlToMarkdown(node).trim()}`;
    if (tag === "blockquote") {
      return inlineHtmlToMarkdown(node).trim();
    }
    if (["table", "thead", "tbody", "tr"].includes(tag)) {
      return Array.from(node.childNodes).map(blockHtmlToMarkdown).filter(Boolean).join("\n");
    }
    if (["th", "td"].includes(tag)) return inlineHtmlToMarkdown(node).trim();

    const children = Array.from(node.childNodes).map(blockHtmlToMarkdown).filter(Boolean);
    if (children.length) return children.join("\n\n");
    return inlineHtmlToMarkdown(node).trim();
  }

  function pastedHtmlToMarkdown(html) {
    const documentFragment = new DOMParser().parseFromString(html, "text/html");
    const codeBlocks = Array.from(documentFragment.body.querySelectorAll("pre, code")).filter(isStandaloneCode);
    if (!codeBlocks.length) return "";
    return Array.from(documentFragment.body.childNodes)
      .map(blockHtmlToMarkdown)
      .filter(Boolean)
      .join("\n\n")
      .replace(/[ \t]+\n/g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function fileExtensionForImage(file) {
    const byType = {
      "image/gif": "gif",
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp",
    };
    return byType[file.type] || "png";
  }

  function insertMarkdownAtCursor(markdown) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = start > 0 && textarea.value[start - 1] !== "\n" ? "\n\n" : "";
    const after = end < textarea.value.length && textarea.value[end] !== "\n" ? "\n\n" : "";
    textarea.setRangeText(`${before}${markdown}${after}`, start, end, "end");
    textarea.focus();
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }

  async function uploadPastedImage(file, index) {
    if (!uploadImageUrl || !csrfToken) throw new Error("Image uploads are not ready on this page.");
    const extension = fileExtensionForImage(file);
    const uploadFile = file.name ? file : new File([file], `pasted-image-${index + 1}.${extension}`, { type: file.type || "image/png" });
    const formData = new FormData();
    formData.append("csrf_token", csrfToken);
    formData.append("image", uploadFile);
    const response = await fetch(uploadImageUrl, {
      method: "POST",
      body: formData,
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "Image upload failed.");
    return payload.markdown || `![Pasted image](${payload.url})`;
  }

  async function pasteImages(files) {
    setPasteStatus(files.length === 1 ? "Uploading pasted image..." : `Uploading ${files.length} pasted images...`);
    const markdown = [];
    for (const [index, file] of files.entries()) {
      markdown.push(await uploadPastedImage(file, index));
    }
    insertMarkdownAtCursor(markdown.join("\n\n"));
    setPasteStatus(files.length === 1 ? "Image inserted." : "Images inserted.", "success");
    window.setTimeout(() => setPasteStatus(""), 2400);
  }

  textarea.addEventListener("paste", (event) => {
    const imageFiles = Array.from(event.clipboardData?.items || [])
      .filter((item) => item.kind === "file" && item.type.startsWith("image/"))
      .map((item) => item.getAsFile())
      .filter(Boolean);
    if (imageFiles.length) {
      event.preventDefault();
      pasteImages(imageFiles).catch((error) => {
        setPasteStatus(error.message || "Image paste failed.", "error");
      });
      return;
    }

    const html = event.clipboardData?.getData("text/html") || "";
    if (!html) return;
    const markdown = pastedHtmlToMarkdown(html);
    if (!markdown) return;
    event.preventDefault();
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = start > 0 && textarea.value[start - 1] !== "\n" ? "\n\n" : "";
    const after = end < textarea.value.length && textarea.value[end] !== "\n" ? "\n\n" : "";
    const replacement = `${before}${markdown}${after}`;
    textarea.setRangeText(replacement, start, end, "end");
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  });
  textarea.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey || event.metaKey)) return;
    const key = event.key.toLowerCase();
    const actions = { b: "bold", i: "italic", k: "link" };
    if (!actions[key]) return;
    event.preventDefault();
    runAction(actions[key]);
  });
  textarea.addEventListener("input", update);
  textarea.form?.addEventListener("reset", () => window.setTimeout(update, 0));
  update();
})();
