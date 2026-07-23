document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-module-access-editor]").forEach((editor) => {
    const search = editor.querySelector("[data-module-access-search]");
    const options = Array.from(editor.querySelectorAll("[data-module-access-option]"));
    const empty = editor.querySelector("[data-module-access-empty]");
    if (!search) return;
    const filter = () => {
      const term = search.value.trim().toLowerCase();
      let visible = 0;
      options.forEach((option) => {
        option.hidden = Boolean(term) && !option.textContent.toLowerCase().includes(term);
        if (!option.hidden) visible += 1;
      });
      if (empty) empty.hidden = visible !== 0;
    };
    search.addEventListener("input", filter);
  });
});
