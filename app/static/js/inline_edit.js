(function () {
  function setEditing(form, editing) {
    form.classList.toggle("is-editing", editing);
    form.querySelectorAll("[data-edit]").forEach((field) => {
      if (!("disabled" in field)) {
        return;
      }
      field.disabled = field.hasAttribute("data-display-copy") || !editing;
    });
  }

  document.querySelectorAll("[data-inline-edit]").forEach((form) => {
    const editButton = form.querySelector("[data-edit-toggle]");
    const cancelButton = form.querySelector("[data-edit-cancel]");

    setEditing(form, false);

    if (editButton) {
      editButton.addEventListener("click", () => {
        setEditing(form, true);
        const firstField = form.querySelector("[data-edit]:not([disabled])");
        if (firstField) {
          firstField.focus();
          if (typeof firstField.select === "function") {
            firstField.select();
          }
        }
      });
    }

    if (cancelButton) {
      cancelButton.addEventListener("click", () => {
        form.reset();
        setEditing(form, false);
      });
    }
  });
})();
