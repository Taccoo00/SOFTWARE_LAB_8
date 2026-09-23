document.addEventListener("click", (event) => {
  const dismiss = event.target.closest(".flash button");
  if (dismiss) dismiss.closest(".flash").remove();

  const opener = event.target.closest("[data-dialog-open]");
  if (opener) document.getElementById(opener.dataset.dialogOpen)?.showModal();

  const closer = event.target.closest("[data-dialog-close]");
  if (closer) closer.closest("dialog")?.close();

  const passwordToggle = event.target.closest(".show-password");
  if (passwordToggle) {
    const input = document.getElementById(passwordToggle.dataset.target);
    input.type = input.type === "password" ? "text" : "password";
    passwordToggle.textContent = input.type === "password" ? "Show" : "Hide";
  }
});

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    const box = dialog.getBoundingClientRect();
    const outside = event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom;
    if (outside) dialog.close();
  });
});
