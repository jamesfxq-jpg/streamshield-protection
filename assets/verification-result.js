"use strict";
(() => {
  const params = new URLSearchParams(window.location.search);
  const title = params.get("title");
  const message = params.get("message");
  const status = params.get("status");
  if (typeof title === "string" && title.trim()) {
    document.getElementById("result-title").textContent = title.trim().slice(0, 180);
  }
  if (typeof message === "string" && message.trim()) {
    document.getElementById("result-message").textContent = message.trim().slice(0, 3000);
  }
  if (typeof status === "string" && /^[1-5][0-9]{2}$/.test(status)) {
    const badge = document.getElementById("result-status");
    badge.textContent = "Status " + status;
    badge.hidden = false;
    if (Number(status) >= 400) badge.classList.add("error");
  }
})();
