"use strict";
(() => {
  const backend = "https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend";
  const params = new URLSearchParams(window.location.search);
  const request = params.get("request");
  const broadcaster = params.get("broadcaster_id");
  const form = document.getElementById("verification-form");
  const fields = document.getElementById("verification-fields");
  const button = document.getElementById("continue-button");
  const status = document.getElementById("link-status");
  const hasRequest = params.has("request");
  const hasBroadcaster = params.has("broadcaster_id");
  const oneMode = hasRequest !== hasBroadcaster;
  const noDuplicate = params.getAll("request").length <= 1 && params.getAll("broadcaster_id").length <= 1;
  const validRequest = typeof request === "string" && /^[A-Za-z0-9_-]{32,512}$/.test(request);
  const validBroadcaster = typeof broadcaster === "string" && /^[1-9][0-9]{0,15}$/.test(broadcaster) && Number.isSafeInteger(Number(broadcaster));
  const valid = oneMode && noDuplicate && (hasRequest ? validRequest : validBroadcaster);

  if (!valid) {
    status.hidden = false;
    status.textContent = "This verification link is invalid. Ask the channel moderator for a new one.";
    form.removeAttribute("action");
    form.addEventListener("submit", (event) => event.preventDefault());
    return;
  }

  form.method = "post";
  form.action = hasRequest
    ? backend + "/verification/kick?request=" + encodeURIComponent(request)
    : backend + "/network/start?broadcaster_id=" + encodeURIComponent(broadcaster);

  fields.disabled = false;
  button.disabled = false;
})();