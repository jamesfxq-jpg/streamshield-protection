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
  const details = document.getElementById("consent-details");
  const context = document.getElementById("verification-context");
  const hasRequest = params.has("request");
  const hasBroadcaster = params.has("broadcaster_id");
  const oneMode = hasRequest !== hasBroadcaster;
  const noDuplicate = params.getAll("request").length <= 1 && params.getAll("broadcaster_id").length <= 1;
  const validRequest = typeof request === "string" && /^[A-Za-z0-9_-]{32,512}$/.test(request);
  const validBroadcaster = typeof broadcaster === "string" && /^[1-9][0-9]{0,15}$/.test(broadcaster) && Number.isSafeInteger(Number(broadcaster));
  const valid = oneMode && noDuplicate && (hasRequest ? validRequest : validBroadcaster);
  if (!valid) {
    document.getElementById("verification-title").textContent = "This verification link is invalid.";
    status.textContent = "The link is missing required information or is invalid. Ask the channel’s moderators for a fresh verification link. If a previous request expired, you need a new request.";
    status.classList.add("error");
    form.removeAttribute("action");
    form.addEventListener("submit", (event) => event.preventDefault());
    return;
  }
  form.method = "post";
  if (hasRequest) {
    form.action = backend + "/verification/kick?request=" + encodeURIComponent(request);
    document.getElementById("verification-title").textContent = "Verify your KICK account for this channel.";
    context.textContent = "A channel moderator requested verification of a specific KICK account. Read the information below before starting. The service will check whether this request is still active.";
    document.getElementById("browser-token-disclosure").hidden = false;
    document.getElementById("targeted-disclosure").hidden = false;
  } else {
    form.action = backend + "/network/start?broadcaster_id=" + encodeURIComponent(broadcaster);
    document.getElementById("verification-title").textContent = "Verify your connection for this channel.";
    context.textContent = "This link is for KICK broadcaster ID " + broadcaster + ". Continue only if this is the verification link provided by the channel you intended to visit.";
  }
  status.textContent = "No verification has started. Review the consent notice, then choose whether to continue.";
  details.hidden = false;
  fields.disabled = false;
  button.disabled = false;
})();
