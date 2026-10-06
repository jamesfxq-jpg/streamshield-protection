(() => {
  const box = document.getElementById("feedback-error");
  if (!box) return;
  const code = new URLSearchParams(location.search).get("error");
  if (!code) return;
  const messages = {
    origin: "The feedback form could not verify where the submission came from. Please reopen the beta page and submit again.",
    format: "The feedback form was submitted in an unsupported format. Please reload the page and try again.",
    too_large: "That report is too large. Shorten the text and submit again.",
    acknowledgement: "Please confirm the beta-testing acknowledgement before submitting.",
    required: "Please complete all required fields and add a short summary.",
    email: "The email address does not look valid. Correct it or leave it blank.",
    service: "The feedback service is temporarily unavailable. Keep your notes and try again shortly."
  };
  box.textContent = messages[code] || "The feedback report could not be submitted. Please review the form and try again.";
  box.hidden = false;
})();