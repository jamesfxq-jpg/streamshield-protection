(() => {
  const el = document.getElementById("feedback-ref");
  if (!el) return;
  const ref = new URLSearchParams(location.search).get("ref");
  if (ref && /^SSB-[A-F0-9]{8}$/.test(ref)) el.textContent = "Reference: " + ref;
})();