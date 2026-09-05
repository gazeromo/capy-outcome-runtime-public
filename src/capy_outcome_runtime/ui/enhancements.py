"""Fixed local progressive enhancements selected by semantic key."""

CHAT_ENHANCEMENT = r'''
(() => {
  const form = document.getElementById("message-composer");
  const timeline = document.getElementById("timeline");
  const status = document.getElementById("chat-live-status");
  if (!form || !timeline || !status || !window.fetch || !window.DOMParser) return;
  const send = document.getElementById("message-send");
  const text = document.getElementById("message-text");
  const files = document.getElementById("message-files");
  const chips = document.getElementById("file-chips");
  let submitting = false, pollTimer = null, pollFailures = 0;
  const setStatus = (value, problem = false) => {
    status.textContent = value;
    status.classList.toggle("problem", problem);
  };
  const isActive = () => timeline.dataset.active === "true";
  const message = (role, body, working = false) => {
    const section = document.createElement("section");
    section.className = `ui-message message ${role === "owner" ? "ui-message--user" : "ui-message--assistant"} ${role} optimistic`;
    const meta = document.createElement("div");
    meta.className = "ui-speaker speaker";
    meta.textContent = role === "owner" ? "You" : "Capy";
    const content = document.createElement("div");
    content.className = working ? "ui-working working-card" : "ui-message-body message-body";
    if (working) {
      const dot = document.createElement("span");
      dot.className = "ui-working-mark working-dot";
      dot.setAttribute("aria-hidden", "true");
      content.append(dot);
      const copy = document.createElement("p");
      copy.textContent = body;
      content.append(copy);
    } else content.textContent = body;
    section.append(meta, content);
    return section;
  };
  const showOptimistic = (body, fileCount) => {
    const suffix = fileCount ? `\n${fileCount} file${fileCount === 1 ? "" : "s"} attached` : "";
    timeline.append(message("owner", body + suffix));
    timeline.append(message("assistant", "Working… No application or external action has run yet.", true));
    timeline.dataset.active = "true";
    window.scrollTo({top: document.body.scrollHeight, behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth"});
  };
  const parse = body => new DOMParser().parseFromString(body, "text/html");
  const reconcile = doc => {
    const fresh = doc.getElementById("timeline");
    if (!fresh) throw new Error("CHAT_PAGE_MISSING");
    timeline.replaceChildren(...Array.from(fresh.childNodes).map(node => node.cloneNode(true)));
    timeline.dataset.active = fresh.dataset.active;
    const freshSubmission = doc.querySelector('#message-composer input[name="submission"]');
    const submission = form.querySelector('input[name="submission"]');
    if (freshSubmission && submission) submission.value = freshSubmission.value;
    const freshTitle = doc.querySelector("main h1"), title = document.querySelector("main h1");
    if (freshTitle && title) title.textContent = freshTitle.textContent;
  };
  const schedulePoll = (delay = 900) => {
    if (pollTimer !== null) return;
    pollTimer = window.setTimeout(poll, delay);
  };
  const poll = async () => {
    pollTimer = null;
    try {
      const response = await fetch(window.location.href, {credentials: "same-origin", cache: "no-store"});
      if (!response.ok) throw new Error("CHAT_REFRESH_FAILED");
      reconcile(parse(await response.text()));
      pollFailures = 0;
      if (isActive() || submitting) {
        setStatus("Capy is still working. This page will update automatically."); schedulePoll();
      } else setStatus("Response received.");
    } catch (_error) {
      pollFailures += 1;
      setStatus("Connection interrupted. Capy will keep checking; you can safely retry the same message if needed.", true);
      if (isActive() || submitting) schedulePoll(Math.min(5000, 900 * (pollFailures + 1)));
    }
  };
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submitting || !form.reportValidity()) return;
    const data = new FormData(form), body = String(data.get("text") || "").trim();
    if (!body) return;
    const fileCount = files && files.files ? files.files.length : 0;
    showOptimistic(body, fileCount);
    text.value = "";
    if (files) files.value = "";
    if (chips) chips.replaceChildren();
    submitting = true; send.disabled = true; setStatus("Sending securely…"); schedulePoll(250);
    try {
      const response = await fetch(form.action, {method: "POST", body: data, credentials: "same-origin", redirect: "follow"});
      if (!response.ok) throw new Error("CHAT_SUBMISSION_FAILED");
      reconcile(parse(await response.text()));
      submitting = false; send.disabled = false;
      if (isActive()) { setStatus("Capy is still working. This page will update automatically."); schedulePoll(); }
      else setStatus("Response received.");
    } catch (_error) {
      submitting = false; send.disabled = false;
      setStatus("Connection interrupted. Your message may still be processing. Retrying uses the same safe submission.", true);
      schedulePoll(1200);
    }
  });
  if (files && chips) files.addEventListener("change", () => {
    chips.replaceChildren(...Array.from(files.files || []).map(file => {
      const chip = document.createElement("span");
      chip.className = "ui-file-chip file-chip"; chip.textContent = file.name; chip.title = file.name;
      return chip;
    }));
  });
  text.addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); form.requestSubmit(); }
  });
  if (isActive()) { setStatus("Capy is still working. This page will update automatically."); schedulePoll(250); }
})();
'''.strip()

FORM_PROTECTION_ENHANCEMENT = r'''
(() => {
  const forms = Array.from(document.querySelectorAll("form[data-protect-draft]"));
  if (!forms.length) return;
  let dirty = false, submitting = false;
  for (const form of forms) {
    form.addEventListener("input", event => { if (event.target && event.target.type !== "hidden") dirty = true; });
    form.addEventListener("change", event => { if (event.target && event.target.type !== "hidden") dirty = true; });
    form.addEventListener("submit", () => { submitting = true; });
  }
  window.addEventListener("beforeunload", event => {
    if (!dirty || submitting) return;
    event.preventDefault(); event.returnValue = "";
  });
})();
'''.strip()

ENHANCEMENTS = {
    "none": "",
    "chat": CHAT_ENHANCEMENT,
    "form-protection": FORM_PROTECTION_ENHANCEMENT,
}
