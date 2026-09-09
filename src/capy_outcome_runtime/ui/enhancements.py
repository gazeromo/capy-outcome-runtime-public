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

DEVELOPER_STATUS_ENHANCEMENT = r''' 
(() => {
  if (!document.getElementById("developer-status")) return;
  const openForm = document.querySelector("form[data-developer-open]");
  const fallback = document.getElementById("developer-launch-fallback");
  const notice = document.getElementById("developer-launch-notice");
  let opening = false;
  if (openForm && fallback && notice) openForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (opening) return;
    opening = true;
    const button = openForm.querySelector("button");
    button.disabled = true;
    fallback.hidden = true;
    notice.textContent = "Preparing a fresh Codex launch…";
    try {
      const destination = new URL(openForm.action, window.location.href);
      if (destination.origin !== window.location.origin || destination.pathname !== window.location.pathname + "/open" || destination.search || destination.hash) throw new Error("invalid action");
      const response = await fetch(destination.href, {method: "POST", credentials: "same-origin", cache: "no-store", body: new URLSearchParams(new FormData(openForm))});
      const returned = new URL(response.url);
      if (!response.ok || returned.origin !== window.location.origin || returned.pathname !== window.location.pathname || returned.search || returned.hash) throw new Error("launch unavailable");
      const markup = await response.text();
      if (markup.length > 262144) throw new Error("response too large");
      const page = new DOMParser().parseFromString(markup, "text/html");
      const prepared = page.getElementById("developer-launch-fallback");
      const pattern = /^capy-dev:\/\/handoff\/(hof_[0-9a-f]{32})\?site=(site_[0-9a-f]{32})&launch=([1-9][0-9]{0,9})$/;
      const prior = pattern.exec(fallback.getAttribute("href"));
      const href = prepared && prepared.getAttribute("href");
      const next = typeof href === "string" && pattern.exec(href);
      if (!prior || !next || next[1] !== prior[1] || next[2] !== prior[2] || Number(next[3]) <= Number(prior[3]) || Number(next[3]) > 2147483647) throw new Error("invalid launch link");
      fallback.setAttribute("href", href);
      fallback.hidden = false;
      notice.textContent = "Codex launch requested. If it did not open, use Launch prepared task. It may open a new conversation in the same workspace.";
      window.location.assign(href);
    } catch (_) {
      notice.textContent = "Could not confirm a fresh launch. Refresh status, then use Launch prepared task or press Open Codex again.";
    } finally {
      opening = false;
      button.disabled = false;
    }
  });
  let stopped = false, observations = 0;
  const poll = async () => {
    if (stopped) return;
    if (++observations > 60) {
      stopped = true;
      document.getElementById("developer-status").append(" Automatic observation paused. Refresh status to reconnect.");
      return;
    }
    try {
      if (!document.hidden) {
        const response = await fetch(window.location.pathname, {credentials: "same-origin", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(10000)});
        if (response.status === 403 || response.status === 404) { stopped = true; return; }
        if (!response.ok) throw new Error("status unavailable");
        const markup = await response.text();
        if (markup.length > 262144) throw new Error("status too large");
        const page = new DOMParser().parseFromString(markup, "text/html");
        const next = page.getElementById("developer-status"), current = document.getElementById("developer-status");
        if (next && current && !current.contains(document.activeElement) && next.innerHTML !== current.innerHTML) current.replaceChildren(...next.childNodes);
      }
    } catch (_) {
      stopped = true;
      document.getElementById("developer-status").append(" Status unconfirmed. The last report is retained; refresh to reconnect.");
    }
    window.setTimeout(poll, 10000);
  };
  window.setTimeout(poll, 10000);
})();
'''.strip()

HUMAN_STATUS_ENHANCEMENT = r"""
(() => {
  const follow = async (card, attempt = 0) => {
    if (!card.isConnected || !['saved', 'processing'].includes(card.dataset.status)) return;
    if (attempt >= 60) {
      const note = card.querySelector('[data-poll-note]');
      if (note) { note.hidden = false; note.textContent = 'This is taking longer. Your response is saved; you can check the current result below.'; }
      return;
    }
    if (document.hidden) { setTimeout(() => follow(card, attempt), 3000); return; }
    try {
      const response = await fetch(card.dataset.request + '/status', {credentials:'same-origin', cache:'no-store', redirect:'error'});
      if (!response.ok) throw new Error();
      const value = await response.json();
      if (value.status !== card.dataset.status) {
        const wrapper = document.createElement('div'); wrapper.innerHTML = value.html;
        const next = wrapper.firstElementChild; card.replaceWith(next); card = next;
        card.querySelector('[role=status]')?.focus();
      }
    } catch (_) {
      const note = card.querySelector('[data-poll-note]');
      if (note) { note.hidden = false; note.textContent = 'Connection interrupted. Your saved response is retained.'; }
      return;
    }
    setTimeout(() => follow(card, attempt + 1), Math.min(5000, 1000 + attempt * 250));
  };
  document.querySelectorAll('[data-request][data-status]').forEach(card => follow(card));
  document.querySelectorAll('form[data-quick-answer]').forEach(form => form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button'); if (button.disabled) return; button.disabled = true;
    const card = form.closest('[data-request]');
    try {
      const response = await fetch(form.action, {method:'POST', credentials:'same-origin', cache:'no-store', redirect:'error',
        headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams(new FormData(form))});
      if (response.status === 422) {
        const value = await response.json(); form.querySelector('[role=alert]').textContent = value.error;
        form.querySelector('[name=answer]').focus(); button.disabled = false; return;
      }
      if (!response.ok) throw new Error();
      const acknowledgment = await response.json();
      card.dataset.status = 'saved';
      card.innerHTML = '<div role="status" tabindex="-1"><h2>Response saved. Preparing your result…</h2></div><p data-poll-note hidden></p><a href="' + card.dataset.request + '">Check current result</a>';
      card.querySelector('[role=status]').focus(); follow(card);
      const nav = document.querySelector('a[href="/needs-you"]');
      if (nav) nav.textContent = 'Needs you' + (acknowledgment.waiting_count ? ' ' + acknowledgment.waiting_count : '');
    } catch (_) {
      form.querySelector('[role=alert]').textContent = 'Submission could not be confirmed. Your entry is still here. Check the current request before trying again.';
      const link = document.createElement('a'); link.href = card.dataset.request; link.textContent = 'Check current request'; form.append(link);
    }
  }));
})();
""".strip()

HUMAN_LAUNCH_ENHANCEMENT = r"""
(() => {
  const frame = document.querySelector('iframe[data-human-application]'); if (!frame) return;
  const stage = frame.parentElement, origin = new URL(frame.src).origin;
  const notice = document.querySelector('[data-app-notice]'), result = stage.querySelector('.app-result');
  let dirty = false, acknowledged = false, leaving = false, finished = false, attempts = 0;
  const show = text => { notice.hidden = false; notice.textContent = text; };
  window.addEventListener('message', event => {
    const data = event.data;
    if (event.origin !== origin || event.source !== frame.contentWindow || !data ||
        data.binding !== stage.dataset.binding || data.generation !== Number(stage.dataset.generation) ||
        !['dirty', 'saved'].includes(data.type) || Object.keys(data).some(k => !['binding','generation','type','dirty'].includes(k))) return;
    if (data.type === 'dirty' && typeof data.dirty === 'boolean') dirty = data.dirty;
    if (data.type === 'saved') { acknowledged = true; dirty = false; poll(); }
  });
  document.querySelector('[data-human-return]').addEventListener('click', event => {
    if (dirty && !confirm('Discard your unsaved edits?')) { event.preventDefault(); return; }
    leaving = true;
  });
  window.addEventListener('beforeunload', event => {
    if (dirty && !leaving) { event.preventDefault(); event.returnValue = ''; }
  });
  let polling = false;
  const poll = async () => {
    if (finished || polling) return;
    if (document.hidden) { setTimeout(poll, 3000); return; }
    if (++attempts > 180) { show('Live updates paused. Back to Capy shows the current request; your edits remain here.'); return; }
    polling = true;
    try {
      const response = await fetch(stage.dataset.request + '/status', {credentials:'same-origin',cache:'no-store',redirect:'error'});
      if (!response.ok) throw new Error();
      const value = await response.json();
      if (value.status !== 'waiting') {
        if (acknowledged && value.generation === Number(stage.dataset.generation) + 1) {
          notice.hidden = true; notice.textContent = '';
          document.querySelector('.app-bar a[target="_blank"]').href = stage.dataset.request;
          frame.hidden = true; result.hidden = false; result.innerHTML = value.html;
          if (!result.dataset.focused) { result.focus(); result.dataset.focused = 'true'; }
          if (!['saved','processing'].includes(value.status)) finished = true;
        } else {
          show('This request changed elsewhere. Your edits remain here; return to Capy to see the current result.');
          frame.contentWindow.postMessage({type:'stale',binding:stage.dataset.binding,generation:Number(stage.dataset.generation)}, origin);
        }
      }
    } catch (_) { show('The connection could not be confirmed. Your edits remain here. Return to Capy to check the current request.'); }
    finally { polling = false; }
    if (!finished) setTimeout(poll, Math.min(5000, 1500 + attempts * 100));
  };
  poll();
})();
""".strip()

RELEASE_STATUS_ENHANCEMENT = r"""
(() => {
  const status = document.querySelector('[data-release-observation]');
  if (!status) return;
  let observations = 0;
  async function observe() {
    if (++observations > 60) {
      status.textContent = 'Automatic status checks paused. Refresh to observe current progress. Your saved version is retained.';
      return;
    }
    try {
      const response = await fetch(status.dataset.statusUrl, {credentials:'same-origin', cache:'no-store', signal:AbortSignal.timeout(10000)});
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error();
      const value = await response.json();
      if (typeof value.observation !== 'string') throw new Error();
      if (value.observation !== status.dataset.releaseObservation) { location.reload(); return; }
      setTimeout(observe, 3000);
    } catch (_) {
      status.textContent = 'Status unconfirmed. Refresh to reconnect. No action was retried.';
    }
  }
  setTimeout(observe, 3000);
})();
"""

ENHANCEMENTS = {
    "release-status": RELEASE_STATUS_ENHANCEMENT,
    "human-status": HUMAN_STATUS_ENHANCEMENT,
    "human-launch": HUMAN_LAUNCH_ENHANCEMENT,
    "none": "",
    "developer-status": DEVELOPER_STATUS_ENHANCEMENT,
    "chat": CHAT_ENHANCEMENT,
    "form-protection": FORM_PROTECTION_ENHANCEMENT,
}
