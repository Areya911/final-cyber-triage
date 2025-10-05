// static/js/timeline.js
// Timeline renderer for Cyber Triage (clean version, no "Why?" modal)
// - defensive extraction of filenames/analysis from many shapes
// - supports case-specific /api/timeline/<case_id> or global /api/timeline
// - shows friendly timestamp, source/type, filename, score and a Show JSON toggle

(function(){
  "use strict";

  // -----------------------
  // Helpers
  // -----------------------
  function safeParseJsonSafe(text) {
    try { return JSON.parse(text); } catch(e) { return null; }
  }

  // Extract artifact info from many possible event shapes
  function extractArtifactInfo(ev) {
    const out = { artifact_id: null, filename: null, score: null, analysis: null, raw: ev };
    try {
      // Prefer ev.details if present
      const d = (ev && ev.details) ? ev.details : ev;

      // 1) events.json processor shape: d.details.artifacts -> [{ artifact: {...}, type, note }]
      if (d && d.details && Array.isArray(d.details.artifacts) && d.details.artifacts.length) {
        const artWrap = d.details.artifacts[0]; // first artifact in event
        const art = (artWrap && (artWrap.artifact || artWrap)) || null;
        if (art) {
          out.artifact_id = out.artifact_id || art.artifact_id || art.artifactId || art.id || null;
          out.filename = out.filename || art.original_filename || art.saved_filename || (art.saved_path && art.saved_path.split(/[\\/]/).pop()) || null;
          out.analysis = out.analysis || art.analysis || null;
        }
      }

      // 2) fallback: d.artifact or d.artifact_id directly
      if (!out.artifact_id && d && (d.artifact || d.artifact_id)) {
        const a = d.artifact || {};
        out.artifact_id = out.artifact_id || a.artifact_id || d.artifact_id || a.id || null;
        out.filename = out.filename || a.original_filename || a.saved_filename || d.original_filename || d.saved_filename || (a.saved_path && a.saved_path.split(/[\\/]/).pop()) || null;
        out.analysis = out.analysis || a.analysis || d.analysis || null;
      }

      // 3) top-level common fields
      if (!out.filename && d) {
        if (d.original_filename) out.filename = d.original_filename;
        else if (d.saved_filename) out.filename = d.saved_filename;
        else if (d.name) out.filename = d.name;
        else if (d.filename) out.filename = d.filename;
        else if (d.path) out.filename = (typeof d.path === "string") ? d.path.split(/[\\/]/).pop() : null;
      }

      // 4) artifact id fallback from top-level
      if (!out.artifact_id) {
        out.artifact_id = ev.artifact_id || ev.artifact || ev.id || null;
      }

      // 5) score extraction
      const analysisCandidates = out.analysis || (d && (d.analysis || (d.details && d.details.analysis))) || null;
      if (analysisCandidates) {
        out.score = analysisCandidates.final_score || analysisCandidates.suspicion_score || analysisCandidates.score || null;
        out.analysis = out.analysis || analysisCandidates;
      } else {
        // deep lookup
        try {
          const maybe = (d && d.details && Array.isArray(d.details.artifacts) && d.details.artifacts[0] && d.details.artifacts[0].artifact && d.details.artifacts[0].artifact.analysis) || (d && d.artifact && d.artifact.analysis) || null;
          if (maybe) {
            out.score = out.score || maybe.final_score || maybe.suspicion_score || null;
            out.analysis = out.analysis || maybe;
          }
        } catch (e) { /* ignore */ }
      }
    } catch (e) {
      console.debug("extractArtifactInfo error", e, ev);
    }
    return out;
  }

  function createButton(label, cls) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = cls || 'btn btn-sm';
    b.textContent = label;
    b.style.marginLeft = '6px';
    return b;
  }

  function formatTimestamp(ts) {
    if (!ts) return '(no timestamp)';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;

      // convert to IST (+5:30)
      const options = {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      };
      return new Intl.DateTimeFormat("en-IN", options).format(d) + " IST";
    } catch (e) {
      return String(ts);
    }
}


  // -----------------------
  // Rendering
  // -----------------------
  async function render() {
    const container = document.getElementById('timeline');
    if (!container) return;
    container.innerHTML = '';

    try {
      const caseId = (typeof CASE_ID !== 'undefined' && CASE_ID) ? CASE_ID : (new URLSearchParams(window.location.search)).get('case_id') || null;
      const url = caseId ? `/api/timeline/${encodeURIComponent(caseId)}` : '/api/timeline';
      console.debug("Fetching timeline from", url);

      const resp = await fetch(url);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const payload = await resp.json();

      // timeline can be { timeline: [...] } or list
      const list = payload && (payload.timeline || payload.events) ? (payload.timeline || payload.events) : (Array.isArray(payload) ? payload : (payload && payload.timeline ? payload.timeline : []));
      if (!list || list.length === 0) {
        container.textContent = 'No events found.';
        return;
      }

      // iterate and render each event
      for (const ev of list) {
        const info = extractArtifactInfo(ev);

        const el = document.createElement('div');
        el.className = 'event';

        // timestamp
        const ts = document.createElement('div'); ts.className = 'ts';
        ts.textContent = formatTimestamp(ev.timestamp || (ev.details && ev.details.timestamp) || (ev.created_at || ev.ts || ev.time));
        el.appendChild(ts);

        // meta
        const meta = document.createElement('div'); meta.className = 'meta';
        meta.textContent = `${ev.source || ''} — ${ev.type || 'event'}`;
        el.appendChild(meta);

        // body container
        const body = document.createElement('div');
        body.style.marginTop = '6px';

        // friendly filename line
        const filename =
          info.filename
          || (info.raw && info.raw.details && info.raw.details.id)
          // deep fallback: events.json processor shape often nests filename inside details.details.artifacts[*].artifact.original_filename
          || (info.raw && info.raw.details && info.raw.details.details && Array.isArray(info.raw.details.details.artifacts) && (info.raw.details.details.artifacts[0]?.artifact?.original_filename || info.raw.details.details.artifacts[0]?.artifact?.saved_filename))
          || '(unknown file)';
        const line = document.createElement('div');
        line.innerHTML = `<strong>${ev.type || 'event'}</strong> — <code style="font-size:0.95em">${escapeHtml(filename)}</code>`;
        body.appendChild(line);

        // artifact id and score (if available)
        const sub = document.createElement('div');
        sub.style.marginTop = '6px';
        sub.style.fontSize = '0.9em';
        sub.style.color = '#556677';
        const artIdText = info.artifact_id ? `artifact: ${escapeHtml(String(info.artifact_id))}` : '';
        const scoreText = (info.score !== null && info.score !== undefined) ? `${String(info.score)}% score` : '';
        sub.innerHTML = `${artIdText} ${scoreText ? ' — ' + escapeHtml(scoreText) : ''}`;
        body.appendChild(sub);

        // Controls row (Show JSON only)
        const ctrl = document.createElement('div');
        ctrl.style.marginTop = '8px';
        ctrl.style.display = 'flex';
        ctrl.style.alignItems = 'center';

        // Show JSON toggle
        const rawBtn = createButton('Show JSON', 'btn btn-sm btn-outline-secondary');
        rawBtn.addEventListener('click', function(){
          const pre = ctrl.nextSibling;
          if (!pre) return;
          if (pre.style.display === 'none' || !pre.style.display) {
            pre.style.display = 'block';
            rawBtn.textContent = 'Hide JSON';
          } else {
            pre.style.display = 'none';
            rawBtn.textContent = 'Show JSON';
          }
        });
        ctrl.appendChild(rawBtn);

        body.appendChild(ctrl);

        // pretty-printed JSON (collapsed by default)
        const pre = document.createElement('pre');
        try { pre.textContent = JSON.stringify(ev, null, 2); } catch (e) { pre.textContent = String(ev); }
        pre.style.display = 'none';
        pre.style.marginTop = '8px';
        pre.style.background = '#f7fafc';
        pre.style.padding = '8px';
        pre.style.borderRadius = '4px';
        body.appendChild(pre);

        el.appendChild(body);
        container.appendChild(el);
      }

    } catch (err) {
      container.textContent = 'Failed to load timeline: ' + String(err);
      console.error(err);
    }
  }

  // small helper to escape html for filenames
  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  document.addEventListener('DOMContentLoaded', render);
  // If ArtifactsLoader exists, wire its onUploadSuccess to refresh timeline automatically.
  try {
    if (window.ArtifactsLoader && typeof window.ArtifactsLoader.onUploadSuccess === 'undefined') {
      window.ArtifactsLoader.onUploadSuccess = function(payload) {
        // small delay so server has time to commit files & events
        setTimeout(function(){
          try { render(); } catch(e) { console.debug('timeline refresh after upload failed', e); }
        }, 600);
      };
    }
  } catch(e) {
    console.debug('ArtifactsLoader wiring skipped', e);
  }

  // expose for manual refresh if needed
  window.TriageTimeline = { render };

})();

// static/js/timeline_line.js
document.addEventListener("DOMContentLoaded", async function () {
  const container = document.getElementById("timeline-line");
  if (!container) return;

  const caseId = (typeof CASE_ID !== 'undefined' && CASE_ID) ? CASE_ID : null;
  const url = caseId ? `/api/timeline/${encodeURIComponent(caseId)}` : "/api/timeline";
  const resp = await fetch(url);
  if (!resp.ok) {
    container.innerHTML = "Failed to load timeline line.";
    return;
  }

  const payload = await resp.json();
  const list = payload.timeline || payload.events || (Array.isArray(payload) ? payload : []);
  if (!list.length) {
    container.innerHTML = "No events for timeline line.";
    return;
  }

  // Normalize timestamps
  const times = list
    .map(ev => new Date(ev.timestamp || ev.ts || ev.time || ev.created_at))
    .filter(d => !isNaN(d))
    .map(d => d.getTime());

  const min = Math.min(...times);
  const max = Math.max(...times);

  // Create dots
  list.forEach(ev => {
    const t = new Date(ev.timestamp || ev.ts || ev.time || ev.created_at);
    if (isNaN(t)) return;
    const pos = ((t.getTime() - min) / (max - min)) * 100;

    const dot = document.createElement("div");
    dot.className = "timeline-dot";
    dot.style.left = pos + "%";

    // Tooltip text
    const msg = `${t.toISOString()} — ${ev.type || "event"} (${ev.source || ""})`;
    dot.setAttribute("title", msg);

    container.appendChild(dot);
  });

  // Enable Bootstrap tooltips if available
  if (window.bootstrap) {
    const tooltipTriggerList = [].slice.call(container.querySelectorAll('[title]'));
    tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));
  }
});
