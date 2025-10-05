// static/js/timeline.js
// Improved timeline renderer with better filename extraction and cinematic bar behaviors.
// - preserves previous functionalities
// - clicking a dot scrolls to the corresponding event card (no JSON popup)
// - IST formatting for timestamps
// - coc_verify cards show verification outcome and filename when available

(function(){
  "use strict";

  // -----------------------
  // Helpers
  // -----------------------
  function safeParseJsonSafe(text) {
    try { return JSON.parse(text); } catch(e) { return null; }
  }

  // Format date to IST (India) in human friendly format
  function formatToIST(ts) {
    if (!ts) return '--';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return String(ts);
      const opts = {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      };
      return new Intl.DateTimeFormat("en-GB", opts).format(d) + " IST";
    } catch (e) { return String(ts); }
  }

  // Human readable size: bytes -> KB/MB/GB/TB (rounded two decimals)
  function humanSize(bytes) {
    if (bytes === null || bytes === undefined || bytes === "") return "--";
    const b = Number(bytes) || 0;
    if (b === 0) return "0 B";
    const units = ["B","KB","MB","GB","TB"];
    let i = 0;
    let val = b;
    while (val >= 1024 && i < units.length-1) { val = val/1024; i++; }
    return `${(Math.round(val*100)/100).toFixed( (i===0)?0:2 )} ${units[i]}`;
  }

  // Recursively search an object for likely filename keys
  function findFilename(obj) {
    if (!obj) return null;
    const keys = ["original_filename","saved_filename","filename","name","path","absolute_path","saved_path","display_name","file","target","summary","file_name"];
    if (typeof obj === "string") return obj;
    if (Array.isArray(obj)) {
      for (const it of obj) {
        const r = findFilename(it);
        if (r) return r;
      }
      return null;
    }
    if (typeof obj === "object") {
      for (const k of keys) {
        if (k in obj) {
          const v = obj[k];
          if (typeof v === "string" && v.trim()) return (v.split(/[\\/]/).pop());
          if (typeof v === "object") {
            // nested summary may contain filename
            const r = findFilename(v);
            if (r) return r;
          }
        }
      }
      // fallback: search all string values shallowly
      for (const k of Object.keys(obj)) {
        const v = obj[k];
        if (typeof v === "string" && /[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]{1,5}$/.test(v)) {
          return v.split(/[\\/]/).pop();
        } else if (typeof v === "object") {
          const r = findFilename(v);
          if (r) return r;
        }
      }
    }
    return null;
  }

  // Extract artifact-like info from many event shapes
  function extractArtifactInfo(ev) {
    const out = { artifact_id: null, filename: null, score: null, analysis: null, raw: ev };
    try {
      // prefer details if present
      const d = (ev && ev.details) ? ev.details : ev;

      // common artifact-wrapping shapes
      if (d && d.artifacts && Array.isArray(d.artifacts) && d.artifacts.length) {
        const wrapper = d.artifacts[0];
        const art = (wrapper && (wrapper.artifact || wrapper)) || wrapper;
        if (art) {
          out.artifact_id = out.artifact_id || art.artifact_id || art.id || null;
          out.filename = out.filename || findFilename(art) || null;
          out.analysis = out.analysis || art.analysis || null;
        }
      }

      if (!out.artifact_id && d) {
        if (d.artifact && typeof d.artifact === "object") {
          const a = d.artifact;
          out.artifact_id = out.artifact_id || a.artifact_id || a.id || null;
          out.filename = out.filename || findFilename(a) || null;
          out.analysis = out.analysis || a.analysis || null;
        }
        if (d.artifact_id && !out.artifact_id) out.artifact_id = d.artifact_id;
      }

      // Some flows present 'summary' or 'details.summary' with filename
      if (!out.filename) {
        out.filename = findFilename(d) || findFilename(ev) || null;
      }

      // attempt various other fallbacks
      if (!out.filename && ev && ev.summary && typeof ev.summary === "object") {
        out.filename = findFilename(ev.summary) || null;
      }

      // score extraction
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

  function createLabelBadge(type) {
    const span = document.createElement('span');
    span.className = 'badge-type ' + ('badge-' + type);
    span.textContent = type;
    return span;
  }

  // -----------------------
  // Rendering: event list
  // -----------------------
  async function render(caseId) {
    const container = document.getElementById('timeline');
    if (!container) return;
    container.innerHTML = '';

    try {
      const url = caseId ? `/api/timeline/${encodeURIComponent(caseId)}` : '/api/timeline';
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const payload = await resp.json();

      const list = payload && (payload.timeline || payload.events) ? (payload.timeline || payload.events) : (Array.isArray(payload) ? payload : (payload && payload.timeline ? payload.timeline : []));
      if (!list || list.length === 0) {
        container.textContent = 'No events found.';
        return;
      }

      // For accessibility focus later
      let index = 0;
      for (const ev of list) {
        index++;
        const info = extractArtifactInfo(ev);
        const evType = ev.type || ev.event || 'event';
        const finalFilename = info.filename || '(no file associated)';

        const el = document.createElement('div');
        el.className = 'event';
        el.id = `event-${index}`;

        // header row: badge + filename + timestamp
        const headerRow = document.createElement('div');
        headerRow.className = 'header-row';

        const left = document.createElement('div');
        const badge = document.createElement('span');
        badge.className = 'badge-type badge-' + evType;
        badge.textContent = evType;
        left.appendChild(badge);

        const fn = document.createElement('span');
        fn.className = 'filename-pill';
        fn.textContent = finalFilename;
        left.appendChild(fn);
        headerRow.appendChild(left);

        const ts = document.createElement('div');
        ts.className = 'muted';
        const tsRaw = ev.timestamp || ev.ts || ev.time || (ev.timestamp_dt || ev.created_at);
        ts.textContent = formatToIST(tsRaw);
        headerRow.appendChild(ts);

        el.appendChild(headerRow);

        // friendly summary description
        const desc = document.createElement('div');
        desc.style.marginTop = '10px';
        const humanDesc = buildHumanDescription(ev, info);
        desc.innerHTML = humanDesc;
        el.appendChild(desc);

        // metadata table (concise, user-friendly). Hide IDs/SHAs as requested.
        const table = document.createElement('div');
        table.className = 'meta-table';

        // Type
        const k1 = document.createElement('div'); k1.className='k'; k1.textContent='Type';
        const v1 = document.createElement('div'); v1.className='v'; v1.textContent = String(evType);
        table.appendChild(k1); table.appendChild(v1);

        // Source
        const k2 = document.createElement('div'); k2.className='k'; k2.textContent='Source';
        const v2 = document.createElement('div'); v2.className='v'; v2.textContent = ev.source || 'events.json';
        table.appendChild(k2); table.appendChild(v2);

        // Size (if available) - show human readable
        let sizeVal = null;
        try {
          const maybe = info.raw && (info.raw.summary || info.raw.details || info.raw) ;
          if (maybe) {
            const candidateBytes = (maybe.size_bytes || maybe.size || maybe.file_size || (maybe.details && maybe.details.size_bytes));
            if (candidateBytes) sizeVal = humanSize(candidateBytes);
          }
        } catch(e){ sizeVal = null; }

        if (sizeVal) {
          const k3 = document.createElement('div'); k3.className='k'; k3.textContent='Size';
          const v3 = document.createElement('div'); v3.className='v'; v3.textContent = sizeVal;
          table.appendChild(k3); table.appendChild(v3);
        }

        // For coc_verify: show verification outcome & human-friendly details
        if (evType === 'coc_verify' || ev.type === 'coc_verify' || (ev.action && ev.action.includes('verify'))) {
          // metadata signature
          const ok = ev.metadata_hmac_ok === true || (ev.metadata_hmac_status === 'ok');
          const kSig = document.createElement('div'); kSig.className='k'; kSig.textContent='Metadata signature';
          const vSig = document.createElement('div'); vSig.className='v'; vSig.textContent = ok ? 'OK (valid)' : (ev.metadata_hmac_details || 'MISMATCH');
          table.appendChild(kSig); table.appendChild(vSig);

          // SHA match (presented as human friendly)
          const onDisk = ev.on_disk_sha256 || ev.on_disk_hash || (ev.details && ev.details.on_disk_sha256);
          const comp = ev.computed_sha256 || ev.computed_hash || (ev.details && ev.details.computed_sha256);
          if (onDisk || comp) {
            const ksha = document.createElement('div'); ksha.className='k'; ksha.textContent='SHA match';
            const vsha = document.createElement('div'); vsha.className='v';
            if (onDisk && comp) {
              vsha.textContent = (onDisk === comp) ? 'Yes — contents match' : 'No — contents differ';
            } else {
              vsha.textContent = onDisk ? 'Present on disk' : 'Computed' ;
            }
            table.appendChild(ksha); table.appendChild(vsha);
          }

          // optionally show who verified (actor)
          if (ev.actor || (ev.details && ev.details.actor)) {
            const kact = document.createElement('div'); kact.className='k'; kact.textContent='Verified by';
            const vact = document.createElement('div'); vact.className='v'; vact.textContent = ev.actor || ev.details.actor;
            table.appendChild(kact); table.appendChild(vact);
          }
        }

        el.appendChild(table);
        container.appendChild(el);
      }

      // After rendering, make sure there's an id mapping for dots -> event cards
      // expose a list for cinematic renderer to use
      window.__TRIAGE_EVENTS = {
        list: list.map((ev, i) => ({ idx: i+1, ev })),
        updated: new Date().toISOString()
      };

    } catch (err) {
      container.textContent = 'Failed to load timeline: ' + String(err);
      console.error(err);
    }
  }

  // build plain english summary for a card so non-experts understand what happened
  function buildHumanDescription(ev, info) {
    const type = ev.type || ev.event || 'event';
    const fname = info.filename || findFilename(ev) || '(no file associated)';
    if (type === 'artifact_uploaded' || type === 'artifact_uploaded') {
      const who = ev.uploader || ev.actor || (ev.details && ev.details.actor) || 'Unknown';
      const when = formatToIST(ev.timestamp || ev.ts || ev.time || ev.timestamp_dt);
      return `<div><strong style="color:#111">${escapeHtml(fname)}</strong> was uploaded by <strong>${escapeHtml(who)}</strong> on <span class="muted">${when}</span>.</div>`;
    } else if (type === 'file_saved') {
      return `<div>File <strong style="color:#111">${escapeHtml(fname)}</strong> was saved to the case storage.</div>`;
    } else if (type === 'coc_verify' || (ev.action && ev.action.includes('verify'))) {
      // explain verification results
      const ok = ev.metadata_hmac_ok === true || (ev.metadata_hmac_status === 'ok');
      const shaMatch = (ev.on_disk_sha256 && ev.computed_sha256 && ev.on_disk_sha256 === ev.computed_sha256) ? 'Contents match' : ((ev.on_disk_sha256 || ev.computed_sha256) ? 'Contents differ' : 'No content comparison');
      const actor = ev.actor || (ev.details && ev.details.actor) || 'system';
      return `<div>A chain-of-custody verification took place for <strong style="color:#111">${escapeHtml(fname)}</strong>. Action: <strong>${escapeHtml(ev.action || 'verification')}</strong>. Result: <strong>${ok ? 'Metadata signature OK' : 'Metadata signature MISMATCH'}</strong>. ${escapeHtml(shaMatch)}. Performed by <strong>${escapeHtml(actor)}</strong>.</div>`;
    } else if (type === 'process' || type === 'process') {
      const exe = (ev.exe || (ev.details && ev.details.exe) || (ev.raw && ev.raw.exe)) || 'unknown program';
      return `<div>A process was observed: <strong>${escapeHtml(String(exe))}</strong>. Associated file (if any): <strong style="color:#111">${escapeHtml(fname)}</strong>.</div>`;
    } else {
      // generic fallback
      return `<div>${escapeHtml(String(ev.summary || ev.message || ev.type || 'Event'))} — file: <strong style="color:#111">${escapeHtml(fname)}</strong>.</div>`;
    }
  }

  // helper to escape html
  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // -----------------------
  // Cinematic bar renderer
  // -----------------------
  async function renderCinematic(caseId) {
    const barContainer = document.getElementById('cinematic-bar');
    const countEl = document.getElementById('cinematic-count');
    const startEl = document.getElementById('cinematic-start');
    const midEl = document.getElementById('cinematic-mid');
    const endEl = document.getElementById('cinematic-end');
    const timespanEl = document.getElementById('cinematic-timespan');
    const riskEl = document.getElementById('cinematic-risk');

    if (!barContainer) return;
    barContainer.innerHTML = ''; // reset

    try {
      const url = caseId ? `/api/timeline/${encodeURIComponent(caseId)}` : '/api/timeline';
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const payload = await resp.json();

      const list = payload && (payload.timeline || payload.events) ? (payload.timeline || payload.events) : (Array.isArray(payload) ? payload : []);
      if (!list || list.length === 0) {
        countEl && (countEl.textContent = '0');
        startEl && (startEl.textContent = '--');
        midEl && (midEl.textContent = '--');
        endEl && (endEl.textContent = '--');
        return;
      }

      // normalize timestamps, keep pairs (index -> ms)
      const mapped = list.map((ev, i) => {
        const tRaw = ev.timestamp || ev.ts || ev.time || ev.timestamp_dt || ev.created_at;
        const d = new Date(tRaw);
        return { ev, idx: i+1, t: (isNaN(d.getTime()) ? null : d.getTime()) };
      }).filter(it => it.t !== null);
      if (!mapped.length) return;

      mapped.sort((a,b)=>a.t-b.t);
      const min = mapped[0].t;
      const max = mapped[mapped.length-1].t;
      const mid = min + Math.floor((max-min)/2);

      // set textual times
      startEl && (startEl.textContent = formatToIST(new Date(min).toISOString()));
      midEl && (midEl.textContent = formatToIST(new Date(mid).toISOString()));
      endEl && (endEl.textContent = formatToIST(new Date(max).toISOString()));

      // timespan
      const msSpan = max - min;
      const hours = Math.floor(msSpan / 3600000);
      const days = Math.floor(hours/24);
      timespanEl && (timespanEl.textContent = days>0? `${days}d` : (hours>0? `${hours}h` : `${Math.round(msSpan/60000)}m`));

      // basic risk heuristic: many artifact_uploaded and coc_verify in short time => medium/high
      let risk = 'LOW';
      const uploads = mapped.filter(x => (x.ev.type==='artifact_uploaded' || x.ev.type==='artifact_uploaded')).length;
      const verifies = mapped.filter(x => (x.ev.type==='coc_verify' || (x.ev.action && x.ev.action.includes('verify')))).length;
      if ((uploads+verifies) >= 5) risk = 'MEDIUM';
      if ((uploads+verifies) >= 12) risk = 'HIGH';
      riskEl && (riskEl.textContent = risk);

      // count
      countEl && (countEl.textContent = mapped.length);

      // render dots
      mapped.forEach(item => {
        const posPct = ((item.t - min) / (max - min)) * 100;
        const dot = document.createElement('div');
        dot.className = 'cinematic-dot';
        // pick color class
        const t = item.ev.type || item.ev.event || (item.ev.action || 'event');
        if (t === 'process') dot.classList.add('dot-process');
        else if (t === 'file_saved') dot.classList.add('dot-file_saved');
        else if (t === 'artifact_uploaded') dot.classList.add('dot-artifact_uploaded');
        else if (t === 'coc_verify' || (item.ev.action && item.ev.action.includes('verify'))) dot.classList.add('dot-coc_verify');
        else dot.style.background = '#9aa0a6';

        dot.style.left = posPct + '%';
        dot.title = `${formatToIST(item.ev.timestamp || item.ev.ts || item.ev.time || item.ev.timestamp_dt)} — ${item.ev.type || item.ev.event || ''}`;

        // on hover show a lightweight popup (native tooltip is fine), but add aria label
        dot.setAttribute('aria-label', dot.title);

        // click -> scroll to event card
        dot.addEventListener('click', function(e){
          // find corresponding rendered event index (we used idx = position in list)
          const targetId = `event-${item.idx}`;
          const targetEl = document.getElementById(targetId);
          if (targetEl) {
            targetEl.scrollIntoView({ behavior:'smooth', block:'center' });
            // optionally highlight briefly
            targetEl.style.transition = 'box-shadow 0.3s ease';
            const old = targetEl.style.boxShadow;
            targetEl.style.boxShadow = '0 0 0 4px rgba(33,150,243,0.18)';
            setTimeout(()=>{ targetEl.style.boxShadow = old; }, 1600);
          }
        });

        barContainer.appendChild(dot);
      });

    } catch (e) {
      console.error('cinematic render error', e);
    }
  }

  // expose API
  window.TriageTimeline = window.TriageTimeline || {};
  window.TriageTimeline.render = render;
  window.TriageTimeline.renderCinematic = renderCinematic;

  // auto-run for DOMContentLoaded if available
  document.addEventListener('DOMContentLoaded', function(){
    const caseId = (typeof CASE_ID !== 'undefined' && CASE_ID) ? CASE_ID : (new URLSearchParams(window.location.search)).get('case_id') || null;
    try { render(caseId); renderCinematic(caseId); } catch(e){ console.debug('initial timeline render failed', e); }
  });
})();
