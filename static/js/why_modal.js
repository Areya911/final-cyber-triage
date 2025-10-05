// static/js/why_modal.js
(function(){
  "use strict";

  // safe JSON parse accepting objects or JSON strings
  function safeParse(raw){
    if(!raw && raw !== 0) return null;
    if(typeof raw === 'object') return raw;
    try { return JSON.parse(raw); } catch(e){ return null; }
  }

  // helper selectors
  function q(sel, ctx){ return (ctx || document).querySelector(sel); }
  function qa(sel, ctx){ return Array.from((ctx || document).querySelectorAll(sel)); }

  // little DOM helpers
  function make(tag, cls, txt){ const e = document.createElement(tag || 'div'); if(cls) e.className = cls; if(txt !== undefined) e.textContent = txt; return e; }

  // animate numeric progress width
  function animateBar(barEl, value){
    if(!barEl) return;
    // ensure starts at 0
    barEl.style.width = '0%';
    setTimeout(function(){ barEl.style.width = Math.max(0, Math.min(100, parseInt(value)||0)) + '%'; }, 40);
    barEl.setAttribute('aria-valuenow', Math.max(0, Math.min(100, parseInt(value)||0)));
  }

  // Render the top horizontal weights bars (like the screenshot)
  function renderWeightBars(weights){
    // weights expected like {ioc:0.4, yara:0.3, heuristics:0.3} or similar
    const wrap = make('div', '');
    wrap.style.display = 'flex';
    wrap.style.gap = '12px';
    wrap.style.alignItems = 'center';

    const comps = [
      {k:'ioc', label:'IOC'},
      {k:'yara', label:'YARA'},
      {k:'heuristics', label:'HEURISTICS'}
    ];

    comps.forEach(c => {
      const val = Math.round(((weights && typeof weights[c.k] !== 'undefined') ? weights[c.k] : 0) * 100);
      const colWrap = make('div', 'd-flex flex-column');
      colWrap.style.width = '180px';

      const lbl = make('div', 'small', `${c.label} (${val}%)`);
      lbl.style.marginBottom = '4px';
      const prog = make('div', 'progress');
      prog.style.height = '8px';
      const bar = make('div', 'progress-bar');
      bar.style.width = '0%';
      bar.setAttribute('role','progressbar');
      bar.setAttribute('aria-valuemin','0');
      bar.setAttribute('aria-valuemax','100');
      bar.setAttribute('aria-valuenow','0');

      // color by weight (not value) to keep consistent look
      if(val >= 70) bar.classList.add('bg-danger');
      else if(val > 30) bar.classList.add('bg-warning');
      else bar.classList.add('bg-success');

      prog.appendChild(bar);
      colWrap.appendChild(lbl);
      colWrap.appendChild(prog);
      wrap.appendChild(colWrap);

      // animate little later
      setTimeout(()=> animateBar(bar, val), 80);
    });

    return wrap;
  }

  // Render detailed component breakdown bars (IOC/YARA/Heuristics component score)
  function renderComponentBars(breakdown, weights){
    const wrapper = make('div', '');
    wrapper.style.marginTop = '6px';

    const rows = [
      {key:'ioc_component', label:'IOC'},
      {key:'yara_component', label:'YARA'},
      {key:'heuristics_component', label:'HEURISTICS'},
      {key:'reputation_component', label:'REPUTATION'}
    ];

    rows.forEach(r => {
      const val = parseInt((breakdown && typeof breakdown[r.key] !== 'undefined') ? breakdown[r.key] : 0) || 0;
      const row = make('div', 'mb-2');
      const rowInner = make('div', 'd-flex align-items-center');

      const badge = make('div', '', '');
      badge.style.minWidth = '60px';
      badge.style.marginRight = '8px';
      badge.innerHTML = `<strong>${r.label}</strong>`;

      const progWrap = make('div', 'flex-fill');
      const progOuter = make('div', 'progress');
      progOuter.style.height = '10px';
      const bar = make('div', 'progress-bar');
      bar.style.width = '0%';
      bar.setAttribute('role','progressbar');
      bar.setAttribute('aria-valuemin','0');
      bar.setAttribute('aria-valuemax','100');
      bar.setAttribute('aria-valuenow','0');

      // color by severity
      if(val >= 70) bar.classList.add('bg-danger');
      else if(val > 30) bar.classList.add('bg-warning');
      else bar.classList.add('bg-success');

      progOuter.appendChild(bar);
      progWrap.appendChild(progOuter);
      const percentLabel = make('div', 'ms-2 small', val + '%');

      rowInner.appendChild(badge);
      rowInner.appendChild(progWrap);
      rowInner.appendChild(percentLabel);
      row.appendChild(rowInner);
      wrapper.appendChild(row);

      // animate
      setTimeout(()=> animateBar(bar, val), 60);
    });

    return wrapper;
  }

  // Render lists of IOC / YARA matches into the details area
  function renderDetailsLists(data, detailsEl){
    detailsEl.innerHTML = '';

    // IOC matches
    if(Array.isArray(data.ioc_matches) && data.ioc_matches.length){
      const h = make('h6','mt-2','IOC Matches');
      detailsEl.appendChild(h);
      const ul = make('ul','small');
      data.ioc_matches.forEach(m => {
        const li = make('li','');
        try {
          const t = m.type || m.match_type || '';
          const v = m.value || m.ioc || m.hash || m.filename || (typeof m === 'string' ? m : JSON.stringify(m));
          const conf = m.confidence ? ` (confidence=${m.confidence})` : '';
          li.textContent = `${t ? (t + ': ') : ''}${v}${conf}`;
        } catch(e){
          li.textContent = JSON.stringify(m);
        }
        ul.appendChild(li);
      });
      detailsEl.appendChild(ul);
    }

    // YARA matches
    if(Array.isArray(data.yara_matches) && data.yara_matches.length){
      const h = make('h6','mt-2','YARA Matches');
      detailsEl.appendChild(h);
      data.yara_matches.forEach(y => {
        const row = make('div','mb-2 small');
        try {
          const name = y.rule || y.rule_name || (y.meta && y.meta.name) || '<unnamed>';
          const tags = Array.isArray(y.tags) ? (` [${y.tags.join(',')}]`) : '';
          row.innerHTML = `<strong>${name}</strong>${tags}<br/>`;
          // include meta if present and small
          if(y.meta && typeof y.meta === 'object' && Object.keys(y.meta).length){
            const pre = make('pre','small');
            pre.style.fontSize = '11px';
            pre.textContent = JSON.stringify(y.meta, null, 2);
            row.appendChild(pre);
          }
        } catch(e){
          row.textContent = JSON.stringify(y);
        }
        detailsEl.appendChild(row);
      });
    }

    // Heuristics raw (if present)
    if(data.heuristics && (typeof data.heuristics === 'object') && Object.keys(data.heuristics).length){
      const h = make('h6','mt-2','Heuristics (raw)');
      detailsEl.appendChild(h);
      const pre = make('pre','small');
      pre.style.fontSize = '11px';
      // try to show compact heuristics keys (don't dump huge binary)
      const copy = Object.assign({}, data.heuristics);
      // redact binary-ish entries if present
      try {
        if(copy.component_scores) copy.component_scores = copy.component_scores;
      } catch(e){}
      pre.textContent = JSON.stringify(copy, null, 2);
      detailsEl.appendChild(pre);
    }

    if(detailsEl.innerHTML.trim() === ''){
      detailsEl.innerHTML = '<div class="text-muted small">No detailed matches found.</div>';
    }
  }

  // Populate the modal UI given the analysis payload
  function populateModal(payload){
    if(!payload) return;
    const scoreEl = q('#why-score');
    const badgeEl = q('#why-badge');
    const idEl = q('#why-artifact-id');
    const breakdownEl = q('#why-breakdown');
    const detailsEl = q('#why-details');
    const reasonsEl = q('#why-reasons');

    if(!scoreEl || !breakdownEl || !detailsEl || !reasonsEl) return;

    // normalize fields and fallback locations
    const finalScore = payload.final_score || payload.final || payload.finalScore || (payload.analysis && (payload.analysis.final_score || payload.analysis.suspicion_score)) || 0;
    const artifact_id = payload.artifact_id || payload.artifact || (payload.analysis && payload.analysis.artifact_id) || '';

    scoreEl.textContent = (typeof finalScore === 'number' ? Math.round(finalScore) : finalScore) + '%';
    idEl.textContent = artifact_id;

    // Build weight display for top bars
    const weights = payload.weights || (payload.analysis && payload.analysis.weights) || (function(){
      // fallback: try derive from payload.analysis or default to 40/30/30
      return {ioc:0.40, yara:0.30, heuristics:0.30};
    })();

    // Top header: clean existing
    badgeEl.innerHTML = '';
    const wb = renderWeightBars(weights);
    badgeEl.appendChild(wb);

    // component breakdown: payload.breakdown or components
    const breakdown = payload.breakdown || payload.final_breakdown || (payload.components && {
      ioc_component: payload.components.ioc && payload.components.ioc.score,
      yara_component: payload.components.yara && payload.components.yara.score,
      heuristics_component: payload.components.heuristics && payload.components.heuristics.score,
      reputation_component: payload.components.reputation && payload.components.reputation.score
    }) || {};

    // clear and add component bars
    breakdownEl.innerHTML = '';
    breakdownEl.appendChild(renderComponentBars(breakdown, weights));

    // details lists (ioc/yara/heuristics)
    renderDetailsLists(payload, detailsEl);

    // reasons list
    reasonsEl.innerHTML = '';
    const reasons = payload.reasons || (payload.analysis && payload.analysis.reasons) || [];
    if(Array.isArray(reasons) && reasons.length){
      reasons.forEach(r => {
        const li = make('li', 'small', (typeof r === 'string' ? r : (r.msg || JSON.stringify(r))));
        reasonsEl.appendChild(li);
      });
    } else {
      reasonsEl.innerHTML = '<li class="small text-muted">No summary reasons available.</li>';
    }
  }

  // Copy JSON button behavior
  function wireCopyJson(payloadProvider){
    const copyBtn = q('#copyWhyBtn');
    if(!copyBtn) return;
    copyBtn.addEventListener('click', function(){
      try {
        const payload = payloadProvider();
        if(!payload) return;
        const txt = JSON.stringify(payload, null, 2);
        if(navigator.clipboard && navigator.clipboard.writeText){
          navigator.clipboard.writeText(txt).then(function(){
            const prev = copyBtn.textContent;
            copyBtn.textContent = 'Copied ✓';
            setTimeout(()=> copyBtn.textContent = prev, 1200);
          }).catch(function(){
            fallbackCopy(txt, copyBtn);
          });
        } else {
          fallbackCopy(txt, copyBtn);
        }
      } catch(e){
        console.warn('copy failed', e);
      }
    });
  }

  function fallbackCopy(text, btn){
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      const prev = btn.textContent;
      btn.textContent = 'Copied ✓';
      setTimeout(()=> btn.textContent = prev, 1200);
    } catch(e){
      alert('Copy failed. Open console to access JSON.');
    }
    ta.remove();
  }

  // Main wiring: attach click handlers to .why-btn (idempotent)
  function attachWhyButtons(root){
    root = root || document;
    qa('.why-btn', root).forEach(btn => {
      if(btn.getAttribute('data-why-bound') === '1') return;
      btn.setAttribute('data-why-bound','1');

      btn.addEventListener('click', function(ev){
        // parse payload from data-analysis (stringified JSON) or data attributes
        const raw = btn.getAttribute('data-analysis') || btn.dataset.analysis;
        let payload = safeParse(raw);
        // sometimes the compact_blob is already an object set by Jinja; dataset may have it as object in some browsers
        if(!payload){
          // fallback: try to pick fields on the button itself
          const aid = btn.getAttribute('data-artifact') || btn.dataset.artifact;
          payload = { artifact_id: aid, final_score: 0, reasons: ['no analysis available'] };
        }

        // populate modal before Bootstrap shows it (modal is in DOM already)
        populateModal(payload);

        // wire copy button to always copy the most recent payload shown
        wireCopyJson(()=> payload);
      });
    });
  }

  // boot
  document.addEventListener('DOMContentLoaded', function(){
    attachWhyButtons(document);
    // defensive: attach again a tick later in case template inserted dynamically
    setTimeout(()=> attachWhyButtons(document), 120);
  });

  // Observe DOM mutations to attach handlers to new elements
  const mo = new MutationObserver(function(muts){
    attachWhyButtons(document);
  });
  mo.observe(document.body, { childList:true, subtree:true });

})();
