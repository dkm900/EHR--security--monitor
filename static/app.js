/* ============================================================
   EHR Security Monitor -- front-end logic
   Talks to the Flask JSON API. No detection logic lives here;
   the server is the single source of truth for verdicts.
   ============================================================ */

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  staff: [],
  staffById: {},
  selected: new Set(),
  records: [],
  knownAlertIds: new Set(),
  live: true,
};

// ---------- tiny helpers ----------
async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  return res.json();
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(title, body, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<b>${escapeHtml(title)}</b>${escapeHtml(body)}`;
  $('#toasts').appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 300);
  }, 5200);
}

function setText(sel, value) {
  const el = $(sel);
  const next = String(value);
  if (el.textContent !== next) {
    el.textContent = next;
    const card = el.closest('.kpi');
    if (card) {
      card.classList.remove('flash');
      void card.offsetWidth;   // restart the CSS animation
      card.classList.add('flash');
    }
  }
}

function timeOf(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '--:--:--' : d.toTimeString().slice(0, 8);
}

// ---------- boot ----------
async function boot() {
  const data = await api('/api/bootstrap');
  state.staff = data.staff;
  state.staff.forEach((s) => { state.staffById[s.user_id] = s; });

  renderStaffSelect();
  renderScenarios(data.scenarios);
  renderRules(data.rules);
  renderHeuristicNote(data.heuristic);
  updateScopeHint();
  await loadRecords();
  await refreshAll();
  setInterval(() => { if (state.live) refreshAll(); }, 2500);
}

function renderStaffSelect() {
  const sel = $('#selUser');
  sel.innerHTML = state.staff
    .map((s) => `<option value="${escapeHtml(s.user_id)}">${escapeHtml(s.name)} — ${escapeHtml(s.role)}${s.active ? '' : ' (deactivated)'}</option>`)
    .join('');
  sel.addEventListener('change', updateScopeHint);
}

function renderScenarios(scenarios) {
  const grid = $('#scenarioGrid');
  grid.innerHTML = scenarios.map((s) => {
    const quiet = s.expect === 'no alert';
    return `
      <button class="scenario" data-key="${escapeHtml(s.key)}">
        <span class="s-title">${escapeHtml(s.title)}</span>
        <span class="s-blurb">${escapeHtml(s.blurb)}</span>
        <span class="s-expect ${quiet ? 'quiet' : 'alert'}">expect: ${escapeHtml(s.expect)}</span>
      </button>`;
  }).join('');

  $$('.scenario').forEach((btn) => {
    btn.addEventListener('click', () => runScenario(btn));
  });
}

function renderRules(rules) {
  const blurbs = {
    'EHR-001': 'Three or more failed authentications for one account inside the window. Severity climbs with the count.',
    'EHR-002': 'More than 50 records read inside the window. Reads marked exempt by the busy-clinician heuristic are not counted.',
    'EHR-003': 'An access refused because the role may not perform the action, may not touch that record section, or is not assigned to that ward.',
  };
  $('#ruleList').innerHTML = rules.map((r) => `
    <div class="rule-item">
      <span class="rule-id">${escapeHtml(r.id)}</span>
      <div>
        <h5>${escapeHtml(r.name)}</h5>
        <p>${escapeHtml(blurbs[r.id] || '')}</p>
        <span class="win">window: ${r.window_minutes} min</span>
      </div>
    </div>`).join('');
}

function renderHeuristicNote(cfg) {
  $('#scopeHint').insertAdjacentHTML('beforeend',
    `<div style="margin-top:8px;padding-top:8px;border-top:1px dashed rgba(122,150,205,.2)">
       <b>Busy-clinician heuristic</b> &mdash; exempts single-chart reads by
       Doctor/Nurse when batch &le; ${cfg.max_batch},
       click gap &ge; ${cfg.min_interval_seconds}s, and sustained rate
       &le; ${cfg.max_rate_per_second}/sec. Anything faster loses the exemption.
     </div>`);
}

// ---------- scope hint ----------
function updateScopeHint() {
  const staff = state.staffById[$('#selUser').value];
  if (!staff) return;
  const allCats = ['demographic', 'clinical', 'lab', 'billing', 'psych', 'pediatric'];
  const readChips = allCats.map((c) => {
    const ok = staff.can_read.includes(c);
    return `<span class="chip ${ok ? '' : 'no'}">${c}</span>`;
  }).join('');
  $('#scopeHint').innerHTML = `
    <b>${escapeHtml(staff.role)}</b>
    ${staff.active ? '' : '<span class="chip no">deactivated</span>'}
    &middot; wards: ${staff.departments.map(escapeHtml).join(', ') || 'none'}
    <div style="margin-top:7px">may read &rarr; ${readChips}</div>
    <div style="margin-top:5px">may act &rarr; ${staff.can_do.map((a) => `<span class="chip">${escapeHtml(a)}</span>`).join(' ')}</div>`;
}

// ---------- records ----------
async function loadRecords() {
  const params = new URLSearchParams({
    q: $('#inpSearch').value.trim(),
    department: $('#selDept').value,
    category: $('#selCat').value,
    limit: $('#selLimit').value,
  });
  const data = await api(`/api/records?${params}`);
  state.records = data.records;
  renderRecords(data);
}

function renderRecords(data) {
  const body = $('#recordBody');
  if (!data.records.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty"><span class="big">( )</span>No charts match those filters.</td></tr>`;
  } else {
    body.innerHTML = data.records.map((r) => `
      <tr class="${state.selected.has(r.record_id) ? 'sel' : ''}" data-id="${escapeHtml(r.record_id)}">
        <td class="tick"><input type="checkbox" class="tickbox" ${state.selected.has(r.record_id) ? 'checked' : ''}></td>
        <td class="patient">${escapeHtml(r.patient_name)}</td>
        <td class="mono">${escapeHtml(r.record_id)}</td>
        <td class="mono">${r.age}</td>
        <td><span class="dept">${escapeHtml(r.department)}</span></td>
        <td>${r.categories.map((c) => `<span class="sect ${escapeHtml(c)}">${escapeHtml(c)}</span>`).join('')}</td>
      </tr>`).join('');

    $$('#recordBody .tickbox').forEach((box) => {
      box.addEventListener('change', (e) => {
        const id = e.target.closest('tr').dataset.id;
        if (e.target.checked) state.selected.add(id); else state.selected.delete(id);
        e.target.closest('tr').classList.toggle('sel', e.target.checked);
        updateSelCount();
      });
    });
  }
  $('#recordMeta').textContent =
    `showing ${data.records.length} of ${data.in_catalog} charts`;
  updateSelCount();
}

function updateSelCount() {
  $('#selCount').textContent = `${state.selected.size} selected`;
}

// ---------- monitoring output ----------
async function refreshAll() {
  const [stats, alerts, audit] = await Promise.all([
    api('/api/stats'),
    api('/api/alerts'),
    api('/api/audit?limit=60'),
  ]);
  renderStats(stats);
  renderAlerts(alerts, audit);
  renderAudit(audit);

  const badge = $('#chainBadge');
  const ok = audit.integrity.chain_ok;
  badge.classList.toggle('ok', ok);
  badge.classList.toggle('bad', !ok);
  $('#chainText').textContent = ok
    ? `chain intact · ${audit.total} entries`
    : `TAMPERED @ ${audit.integrity.first_bad_event}`;
}

function renderStats(s) {
  setText('#kpiCritical', s.by_severity.critical);
  setText('#kpiHigh', s.by_severity.high);
  setText('#kpiMedium', s.by_severity.medium);
  setText('#kpiReads', s.records_read);
  setText('#kpiExempt', s.records_exempt);
  setText('#kpiDenied', s.outcomes.denied + s.outcomes.failed);
}

function renderAlerts(payload, audit) {
  const list = $('#alertList');
  if (!payload.open.length) {
    list.innerHTML = `<div class="empty"><span class="big">&#10003;</span>
      No open alerts.<br>Run a scenario to exercise the rules.</div>`;
    return;
  }
  list.innerHTML = payload.open.map((a) => `
    <div class="alert ${escapeHtml(a.severity)}" data-id="${escapeHtml(a.alert_id)}">
      <div class="alert-top">
        <span class="sev ${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span>
        <span class="rule-id">${escapeHtml(a.rule_id)}</span>
        <span class="occ">${a.occurrences}&times;</span>
      </div>
      <h4>${escapeHtml(a.title)}</h4>
      <p>${escapeHtml(a.detail)}</p>
      <button class="ack">Acknowledge</button>
    </div>`).join('');

  $$('.alert .ack').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.closest('.alert').dataset.id;
      await api(`/api/alerts/${id}/ack`, { method: 'POST' });
      refreshAll();
    });
  });

  // toast only genuinely new alerts, so re-polling is not noisy
  payload.open.forEach((a) => {
    if (!state.knownAlertIds.has(a.alert_id)) {
      state.knownAlertIds.add(a.alert_id);
      toast(`${a.rule_id} · ${a.severity}`, a.title, a.severity);
    }
  });
}

function renderAudit(payload) {
  const list = $('#auditList');
  if (!payload.events.length) {
    list.innerHTML = `<div class="empty">No access attempts recorded yet.</div>`;
    return;
  }
  list.innerHTML = payload.events.map((e) => {
    const kind = e.outcome === 'success' ? 'ok'
               : e.outcome === 'denied' ? 'denied' : 'failed';
    const target = e.record_ids.length
      ? (e.record_ids.length > 1
          ? `${e.record_ids.length} records`
          : escapeHtml(e.record_ids[0]))
      : '<span style="opacity:.5">—</span>';
    return `
      <div class="ev ${kind}">
        <span class="t">${timeOf(e.timestamp)}</span>
        <span class="what">
          <b>${escapeHtml(e.user_id)}</b> ${escapeHtml(e.action)} ${target}
          ${e.reason ? `<span class="why">${escapeHtml(e.reason)}</span>` : ''}
        </span>
        ${e.exempt_reason
          ? `<span class="tag">exempt</span>`
          : (kind !== 'ok' ? `<span class="tag ${kind}">${escapeHtml(e.outcome)}</span>` : '')}
      </div>`;
  }).join('');
}

// ---------- actions ----------
$('#btnLogin').addEventListener('click', async () => {
  const res = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({
      user_id: $('#selUser').value,
      password: $('#inpPassword').value,
      source_ip: $('#inpIp').value,
    }),
  });
  showVerdict(res, 'Login');
});

$('#btnOpenSelected').addEventListener('click', async () => {
  if (!state.selected.size) {
    toast('Nothing selected', 'Tick at least one chart in the table below.', 'medium');
    return;
  }
  const res = await api('/api/access', {
    method: 'POST',
    body: JSON.stringify({
      user_id: $('#selUser').value,
      record_ids: Array.from(state.selected),
      action: $('#selAction').value,
      source_ip: $('#inpIp').value,
    }),
  });
  showVerdict(res, 'Chart access');
  await refreshAll();
});

$('#btnClearSel').addEventListener('click', () => {
  state.selected.clear();
  renderRecords({ records: state.records, in_catalog: state.records.length });
});

$('#ackAllBtn').addEventListener('click', async () => {
  await api('/api/alerts/ack-all', { method: 'POST' });
  refreshAll();
});

$('#resetBtn').addEventListener('click', async () => {
  await api('/api/reset', { method: 'POST' });
  state.knownAlertIds.clear();
  state.selected.clear();
  toast('State cleared', 'Audit log, alerts and heuristic history reset.', 'success');
  await loadRecords();
  refreshAll();
});

$('#liveToggle').addEventListener('change', (e) => {
  state.live = e.target.checked;
});

['#inpSearch', '#selDept', '#selCat', '#selLimit'].forEach((sel) => {
  let t;
  $(sel).addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(loadRecords, 220);
  });
});

function showVerdict(res, label) {
  const box = $('#verdict');
  box.hidden = false;
  const outcome = res.event.outcome;
  let cls = 'allow';
  let head = 'Allowed';
  if (outcome === 'denied') { cls = 'deny'; head = 'Denied by access control'; }
  else if (outcome === 'failed') { cls = 'deny'; head = 'Failed'; }
  else if (res.exempt) { cls = 'exempt'; head = 'Allowed — exempt as clinical workflow'; }

  box.className = `verdict ${cls}`;
  box.innerHTML = `
    <span class="v-title">${escapeHtml(label)}: ${escapeHtml(head)}</span>
    ${res.event.reason ? escapeHtml(res.event.reason) : 'No policy objection.'}
    ${res.exempt_reason ? `<div class="v-meta">heuristic: ${escapeHtml(res.exempt_reason)}</div>` : ''}
    <div class="v-meta">
      event ${escapeHtml(res.event.event_id)} &middot; batch ${res.event.batch_size}
      &middot; ${escapeHtml(res.event.department_label || 'n/a')}
      &middot; hash ${escapeHtml(res.event.entry_hash.slice(0, 12))}…
    </div>`;
}

async function runScenario(btn) {
  const key = btn.dataset.key;
  btn.classList.add('running');
  const res = await api(`/api/scenarios/${key}`, { method: 'POST' });
  btn.classList.remove('running');

  const okMark = res.behaved_as_expected ? 'as expected' : 'UNEXPECTED';
  const rules = res.rule_ids_fired.length ? res.rule_ids_fired.join(', ') : 'none';
  toast(
    `${res.title} — ${okMark}`,
    `rules fired: ${rules}`,
    res.behaved_as_expected ? (res.should_alert ? 'high' : 'success') : 'critical',
  );

  res.steps.slice(-6).forEach((s) => {
    toast(`${s.label} → ${s.outcome}`, s.note, s.outcome === 'success' ? 'info' : 'medium');
  });

  await refreshAll();
}

boot().catch((err) => {
  console.error(err);
  toast('Startup failed', String(err), 'critical');
});
