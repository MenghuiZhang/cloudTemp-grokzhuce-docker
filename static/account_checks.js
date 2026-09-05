'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let token = '', overview = null, previewId = '', selectedJob = '', report = null, timer = null;
  function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
  async function api(path, data, method) {
    const headers = {'X-Monitor-Token': token};
    let body;
    if (data instanceof FormData) body = data;
    else if (data !== undefined) {headers['Content-Type'] = 'application/json'; body = JSON.stringify(data);}
    const res = await fetch('/api/account-checks' + path, {method: method || (body ? 'POST' : 'GET'), headers, body});
    const value = await res.json();
    if (!res.ok || value.ok === false) throw new Error(value.message || `HTTP ${res.status}`);
    return value;
  }
  function resetPreview() {previewId = ''; $('start').disabled = true; $('previewRows').replaceChildren(); $('previewInfo').textContent = '';}
  function sources() {
    resetPreview();
    const source = $('source').value;
    $('selection').hidden = source === 'upload'; $('uploadBox').hidden = source !== 'upload';
    const rows = source === 'recent' ? overview.recent.map(r => [r.id, r.email]) : (overview.sources[source] || []).map(n => [n, n]);
    $('files').innerHTML = rows.map(([id, name]) => `<option value="${esc(id)}">${esc(name)}</option>`).join('');
  }
  async function load() {
    overview = await api('');
    for (const key of ['model','workers','timeout']) $(key).value = overview.config[key];
    $('base').value = overview.config.base_url; $('automatic').checked = overview.config.automatic;
    $('content').hidden = false; $('authPanel').hidden = true; sources(); renderJobs(overview.jobs);
  }
  async function save() {
    const data = await api('/config', {base_url: $('base').value.trim(), model: $('model').value.trim(), workers: Number($('workers').value), timeout: Number($('timeout').value), automatic: $('automatic').checked});
    overview.config = data.config; message('检测设置已保存。');
  }
  async function preview() {
    resetPreview();
    let body;
    if ($('source').value === 'upload') {
      const file = $('upload').files[0]; if (!file) throw new Error('请选择文件');
      body = new FormData(); body.append('file', file);
    } else {
      const chosen = [...$('files').selectedOptions].map(o => o.value);
      body = {source: $('source').value, ...($('source').value === 'recent' ? {ids: chosen} : {files: chosen})};
    }
    const data = await api('/preview', body); previewId = data.preview_id; $('start').disabled = false;
    $('previewInfo').textContent = `${data.total} 个账号已去重；仅展示脱敏信息。`;
    $('previewRows').innerHTML = data.accounts.map(a => `<div>${esc(a.email)} · ${esc(a.fingerprint)} · ${esc(a.state.toUpperCase())}</div>`).join('');
  }
  const active = status => ['running','queued','cancelling'].includes(status);
  function renderJobs(jobs) {
    $('jobs').innerHTML = jobs.length ? jobs.map(j => `<div class="job"><div class="actions"><span>${esc(j.created_at)} · ${esc(j.source)} · <b>${esc(j.status)}</b> · ${j.completed}/${j.total}</span><span><button data-action="view" data-id="${esc(j.id)}">查看</button> ${active(j.status) ? `<button data-action="cancel" data-id="${esc(j.id)}">取消</button>` : j.source !== 'automatic' && j.status !== 'failed' ? `<button data-action="apply" data-id="${esc(j.id)}">应用结果</button>` : ''}</span></div><progress max="${j.total}" value="${j.completed}"></progress><div class="hint">${Object.entries(j.counts).map(([s,n]) => `${esc(s.toUpperCase())} ${n}`).join(' · ')}</div></div>`).join('') : '<div class="empty">暂无检测任务</div>';
  }
  async function detail(id) {
    const data = await api('/jobs/' + encodeURIComponent(id)); report = data.job; selectedJob = id;
    $('detail').hidden = false; $('detailTitle').textContent = `检测结果 · ${report.completed}/${report.total}`;
    $('results').innerHTML = report.items.map(r => {const q = r.quality || {};return `<tr><td>${esc(r.email)}<br><small>${esc(r.fingerprint)}</small></td><td><span class="badge ${esc(r.state)}">${esc(r.state.toUpperCase())}</span></td><td>${esc(r.reason)}${q.retry_after ? `<br>建议 ${Math.ceil(q.retry_after)} 秒后复检` : ''}</td><td>${esc(q.output_tokens ?? '—')}</td><td>${esc(q.tps ?? '—')}</td><td>${q.has_thinking === undefined ? '—' : q.has_thinking ? '有' : '未观察到'}</td><td>${r.applied ? '已应用' : '未应用'}</td></tr>`;}).join('');
  }
  async function refresh() {const data = await api('/jobs'); renderJobs(data.jobs); if (selectedJob) await detail(selectedJob);}
  async function poll() {clearTimeout(timer); if (!token) return; try {await refresh();} catch (e) {message(e.message, true);} timer = setTimeout(poll, 2000);}
  const run = fn => async event => {const button = event.currentTarget; button.disabled = true; try {await fn(event);} catch (e) {message(e.message, true);} finally {button.disabled = button.id === 'start' && !previewId;}};
  $('connect').onclick = run(async () => {token = $('monitor').value.trim(); await load(); $('monitor').value = ''; message('已连接，可直接选择账号开始检测。'); poll();});
  $('source').onchange = sources; $('files').onchange = resetPreview; $('upload').onchange = resetPreview;
  $('save').onclick = run(save); $('preview').onclick = run(preview); $('refresh').onclick = run(refresh);
  $('start').onclick = run(async () => {if (!previewId) throw new Error('请先预览'); await save(); const data = await api('/jobs', {preview_id: previewId, passive: $('mode').value === 'passive'}); resetPreview(); await detail(data.job.id); await refresh(); message('后台检测已开始。');});
  $('jobs').onclick = async event => {const b = event.target.closest('button[data-action]'); if (!b) return; b.disabled = true; try {const {id, action} = b.dataset; if (action === 'view') await detail(id); else {const data = await api('/jobs/' + encodeURIComponent(id) + '/' + action, {}); if (action === 'apply') message(`已应用 ${data.changed} 条，跳过 ${data.skipped} 条（已应用、凭据变更或无可用来源）。`); await refresh();}} catch (e) {message(e.message, true);} finally {b.disabled = false;}};
  $('export').onclick = () => {if (!report) return; const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `account-check-${report.id}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);};
  window.addEventListener('pagehide', () => {clearTimeout(timer); token = '';});
})();
