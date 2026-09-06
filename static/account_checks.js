'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let overview = null, previewId = '', selectedJob = '', report = null, timer = null;
  function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
  async function api(path, data, method) {
    const headers = {};
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
    $('automaticDelay').textContent = overview.delay_seconds ?? 60;
    $('content').hidden = false; sources(); renderJobs(overview.jobs);
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
  const active = status => ['running','queued','scheduled','result_ready','applying','cancelling'].includes(status);
  function renderJobs(jobs) {
    $('clearHistory').disabled = !jobs.some(j => !active(j.status));
    $('jobs').innerHTML = jobs.length ? jobs.map(j => {
      const controls = active(j.status)
        ? `<button data-action="cancel" data-id="${esc(j.id)}">取消</button>`
        : `${j.source !== 'automatic' && j.status !== 'failed' ? `<button data-action="apply" data-id="${esc(j.id)}">应用结果</button>` : ''}<button class="danger" data-action="delete" data-id="${esc(j.id)}">删除</button>`;
      return `<div class="job"><div class="actions"><span class="job-meta">${esc(j.created_at)} · ${esc(j.source)} · <b>${esc(j.status)}</b> · ${j.completed}/${j.total}</span><span class="job-buttons"><button data-action="view" data-id="${esc(j.id)}">查看</button>${controls}</span></div><progress max="${j.total}" value="${j.completed}"></progress><div class="hint">${Object.entries(j.counts).map(([s,n]) => `${esc(s.toUpperCase())} ${n}`).join(' · ')}</div></div>`;
    }).join('') : '<div class="empty">暂无检测任务</div>';
  }
  function clearDetail() {
    selectedJob = ''; report = null; $('results').replaceChildren(); $('detail').hidden = true;
  }
  async function detail(id, scroll = false) {
    const data = await api('/jobs/' + encodeURIComponent(id)); report = data.job; selectedJob = id;
    $('detail').hidden = false; $('detailTitle').textContent = `检测结果 · ${report.completed}/${report.total}`;
    $('results').innerHTML = report.items.map(r => {const q = r.quality || {};return `<tr><td>${esc(r.email)}<br><small>${esc(r.fingerprint)}</small></td><td><span class="badge ${esc(r.state)}">${esc(r.state.toUpperCase())}</span></td><td>${esc(r.reason)}${q.retry_after ? `<br>建议 ${Math.ceil(q.retry_after)} 秒后复检` : ''}</td><td>${esc(q.output_tokens ?? '—')}</td><td>${esc(q.tps ?? '—')}</td><td>${q.has_thinking === undefined ? '—' : q.has_thinking ? '有' : '未观察到'}</td><td>${r.applied ? '已应用' : '未应用'}</td></tr>`;}).join('');
    if (scroll) $('detail').scrollIntoView({behavior: 'smooth', block: 'start'});
  }
  async function refresh() {const data = await api('/jobs'); renderJobs(data.jobs); if (selectedJob) {if (data.jobs.some(j => j.id === selectedJob)) await detail(selectedJob); else clearDetail();}}
  async function poll() {clearTimeout(timer); try {await refresh();} catch (e) {message(e.message, true);} timer = setTimeout(poll, 2000);}
  const run = fn => async event => {const button = event.currentTarget; button.disabled = true; try {await fn(event);} catch (e) {message(e.message, true);} finally {button.disabled = button.id === 'start' && !previewId;}};
  $('source').onchange = sources; $('files').onchange = resetPreview; $('upload').onchange = resetPreview;
  $('save').onclick = run(save); $('preview').onclick = run(preview); $('refresh').onclick = run(refresh);
  $('clearHistory').onclick = run(async () => {if (!confirm('确定清空全部已结束的检测历史吗？运行中和待应用任务会保留。')) return; const data = await api('/jobs', undefined, 'DELETE'); await refresh(); message(`已清空 ${data.deleted} 条检测历史。`);});
  $('start').onclick = run(async () => {if (!previewId) throw new Error('请先预览'); await save(); const data = await api('/jobs', {preview_id: previewId, passive: $('mode').value === 'passive'}); resetPreview(); await detail(data.job.id, true); await refresh(); message('后台检测已开始。');});
  $('jobs').onclick = async event => {const b = event.target.closest('button[data-action]'); if (!b) return; b.disabled = true; try {const {id, action} = b.dataset; if (action === 'view') await detail(id, true); else if (action === 'delete') {if (!confirm('确定删除这条检测历史吗？删除后无法恢复。')) return; await api('/jobs/' + encodeURIComponent(id), undefined, 'DELETE'); if (selectedJob === id) clearDetail(); await refresh(); message('检测历史已删除。');} else {const data = await api('/jobs/' + encodeURIComponent(id) + '/' + action, {}); if (action === 'apply') message(`已应用 ${data.changed} 条，跳过 ${data.skipped} 条（已应用、凭据变更或无可用来源）。`); await refresh();}} catch (e) {message(e.message, true);} finally {b.disabled = false;}};
  $('export').onclick = () => {if (!report) return; const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `account-check-${report.id}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);};
  window.addEventListener('pagehide', () => clearTimeout(timer));
  load().then(poll).catch(e => message(e.message, true));
})();
