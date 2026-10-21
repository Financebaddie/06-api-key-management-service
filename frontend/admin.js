const pageError = document.querySelector('#page-error');
const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const request = async (url, options = {}) => {
  const response = await fetch(url, { credentials: 'same-origin', ...options,
    headers: { ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) { window.location.assign('/admin/login'); throw new Error('Please log in again.'); }
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
};

async function loadDashboard() {
  const data = await request('/api/admin/dashboard');
  document.querySelector('#total-links').textContent = data.totalLinks;
  document.querySelector('#total-clicks').textContent = data.totalClicks;
  renderRequests(data.requests);
  renderKeys(data.keys);
}

function renderRequests(requests) {
  const body = document.querySelector('#requests');
  if (!requests.length) { body.innerHTML = '<tr><td class="empty" colspan="6">No API key requests yet.</td></tr>'; return; }
  body.innerHTML = requests.map((item) => `<tr>
    <td><strong>${escapeHtml(item.requester_name)}</strong><small>${escapeHtml(item.email)}</small></td>
    <td class="reason">${escapeHtml(item.reason || 'No details provided')}</td><td>${escapeHtml(item.created_at)}</td>
    <td>${item.requested_expires_at ? escapeHtml(item.requested_expires_at.slice(0, 10)) : 'Not specified'}</td>
    <td><span class="status ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>${item.key_prefix ? `<small><code>${escapeHtml(item.key_prefix)}…</code></small>` : ''}</td>
    <td>${item.status === 'pending' ? `<div class="actions"><button class="primary" data-action="approve" data-id="${item.id}">Approve &amp; create key</button><button class="danger" data-action="reject" data-id="${item.id}">Reject</button></div>` : escapeHtml(item.reviewed_at || '')}</td>
  </tr>`).join('');
}

function renderKeys(keys) {
  const body = document.querySelector('#keys');
  if (!keys.length) { body.innerHTML = '<tr><td class="empty" colspan="7">No API keys yet.</td></tr>'; return; }
  body.innerHTML = keys.map((key) => {
    const expired = key.expires_at && Date.parse(key.expires_at) <= Date.now();
    const status = !key.is_active ? 'revoked' : expired ? 'expired' : 'active';
    return `<tr><td><strong>${escapeHtml(key.owner)}</strong><small>${escapeHtml(key.email || 'No email')}</small></td>
      <td><code>${escapeHtml(key.key_prefix)}…</code></td><td><span class="status ${status}">${status}</span></td>
      <td>${key.link_count}</td><td>${escapeHtml(key.created_at)}</td>
      <td><button class="${key.is_active ? 'danger' : 'primary'}" data-action="toggle" data-id="${key.id}">${key.is_active ? 'Revoke' : 'Grant access'}</button></td>
      <td><form class="inline-form" data-action="expiration" data-id="${key.id}"><input aria-label="Expiration date for ${escapeHtml(key.owner)}" type="date" name="expiresAt" value="${key.expires_at ? escapeHtml(key.expires_at.slice(0, 10)) : ''}" min="${new Date().toISOString().slice(0, 10)}"><button class="secondary" type="submit">Save</button><small>Blank means never expires</small></form></td></tr>`;
  }).join('');
}

function showError(message) { pageError.textContent = message; pageError.classList.remove('hidden'); }
function showNewKey(secret) {
  const box = document.querySelector('#new-key');
  box.innerHTML = `<strong>Copy this API key now. It will not be shown again.</strong><p><code id="secret-value">${escapeHtml(secret)}</code> <button class="secondary" id="copy-secret" type="button">Copy</button></p>`;
  box.classList.remove('hidden');
  document.querySelector('#copy-secret').addEventListener('click', async () => {
    await navigator.clipboard.writeText(secret); document.querySelector('#copy-secret').textContent = 'Copied';
  });
}

document.querySelector('#create-key-form').addEventListener('submit', async (event) => {
  event.preventDefault(); pageError.classList.add('hidden');
  try {
    const body = Object.fromEntries(new FormData(event.currentTarget));
    const data = await request('/api/admin/keys', { method: 'POST', body: JSON.stringify(body) });
    showNewKey(data.apiKey); event.currentTarget.reset(); await loadDashboard();
  } catch (error) { showError(error.message); }
});

document.querySelector('#requests').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]'); if (!button) return;
  pageError.classList.add('hidden');
  try {
    const data = await request(`/api/admin/requests/${button.dataset.id}/${button.dataset.action}`, { method: 'POST', body: '{}' });
    if (data.apiKey) showNewKey(data.apiKey); await loadDashboard();
  } catch (error) { showError(error.message); }
});

document.querySelector('#keys').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action="toggle"]'); if (!button) return;
  try { await request(`/api/admin/keys/${button.dataset.id}/toggle`, { method: 'POST', body: '{}' }); await loadDashboard(); }
  catch (error) { showError(error.message); }
});

document.querySelector('#keys').addEventListener('submit', async (event) => {
  const form = event.target.closest('form[data-action="expiration"]'); if (!form) return;
  event.preventDefault();
  try {
    const body = Object.fromEntries(new FormData(form));
    await request(`/api/admin/keys/${form.dataset.id}/expiration`, { method: 'POST', body: JSON.stringify(body) });
    await loadDashboard();
  } catch (error) { showError(error.message); }
});

document.querySelector('#logout').addEventListener('click', async () => {
  await request('/api/admin/logout', { method: 'POST', body: '{}' }); window.location.assign('/admin/login');
});

loadDashboard().catch((error) => showError(error.message));
