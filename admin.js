'use strict';

const state = { csrfToken: '', orders: [], inventory: [] };
const byId = (id) => document.getElementById(id);

const statusLabels = {
  creating_checkout: 'יוצרת תשלום',
  pending: 'ממתינה לתשלום',
  confirmed: 'תשלום אושר',
  fulfilled: 'נמסרה',
  paid_awaiting_stock: 'ממתינה למלאי',
  manual_review: 'בדיקה ידנית',
  failed: 'נכשלה',
  cancelled: 'בוטלה',
  checkout_error: 'שגיאת סליקה',
};

const statusClasses = {
  fulfilled: 'border-emerald-300/20 bg-emerald-300/[.07] text-emerald-200',
  confirmed: 'border-sky-300/20 bg-sky-300/[.07] text-sky-200',
  paid_awaiting_stock: 'border-amber-300/20 bg-amber-300/[.07] text-amber-100',
  manual_review: 'border-amber-300/20 bg-amber-300/[.07] text-amber-100',
  failed: 'border-rose-300/20 bg-rose-300/[.07] text-rose-200',
  cancelled: 'border-slate-300/20 bg-slate-300/[.07] text-slate-300',
};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;',
  }[character]));
}

function showNotice(message, type = 'success') {
  const notice = byId('notice');
  notice.textContent = message;
  notice.className = `mt-5 rounded-xl border px-4 py-3 text-sm font-bold ${
    type === 'error'
      ? 'border-rose-300/20 bg-rose-300/[.07] text-rose-200'
      : 'border-emerald-300/20 bg-emerald-300/[.07] text-emerald-200'
  }`;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => notice.classList.add('hidden'), 5000);
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(state.csrfToken ? { 'X-CSRF-Token': state.csrfToken } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(data.error || 'הפעולה נכשלה');
  }
  return data;
}

function showLogin() {
  byId('dashboardView').classList.add('hidden');
  byId('loginView').classList.remove('hidden');
}

function showDashboard() {
  byId('loginView').classList.add('hidden');
  byId('dashboardView').classList.remove('hidden');
}

async function authenticate() {
  try {
    const data = await api('/api/admin/me');
    state.csrfToken = data.csrfToken;
    showDashboard();
    await loadDashboard();
  } catch {
    showLogin();
  }
}

byId('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = byId('loginError');
  error.classList.add('hidden');
  try {
    const data = await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: byId('password').value }),
    });
    state.csrfToken = data.csrfToken;
    byId('password').value = '';
    showDashboard();
    await loadDashboard();
  } catch (loginError) {
    error.textContent = loginError.message;
    error.classList.remove('hidden');
  }
});

byId('logoutButton').addEventListener('click', async () => {
  try {
    await api('/api/admin/logout', { method: 'POST' });
  } finally {
    state.csrfToken = '';
    showLogin();
  }
});

async function loadDashboard() {
  try {
    const filter = byId('statusFilter').value;
    const [summary, orders, inventory] = await Promise.all([
      api('/api/admin/summary'),
      api(`/api/admin/orders${filter ? `?status=${encodeURIComponent(filter)}` : ''}`),
      api('/api/admin/inventory'),
    ]);
    state.orders = orders;
    state.inventory = inventory;
    renderSummary(summary);
    renderOrders();
    renderInventory();
  } catch (error) {
    showNotice(error.message, 'error');
  }
}

function countRows(rows) {
  return Object.fromEntries(rows.map((row) => [row.status, Number(row.count)]));
}

function renderSummary(summary) {
  const inventory = countRows(summary.inventory);
  const orders = countRows(summary.orders);
  byId('availableCount').textContent = inventory.available || 0;
  byId('paidCount').textContent =
    (orders.fulfilled || 0) + (orders.confirmed || 0) + (orders.paid_awaiting_stock || 0);
  byId('waitingCount').textContent = (orders.paid_awaiting_stock || 0) + (orders.manual_review || 0);
  byId('revenue').textContent = `${Number(summary.revenue).toLocaleString('he-IL')} ${summary.currency}`;
}

function renderInventory() {
  byId('inventoryTotal').textContent = `${state.inventory.length} קישורים`;
  const list = byId('inventoryList');
  if (!state.inventory.length) {
    list.innerHTML = '<div class="rounded-xl border border-dashed border-white/10 p-5 text-center text-sm text-slate-500">המלאי עדיין ריק</div>';
    return;
  }

  list.innerHTML = state.inventory.map((item) => `
    <article class="rounded-xl border border-white/[.07] bg-black/10 p-3">
      <div class="flex items-center justify-between gap-3">
        <span class="rounded-full px-2.5 py-1 text-[10px] font-black ${
          item.status === 'available'
            ? 'bg-emerald-300/10 text-emerald-200'
            : item.status === 'assigned'
              ? 'bg-sky-300/10 text-sky-200'
              : 'bg-slate-300/10 text-slate-400'
        }">${item.status === 'available' ? 'פנוי' : item.status === 'assigned' ? 'הוקצה' : 'מושבת'}</span>
        <span class="text-[10px] text-slate-600">${new Date(item.createdAt).toLocaleString('he-IL')}</span>
      </div>
      <p class="mt-2 truncate text-left text-xs text-slate-400" dir="ltr" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</p>
      <div class="mt-2 flex gap-2">
        <button data-copy="${escapeHtml(item.url)}" class="rounded-lg border border-white/10 px-2.5 py-1.5 text-xs font-bold">העתקה</button>
        ${item.status === 'available' ? `<button data-disable="${item.id}" class="rounded-lg border border-rose-300/15 px-2.5 py-1.5 text-xs font-bold text-rose-200">השבתה</button>` : ''}
      </div>
    </article>
  `).join('');
}

function renderOrders() {
  const list = byId('ordersList');
  if (!state.orders.length) {
    list.innerHTML = '<div class="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-500">אין הזמנות להצגה</div>';
    return;
  }

  list.innerHTML = state.orders.map((order) => `
    <article class="rounded-2xl border border-white/[.07] bg-black/10 p-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p class="font-mono text-xs text-slate-500" dir="ltr">${escapeHtml(order.publicId.slice(0, 13))}…</p>
          <p class="mt-1 font-display text-lg font-black">${Number(order.amount).toLocaleString('he-IL')} ${escapeHtml(order.currency)}</p>
        </div>
        <span class="rounded-full border px-3 py-1 text-xs font-black ${statusClasses[order.status] || 'border-white/10 bg-white/[.05] text-slate-300'}">
          ${escapeHtml(statusLabels[order.status] || order.status)}
        </span>
      </div>
      <div class="mt-3 grid gap-1 text-xs text-slate-500 sm:grid-cols-2">
        <p>נוצרה: ${new Date(order.createdAt).toLocaleString('he-IL')}</p>
        <p>לקוח: ${escapeHtml(order.customerEmail || 'טרם התקבל')}</p>
        ${order.transactionId ? `<p class="truncate" dir="ltr">Txn: ${escapeHtml(order.transactionId)}</p>` : ''}
        <p>מסירה: ${escapeHtml(order.deliveryStatus)}</p>
      </div>
      ${order.deliveryError ? `<p class="mt-3 rounded-lg bg-rose-300/[.06] p-2 text-xs text-rose-200">${escapeHtml(order.deliveryError)}</p>` : ''}
      ${order.redemptionUrl ? `<p class="mt-3 truncate rounded-lg bg-white/[.035] p-2 text-left text-xs text-slate-400" dir="ltr">${escapeHtml(order.redemptionUrl)}</p>` : ''}
      <div class="mt-3 flex flex-wrap gap-2">
        ${order.redemptionUrl ? `<button data-copy="${escapeHtml(order.redemptionUrl)}" class="rounded-lg border border-white/10 px-3 py-2 text-xs font-bold">העתקת קישור</button>` : ''}
        ${['confirmed', 'paid_awaiting_stock', 'manual_review'].includes(order.status) ? `<button data-deliver="${order.id}" class="rounded-lg bg-mint px-3 py-2 text-xs font-black text-ink">מסירה ידנית</button>` : ''}
        ${order.redemptionUrl && order.customerEmail ? `<button data-resend="${order.id}" class="rounded-lg border border-white/10 px-3 py-2 text-xs font-bold">שליחה חוזרת</button>` : ''}
      </div>
    </article>
  `).join('');
}

byId('inventoryForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/admin/inventory', {
      method: 'POST',
      body: JSON.stringify({ links: byId('inventoryLinks').value }),
    });
    byId('inventoryLinks').value = '';
    showNotice(`נוספו ${result.added} קישורים${result.duplicates ? ` · ${result.duplicates} כפולים דולגו` : ''}`);
    await loadDashboard();
  } catch (error) {
    showNotice(error.message, 'error');
  }
});

byId('inventoryList').addEventListener('click', async (event) => {
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) {
    await navigator.clipboard.writeText(copyButton.dataset.copy);
    return showNotice('הקישור הועתק');
  }
  const disableButton = event.target.closest('[data-disable]');
  if (disableButton && confirm('להשבית את הקישור הפנוי?')) {
    try {
      await api(`/api/admin/inventory/${disableButton.dataset.disable}`, { method: 'DELETE' });
      showNotice('הקישור הושבת');
      await loadDashboard();
    } catch (error) {
      showNotice(error.message, 'error');
    }
  }
});

byId('ordersList').addEventListener('click', async (event) => {
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) {
    await navigator.clipboard.writeText(copyButton.dataset.copy);
    return showNotice('הקישור הועתק');
  }
  const deliveryButton = event.target.closest('[data-deliver]');
  if (deliveryButton) {
    byId('deliveryOrderId').value = deliveryButton.dataset.deliver;
    byId('manualUrl').value = '';
    byId('deliveryDialog').showModal();
    return;
  }
  const resendButton = event.target.closest('[data-resend]');
  if (resendButton) {
    try {
      const result = await api(`/api/admin/orders/${resendButton.dataset.resend}/resend`, { method: 'POST' });
      showNotice(result.emailed ? 'האימייל נשלח מחדש' : 'אין שירות אימייל מוגדר; הקישור זמין להעתקה');
      await loadDashboard();
    } catch (error) {
      showNotice(error.message, 'error');
    }
  }
});

byId('deliveryForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api(`/api/admin/orders/${byId('deliveryOrderId').value}/deliver`, {
      method: 'POST',
      body: JSON.stringify({ redemptionUrl: byId('manualUrl').value.trim() || null }),
    });
    byId('deliveryDialog').close();
    await navigator.clipboard.writeText(result.redemptionUrl);
    showNotice('הקישור הוקצה והועתק ללוח');
    await loadDashboard();
  } catch (error) {
    showNotice(error.message, 'error');
  }
});

byId('closeDelivery').addEventListener('click', () => byId('deliveryDialog').close());
byId('refreshButton').addEventListener('click', loadDashboard);
byId('statusFilter').addEventListener('change', loadDashboard);

authenticate();
