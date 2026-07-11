'use strict';

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');

const port = 4197;
const baseUrl = `http://127.0.0.1:${port}`;
const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'pro18-test-'));
let adminCookie;
let csrfToken;
const server = spawn(process.execPath, ['server.js'], {
  cwd: path.resolve(__dirname, '..'),
  env: {
    ...process.env,
    NODE_ENV: 'test',
    PORT: String(port),
    PUBLIC_BASE_URL: baseUrl,
    ADMIN_PASSWORD: 'test-admin-password',
    SESSION_SECRET: 'test-session-secret',
    INVENTORY_ENCRYPTION_KEY: 'test-inventory-secret',
    DATA_DIRECTORY: temporaryDirectory,
    CLEARO_API_KEY: '',
    CLEARO_WEBHOOK_SECRET: 'test-webhook-secret',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Test server did not start');
}

after(async () => {
  if (server.exitCode === null) {
    const exited = new Promise((resolve) => server.once('exit', resolve));
    server.kill();
    await exited;
  }
  fs.rmSync(temporaryDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test('health endpoint and protected admin flow work', async () => {
  await waitForServer();

  const healthResponse = await fetch(`${baseUrl}/health`);
  const health = await healthResponse.json();
  assert.equal(health.ok, true);
  assert.equal(health.inventoryAvailable, 0);

  const unauthorized = await fetch(`${baseUrl}/api/admin/summary`);
  assert.equal(unauthorized.status, 401);

  const loginResponse = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'test-admin-password' }),
  });
  assert.equal(loginResponse.status, 200);
  const login = await loginResponse.json();
  const cookie = loginResponse.headers.get('set-cookie').split(';')[0];
  assert.ok(login.csrfToken);
  adminCookie = cookie;
  csrfToken = login.csrfToken;

  const addResponse = await fetch(`${baseUrl}/api/admin/inventory`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie,
      'X-CSRF-Token': login.csrfToken,
    },
    body: JSON.stringify({
      links: [
        'https://example.com/redeem/one',
        'https://example.com/redeem/two',
        'https://example.com/redeem/one',
      ],
    }),
  });
  assert.equal(addResponse.status, 201);
  assert.deepEqual(await addResponse.json(), { added: 2, duplicates: 0 });

  const inventoryResponse = await fetch(`${baseUrl}/api/admin/inventory`, {
    headers: { Cookie: cookie },
  });
  const inventory = await inventoryResponse.json();
  assert.equal(inventory.length, 2);
});

test('confirmed payment assigns exactly one link across duplicate webhooks', async () => {
  await waitForServer();
  const database = new Database(path.join(temporaryDirectory, 'pro18.sqlite'));
  const timestamp = new Date().toISOString();
  database.prepare(`
    INSERT INTO orders (
      id, public_id, access_token_hash, payment_link_id, amount, currency,
      status, delivery_status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 249, 'ILS', 'pending', 'not_ready', ?, ?)
  `).run('order-test', 'public-test', 'unused-token-hash', 'pl_test', timestamp, timestamp);
  database.close();

  const payload = JSON.stringify({
    event: 'payment.confirmed',
    data: {
      transaction_id: 'txn_test',
      payment_link_id: 'pl_test',
      amount: 249,
      currency: 'ILS',
      status: 'confirmed',
    },
    timestamp,
  });
  const signature = crypto.createHmac('sha256', 'test-webhook-secret').update(payload).digest('hex');

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await fetch(`${baseUrl}/api/webhooks/clearo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Clearo-Signature': signature },
      body: payload,
    });
    assert.equal(response.status, 200);
  }

  const summary = await fetch(`${baseUrl}/api/admin/summary`, {
    headers: { Cookie: adminCookie },
  }).then((response) => response.json());
  const inventoryCounts = Object.fromEntries(summary.inventory.map((row) => [row.status, row.count]));
  assert.equal(inventoryCounts.assigned, 1);
  assert.equal(inventoryCounts.available, 1);

  const orders = await fetch(`${baseUrl}/api/admin/orders`, {
    headers: { Cookie: adminCookie },
  }).then((response) => response.json());
  const fulfilled = orders.find((order) => order.id === 'order-test');
  assert.equal(fulfilled.status, 'fulfilled');
  assert.ok(fulfilled.redemptionUrl);
});

test('checkout fails safely when payment API is not configured', async () => {
  await waitForServer();
  const response = await fetch(`${baseUrl}/api/checkout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.equal(response.status, 502);
  const body = await response.json();
  assert.match(body.error, /לא ניתן לפתוח/);
});
