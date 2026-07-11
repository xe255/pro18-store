'use strict';

require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const Database = require('better-sqlite3');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 4173);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const CLEARO_API_KEY = String(process.env.CLEARO_API_KEY || '').includes('|')
  ? String(process.env.CLEARO_API_KEY).split('|').pop()
  : String(process.env.CLEARO_API_KEY || '');
const CLEARO_WEBHOOK_SECRET = process.env.CLEARO_WEBHOOK_SECRET || '';
const CLEARO_AMOUNT = Number(process.env.CLEARO_AMOUNT || 249);
const CLEARO_CURRENCY = String(process.env.CLEARO_CURRENCY || 'ILS').toUpperCase();
const PAYMENT_SURCHARGE_PERCENT = Number(process.env.PAYMENT_SURCHARGE_PERCENT || 4.5);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (IS_PRODUCTION ? '' : 'change-me');
const SESSION_SECRET = process.env.SESSION_SECRET || (IS_PRODUCTION ? '' : 'dev-session-secret-change-me');
const INVENTORY_SECRET = process.env.INVENTORY_ENCRYPTION_KEY || (IS_PRODUCTION ? '' : 'dev-inventory-secret-change-me');
const META_PIXEL_ID = (() => {
  const value = String(process.env.META_PIXEL_ID || '').trim();
  return /^\d+$/.test(value) ? value : '';
})();

if (IS_PRODUCTION) {
  const missing = [
    ['PUBLIC_BASE_URL', process.env.PUBLIC_BASE_URL],
    ['CLEARO_API_KEY', CLEARO_API_KEY],
    ['CLEARO_WEBHOOK_SECRET', CLEARO_WEBHOOK_SECRET],
    ['ADMIN_PASSWORD', ADMIN_PASSWORD],
    ['SESSION_SECRET', SESSION_SECRET],
    ['INVENTORY_ENCRYPTION_KEY', INVENTORY_SECRET],
  ].filter(([, value]) => !value).map(([name]) => name);

  if (missing.length) {
    throw new Error(`Missing required production environment variables: ${missing.join(', ')}`);
  }
}

if (!Number.isFinite(CLEARO_AMOUNT) || CLEARO_AMOUNT <= 0) {
  throw new Error('CLEARO_AMOUNT must be a positive number');
}

if (!Number.isFinite(PAYMENT_SURCHARGE_PERCENT) || PAYMENT_SURCHARGE_PERCENT < 0 || PAYMENT_SURCHARGE_PERCENT >= 100) {
  throw new Error('PAYMENT_SURCHARGE_PERCENT must be between 0 and 100');
}

function paymentLinkAmount(displayTotal) {
  const adjusted = Number(displayTotal) / (1 + PAYMENT_SURCHARGE_PERCENT / 100);
  return Math.round(adjusted * 100) / 100;
}

const dataDirectory = process.env.DATA_DIRECTORY
  ? path.resolve(process.env.DATA_DIRECTORY)
  : path.join(ROOT, 'data');
fs.mkdirSync(dataDirectory, { recursive: true });
const db = new Database(path.join(dataDirectory, 'pro18.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS inventory_links (
    id TEXT PRIMARY KEY,
    encrypted_url TEXT NOT NULL,
    url_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'available'
      CHECK (status IN ('available', 'assigned', 'disabled')),
    assigned_order_id TEXT,
    created_at TEXT NOT NULL,
    assigned_at TEXT,
    FOREIGN KEY (assigned_order_id) REFERENCES orders(id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    access_token_hash TEXT NOT NULL,
    payment_link_id TEXT UNIQUE,
    payment_link_slug TEXT,
    payment_url TEXT,
    transaction_id TEXT UNIQUE,
    amount REAL NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL,
    customer_email TEXT,
    customer_phone TEXT,
    inventory_link_id TEXT UNIQUE,
    delivery_status TEXT NOT NULL DEFAULT 'not_ready',
    delivery_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    paid_at TEXT,
    fulfilled_at TEXT,
    quantity INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (inventory_link_id) REFERENCES inventory_links(id)
  );

  CREATE TABLE IF NOT EXISTS order_redemptions (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    inventory_link_id TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (inventory_link_id) REFERENCES inventory_links(id)
  );

  CREATE TABLE IF NOT EXISTS webhook_events (
    id TEXT PRIMARY KEY,
    payload_hash TEXT NOT NULL UNIQUE,
    event_name TEXT NOT NULL,
    transaction_id TEXT,
    order_id TEXT,
    received_at TEXT NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id)
  );

  CREATE INDEX IF NOT EXISTS idx_inventory_status ON inventory_links(status, created_at);
  CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_orders_payment_link ON orders(payment_link_id);
  CREATE INDEX IF NOT EXISTS idx_order_redemptions_order ON order_redemptions(order_id);
`);

const encryptionKey = crypto.createHash('sha256').update(INVENTORY_SECRET).digest();
const now = () => new Date().toISOString();
const randomId = () => crypto.randomUUID();
const hash = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
const hmac = (value, secret = SESSION_SECRET) =>
  crypto.createHmac('sha256', secret).update(String(value)).digest('hex');

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function encryptUrl(url) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(url, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64url')).join('.');
}

function decryptUrl(value) {
  const [iv, tag, ciphertext] = value.split('.').map((part) => Buffer.from(part, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

(function migrateSchema() {
  const orderColumns = db.prepare('PRAGMA table_info(orders)').all();
  if (!orderColumns.some((column) => column.name === 'quantity')) {
    db.exec('ALTER TABLE orders ADD COLUMN quantity INTEGER NOT NULL DEFAULT 1');
  }

  const legacyOrders = db.prepare(`
    SELECT id, inventory_link_id FROM orders
    WHERE inventory_link_id IS NOT NULL
      AND id NOT IN (SELECT order_id FROM order_redemptions)
  `).all();

  const backfill = db.prepare(`
    INSERT INTO order_redemptions (id, order_id, inventory_link_id, position, created_at)
    VALUES (?, ?, ?, 1, ?)
  `);

  for (const order of legacyOrders) {
    backfill.run(randomId(), order.id, order.inventory_link_id, now());
  }
})();

const BUNDLE_TIERS = {
  1: { unitPrice: 249, total: 249, discount: 0 },
  2: { unitPrice: 229, total: 458, discount: 8 },
  3: { unitPrice: 224, total: 672, discount: 10 },
};

function bundlePricing(rawQuantity) {
  const quantity = [1, 2, 3].includes(Number(rawQuantity)) ? Number(rawQuantity) : 1;
  const tier = BUNDLE_TIERS[quantity];
  const listTotal = CLEARO_AMOUNT * quantity;
  const total = tier.total;
  return {
    quantity,
    unitPrice: tier.unitPrice,
    total,
    paymentTotal: paymentLinkAmount(total),
    discountPercent: tier.discount,
    savings: listTotal - total,
    listTotal,
    currency: CLEARO_CURRENCY,
  };
}

function getOrderRedemptionUrls(orderId) {
  return db.prepare(`
    SELECT il.encrypted_url
    FROM order_redemptions redemption
    JOIN inventory_links il ON il.id = redemption.inventory_link_id
    WHERE redemption.order_id = ?
    ORDER BY redemption.position ASC
  `).all(orderId).map((row) => decryptUrl(row.encrypted_url));
}

function validateRedemptionUrl(value) {
  try {
    const url = new URL(String(value).trim());
    if (url.protocol !== 'https:') throw new Error();
    return url.toString();
  } catch {
    throw new Error('Each redemption link must be a valid HTTPS URL');
  }
}

function parseCookies(request) {
  return Object.fromEntries(
    String(request.headers.cookie || '')
      .split(';')
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        const index = item.indexOf('=');
        return [decodeURIComponent(item.slice(0, index)), decodeURIComponent(item.slice(index + 1))];
      })
  );
}

function createAdminSession() {
  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + (8 * 60 * 60 * 1000),
    nonce: crypto.randomBytes(18).toString('base64url'),
  })).toString('base64url');
  return `${payload}.${hmac(payload)}`;
}

function readAdminSession(request) {
  try {
    const token = parseCookies(request).pro18_admin;
    if (!token) return null;
    const [payload, signature] = token.split('.');
    if (!payload || !signature || !safeEqual(signature, hmac(payload))) return null;
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return parsed.exp > Date.now() ? parsed : null;
  } catch {
    return null;
  }
}

function csrfFor(session) {
  return hmac(`csrf:${session.nonce}`);
}

function requireAdmin(request, response, next) {
  const session = readAdminSession(request);
  if (!session) return response.status(401).json({ error: 'נדרשת התחברות מנהל' });
  request.adminSession = session;
  next();
}

function requireCsrf(request, response, next) {
  if (!safeEqual(request.headers['x-csrf-token'] || '', csrfFor(request.adminSession))) {
    return response.status(403).json({ error: 'בקשה לא מאומתת' });
  }
  next();
}

const fulfillOrderTransaction = db.transaction((orderId, preferredInventoryId, manualUrl) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) throw new Error('Order not found');

  const quantity = Math.max(1, Number(order.quantity) || 1);
  const existingCount = db.prepare('SELECT COUNT(*) AS count FROM order_redemptions WHERE order_id = ?').get(orderId).count;

  if (existingCount >= quantity) {
    const firstInventory = db.prepare(`
      SELECT il.*
      FROM order_redemptions redemption
      JOIN inventory_links il ON il.id = redemption.inventory_link_id
      WHERE redemption.order_id = ?
      ORDER BY redemption.position ASC
      LIMIT 1
    `).get(orderId);
    return {
      order,
      inventory: firstInventory,
      redemptionUrls: getOrderRedemptionUrls(orderId),
      alreadyAssigned: true,
    };
  }

  if (manualUrl && quantity === 1 && existingCount === 0) {
    const normalized = validateRedemptionUrl(manualUrl);
    const urlHash = hash(normalized);
    const existing = db.prepare('SELECT id, status FROM inventory_links WHERE url_hash = ?').get(urlHash);
    if (existing && existing.status !== 'available') throw new Error('This link is already assigned or disabled');

    let inventoryId = existing?.id || randomId();
    if (!existing) {
      db.prepare(`
        INSERT INTO inventory_links (id, encrypted_url, url_hash, status, created_at)
        VALUES (?, ?, ?, 'available', ?)
      `).run(inventoryId, encryptUrl(normalized), urlHash, now());
    }

    const inventory = db.prepare("SELECT * FROM inventory_links WHERE id = ? AND status = 'available'").get(inventoryId);
    if (!inventory) throw new Error('Manual redemption link is not available');

    const assignedAt = now();
    const assignment = db.prepare(`
      UPDATE inventory_links
      SET status = 'assigned', assigned_order_id = ?, assigned_at = ?
      WHERE id = ? AND status = 'available'
    `).run(orderId, assignedAt, inventory.id);
    if (assignment.changes !== 1) throw new Error('Redemption link was assigned concurrently');

    db.prepare(`
      INSERT INTO order_redemptions (id, order_id, inventory_link_id, position, created_at)
      VALUES (?, ?, ?, 1, ?)
    `).run(randomId(), orderId, inventory.id, assignedAt);

    db.prepare(`
      UPDATE orders
      SET status = 'fulfilled', inventory_link_id = ?, delivery_status = 'ready',
          delivery_error = NULL, fulfilled_at = ?, updated_at = ?
      WHERE id = ? AND inventory_link_id IS NULL
    `).run(inventory.id, assignedAt, assignedAt, orderId);

    return {
      order: db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId),
      inventory: db.prepare('SELECT * FROM inventory_links WHERE id = ?').get(inventory.id),
      redemptionUrls: getOrderRedemptionUrls(orderId),
      alreadyAssigned: false,
    };
  }

  const assignedInventories = [];
  const needed = quantity - existingCount;

  for (let index = 0; index < needed; index += 1) {
    const inventory = preferredInventoryId && index === 0 && existingCount === 0
      ? db.prepare("SELECT * FROM inventory_links WHERE id = ? AND status = 'available'").get(preferredInventoryId)
      : db.prepare("SELECT * FROM inventory_links WHERE status = 'available' ORDER BY created_at ASC LIMIT 1").get();

    if (!inventory) break;

    const assignedAt = now();
    const assignment = db.prepare(`
      UPDATE inventory_links
      SET status = 'assigned', assigned_order_id = ?, assigned_at = ?
      WHERE id = ? AND status = 'available'
    `).run(orderId, assignedAt, inventory.id);

    if (assignment.changes !== 1) continue;

    db.prepare(`
      INSERT INTO order_redemptions (id, order_id, inventory_link_id, position, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(randomId(), orderId, inventory.id, existingCount + assignedInventories.length + 1, assignedAt);

    assignedInventories.push(inventory);
  }

  const totalAssigned = existingCount + assignedInventories.length;
  const redemptionUrls = getOrderRedemptionUrls(orderId);

  if (totalAssigned >= quantity) {
    const firstLinkId = db.prepare(`
      SELECT inventory_link_id FROM order_redemptions
      WHERE order_id = ? ORDER BY position ASC LIMIT 1
    `).get(orderId).inventory_link_id;
    const assignedAt = now();
    db.prepare(`
      UPDATE orders
      SET status = 'fulfilled', inventory_link_id = ?, delivery_status = 'ready',
          delivery_error = NULL, fulfilled_at = ?, updated_at = ?
      WHERE id = ?
    `).run(firstLinkId, assignedAt, assignedAt, orderId);
  } else if (totalAssigned === 0) {
    db.prepare(`
      UPDATE orders
      SET status = 'paid_awaiting_stock', delivery_status = 'awaiting_stock',
          delivery_error = 'No available redemption links', updated_at = ?
      WHERE id = ?
    `).run(now(), orderId);
  } else {
    db.prepare(`
      UPDATE orders
      SET status = 'paid_awaiting_stock', delivery_status = 'awaiting_stock',
          delivery_error = ?, updated_at = ?
      WHERE id = ?
    `).run(`Assigned ${totalAssigned}/${quantity} links`, now(), orderId);
  }

  const firstInventory = assignedInventories[0] || db.prepare(`
    SELECT il.*
    FROM order_redemptions redemption
    JOIN inventory_links il ON il.id = redemption.inventory_link_id
    WHERE redemption.order_id = ?
    ORDER BY redemption.position ASC
    LIMIT 1
  `).get(orderId);

  return {
    order: db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId),
    inventory: firstInventory || null,
    redemptionUrls,
    alreadyAssigned: false,
  };
});

function fulfillOrder(orderId, options = {}) {
  return fulfillOrderTransaction.immediate(
    orderId,
    options.preferredInventoryId || null,
    options.manualUrl || null
  );
}

async function sendEmail({ to, subject, html }) {
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM || !to) return false;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: process.env.EMAIL_FROM, to: [to], subject, html }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Email provider returned ${response.status}`);
  return true;
}

async function notifyOwner(title, details) {
  const text = `${title}\n${details}`;
  const jobs = [];

  if (process.env.OWNER_EMAIL) {
    jobs.push(sendEmail({
      to: process.env.OWNER_EMAIL,
      subject: title,
      html: `<div dir="rtl" style="font-family:Arial,sans-serif"><h2>${escapeHtml(title)}</h2><p>${escapeHtml(details).replace(/\n/g, '<br>')}</p></div>`,
    }));
  }

  if (process.env.OWNER_NOTIFICATION_WEBHOOK_URL) {
    jobs.push(fetch(process.env.OWNER_NOTIFICATION_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, title, details }),
      signal: AbortSignal.timeout(10000),
    }).then((response) => {
      if (!response.ok) throw new Error(`Owner webhook returned ${response.status}`);
    }));
  }

  await Promise.allSettled(jobs);
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;',
  }[character]));
}

async function deliverOrder(order) {
  const redemptionUrls = getOrderRedemptionUrls(order.id);
  if (!redemptionUrls.length && order.inventory_link_id) {
    const inventory = db.prepare('SELECT encrypted_url FROM inventory_links WHERE id = ?').get(order.inventory_link_id);
    if (inventory) redemptionUrls.push(decryptUrl(inventory.encrypted_url));
  }
  if (!redemptionUrls.length) return false;

  let delivered = false;
  if (order.customer_email) {
    try {
      const linksHtml = redemptionUrls.map((url, index) => `
        <p style="margin:16px 0">
          <a href="${escapeHtml(url)}" style="display:inline-block;background:#10b981;color:#052e2b;padding:14px 24px;border-radius:12px;text-decoration:none;font-weight:bold">
            ${redemptionUrls.length > 1 ? `פתיחת קישור מימוש ${index + 1}` : 'פתיחת קישור המימוש'}
          </a>
        </p>
      `).join('');

      delivered = await sendEmail({
        to: order.customer_email,
        subject: redemptionUrls.length > 1
          ? `קישורי המימוש שלך ל־Google AI Pro (${redemptionUrls.length})`
          : 'קישור המימוש שלך ל־Google AI Pro',
        html: `
          <div dir="rtl" style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#0f172a">
            <h1>התשלום אושר — הקישורים שלך מוכנים</h1>
            <p>לחצו על הכפתורים כדי לפתוח את קישורי המימוש של Google.</p>
            ${linksHtml}
            <p style="font-size:12px;color:#64748b">כל קישור מיועד להפעלה אחת. אין להעביר אותם לאחרים.</p>
          </div>`,
      });
    } catch (error) {
      db.prepare(`
        UPDATE orders SET delivery_status = 'email_failed', delivery_error = ?, updated_at = ? WHERE id = ?
      `).run(error.message, now(), order.id);
      await notifyOwner('Pro18: מסירת אימייל נכשלה', `הזמנה ${order.public_id}\n${error.message}`);
      return false;
    }
  }

  db.prepare(`
    UPDATE orders SET delivery_status = ?, delivery_error = NULL, updated_at = ? WHERE id = ?
  `).run(delivered ? 'emailed' : 'ready', now(), order.id);
  return delivered;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const contentSecurityPolicy = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
  imgSrc: ["'self'", 'data:'],
  connectSrc: ["'self'"],
  frameAncestors: ["'none'"],
};

if (META_PIXEL_ID) {
  contentSecurityPolicy.scriptSrc.push('https://connect.facebook.net');
  contentSecurityPolicy.connectSrc.push('https://www.facebook.com', 'https://connect.facebook.net');
  contentSecurityPolicy.imgSrc.push('https://www.facebook.com');
}

app.use(helmet({
  contentSecurityPolicy: { directives: contentSecurityPolicy },
  crossOriginEmbedderPolicy: false,
}));

const apiLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false });
const checkoutLimiter = rateLimit({ windowMs: 10 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 8, standardHeaders: true, legacyHeaders: false });

app.get('/health', (request, response) => {
  const inventory = db.prepare("SELECT COUNT(*) AS count FROM inventory_links WHERE status = 'available'").get().count;
  response.json({ ok: true, inventoryAvailable: inventory, timestamp: now() });
});

app.post('/api/webhooks/clearo', express.raw({ type: 'application/json', limit: '256kb' }), async (request, response) => {
  try {
    if (!CLEARO_WEBHOOK_SECRET) return response.status(503).json({ error: 'Webhook is not configured' });
    const body = request.body;
    const supplied = String(request.headers['x-clearo-signature'] || '').replace(/^sha256=/, '');
    const expected = crypto.createHmac('sha256', CLEARO_WEBHOOK_SECRET).update(body).digest('hex');
    if (!safeEqual(supplied, expected)) return response.status(401).json({ error: 'Invalid signature' });

    const payloadHash = hash(body);
    const payload = JSON.parse(body.toString('utf8'));
    const eventName = payload.event;
    const data = payload.data || {};
    const existingEvent = db.prepare('SELECT * FROM webhook_events WHERE payload_hash = ?').get(payloadHash);

    let order = db.prepare(`
      SELECT * FROM orders
      WHERE payment_link_id = ? OR transaction_id = ?
      ORDER BY created_at DESC LIMIT 1
    `).get(data.payment_link_id || '', data.transaction_id || '');

    if (existingEvent) {
      if (order && ['confirmed', 'paid_awaiting_stock'].includes(order.status)) {
        const result = fulfillOrder(order.id);
        if (result.redemptionUrls?.length) await deliverOrder(result.order);
      }
      return response.json({ received: true, duplicate: true });
    }

    if (!order) {
      db.prepare(`
        INSERT INTO webhook_events (id, payload_hash, event_name, transaction_id, received_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(randomId(), payloadHash, eventName || 'unknown', data.transaction_id || null, now());
      await notifyOwner('Pro18: Webhook ללא הזמנה', `${eventName || 'unknown'}\n${data.transaction_id || 'ללא מזהה עסקה'}`);
      return response.status(202).json({ received: true, matched: false });
    }

    const timestamp = now();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO webhook_events (id, payload_hash, event_name, transaction_id, order_id, received_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(randomId(), payloadHash, eventName, data.transaction_id || null, order.id, timestamp);

      if (eventName === 'payment.confirmed') {
        const amountMatches = Math.abs(Number(data.amount) - Number(order.amount)) < 0.001;
        const currencyMatches = String(data.currency || '').toUpperCase() === order.currency;
        if (!amountMatches || !currencyMatches) {
          db.prepare(`
            UPDATE orders SET status = 'manual_review', transaction_id = COALESCE(transaction_id, ?),
              customer_email = COALESCE(?, customer_email),
              delivery_error = 'Payment amount or currency mismatch', updated_at = ?
            WHERE id = ?
          `).run(data.transaction_id || null, data.customer_email || null, timestamp, order.id);
        } else if (order.status !== 'fulfilled') {
          db.prepare(`
            UPDATE orders SET status = 'confirmed', transaction_id = COALESCE(transaction_id, ?),
              customer_email = COALESCE(?, customer_email),
              customer_phone = COALESCE(?, customer_phone),
              paid_at = COALESCE(paid_at, ?), updated_at = ?
            WHERE id = ?
          `).run(
            data.transaction_id || null,
            data.customer_email || null,
            data.customer_phone || null,
            timestamp,
            timestamp,
            order.id
          );
        }
      } else if (eventName === 'payment.failed' && order.status !== 'fulfilled') {
        db.prepare("UPDATE orders SET status = 'failed', updated_at = ? WHERE id = ?").run(timestamp, order.id);
      } else if (eventName === 'payment.cancelled' && order.status !== 'fulfilled') {
        db.prepare("UPDATE orders SET status = 'cancelled', updated_at = ? WHERE id = ?").run(timestamp, order.id);
      }
    })();

    order = db.prepare('SELECT * FROM orders WHERE id = ?').get(order.id);

    if (eventName === 'payment.confirmed' && order.status === 'confirmed') {
      const result = fulfillOrder(order.id);
      if (result.redemptionUrls?.length) {
        await deliverOrder(result.order);
        await notifyOwner('Pro18: הזמנה חדשה הושלמה', `הזמנה ${order.public_id}\nכמות: ${order.quantity || 1}\nסכום: ${order.amount} ${order.currency}`);
      } else {
        await notifyOwner('Pro18: התשלום אושר — המלאי ריק', `הזמנה ${order.public_id} ממתינה למסירה ידנית`);
      }
    } else if (order.status === 'manual_review') {
      await notifyOwner('Pro18: עסקה דורשת בדיקה ידנית', `הזמנה ${order.public_id}\nאי התאמה בסכום או במטבע`);
    } else if (eventName === 'payment.failed' || eventName === 'payment.cancelled') {
      await notifyOwner(`Pro18: ${eventName === 'payment.failed' ? 'תשלום נכשל' : 'תשלום בוטל'}`, `הזמנה ${order.public_id}`);
    }

    response.json({ received: true });
  } catch (error) {
    console.error('Clearo webhook processing failed:', error.message);
    response.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.use(express.json({ limit: '256kb' }));
app.use('/api', apiLimiter);

app.get('/api/pricing', (request, response) => {
  response.json({
    unitPrice: CLEARO_AMOUNT,
    currency: CLEARO_CURRENCY,
    tiers: [1, 2, 3].map((quantity) => {
      const pricing = bundlePricing(quantity);
      return {
        quantity: pricing.quantity,
        unitPrice: pricing.unitPrice,
        total: pricing.total,
        discountPercent: pricing.discountPercent,
        savings: pricing.savings,
        listTotal: pricing.listTotal,
        currency: pricing.currency,
      };
    }),
  });
});

app.post('/api/checkout', checkoutLimiter, async (request, response) => {
  const pricing = bundlePricing(request.body?.quantity);
  const publicId = randomId();
  const accessToken = crypto.randomBytes(24).toString('base64url');
  const orderId = randomId();
  const timestamp = now();

  db.prepare(`
    INSERT INTO orders (
      id, public_id, access_token_hash, amount, currency, status,
      delivery_status, quantity, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'creating_checkout', 'not_ready', ?, ?, ?)
  `).run(orderId, publicId, hash(accessToken), pricing.paymentTotal, CLEARO_CURRENCY, pricing.quantity, timestamp, timestamp);

  try {
    if (!CLEARO_API_KEY) throw new Error('Clearo API is not configured');

    const successUrl = `${PUBLIC_BASE_URL}/success?order=${encodeURIComponent(publicId)}&token=${encodeURIComponent(accessToken)}`;
    const clearoResponse = await fetch('https://clearo.top/v1/payment-links', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${CLEARO_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        amount: pricing.paymentTotal,
        currency: CLEARO_CURRENCY,
        description: pricing.quantity > 1
          ? `Google AI Pro x${pricing.quantity} (18 months)`
          : 'Google AI Pro - 18 months',
        webhook_url: `${PUBLIC_BASE_URL}/api/webhooks/clearo`,
        success_url: successUrl,
        redirect_url: successUrl,
        failure_url: `${PUBLIC_BASE_URL}/failed?order=${encodeURIComponent(publicId)}`,
        cancel_url: `${PUBLIC_BASE_URL}/cancelled?order=${encodeURIComponent(publicId)}`,
      }),
      signal: AbortSignal.timeout(15000),
    });

    const result = await clearoResponse.json().catch(() => ({}));
    if (!clearoResponse.ok || !result.success || !result.data?.url) {
      throw new Error(result.error?.message || `Clearo returned ${clearoResponse.status}`);
    }

    db.prepare(`
      UPDATE orders SET status = 'pending', payment_link_id = ?, payment_link_slug = ?,
        payment_url = ?, updated_at = ? WHERE id = ?
    `).run(result.data.id, result.data.slug || null, result.data.url, now(), orderId);

    response.status(201).json({
      checkoutUrl: result.data.url,
      orderId: publicId,
      token: accessToken,
      quantity: pricing.quantity,
      total: pricing.total,
      savings: pricing.savings,
    });
  } catch (error) {
    db.prepare(`
      UPDATE orders SET status = 'checkout_error', delivery_error = ?, updated_at = ? WHERE id = ?
    `).run(error.message, now(), orderId);
    console.error('Checkout creation failed:', error.message);
    response.status(502).json({ error: 'לא ניתן לפתוח את התשלום כרגע. נסו שוב בעוד רגע.' });
  }
});

app.get('/api/orders/:publicId', (request, response) => {
  const token = String(request.query.token || '');
  const order = db.prepare('SELECT * FROM orders WHERE public_id = ?').get(request.params.publicId);
  if (!order || !safeEqual(hash(token), order.access_token_hash)) {
    return response.status(404).json({ error: 'ההזמנה לא נמצאה' });
  }

  const result = {
    id: order.public_id,
    status: order.status,
    amount: order.amount,
    total: Math.round(order.amount * (1 + PAYMENT_SURCHARGE_PERCENT / 100) * 100) / 100,
    currency: order.currency,
    quantity: order.quantity || 1,
    deliveryStatus: order.delivery_status,
  };

  const redemptionUrls = getOrderRedemptionUrls(order.id);
  if (!redemptionUrls.length && order.status === 'fulfilled' && order.inventory_link_id) {
    const inventory = db.prepare('SELECT encrypted_url FROM inventory_links WHERE id = ?').get(order.inventory_link_id);
    if (inventory) redemptionUrls.push(decryptUrl(inventory.encrypted_url));
  }

  if (order.status === 'fulfilled' && redemptionUrls.length) {
    result.redemptionUrls = redemptionUrls;
    result.redemptionUrl = redemptionUrls[0];
  }

  response.json(result);
});

app.post('/api/admin/login', loginLimiter, (request, response) => {
  if (!ADMIN_PASSWORD || !safeEqual(request.body?.password || '', ADMIN_PASSWORD)) {
    return response.status(401).json({ error: 'סיסמה שגויה' });
  }

  const token = createAdminSession();
  response.setHeader('Set-Cookie', [
    `pro18_admin=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800${IS_PRODUCTION ? '; Secure' : ''}`,
  ]);
  const session = readAdminSession({ headers: { cookie: `pro18_admin=${token}` } });
  response.json({ ok: true, csrfToken: csrfFor(session) });
});

app.get('/api/admin/me', requireAdmin, (request, response) => {
  response.json({ authenticated: true, csrfToken: csrfFor(request.adminSession) });
});

app.post('/api/admin/logout', requireAdmin, requireCsrf, (request, response) => {
  response.setHeader('Set-Cookie', 'pro18_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  response.json({ ok: true });
});

app.get('/api/admin/summary', requireAdmin, (request, response) => {
  const inventory = db.prepare(`
    SELECT status, COUNT(*) AS count FROM inventory_links GROUP BY status
  `).all();
  const orders = db.prepare(`
    SELECT status, COUNT(*) AS count FROM orders GROUP BY status
  `).all();
  const revenue = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) AS total
    FROM orders WHERE status IN ('confirmed', 'fulfilled', 'paid_awaiting_stock')
  `).get().total;
  response.json({ inventory, orders, revenue, currency: CLEARO_CURRENCY });
});

app.get('/api/admin/orders', requireAdmin, (request, response) => {
  const status = String(request.query.status || '');
  const orders = status
    ? db.prepare('SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC LIMIT 200').all(status)
    : db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200').all();

  response.json(orders.map((order) => {
    const redemptionUrls = getOrderRedemptionUrls(order.id);
    if (!redemptionUrls.length && order.inventory_link_id) {
      const inventory = db.prepare('SELECT encrypted_url FROM inventory_links WHERE id = ?').get(order.inventory_link_id);
      if (inventory) redemptionUrls.push(decryptUrl(inventory.encrypted_url));
    }
    return {
      id: order.id,
      publicId: order.public_id,
      status: order.status,
      amount: order.amount,
      currency: order.currency,
      quantity: order.quantity || 1,
      customerEmail: order.customer_email,
      transactionId: order.transaction_id,
      deliveryStatus: order.delivery_status,
      deliveryError: order.delivery_error,
      redemptionUrl: redemptionUrls[0] || null,
      redemptionUrls,
      createdAt: order.created_at,
      paidAt: order.paid_at,
      fulfilledAt: order.fulfilled_at,
    };
  }));
});

app.get('/api/admin/inventory', requireAdmin, (request, response) => {
  const links = db.prepare(`
    SELECT id, encrypted_url, status, assigned_order_id, created_at, assigned_at
    FROM inventory_links ORDER BY created_at DESC LIMIT 500
  `).all();
  response.json(links.map((item) => ({
    id: item.id,
    url: decryptUrl(item.encrypted_url),
    status: item.status,
    assignedOrderId: item.assigned_order_id,
    createdAt: item.created_at,
    assignedAt: item.assigned_at,
  })));
});

app.post('/api/admin/inventory', requireAdmin, requireCsrf, (request, response) => {
  try {
    const submitted = Array.isArray(request.body?.links)
      ? request.body.links
      : String(request.body?.links || '').split(/\r?\n/);
    const links = [...new Set(submitted.map((item) => String(item).trim()).filter(Boolean))];
    if (!links.length || links.length > 500) {
      return response.status(400).json({ error: 'יש להזין בין 1 ל־500 קישורים' });
    }

    const insert = db.prepare(`
      INSERT OR IGNORE INTO inventory_links (id, encrypted_url, url_hash, status, created_at)
      VALUES (?, ?, ?, 'available', ?)
    `);
    let added = 0;
    db.transaction(() => {
      for (const rawUrl of links) {
        const url = validateRedemptionUrl(rawUrl);
        added += insert.run(randomId(), encryptUrl(url), hash(url), now()).changes;
      }
    })();
    response.status(201).json({ added, duplicates: links.length - added });
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

app.delete('/api/admin/inventory/:id', requireAdmin, requireCsrf, (request, response) => {
  const result = db.prepare(`
    UPDATE inventory_links SET status = 'disabled'
    WHERE id = ? AND status = 'available'
  `).run(request.params.id);
  if (!result.changes) return response.status(409).json({ error: 'ניתן להשבית רק קישור פנוי' });
  response.json({ ok: true });
});

app.post('/api/admin/orders/:id/deliver', requireAdmin, requireCsrf, async (request, response) => {
  try {
    const result = fulfillOrder(request.params.id, {
      preferredInventoryId: request.body?.inventoryId || null,
      manualUrl: request.body?.redemptionUrl || null,
    });
    if (!result.inventory) return response.status(409).json({ error: 'אין קישור פנוי במלאי' });
    await deliverOrder(result.order);
    await notifyOwner('Pro18: מסירה ידנית הושלמה', `הזמנה ${result.order.public_id}`);
    response.json({ ok: true, redemptionUrl: decryptUrl(result.inventory.encrypted_url) });
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

app.post('/api/admin/orders/:id/resend', requireAdmin, requireCsrf, async (request, response) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(request.params.id);
  if (!order?.inventory_link_id) return response.status(404).json({ error: 'להזמנה אין קישור שהוקצה' });
  const inventory = db.prepare('SELECT * FROM inventory_links WHERE id = ?').get(order.inventory_link_id);
  const delivered = await deliverOrder(order);
  response.json({ ok: true, emailed: delivered });
});

const FAVICON_FILES = {
  '/favicon.ico': 'favicon.ico',
  '/favicon.svg': 'favicon.svg',
  '/favicon-16x16.png': 'favicon-16x16.png',
  '/favicon-32x32.png': 'favicon-32x32.png',
  '/apple-touch-icon.png': 'apple-touch-icon.png',
};

for (const [route, file] of Object.entries(FAVICON_FILES)) {
  app.get(route, (request, response) => response.sendFile(path.join(ROOT, file)));
}

const META_PIXEL_PLACEHOLDER = '<!-- META_PIXEL -->';

function metaPixelSnippet() {
  if (!META_PIXEL_ID) return '';
  return `<!-- Meta Pixel Code -->
<script>
!function(f,b,e,v,n,t,s)
{if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];
s.parentNode.insertBefore(t,s)}(window, document,'script',
'https://connect.facebook.net/en_US/fbevents.js');
fbq('init', '${META_PIXEL_ID}');
fbq('track', 'PageView');
</script>
<noscript><img height="1" width="1" style="display:none"
src="https://www.facebook.com/tr?id=${META_PIXEL_ID}&ev=PageView&noscript=1"
/></noscript>
<!-- End Meta Pixel Code -->
<script>
window.pro18Meta={track(event,data){if(typeof fbq==='function')fbq('track',event,data||{})},purchaseOnce(orderId,data){const key='meta_purchase_'+orderId;if(sessionStorage.getItem(key))return;this.track('Purchase',data);sessionStorage.setItem(key,'1')}};
</script>`;
}

function sendPublicHtml(response, fileName) {
  const filePath = path.join(ROOT, fileName);
  if (!META_PIXEL_ID) return response.sendFile(filePath);
  const html = fs.readFileSync(filePath, 'utf8');
  if (!html.includes(META_PIXEL_PLACEHOLDER)) return response.sendFile(filePath);
  return response.type('html').send(html.replace(META_PIXEL_PLACEHOLDER, metaPixelSnippet()));
}

app.get('/', (request, response) => sendPublicHtml(response, 'index.html'));
app.get('/success', (request, response) => sendPublicHtml(response, 'success.html'));
app.get('/failed', (request, response) => sendPublicHtml(response, 'failed.html'));
app.get('/cancelled', (request, response) => sendPublicHtml(response, 'cancelled.html'));
app.get('/admin', (request, response) => response.sendFile(path.join(ROOT, 'admin.html')));
app.get('/admin.js', (request, response) => response.sendFile(path.join(ROOT, 'admin.js')));

app.use((request, response) => response.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`Pro18 server listening on ${PUBLIC_BASE_URL}`);
  if (!IS_PRODUCTION && ADMIN_PASSWORD === 'change-me') {
    console.warn('Development admin password is "change-me". Configure ADMIN_PASSWORD before deployment.');
  }
});
