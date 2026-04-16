/* =====================================================================
 * Generic Product Ordering App - Cloudflare Worker API
 * ---------------------------------------------------------------------
 * Bindings expected (wrangler.toml):
 *   - DB        : D1 database
 *   - IMAGES    : R2 bucket (product images)
 *   - IMAGES_PUBLIC_BASE (var) : public URL prefix for R2 objects
 *                 (e.g. https://images.example.com  OR
 *                  the Worker's own /img/ route if no custom domain)
 *   - ADMIN_API_TOKEN (secret) : bearer token for admin endpoints
 *                 (set via: wrangler secret put ADMIN_API_TOKEN)
 *
 * All JSON.  CORS: permissive for customer reads; admin mutations
 * require Authorization: Bearer <ADMIN_API_TOKEN> PLUS admin PIN hash
 * match so a leaked token alone isn't enough.
 * =====================================================================*/

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Admin-Pin',
  'Access-Control-Max-Age': '86400'
};

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra }
  });

const err = (message, status = 400) => json({ ok: false, error: message }, status);

// ---------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------
function normalizePhone(p) {
  if (!p) return '';
  return String(p).replace(/[^\d+]/g, '');
}

function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function randomCode(len = 6) {
  // alphanumeric, avoids ambiguous chars (0/O/1/I)
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => alphabet[b % alphabet.length]).join('');
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPin(pin, salt) {
  return sha256Hex((salt || '') + ':' + (pin || ''));
}

function orderCode() {
  const d = new Date();
  const stamp = d.toISOString().slice(2, 10).replace(/-/g, '');
  return stamp + '-' + randomCode(4);
}

// Timing-safe string compare
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------------------------------------------------------------
// Admin auth: bearer token + admin PIN
// ---------------------------------------------------------------
async function requireAdmin(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!safeEqual(token, env.ADMIN_API_TOKEN || '')) {
    return { ok: false, resp: err('Unauthorized', 401) };
  }
  const pin = req.headers.get('X-Admin-Pin') || '';
  if (!pin) return { ok: false, resp: err('Admin PIN required', 401) };

  const hashRow = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind('admin_pin_hash').first();
  const saltRow = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind('admin_pin_salt').first();
  const storedHash = hashRow ? hashRow.value : '';
  const storedSalt = saltRow ? saltRow.value : '';
  if (!storedHash) return { ok: false, resp: err('Admin PIN not configured', 401) };
  const candidate = await hashPin(pin, storedSalt);
  if (!safeEqual(candidate, storedHash)) return { ok: false, resp: err('Invalid admin PIN', 401) };
  return { ok: true };
}

// ---------------------------------------------------------------
// Router
// ---------------------------------------------------------------
export default {
  async fetch(req, env, ctx) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    try {
      // Public read-only
      if (req.method === 'GET' && path === '/')             return json({ ok: true, service: 'generic-order-api' });
      if (req.method === 'GET' && path === '/api/menu')     return getMenu(env);
      if (req.method === 'GET' && path === '/api/settings') return getPublicSettings(env);
      if (req.method === 'GET' && path === '/api/verify')   return verifyCustomer(url, env);
      if (req.method === 'GET' && path === '/api/orders')   return getOrdersForCustomer(url, env);

      // Customer writes
      if (req.method === 'POST' && path === '/api/orders')       return createOrder(req, env);
      if (req.method === 'POST' && path === '/api/payment')      return claimPayment(req, env);
      if (req.method === 'POST' && path === '/api/cancel')       return cancelOrder(req, env);
      if (req.method === 'POST' && path === '/api/pin-change')   return changePin(req, env);
      if (req.method === 'POST' && path === '/api/pin-reset')    return useResetToken(req, env);

      // Public image passthrough (optional, only if IMAGES_PUBLIC_BASE unset)
      if (req.method === 'GET' && path.startsWith('/img/')) return serveImage(path, env);

      // --- Admin endpoints (require bearer + admin PIN) ---
      const adminMatch = path.startsWith('/api/admin/');
      if (adminMatch) {
        const auth = await requireAdmin(req, env);
        if (!auth.ok) return auth.resp;

        if (req.method === 'GET'  && path === '/api/admin/orders')     return adminListOrders(url, env);
        if (req.method === 'POST' && path === '/api/admin/notify')     return adminMarkNotified(req, env);
        if (req.method === 'POST' && path === '/api/admin/order-status')return adminSetOrderStatus(req, env);

        if (req.method === 'GET'  && path === '/api/admin/customers')  return adminListCustomers(env);
        if (req.method === 'POST' && path === '/api/admin/customers')  return adminUpsertCustomer(req, env);
        if (req.method === 'POST' && path === '/api/admin/pin-reset')  return adminIssueResetToken(req, env);

        if (req.method === 'GET'  && path === '/api/admin/products')   return adminListProducts(env);
        if (req.method === 'POST' && path === '/api/admin/products')   return adminUpsertProduct(req, env);
        if (req.method === 'POST' && path === '/api/admin/products/delete') return adminDeleteProduct(req, env);

        if (req.method === 'GET'  && path === '/api/admin/categories') return adminListCategories(env);
        if (req.method === 'POST' && path === '/api/admin/categories') return adminUpsertCategory(req, env);
        if (req.method === 'POST' && path === '/api/admin/categories/delete') return adminDeleteCategory(req, env);

        if (req.method === 'POST' && path === '/api/admin/settings')   return adminSaveSettings(req, env);
        if (req.method === 'POST' && path === '/api/admin/admin-pin')  return adminSetAdminPin(req, env);

        if (req.method === 'POST' && path === '/api/admin/image-upload') return adminImageUpload(req, env);
        if (req.method === 'POST' && path === '/api/admin/image-delete') return adminImageDelete(req, env);
      }

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err('Server error: ' + (e.message || String(e)), 500);
    }
  }
};

// =====================================================================
// Public endpoints
// =====================================================================

async function getPublicSettings(env) {
  const { results } = await env.DB.prepare(
    "SELECT key, value FROM settings WHERE key NOT LIKE 'admin_pin%'"
  ).all();
  const out = {};
  for (const r of results) out[r.key] = r.value;
  return json({ ok: true, settings: out });
}

async function getMenu(env) {
  const cats = (await env.DB.prepare(
    "SELECT id, name, emoji, sort_order FROM categories ORDER BY sort_order, name"
  ).all()).results;

  const prods = (await env.DB.prepare(`
    SELECT id, category_id, name, description, unit, price,
           image_key, image_url, in_stock, sort_order
      FROM products
     ORDER BY sort_order, name
  `).all()).results;

  const baseRow = await env.DB.prepare("SELECT value FROM settings WHERE key='images_public_base'").first();
  const publicBase = (baseRow && baseRow.value) || env.IMAGES_PUBLIC_BASE || '';

  for (const p of prods) {
    if (!p.image_url && p.image_key && publicBase) {
      p.image_url = publicBase.replace(/\/$/, '') + '/' + p.image_key.replace(/^\//, '');
    }
  }
  return json({ ok: true, categories: cats, products: prods });
}

async function verifyCustomer(url, env) {
  const phone = normalizePhone(url.searchParams.get('phone'));
  const pin   = (url.searchParams.get('pin') || '').trim();
  if (!phone || !pin) return err('phone and pin required');

  const c = await env.DB.prepare(
    "SELECT id, name, phone, pin_hash, pin_salt FROM customers WHERE phone = ?"
  ).bind(phone).first();

  if (!c)                return err('Phone not registered', 403);
  if (!c.pin_hash)       return err('PIN not set. Ask admin to issue a reset code.', 403);

  const candidate = await hashPin(pin, c.pin_salt);
  if (!safeEqual(candidate, c.pin_hash)) return err('Invalid PIN', 403);
  return json({ ok: true, customer: { id: c.id, name: c.name, phone: c.phone } });
}

async function getOrdersForCustomer(url, env) {
  const phone = normalizePhone(url.searchParams.get('phone'));
  const pin   = (url.searchParams.get('pin') || '').trim();
  if (!phone || !pin) return err('phone and pin required');

  const c = await env.DB.prepare(
    "SELECT id, pin_hash, pin_salt FROM customers WHERE phone = ?"
  ).bind(phone).first();
  if (!c) return err('Phone not registered', 403);
  const candidate = await hashPin(pin, c.pin_salt);
  if (!safeEqual(candidate, c.pin_hash)) return err('Invalid PIN', 403);

  const orders = (await env.DB.prepare(`
    SELECT id, order_code, total_amount, payment_status, payment_method, payment_ref,
           order_status, notified, notes, created_at, updated_at
      FROM orders
     WHERE customer_id = ?
     ORDER BY created_at DESC
     LIMIT 50
  `).bind(c.id).all()).results;

  const orderIds = orders.map(o => o.id);
  let items = [];
  if (orderIds.length) {
    const placeholders = orderIds.map(() => '?').join(',');
    items = (await env.DB.prepare(
      `SELECT order_id, product_name, unit, unit_price, quantity, line_total
         FROM order_items WHERE order_id IN (${placeholders})`
    ).bind(...orderIds).all()).results;
  }
  const byOrder = {};
  for (const it of items) (byOrder[it.order_id] ||= []).push(it);
  for (const o of orders) o.items = byOrder[o.id] || [];

  return json({ ok: true, orders });
}

// ---------------------------------------------------------------
// Customer writes
// ---------------------------------------------------------------
async function createOrder(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone, pin, items, notes } = body;
  if (!phone || !pin || !Array.isArray(items) || items.length === 0) {
    return err('phone, pin and items required');
  }
  const openRow = await env.DB.prepare("SELECT value FROM settings WHERE key='ordering_open'").first();
  if (openRow && openRow.value === '0') return err('Ordering is currently closed', 403);

  const ph = normalizePhone(phone);
  const c = await env.DB.prepare(
    "SELECT id, name, phone, pin_hash, pin_salt FROM customers WHERE phone = ?"
  ).bind(ph).first();
  if (!c) return err('Phone not registered', 403);
  const candidate = await hashPin(pin, c.pin_salt);
  if (!safeEqual(candidate, c.pin_hash)) return err('Invalid PIN', 403);

  // Validate products + compute totals from DB prices (do NOT trust client)
  const productIds = items.map(i => Number(i.product_id)).filter(Boolean);
  if (!productIds.length) return err('No valid product_id in items');
  const placeholders = productIds.map(() => '?').join(',');
  const rows = (await env.DB.prepare(
    `SELECT id, name, unit, price, in_stock FROM products WHERE id IN (${placeholders})`
  ).bind(...productIds).all()).results;
  const byId = {};
  for (const r of rows) byId[r.id] = r;

  const lines = [];
  let total = 0;
  for (const it of items) {
    const p = byId[Number(it.product_id)];
    if (!p) return err('Unknown product: ' + it.product_id);
    if (!p.in_stock) return err('Out of stock: ' + p.name);
    const qty = Number(it.quantity || 0);
    if (!(qty > 0)) continue;
    const lineTotal = Math.round(qty * p.price * 100) / 100;
    total += lineTotal;
    lines.push({ product_id: p.id, product_name: p.name, unit: p.unit, unit_price: p.price, quantity: qty, line_total: lineTotal });
  }
  if (!lines.length) return err('Order is empty');
  total = Math.round(total * 100) / 100;

  const code = orderCode();
  const res = await env.DB.prepare(
    `INSERT INTO orders (order_code, customer_id, customer_name, customer_phone, total_amount, notes)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(code, c.id, c.name || '', c.phone, total, notes || '').run();
  const orderId = res.meta.last_row_id;

  for (const l of lines) {
    await env.DB.prepare(
      `INSERT INTO order_items (order_id, product_id, product_name, unit, unit_price, quantity, line_total)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(orderId, l.product_id, l.product_name, l.unit, l.unit_price, l.quantity, l.line_total).run();
  }

  return json({ ok: true, order: { id: orderId, order_code: code, total_amount: total, items: lines } });
}

async function claimPayment(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone, pin, order_id, payment_method, payment_ref } = body;
  if (!phone || !pin || !order_id) return err('phone, pin, order_id required');
  const c = await authCustomer(env, phone, pin);
  if (!c.ok) return c.resp;

  await env.DB.prepare(
    `UPDATE orders SET payment_status='paid', payment_method=?, payment_ref=?, updated_at=datetime('now')
     WHERE id = ? AND customer_id = ?`
  ).bind(payment_method || '', payment_ref || '', order_id, c.customer.id).run();
  return json({ ok: true });
}

async function cancelOrder(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone, pin, order_id } = body;
  if (!phone || !pin || !order_id) return err('phone, pin, order_id required');
  const c = await authCustomer(env, phone, pin);
  if (!c.ok) return c.resp;

  const o = await env.DB.prepare(
    "SELECT order_status FROM orders WHERE id = ? AND customer_id = ?"
  ).bind(order_id, c.customer.id).first();
  if (!o) return err('Order not found', 404);
  if (o.order_status === 'delivered') return err('Already delivered; cannot cancel');
  await env.DB.prepare(
    "UPDATE orders SET order_status='cancelled', updated_at=datetime('now') WHERE id = ?"
  ).bind(order_id).run();
  return json({ ok: true });
}

async function changePin(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone, old_pin, new_pin } = body;
  if (!phone || !old_pin || !new_pin) return err('phone, old_pin, new_pin required');
  if (String(new_pin).length < 4) return err('New PIN must be at least 4 chars');
  const c = await authCustomer(env, phone, old_pin);
  if (!c.ok) return c.resp;

  const salt = randomHex(8);
  const hash = await hashPin(new_pin, salt);
  await env.DB.prepare(
    "UPDATE customers SET pin_hash=?, pin_salt=?, reset_token=NULL, reset_expires_at=NULL, updated_at=datetime('now') WHERE id=?"
  ).bind(hash, salt, c.customer.id).run();
  return json({ ok: true });
}

async function useResetToken(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone, reset_token, new_pin } = body;
  if (!phone || !reset_token || !new_pin) return err('phone, reset_token, new_pin required');
  if (String(new_pin).length < 4) return err('PIN must be at least 4 chars');

  const ph = normalizePhone(phone);
  const c = await env.DB.prepare(
    "SELECT id, reset_token, reset_expires_at FROM customers WHERE phone = ?"
  ).bind(ph).first();
  if (!c) return err('Phone not registered', 403);
  if (!c.reset_token) return err('No reset pending. Ask admin.', 403);

  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  if (c.reset_expires_at && c.reset_expires_at < now) return err('Reset code expired', 403);
  if (!safeEqual(String(reset_token).toUpperCase(), String(c.reset_token).toUpperCase())) {
    return err('Invalid reset code', 403);
  }

  const salt = randomHex(8);
  const hash = await hashPin(new_pin, salt);
  await env.DB.prepare(
    "UPDATE customers SET pin_hash=?, pin_salt=?, reset_token=NULL, reset_expires_at=NULL, updated_at=datetime('now') WHERE id=?"
  ).bind(hash, salt, c.id).run();
  return json({ ok: true });
}

async function authCustomer(env, phone, pin) {
  const ph = normalizePhone(phone);
  const c = await env.DB.prepare(
    "SELECT id, name, phone, pin_hash, pin_salt FROM customers WHERE phone = ?"
  ).bind(ph).first();
  if (!c) return { ok: false, resp: err('Phone not registered', 403) };
  const candidate = await hashPin(pin, c.pin_salt);
  if (!safeEqual(candidate, c.pin_hash)) return { ok: false, resp: err('Invalid PIN', 403) };
  return { ok: true, customer: c };
}

// =====================================================================
// Admin endpoints
// =====================================================================

async function adminListOrders(url, env) {
  const status = url.searchParams.get('status') || '';
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '200', 10), 500);

  let q = `SELECT o.*, c.name as customer_full_name
             FROM orders o LEFT JOIN customers c ON c.id = o.customer_id`;
  const binds = [];
  if (status) { q += ' WHERE o.order_status = ?'; binds.push(status); }
  q += ' ORDER BY o.created_at DESC LIMIT ?';
  binds.push(limit);

  const orders = (await env.DB.prepare(q).bind(...binds).all()).results;
  if (!orders.length) return json({ ok: true, orders: [] });

  const ids = orders.map(o => o.id);
  const placeholders = ids.map(() => '?').join(',');
  const items = (await env.DB.prepare(
    `SELECT order_id, product_name, unit, unit_price, quantity, line_total
       FROM order_items WHERE order_id IN (${placeholders})`
  ).bind(...ids).all()).results;
  const byOrder = {};
  for (const it of items) (byOrder[it.order_id] ||= []).push(it);
  for (const o of orders) o.items = byOrder[o.id] || [];
  return json({ ok: true, orders });
}

async function adminMarkNotified(req, env) {
  const body = await req.json().catch(() => null);
  const ids = body && Array.isArray(body.order_ids) ? body.order_ids : [];
  if (!ids.length) return err('order_ids required');
  const placeholders = ids.map(() => '?').join(',');
  await env.DB.prepare(
    `UPDATE orders SET notified=1, updated_at=datetime('now') WHERE id IN (${placeholders})`
  ).bind(...ids).run();
  return json({ ok: true, updated: ids.length });
}

async function adminSetOrderStatus(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { order_id, order_status, payment_status } = body;
  if (!order_id) return err('order_id required');
  const fields = []; const binds = [];
  if (order_status)   { fields.push('order_status = ?');   binds.push(order_status); }
  if (payment_status) { fields.push('payment_status = ?'); binds.push(payment_status); }
  if (!fields.length) return err('Nothing to update');
  binds.push(order_id);
  await env.DB.prepare(
    `UPDATE orders SET ${fields.join(', ')}, updated_at=datetime('now') WHERE id = ?`
  ).bind(...binds).run();
  return json({ ok: true });
}

async function adminListCustomers(env) {
  const rows = (await env.DB.prepare(`
    SELECT id, phone, name, notes,
           CASE WHEN pin_hash IS NOT NULL AND pin_hash <> '' THEN 1 ELSE 0 END AS has_pin,
           reset_token, reset_expires_at, created_at, updated_at
      FROM customers ORDER BY name, phone
  `).all()).results;
  return json({ ok: true, customers: rows });
}

async function adminUpsertCustomer(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { id, phone, name, notes } = body;
  const ph = normalizePhone(phone);
  if (!ph) return err('phone required');
  if (id) {
    await env.DB.prepare(
      "UPDATE customers SET phone=?, name=?, notes=?, updated_at=datetime('now') WHERE id=?"
    ).bind(ph, name || '', notes || '', id).run();
    return json({ ok: true, id });
  }
  const res = await env.DB.prepare(
    "INSERT INTO customers (phone, name, notes) VALUES (?,?,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name, notes=excluded.notes, updated_at=datetime('now')"
  ).bind(ph, name || '', notes || '').run();
  return json({ ok: true, id: res.meta.last_row_id || null });
}

async function adminIssueResetToken(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { phone } = body;
  const ph = normalizePhone(phone);
  if (!ph) return err('phone required');
  const c = await env.DB.prepare("SELECT id FROM customers WHERE phone = ?").bind(ph).first();
  if (!c) return err('Customer not found', 404);
  const token = randomCode(6);
  const expires = new Date(Date.now() + 24 * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare(
    "UPDATE customers SET reset_token=?, reset_expires_at=?, updated_at=datetime('now') WHERE id=?"
  ).bind(token, expires, c.id).run();
  await env.DB.prepare(
    "INSERT INTO admin_log (action, target, detail) VALUES ('pin-reset-token', ?, ?)"
  ).bind(ph, 'expires ' + expires).run();
  return json({ ok: true, reset_token: token, expires_at: expires });
}

// ---------------- Products / Categories ----------------
async function adminListProducts(env) {
  const rows = (await env.DB.prepare(`
    SELECT id, category_id, name, description, unit, price,
           image_key, image_url, in_stock, sort_order
      FROM products ORDER BY sort_order, name
  `).all()).results;
  return json({ ok: true, products: rows });
}

async function adminUpsertProduct(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { id, category_id, name, description, unit, price, image_key, image_url, in_stock, sort_order } = body;
  if (!name) return err('name required');
  if (id) {
    await env.DB.prepare(`
      UPDATE products SET category_id=?, name=?, description=?, unit=?, price=?,
             image_key=?, image_url=?, in_stock=?, sort_order=?, updated_at=datetime('now')
       WHERE id=?`
    ).bind(category_id || null, name, description || '', unit || 'each', Number(price || 0),
           image_key || null, image_url || null, in_stock ? 1 : 0, Number(sort_order || 100), id).run();
    return json({ ok: true, id });
  }
  const res = await env.DB.prepare(`
    INSERT INTO products (category_id, name, description, unit, price, image_key, image_url, in_stock, sort_order)
    VALUES (?,?,?,?,?,?,?,?,?)`
  ).bind(category_id || null, name, description || '', unit || 'each', Number(price || 0),
         image_key || null, image_url || null, in_stock ? 1 : 0, Number(sort_order || 100)).run();
  return json({ ok: true, id: res.meta.last_row_id });
}

async function adminDeleteProduct(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || !body.id) return err('id required');
  // also delete R2 image if key is present
  const p = await env.DB.prepare("SELECT image_key FROM products WHERE id=?").bind(body.id).first();
  if (p && p.image_key && env.IMAGES) {
    try { await env.IMAGES.delete(p.image_key); } catch (_) {}
  }
  await env.DB.prepare("DELETE FROM products WHERE id=?").bind(body.id).run();
  return json({ ok: true });
}

async function adminListCategories(env) {
  const rows = (await env.DB.prepare(
    "SELECT id, name, emoji, sort_order FROM categories ORDER BY sort_order, name"
  ).all()).results;
  return json({ ok: true, categories: rows });
}

async function adminUpsertCategory(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return err('Invalid JSON');
  const { id, name, emoji, sort_order } = body;
  if (!name) return err('name required');
  if (id) {
    await env.DB.prepare(
      "UPDATE categories SET name=?, emoji=?, sort_order=? WHERE id=?"
    ).bind(name, emoji || '', Number(sort_order || 100), id).run();
    return json({ ok: true, id });
  }
  const res = await env.DB.prepare(
    "INSERT INTO categories (name, emoji, sort_order) VALUES (?,?,?)"
  ).bind(name, emoji || '', Number(sort_order || 100)).run();
  return json({ ok: true, id: res.meta.last_row_id });
}

async function adminDeleteCategory(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || !body.id) return err('id required');
  await env.DB.prepare("DELETE FROM categories WHERE id=?").bind(body.id).run();
  return json({ ok: true });
}

// ---------------- Settings / Admin PIN ----------------
async function adminSaveSettings(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || typeof body.settings !== 'object') return err('settings object required');
  const entries = Object.entries(body.settings).filter(([k]) => !k.startsWith('admin_pin'));
  for (const [k, v] of entries) {
    await env.DB.prepare(
      "INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    ).bind(k, v == null ? '' : String(v)).run();
  }
  return json({ ok: true, updated: entries.length });
}

async function adminSetAdminPin(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || !body.new_pin) return err('new_pin required');
  if (String(body.new_pin).length < 4) return err('PIN must be at least 4 chars');
  const salt = randomHex(8);
  const hash = await hashPin(body.new_pin, salt);
  await env.DB.prepare(
    "INSERT INTO settings (key,value) VALUES ('admin_pin_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).bind(hash).run();
  await env.DB.prepare(
    "INSERT INTO settings (key,value) VALUES ('admin_pin_salt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).bind(salt).run();
  return json({ ok: true });
}

// ---------------- Images (R2) ----------------
// Admin uploads raw image bytes as body with ?ext=jpg and optional &id=<productId>
async function adminImageUpload(req, env) {
  if (!env.IMAGES) return err('R2 bucket not bound', 500);
  const url = new URL(req.url);
  const ext = (url.searchParams.get('ext') || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 4);
  const productId = url.searchParams.get('id') || randomHex(6);
  const key = `products/${productId}-${randomHex(4)}.${ext}`;
  const contentType = req.headers.get('Content-Type') || 'application/octet-stream';
  const body = await req.arrayBuffer();
  if (!body.byteLength) return err('Empty body');
  if (body.byteLength > 5 * 1024 * 1024) return err('Image too large (>5MB)');
  await env.IMAGES.put(key, body, { httpMetadata: { contentType } });

  const baseRow = await env.DB.prepare("SELECT value FROM settings WHERE key='images_public_base'").first();
  const publicBase = (baseRow && baseRow.value) || env.IMAGES_PUBLIC_BASE || '';
  const publicUrl = publicBase ? publicBase.replace(/\/$/, '') + '/' + key : `/img/${key}`;
  return json({ ok: true, image_key: key, image_url: publicUrl });
}

async function adminImageDelete(req, env) {
  if (!env.IMAGES) return err('R2 bucket not bound', 500);
  const body = await req.json().catch(() => null);
  if (!body || !body.image_key) return err('image_key required');
  await env.IMAGES.delete(body.image_key);
  return json({ ok: true });
}

async function serveImage(path, env) {
  if (!env.IMAGES) return err('R2 not bound', 404);
  const key = path.replace(/^\/img\//, '');
  const obj = await env.IMAGES.get(key);
  if (!obj) return new Response('Not found', { status: 404, headers: CORS });
  const headers = new Headers(CORS);
  headers.set('Content-Type', obj.httpMetadata?.contentType || 'application/octet-stream');
  headers.set('Cache-Control', 'public, max-age=86400');
  return new Response(obj.body, { headers });
}
