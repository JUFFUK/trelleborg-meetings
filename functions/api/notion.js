const ALLOWED_ORIGINS = new Set([
  'https://meetings.trelleborg.one',
  'https://trelleborg.one',
  'https://trelleborg-meetings.pages.dev'
]);

// Only the Notion operations this app actually needs. Extend deliberately, never wildcard.
const ALLOWED_PATHS = [
  { method: 'POST', pattern: /^\/v1\/databases\/[a-f0-9-]+\/query$/ },
  { method: 'GET',  pattern: /^\/v1\/databases\/[a-f0-9-]+$/ },
  { method: 'POST', pattern: /^\/v1\/pages$/ },
  { method: 'PATCH', pattern: /^\/v1\/pages\/[a-f0-9-]+$/ }
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-App-Secret, Authorization',
    'Vary': 'Origin'
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

// ── Password hashing (Web Crypto, no dependencies) ─────────────────────────
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hashBuffer = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return saltHex + ':' + hashHex;
}

async function verifyPassword(password, stored) {
  const encoder = new TextEncoder();
  const [saltHex, hashHex] = (stored || '').split(':');
  if (!saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hashBuffer = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const newHashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHashHex === hashHex;
}

function generateToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  const arr = crypto.getRandomValues(new Uint8Array(64));
  arr.forEach(b => { token += chars[b % chars.length]; });
  return token;
}

async function getSession(request, env) {
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (!token) return null;
  const session = await env.USERS.get('session:' + token, { type: 'json' });
  if (!session || Date.now() > session.expiry) return null;
  return session;
}

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get('Origin') || '';
  const headers = corsHeaders(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...headers, 'Access-Control-Max-Age': '86400' } });
  }

  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers });
  }

  // Shared secret check, set APP_SECRET in Cloudflare Pages environment variables
  // and send the same value from the frontend as an X-App-Secret header.
  const providedSecret = request.headers.get('X-App-Secret') || '';
  if (!env.APP_SECRET || providedSecret !== env.APP_SECRET) {
    return json({ error: 'Unauthorised' }, 401, headers);
  }

  let payload;
  try {
    payload = await request.json();
  } catch (e) {
    return json({ error: 'Invalid request body' }, 400, headers);
  }

  // ── AUTH ACTIONS ──────────────────────────────────────────────────────
  // Reuses the same TRELLEBORG_USERS KV namespace as the Lead Capture app,
  // bound here as USERS, so existing accounts work immediately.
  if (payload.action) {
    if (!env.USERS) return json({ error: 'USERS KV not bound for this project yet' }, 500, headers);

    if (payload.action === 'login') {
      const { email, password } = payload;
      if (!email || !password) return json({ error: 'Email and password required' }, 400, headers);
      const user = await env.USERS.get('user:' + email.toLowerCase(), { type: 'json' });
      if (!user) return json({ error: 'Invalid email or password' }, 401, headers);
      const valid = user.passwordHash ? await verifyPassword(password, user.passwordHash) : false;
      if (!valid) return json({ error: 'Invalid email or password' }, 401, headers);
      const token = generateToken();
      const expiry = Date.now() + 8 * 60 * 60 * 1000;
      await env.USERS.put('user:' + email.toLowerCase(), JSON.stringify({
        ...user, lastLoginAt: new Date().toISOString()
      }));
      await env.USERS.put('session:' + token, JSON.stringify({
        userId: email.toLowerCase(), name: user.name, role: user.role, expiry
      }), { expirationTtl: 28800 });
      return json({ token, name: user.name, email: email.toLowerCase(), role: user.role }, 200, headers);
    }

    if (payload.action === 'verify') {
      const session = await getSession(request, env);
      if (!session) return json({ valid: false }, 401, headers);
      return json({ valid: true, name: session.name, email: session.userId, role: session.role }, 200, headers);
    }

    if (payload.action === 'logout') {
      const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
      if (token) await env.USERS.delete('session:' + token);
      return json({ success: true }, 200, headers);
    }

    if (payload.action === 'register') {
      const { email, password, name, role, adminSecret } = payload;
      if (!email || !password || !name) return json({ error: 'Name, email and password required' }, 400, headers);
      const session = await getSession(request, env);
      const isManager = session && session.role === 'manager';
      const secretOk = env.ADMIN_SECRET && adminSecret === env.ADMIN_SECRET;
      if (!isManager && !secretOk) return json({ error: 'Manager access required' }, 403, headers);
      const existing = await env.USERS.get('user:' + email.toLowerCase());
      if (existing) return json({ error: 'User already exists' }, 409, headers);
      const passwordHash = await hashPassword(password);
      await env.USERS.put('user:' + email.toLowerCase(), JSON.stringify({
        name, email: email.toLowerCase(),
        role: role === 'manager' ? 'manager' : 'team',
        passwordHash, createdAt: new Date().toISOString(),
        lastLoginAt: null
      }));
      return json({ success: true }, 200, headers);
    }

    if (payload.action === 'list-users') {
      const session = await getSession(request, env);
      if (!session) return json({ error: 'Unauthorised' }, 401, headers);
      if (session.role !== 'manager') return json({ error: 'Manager access required' }, 403, headers);
      const list = await env.USERS.list({ prefix: 'user:' });
      const users = await Promise.all(list.keys.map(k => env.USERS.get(k.name, { type: 'json' })));
      const safe = users.filter(Boolean).map(u => ({
        name: u.name, email: u.email, role: u.role,
        createdAt: u.createdAt, lastLoginAt: u.lastLoginAt || null
      }));
      safe.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      return json(safe, 200, headers);
    }

    if (payload.action === 'admin-reset-password') {
      const session = await getSession(request, env);
      if (!session) return json({ error: 'Unauthorised' }, 401, headers);
      if (session.role !== 'manager') return json({ error: 'Manager access required' }, 403, headers);
      const { email, newPassword } = payload;
      if (!email || !newPassword) return json({ error: 'Email and new password required' }, 400, headers);
      if (newPassword.length < 10) return json({ error: 'Password must be at least 10 characters' }, 400, headers);
      const user = await env.USERS.get('user:' + email.toLowerCase(), { type: 'json' });
      if (!user) return json({ error: 'User not found' }, 404, headers);
      const passwordHash = await hashPassword(newPassword);
      await env.USERS.put('user:' + email.toLowerCase(), JSON.stringify({ ...user, passwordHash }));
      return json({ success: true }, 200, headers);
    }

    if (payload.action === 'delete-user') {
      const session = await getSession(request, env);
      if (!session) return json({ error: 'Unauthorised' }, 401, headers);
      if (session.role !== 'manager') return json({ error: 'Manager access required' }, 403, headers);
      const { email } = payload;
      if (!email) return json({ error: 'Email required' }, 400, headers);
      const targetEmail = email.toLowerCase();
      if (targetEmail === session.userId) {
        return json({ error: "You can't delete your own account, ask another manager" }, 400, headers);
      }
      const user = await env.USERS.get('user:' + targetEmail);
      if (!user) return json({ error: 'User not found' }, 404, headers);
      await env.USERS.delete('user:' + targetEmail);
      // Revoke any active sessions for this user immediately, rather than waiting for TTL expiry
      const list = await env.USERS.list({ prefix: 'session:' });
      for (const key of list.keys) {
        const s = await env.USERS.get(key.name, { type: 'json' });
        if (s && s.userId === targetEmail) await env.USERS.delete(key.name);
      }
      return json({ success: true }, 200, headers);
    }

    if (payload.action === 'change-password') {
      const session = await getSession(request, env);
      if (!session) return json({ error: 'Session expired, please sign in again' }, 401, headers);
      const { currentPassword, newPassword } = payload;
      if (!currentPassword || !newPassword) return json({ error: 'Current and new password required' }, 400, headers);
      if (newPassword.length < 10) return json({ error: 'New password must be at least 10 characters' }, 400, headers);
      const user = await env.USERS.get('user:' + session.userId, { type: 'json' });
      if (!user) return json({ error: 'Account not found' }, 404, headers);
      const valid = user.passwordHash ? await verifyPassword(currentPassword, user.passwordHash) : false;
      if (!valid) return json({ error: 'Current password is incorrect' }, 401, headers);
      const passwordHash = await hashPassword(newPassword);
      await env.USERS.put('user:' + session.userId, JSON.stringify({ ...user, passwordHash }));
      return json({ success: true }, 200, headers);
    }

    return json({ error: 'Unknown action' }, 400, headers);
  }

  // ── NOTION PROXY (now requires a valid signed-in session too) ──────────
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Session expired, please sign in again' }, 401, headers);

  try {
    const { path, method, body } = payload;

    const isAllowed = ALLOWED_PATHS.some(
      rule => rule.method === (method || 'GET') && rule.pattern.test(path)
    );
    if (!isAllowed) return json({ error: 'Operation not permitted' }, 403, headers);

    const upstream = await fetch(`https://api.notion.com${path}`, {
      method: method || 'GET',
      headers: {
        'Authorization': `Bearer ${env.NOTION_TOKEN}`,
        'Content-Type': 'application/json',
        'Notion-Version': '2022-06-28',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await upstream.json();
    return json(data, upstream.status, headers);
  } catch (e) {
    return json({ error: e.message }, 500, headers);
  }
}
