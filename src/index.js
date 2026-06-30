/**
 * Cloudflare Worker - 备忘录应用
 * 
 * 功能:
 *   - 预设用户名/密码登录 (环境变量 USERNAME / PASSWORD)
 *   - Session 令牌认证 (基于 Web Crypto HMAC，无需外部依赖)
 *   - 备忘录 CRUD (增删改查)，数据存储在 KV 命名空间 MEMOS_KV
 *   - 内嵌单页 HTML 前端
 *   - 安全增强：登录速率限制、密钥验证、常量时间签名比较、安全响应头
 *   - 第二轮加固：Cookie 解析容错、超长令牌拒绝、输入类型/长度强制、KV 绑定检查
 */

// ── 工具函数：Cookie 解析与生成 ──────────────────────────────────
function parseCookies(cookieHeader) {
  const map = {};
  if (!cookieHeader) return map;
  cookieHeader.split(';').forEach(part => {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) return;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (!key) return;
    try {
      map[key] = decodeURIComponent(val);
    } catch {
      // 忽略解码失败的 cookie 值
    }
  });
  return map;
}

function serializeCookie(name, value, options = {}) {
  let cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value);
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += '; SameSite=' + options.sameSite;
  if (options.maxAge !== undefined) cookie += '; Max-Age=' + options.maxAge;
  if (options.path) cookie += '; Path=' + options.path;
  return cookie;
}

// ── 工具函数：Session 令牌生成与验证 ────────────────────────────
// 格式: "payload:signature"  签名 = HMAC-SHA256(payload, SECRET) hex
async function hmacSha256(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
}

// 常量时间比较，防止时序攻击
function constantTimeEqual(a, b) {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  let diff = aBytes.length ^ bBytes.length;
  const minLen = Math.min(aBytes.length, bBytes.length);
  for (let i = 0; i < minLen; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

async function createSessionToken(username, secret) {
  const payload = username + ':' + Date.now();
  const sig = await hmacSha256(payload, secret);
  return payload + ':' + sig;
}

async function verifySessionToken(token, secret) {
  // 拒绝超长令牌，防止资源消耗
  if (typeof token !== 'string' || token.length > 500) return null;
  const lastColon = token.lastIndexOf(':');
  if (lastColon === -1) return null;
  const payload = token.slice(0, lastColon);
  const expectedSig = token.slice(lastColon + 1);
  const actualSig = await hmacSha256(payload, secret);
  if (!constantTimeEqual(expectedSig, actualSig)) return null;
  
  const parts = payload.split(':');
  if (parts.length < 2) return null;
  const username = parts[0];
  const timestamp = parseInt(parts[1], 10);
  // 会话有效期 24 小时
  if (Date.now() - timestamp > 24 * 60 * 60 * 1000) return null;
  // 验证用户名格式
  if (typeof username !== 'string' || username.length === 0 || username.length > 64) return null;
  if (!/^[a-zA-Z0-9_\-]+$/.test(username)) return null;
  return { username };
}

// ── KV 数据格式 ─────────────────────────────────────────────────
// Key:   memo:<id>
// Value: JSON { id, title, content, folderId?, createdAt, updatedAt }
// Key:   folder:<id>
// Value: JSON { id, name, createdAt }

function genId() {
  return crypto.randomUUID();
}

function isSecureRequest(request) {
  const url = new URL(request.url);
  return url.protocol === 'https:';
}

// ── 路由分发 ─────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    // 验证必要的环境变量和 KV 绑定是否已配置
    if (!env.USERNAME || !env.PASSWORD || !env.SESSION_SECRET) {
      return new Response('Server configuration error: missing required secrets. Please set USERNAME, PASSWORD, and SESSION_SECRET.', { status: 500 });
    }
    if (!env.MEMOS_KV) {
      return new Response('Server configuration error: KV namespace MEMOS_KV is not bound.', { status: 500 });
    }

    // 认证中间件
    const cookieHeader = request.headers.get('Cookie');
    const cookies = parseCookies(cookieHeader);
    const sessionToken = cookies['cf_memo_session'];
    let user = null;
    if (sessionToken) {
      user = await verifySessionToken(sessionToken, env.SESSION_SECRET);
    }

    // ── API 路由 ──────────────────────────────────
    if (path.startsWith('/api/')) {
      // 登录接口不需要认证
      if (path === '/api/login' && method === 'POST') {
        return handleLogin(request, env);
      }
      
      // 其他 API 需要认证
      if (!user) {
        return json({ error: 'Unauthorized' }, 401);
      }

      if (path === '/api/folders') {
        if (method === 'GET') return handleListFolders(env);
        if (method === 'POST') return handleCreateFolder(request, env);
      }
      if (path.startsWith('/api/folders/')) {
        const parts = path.slice('/api/folders/'.length).split('/');
        const folderId = parts[0];
        if (!folderId) return json({ error: 'Missing folder id' }, 400);
        if (parts.length === 1) {
          if (method === 'PUT') return handleUpdateFolder(request, folderId, env);
          if (method === 'DELETE') return handleDeleteFolder(folderId, env);
        }
      }

      // 放在 /api/memos/:id 之前，避免路由抢先匹配
      if (path.startsWith('/api/memos/') && path.endsWith('/folder')) {
        const memoId = path.slice('/api/memos/'.length, -'/folder'.length);
        if (!memoId) return json({ error: 'Missing memo id' }, 400);
        if (method === 'PUT') return handleMoveMemo(request, memoId, env);
      }

      if (path === '/api/memos') {
        if (method === 'GET') return handleListMemos(user, env);
        if (method === 'POST') return handleCreateMemo(request, env);
      }
      
      if (path.startsWith('/api/memos/')) {
        const memoId = path.slice('/api/memos/'.length);
        if (!memoId) return json({ error: 'Missing memo id' }, 400);
        if (method === 'GET') return handleGetMemo(memoId, env);
        if (method === 'PUT') return handleUpdateMemo(request, memoId, env);
        if (method === 'DELETE') return handleDeleteMemo(memoId, env);
      }

      if (path === '/api/logout' && method === 'POST') {
        return handleLogout(request);
      }

      if (path === '/api/me' && method === 'GET') {
        return json({ username: user.username });
      }

      return json({ error: 'Not Found' }, 404);
    }

    // ── 静态页面 ──────────────────────────────────
    if (method === 'GET') {
      if (!user) {
        return serveLoginPage();
      }
      return serveAppPage();
    }

    return json({ error: 'Method Not Allowed' }, 405);
  },
};

// ── 登录 / 登出 ─────────────────────────────────────────────────
async function handleLogin(request, env) {
  if (!request.headers.get('Content-Type')?.includes('application/json')) {
    return json({ error: 'Content-Type must be application/json' }, 415);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  
  const { username, password } = body;
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return json({ error: 'Username and password are required' }, 400);
  }
  // 限制输入长度，防止超大数据包
  if (username.length > 64 || password.length > 128) {
    return json({ error: 'Invalid credentials' }, 401);
  }

  // 登录速率限制 - 基于客户端 IP
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimitKey = 'ratelimit:login:' + clientIP;
  let attempts = 0;
  try {
    const rawAttempts = await env.MEMOS_KV.get(rateLimitKey);
    if (rawAttempts) attempts = parseInt(rawAttempts, 10);
  } catch { /* 获取失败时允许继续 */ }
  if (attempts >= 5) {
    return json({ error: 'Too many login attempts. Please try again later.' }, 429);
  }

  // 使用常量时间比较，并去除环境变量首尾空格（防止配置失误导致无法登录）
  const storedUser = (env.USERNAME || '').trim();
  const storedPass = (env.PASSWORD || '').trim();
  const userMatch = constantTimeEqual(username, storedUser);
  const passMatch = constantTimeEqual(password, storedPass);
  if (!userMatch || !passMatch) {
    try {
      await env.MEMOS_KV.put(rateLimitKey, String(attempts + 1), { expirationTtl: 900 });
    } catch { /* 忽略存储错误 */ }
    // 统一错误消息，避免用户枚举
    return json({ error: 'Invalid credentials' }, 401);
  }

  // 登录成功，清除速率限制计数
  try {
    await env.MEMOS_KV.delete(rateLimitKey);
  } catch { /* 忽略 */ }

  const token = await createSessionToken(username, env.SESSION_SECRET);
  const secure = isSecureRequest(request);
  const cookie = serializeCookie('cf_memo_session', token, {
    httpOnly: true,
    secure: secure,
    sameSite: 'Lax',
    maxAge: 24 * 60 * 60, // 24 小时
    path: '/',
  });

  return json({ ok: true, username }, 200, {
    'Set-Cookie': cookie,
    'Cache-Control': 'no-store',
  });
}

// 更新的 json 辅助函数，支持额外 header
function json(data, status = 200, extraHeaders = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    ...extraHeaders,
  };
  return new Response(JSON.stringify(data), { status, headers });
}

function handleLogout(request) {
  const secure = isSecureRequest(request);
  const cookie = serializeCookie('cf_memo_session', '', {
    httpOnly: true,
    secure: secure,
    sameSite: 'Lax',
    maxAge: 0,
    path: '/',
  });
  return json({ ok: true }, 200, {
    'Set-Cookie': cookie,
    'Cache-Control': 'no-store',
  });
}

// ── 备忘录 CRUD ──────────────────────────────────────────────────
async function handleListMemos(user, env) {
  const memos = [];
  let cursor;
  do {
    const list = await env.MEMOS_KV.list({ prefix: 'memo:', cursor: cursor, limit: 1000 });
    const raws = await Promise.all(list.keys.map(k => env.MEMOS_KV.get(k.name)));
    for (const raw of raws) {
      if (raw) {
        try {
          memos.push(JSON.parse(raw));
        } catch { /* 忽略损坏数据 */ }
      }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  // 按更新时间倒序
  memos.sort((a, b) => b.updatedAt - a.updatedAt);
  return json(memos, 200, { 'Cache-Control': 'public, max-age=2, s-maxage=5' });
}

async function handleCreateMemo(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  
  const { title, content, folderId } = body;
  if (folderId !== undefined && folderId !== null) {
    if (typeof folderId !== 'string' || !/^[a-zA-Z0-9_-]{1,40}$/.test(folderId)) return json({ error: 'Invalid folder id' }, 400);
    const folderExists = await env.MEMOS_KV.get('folder:' + folderId);
    if (!folderExists) return json({ error: 'Folder not found' }, 400);
  }
  if (title !== undefined && typeof title !== 'string') {
    return json({ error: 'Title must be a string' }, 400);
  }
  if (content !== undefined && typeof content !== 'string') {
    return json({ error: 'Content must be a string' }, 400);
  }
  if (!title && !content) {
    return json({ error: 'Title or content is required' }, 400);
  }
  if (title && title.length > 500) {
    return json({ error: 'Title must be 500 characters or less' }, 400);
  }
  if (content && content.length > 20000) {
    return json({ error: 'Content must be 20000 characters or less' }, 400);
  }

  const now = Date.now();
  const memo = {
    id: genId(),
    title: (title || '').trim(),
    content: (content || '').trim(),
    createdAt: now,
    updatedAt: now,
  };
  if (folderId) memo.folderId = folderId;

  await env.MEMOS_KV.put('memo:' + memo.id, JSON.stringify(memo));
  return json(memo, 201);
}

async function handleUpdateMemo(request, memoId, env) {
  // 验证 memoId 格式
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) {
    return json({ error: 'Invalid memo id' }, 400);
  }
  // 先检查是否存在
  const existing = await env.MEMOS_KV.get('memo:' + memoId);
  if (!existing) {
    return json({ error: 'Memo not found' }, 404);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }

  if (body.title !== undefined && typeof body.title !== 'string') {
    return json({ error: 'Title must be a string' }, 400);
  }
  if (body.content !== undefined && typeof body.content !== 'string') {
    return json({ error: 'Content must be a string' }, 400);
  }
  if (body.title !== undefined && body.title.length > 500) {
    return json({ error: 'Title must be 500 characters or less' }, 400);
  }
  if (body.content !== undefined && body.content.length > 20000) {
    return json({ error: 'Content must be 20000 characters or less' }, 400);
  }
  if (body.folderId !== undefined && body.folderId !== null) {
    if (typeof body.folderId !== 'string' || !/^[a-zA-Z0-9_-]{1,40}$/.test(body.folderId)) return json({ error: 'Invalid folder id' }, 400);
    const folderExists = await env.MEMOS_KV.get('folder:' + body.folderId);
    if (!folderExists) return json({ error: 'Folder not found' }, 400);
  }

  let old;
  try {
    old = JSON.parse(existing);
  } catch {
    return json({ error: 'Memo data corrupted' }, 500);
  }
  const updated = {
    ...old,
    title: body.title !== undefined ? body.title.trim() : old.title,
    content: body.content !== undefined ? body.content.trim() : old.content,
    updatedAt: Date.now(),
  };
  if (body.folderId !== undefined) {
    if (body.folderId === null) {
      delete updated.folderId;
    } else {
      updated.folderId = body.folderId;
    }
  }

  await env.MEMOS_KV.put('memo:' + memoId, JSON.stringify(updated));
  return json(updated);
}

async function handleDeleteMemo(memoId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) {
    return json({ error: 'Invalid memo id' }, 400);
  }
  const existing = await env.MEMOS_KV.get('memo:' + memoId);
  if (!existing) {
    return json({ error: 'Memo not found' }, 404);
  }
  await env.MEMOS_KV.delete('memo:' + memoId);
  return json({ ok: true });
}

async function handleGetMemo(memoId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) {
    return json({ error: 'Invalid memo id' }, 400);
  }
  const raw = await env.MEMOS_KV.get('memo:' + memoId);
  if (!raw) return json({ error: 'Memo not found' }, 404);
  try {
    const memo = JSON.parse(raw);
    return json(memo);
  } catch {
    return json({ error: 'Memo data corrupted' }, 500);
  }
}

// ── 文件夹 CRUD ──────────────────────────────────────────────────
async function handleListFolders(env) {
  const folders = [];
  let cursor;
  do {
    const list = await env.MEMOS_KV.list({ prefix: 'folder:', cursor, limit: 1000 });
    const raws = await Promise.all(list.keys.map(k => env.MEMOS_KV.get(k.name)));
    for (const raw of raws) {
      if (raw) {
        try { folders.push(JSON.parse(raw)); } catch { /* 忽略损坏数据 */ }
      }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  folders.sort((a, b) => a.createdAt - b.createdAt);
  return json(folders, 200, { 'Cache-Control': 'public, max-age=2, s-maxage=5' });
}

async function handleCreateFolder(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { name } = body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return json({ error: 'Folder name is required' }, 400);
  }
  if (name.trim().length > 50) {
    return json({ error: 'Folder name must be 50 characters or less' }, 400);
  }
  const folder = { id: genId(), name: name.trim(), createdAt: Date.now() };
  await env.MEMOS_KV.put('folder:' + folder.id, JSON.stringify(folder));
  return json(folder, 201);
}

async function handleUpdateFolder(request, folderId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(folderId)) {
    return json({ error: 'Invalid folder id' }, 400);
  }
  const existing = await env.MEMOS_KV.get('folder:' + folderId);
  if (!existing) return json({ error: 'Folder not found' }, 404);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { name } = body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return json({ error: 'Folder name is required' }, 400);
  }
  if (name.trim().length > 50) {
    return json({ error: 'Folder name must be 50 characters or less' }, 400);
  }
  let folderData;
  try {
    folderData = JSON.parse(existing);
  } catch {
    return json({ error: 'Folder data corrupted' }, 500);
  }
  const folder = { ...folderData, name: name.trim() };
  await env.MEMOS_KV.put('folder:' + folderId, JSON.stringify(folder));
  return json(folder);
}

async function handleDeleteFolder(folderId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(folderId)) {
    return json({ error: 'Invalid folder id' }, 400);
  }
  const existing = await env.MEMOS_KV.get('folder:' + folderId);
  if (!existing) return json({ error: 'Folder not found' }, 404);
  await env.MEMOS_KV.delete('folder:' + folderId);
  // 清除该分类下所有备忘录的 folderId
  let cursor;
  do {
    const list = await env.MEMOS_KV.list({ prefix: 'memo:', cursor, limit: 1000 });
    const raws = await Promise.all(list.keys.map(k => env.MEMOS_KV.get(k.name)));
    const updates = [];
    for (let i = 0; i < list.keys.length; i++) {
      const raw = raws[i];
      if (raw) {
        try {
          const memo = JSON.parse(raw);
          if (memo.folderId === folderId) {
            delete memo.folderId;
            memo.updatedAt = Date.now();
            updates.push(env.MEMOS_KV.put(list.keys[i].name, JSON.stringify(memo)));
          }
        } catch { /* 忽略损坏数据 */ }
      }
    }
    await Promise.all(updates);
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  return json({ ok: true });
}

async function handleMoveMemo(request, memoId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) return json({ error: 'Invalid memo id' }, 400);
  const existing = await env.MEMOS_KV.get('memo:' + memoId);
  if (!existing) return json({ error: 'Memo not found' }, 404);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { folderId } = body;
  if (folderId !== null && folderId !== undefined) {
    if (typeof folderId !== 'string' || !/^[a-zA-Z0-9_-]{1,40}$/.test(folderId)) return json({ error: 'Invalid folder id' }, 400);
    const folderExists = await env.MEMOS_KV.get('folder:' + folderId);
    if (!folderExists) return json({ error: 'Folder not found' }, 404);
  }
  let memo;
  try { memo = JSON.parse(existing); } catch { return json({ error: 'Memo data corrupted' }, 500); }
  if (folderId === null || folderId === undefined) {
    delete memo.folderId;
  } else {
    memo.folderId = folderId;
  }
  memo.updatedAt = Date.now();
  await env.MEMOS_KV.put('memo:' + memoId, JSON.stringify(memo));
  return json(memo);
}

// ── 安全响应头 ──────────────────────────────────────────────────
function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'none'",
    'Permissions-Policy': 'interest-cohort=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  };
}

// ── HTML 页面（纯字符串拼接，彻底消除模板字面量嵌套风险）───────

function serveLoginPage() {
  var h = [];
  h.push('<!DOCTYPE html>');
  h.push('<html lang="zh-CN">');
  h.push('<head>');
  h.push('<meta charset="UTF-8">');
  h.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
  h.push('<title>备忘录 - 登录</title>');
  h.push('<style>');
  h.push('  * { margin: 0; padding: 0; box-sizing: border-box; }');
  h.push('  body {');
  h.push('    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;');
  h.push('    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);');
  h.push('    min-height: 100vh;');
  h.push('    display: flex;');
  h.push('    align-items: center;');
  h.push('    justify-content: center;');
  h.push('  }');
  h.push('  .login-box {');
  h.push('    background: #fff;');
  h.push('    border-radius: 16px;');
  h.push('    padding: 40px 32px;');
  h.push('    width: 90%;');
  h.push('    max-width: 400px;');
  h.push('    box-shadow: 0 20px 60px rgba(0,0,0,0.15);');
  h.push('  }');
  h.push('  h1 { text-align: center; color: #333; margin-bottom: 28px; font-size: 24px; }');
  h.push('  .field { margin-bottom: 18px; }');
  h.push('  .field label { display: block; margin-bottom: 6px; color: #555; font-size: 14px; font-weight: 500; }');
  h.push('  .field input {');
  h.push('    width: 100%;');
  h.push('    padding: 12px 14px;');
  h.push('    border: 1px solid #ddd;');
  h.push('    border-radius: 8px;');
  h.push('    font-size: 15px;');
  h.push('    transition: border-color 0.2s;');
  h.push('  }');
  h.push('  .field input:focus { outline: none; border-color: #667eea; }');
  h.push('  button {');
  h.push('    width: 100%;');
  h.push('    padding: 13px;');
  h.push('    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);');
  h.push('    color: #fff;');
  h.push('    border: none;');
  h.push('    border-radius: 8px;');
  h.push('    font-size: 16px;');
  h.push('    font-weight: 600;');
  h.push('    cursor: pointer;');
  h.push('    transition: opacity 0.2s;');
  h.push('  }');
  h.push('  button:hover { opacity: 0.9; }');
  h.push('  button:active { opacity: 0.8; }');
  h.push('  .error { color: #e74c3c; text-align: center; margin-top: 12px; font-size: 14px; display: none; }');
  h.push('</style>');
  h.push('</head>');
  h.push('<body>');
  h.push('<div class="login-box">');
  h.push('  <h1>\u{1F4DD} 备忘录登录</h1>');
  h.push('  <div class="field">');
  h.push('    <label for="username">用户名</label>');
  h.push('    <input id="username" type="text" placeholder="请输入用户名" autocomplete="username" autofocus>');
  h.push('  </div>');
  h.push('  <div class="field">');
  h.push('    <label for="password">密码</label>');
  h.push('    <input id="password" type="password" placeholder="请输入密码" autocomplete="current-password">');
  h.push('  </div>');
  h.push('  <button id="loginBtn">登 录</button>');
  h.push('  <div class="error" id="error"></div>');
  h.push('</div>');
  h.push('<script>');
  h.push('(function(){');
  h.push('var errorEl = document.getElementById("error");');
  h.push('document.getElementById("loginBtn").addEventListener("click", async function(){');
  h.push('  var username = document.getElementById("username").value.trim();');
  h.push('  var password = document.getElementById("password").value;');
  h.push('  if (!username || !password) {');
  h.push('    errorEl.textContent = "请输入用户名和密码";');
  h.push('    errorEl.style.display = "block";');
  h.push('    return;');
  h.push('  }');
  h.push('  errorEl.style.display = "none";');
  h.push('  try {');
  h.push('    var res = await fetch("/api/login", {');
  h.push('      method: "POST",');
  h.push('      headers: { "Content-Type": "application/json" },');
  h.push('      body: JSON.stringify({ username: username, password: password })');
  h.push('    });');
  h.push('    var data = await res.json();');
  h.push('    if (res.ok && data.ok) {');
  h.push('      window.location.href = "/";');
  h.push('    } else {');
  h.push('      errorEl.textContent = data.error || "登录失败";');
  h.push('      errorEl.style.display = "block";');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    errorEl.textContent = "网络错误，请重试";');
  h.push('    errorEl.style.display = "block";');
  h.push('  }');
  h.push('});');
  h.push('document.getElementById("password").addEventListener("keydown", function(e){');
  h.push('  if (e.key === "Enter") document.getElementById("loginBtn").click();');
  h.push('});');
  h.push('})();');
  h.push('</script>');
  h.push('</body>');
  h.push('</html>');

  return new Response(h.join('\n'), {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      ...securityHeaders(),
    },
  });
}

function serveAppPage() {
  var h = [];
  h.push('<!DOCTYPE html>');
  h.push('<html lang="zh-CN">');
  h.push('<head>');
  h.push('<meta charset="UTF-8">');
  h.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
  h.push('<title>备忘录</title>');
  h.push('<style>');
  h.push('  :root {');
  h.push('    --bg: #f0f2f5; --surface: #fff; --surface-hover: #f8f9fa;');
  h.push('    --primary: #4f6ef7; --primary-hover: #3b5de7; --primary-light: #eef0ff;');
  h.push('    --text: #1a1a2e; --text-secondary: #6b7280; --text-muted: #9ca3af;');
  h.push('    --border: #e5e7eb; --radius: 12px; --radius-sm: 8px; --header-h: 56px;');
  h.push('    --shadow: 0 1px 3px rgba(0,0,0,0.06);');
  h.push('    --shadow-hover: 0 4px 12px rgba(0,0,0,0.08);');
  h.push('  }');
  h.push('  [data-theme="dark"] {');
  h.push('    --bg: #0f0f1a; --surface: #1a1a2e; --surface-hover: #222238;');
  h.push('    --primary-light: #2a2a5e; --text: #e8e8f0;');
  h.push('    --text-secondary: #a0a0b8; --text-muted: #6b6b80;');
  h.push('    --border: #2a2a4a;');
  h.push('    --shadow: 0 1px 3px rgba(0,0,0,0.3);');
  h.push('    --shadow-hover: 0 4px 12px rgba(0,0,0,0.5);');
  h.push('  }');
  h.push('  * { margin:0; padding:0; box-sizing:border-box; }');
  h.push('  body {');
  h.push('    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif;');
  h.push('    background: var(--bg); color: var(--text); min-height: 100vh;');
  h.push('    -webkit-font-smoothing: antialiased;');
  h.push('  }');
  h.push('  .header {');
  h.push('    background: var(--surface); border-bottom: 1px solid var(--border);');
  h.push('    padding: 0 20px; height: var(--header-h);');
  h.push('    display: flex; align-items: center; gap: 12px;');
  h.push('    position: sticky; top: 0; z-index: 10;');
  h.push('    backdrop-filter: blur(8px);');
  h.push('    background: rgba(255,255,255,0.9);');
  h.push('  }');
  h.push('  [data-theme="dark"] .header { background: rgba(26,26,46,0.9); }');
  h.push('  .header h1 { font-size: 18px; font-weight: 700; white-space: nowrap; }');
  h.push('  .search-box { flex:1; max-width:320px; }');
  h.push('  .search-box input {');
  h.push('    width:100%; padding:7px 14px; border:1px solid var(--border); border-radius:20px;');
  h.push('    font-size:13px; background:var(--bg); color:var(--text); transition:all .2s;');
  h.push('  }');
  h.push('  .search-box input:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(79,110,247,0.15); }');
  h.push('  .search-box input::placeholder { color:var(--text-muted); }');
  h.push('  .header .actions { display:flex; gap:8px; align-items:center; flex-shrink:0; }');
  h.push('  .header .user { color:var(--text-muted); font-size:13px; white-space:nowrap; }');
  h.push('  .header button { padding:6px 14px; border:none; border-radius:var(--radius-sm); font-size:13px; cursor:pointer; font-weight:500; transition:all .15s; }');
  h.push('  .btn-new { background:var(--primary); color:#fff; font-size:18px; padding:4px 10px; line-height:1.4; border-radius:50%; }');
  h.push('  .btn-new:hover { background:var(--primary-hover); transform:scale(1.05); }');
  h.push('  .btn-logout { background:var(--surface-hover); color:var(--text-secondary); }');
  h.push('  .btn-logout:hover { background:var(--border); }');
  h.push('  .btn-theme { background:none; border:1px solid var(--border); color:var(--text-muted); font-size:16px; cursor:pointer; padding:4px 8px; border-radius:6px; line-height:1; }');
  h.push('  .btn-theme:hover { background:var(--surface-hover); }');
  h.push('  .app-layout { display:flex; min-height:calc(100vh - var(--header-h)); }');
  h.push('  .sidebar { width:220px; background:var(--surface); border-right:1px solid var(--border); padding:12px 0; flex-shrink:0; overflow-y:auto; transition:width .2s; }');
  h.push('  .sidebar.collapsed { width:40px; min-width:40px; overflow:hidden; }');
  h.push('  .sidebar.collapsed .sidebar-title-text, .sidebar.collapsed .add-folder, .sidebar.collapsed .folder-item { display:none; }');
  h.push('  .sidebar.collapsed .sidebar-title { justify-content:center; padding:8px 0; }');
  h.push('  .sidebar-title { padding:6px 16px; font-size:11px; font-weight:600; color:var(--text-muted); text-transform:uppercase; letter-spacing:.5px; display:flex; justify-content:space-between; align-items:center; }');
  h.push('  .sidebar-title .add-folder { background:none; border:none; color:var(--primary); font-size:18px; cursor:pointer; padding:0 4px; line-height:1; }');
  h.push('  .sidebar-title .add-folder:hover { color:var(--primary-hover); }');
  h.push('  .sidebar-toggle { background:none; border:none; font-size:11px; cursor:pointer; padding:0; color:var(--text-muted); line-height:1; flex-shrink:0; }');
  h.push('  .sidebar-toggle:hover { color:var(--primary); }');
  h.push('  .folder-item { padding:9px 16px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:14px; color:var(--text-secondary); transition:background .12s; position:relative; border-left:3px solid transparent; }');
  h.push('  .folder-item:hover { background:var(--surface-hover); }');
  h.push('  .folder-item.active { background:var(--primary-light); color:var(--primary); font-weight:500; border-left-color:var(--primary); }');
  h.push('  .folder-item .folder-icon { font-size:15px; }');
  h.push('  .folder-item .folder-name { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }');
  h.push('  .folder-item .folder-count { font-size:11px; color:var(--text-muted); background:var(--surface-hover); padding:1px 6px; border-radius:10px; }');
  h.push('  .folder-item.active .folder-count { background:var(--primary); color:#fff; }');
  h.push('  .folder-item .folder-actions { display:none; gap:2px; margin-left:auto; }');
  h.push('  .folder-item:hover .folder-actions { display:flex; }');
  h.push('  .folder-actions button { background:none; border:none; font-size:13px; cursor:pointer; padding:2px 4px; border-radius:3px; color:var(--text-muted); line-height:1; }');
  h.push('  .folder-actions button:hover { background:var(--border); color:var(--text); }');
  h.push('  .main-content { flex:1; min-width:0; }');
  h.push('  .container { max-width:800px; margin:0 auto; padding:20px 24px; }');
  h.push('  .memo-card { background:var(--surface); border-radius:var(--radius); padding:20px; margin-bottom:12px; box-shadow:var(--shadow); transition:box-shadow .2s, transform .15s; position:relative; border:1px solid var(--border); }');
  h.push('  .memo-card:hover { box-shadow:var(--shadow-hover); transform:translateY(-1px); }');
  h.push('  .memo-card h3 { margin-bottom:8px; font-size:16px; color:var(--text); display:flex; align-items:center; gap:8px; }');
  h.push('  .memo-card h3 .memo-folder { font-size:11px; color:var(--primary); background:var(--primary-light); padding:1px 8px; border-radius:10px; font-weight:400; }');
  h.push('  .memo-card p { color:var(--text-secondary); font-size:14px; line-height:1.7; white-space:pre-wrap; }');
  h.push('  .memo-card .time { color:var(--text-muted); font-size:11px; margin-top:10px; }');
  h.push('  .memo-card .card-actions { position:absolute; top:16px; right:16px; display:flex; gap:4px; opacity:0; transition:opacity .15s; }');
  h.push('  .memo-card:hover .card-actions { opacity:1; }');
  h.push('  .card-actions button { background:var(--surface-hover); border:none; font-size:14px; cursor:pointer; padding:4px 6px; border-radius:4px; color:var(--text-muted); line-height:1; transition:all .1s; }');
  h.push('  .card-actions button:hover { background:var(--border); color:var(--text); }');
  h.push('  .memo-card.dragging { opacity:0.5; }');
  h.push('  .empty { text-align:center; color:var(--text-muted); padding:80px 20px; font-size:14px; line-height:1.8; }');
  h.push('  .empty .empty-icon { font-size:48px; margin-bottom:16px; display:block; }');
  h.push('  .modal-overlay { display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.45); z-index:100; align-items:center; justify-content:center; backdrop-filter:blur(2px); }');
  h.push('  .modal-overlay.active { display:flex; }');
  h.push('  .modal { background:var(--surface); border-radius:16px; padding:28px 24px; width:90%; max-width:580px; box-shadow:0 25px 60px rgba(0,0,0,0.2); animation:modalIn .2s ease; }');
  h.push('  @keyframes modalIn { from{opacity:0;transform:scale(.95) translateY(10px)} to{opacity:1;transform:scale(1) translateY(0)} }');
  h.push('  .modal h2 { margin-bottom:20px; font-size:18px; font-weight:600; }');
  h.push('  .modal .field { margin-bottom:16px; }');
  h.push('  .modal .field label { display:block; margin-bottom:6px; font-size:13px; color:var(--text-secondary); font-weight:500; }');
  h.push('  .modal .field input, .modal .field textarea { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:var(--radius-sm); font-size:14px; font-family:inherit; background:var(--surface); color:var(--text); transition:border-color .15s; }');
  h.push('  .modal .field textarea { resize:vertical; min-height:160px; max-height:500px; }');
  h.push('  .modal .field input:focus, .modal .field textarea:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px rgba(79,110,247,0.12); }');
  h.push('  .modal .field select { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:var(--radius-sm); font-size:14px; background:var(--surface); color:var(--text); cursor:pointer; }');
  h.push('  .modal .field select:focus { outline:none; border-color:var(--primary); }');
  h.push('  .char-count { text-align:right; font-size:11px; color:var(--text-muted); margin-top:4px; }');
  h.push('  .char-count.warning { color:#ef4444; }');
  h.push('  .modal-btns { display:flex; gap:10px; justify-content:flex-end; margin-top:12px; align-items:center; }');
  h.push('  .modal-btns button { padding:9px 20px; border:none; border-radius:var(--radius-sm); font-size:14px; cursor:pointer; font-weight:500; transition:all .15s; }');
  h.push('  .btn-save { background:var(--primary); color:#fff; }');
  h.push('  .btn-save:hover { background:var(--primary-hover); }');
  h.push('  .btn-cancel { background:var(--surface-hover); color:var(--text-secondary); }');
  h.push('  .btn-cancel:hover { background:var(--border); }');
  h.push('  .btn-delete-inline { background:#ef4444; color:#fff; margin-right:auto; }');
  h.push('  .btn-delete-inline:hover { background:#dc2626; }');
  h.push('  .folder-modal .modal { max-width:400px; }');
  h.push('  /* Toast */');
  h.push('  .toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%); z-index:200; padding:10px 24px; border-radius:10px; font-size:14px; color:#fff; background:#1f2937; box-shadow:0 4px 16px rgba(0,0,0,.2); animation:toastIn .25s ease; pointer-events:none; }');
  h.push('  [data-theme="dark"] .toast { background:#374151; }');
  h.push('  .toast.leave { animation:toastOut .2s ease forwards; }');
  h.push('  @keyframes toastIn { from{opacity:0;transform:translateX(-50%) translateY(16px)} to{opacity:1;transform:translateX(-50%) translateY(0)} }');
  h.push('  @keyframes toastOut { from{opacity:1} to{opacity:0;transform:translateX(-50%) translateY(16px)} }');
  h.push('  /* Drag & Drop */');
  h.push('  .sidebar.drag-over { background:var(--primary-light); }');
  h.push('  .folder-item.drag-over { background:var(--primary-light); }');
  h.push('  .folder-item.drag-over .folder-name { color:var(--primary); }');
  h.push('  .memo-card h3, .memo-card p { overflow-wrap:break-word; word-break:break-word; }');
  h.push('  /* Responsive */');
  h.push('  @media (max-width:768px) {');
    h.push('    .app-layout { flex-direction:column; }');
    h.push('    .sidebar { width:100%; min-width:0; border-right:none; border-bottom:1px solid var(--border); padding:6px 12px; display:flex; gap:4px; overflow-x:auto; white-space:nowrap; }');
    h.push('    .sidebar-toggle { display:none; }');
    h.push('    .sidebar-title { display:inline-flex; padding:6px 4px 6px 0; align-items:center; border:none; text-transform:none; letter-spacing:0; color:var(--text-muted); }');
    h.push('    .sidebar-title-text { font-size:0; }');
    h.push('    .sidebar-title .add-folder { font-size:20px; padding:0 4px; line-height:1; flex-shrink:0; }');
    h.push('    .sidebar .folder-item { display:inline-flex; padding:6px 12px; border-radius:var(--radius-sm); border-left:none; flex-shrink:0; }');
    h.push('    .sidebar .folder-item.active { border-left:none; background:var(--primary-light); }');
    h.push('    .sidebar .folder-item .folder-actions { display:none; }');
  h.push('    .header { padding:0 12px; gap:8px; }');
  h.push('    .header .search-box { max-width:none; }');
  h.push('    .container { padding:12px; }');
  h.push('    .memo-card { padding:16px; }');
  h.push('    .memo-card .card-actions { opacity:1; }');
  h.push('    .header .user { display:none; }');
  h.push('  }');
  h.push('</style>');
  h.push('</head>');
  h.push('<body>');
  h.push('<div class="header">');
  h.push('  <h1>\u{1F4DD} 我的备忘录</h1>');
  h.push('  <div class="search-box">');
  h.push('    <input type="search" id="searchInput" placeholder="搜索标题或内容...">');
  h.push('  </div>');
  h.push('  <div class="actions">');
  h.push('    <span class="user" id="usernameDisplay"></span>');
  h.push('    <button class="btn-new" id="newMemoBtn">\u{FF0B}</button>');
  h.push('    <button class="btn-theme" id="themeToggle" title="切换深色模式">🌙</button>');
  h.push('    <button class="btn-logout" id="logoutBtn">退出</button>');
  h.push('  </div>');
  h.push('</div>');
  h.push('<div class="app-layout">');
  h.push('  <div class="sidebar" id="folderSidebar">');
  h.push('    <div class="sidebar-title">');
  h.push('      <button class="sidebar-toggle" id="sidebarToggle" title="折叠边栏">\u25C0</button>');
  h.push('      <span class="sidebar-title-text">分类</span>');
  h.push('      <button class="add-folder" id="addFolderBtn" title="新建分类">+</button>');
  h.push('    </div>');
  h.push('    <div class="folder-item active" data-folder="all">');
  h.push('      <span class="folder-icon">📋</span>');
  h.push('      <span class="folder-name">所有备忘录</span>');
  h.push('    </div>');
  h.push('    <div class="folder-item" data-folder="none">');
  h.push('      <span class="folder-icon">📄</span>');
  h.push('      <span class="folder-name">未分类</span>');
  h.push('    </div>');
  h.push('    <div id="folderList"></div>');
  h.push('  </div>');
  h.push('  <div class="main-content">');
  h.push('    <div class="container" id="memoList"></div>');
  h.push('  </div>');
  h.push('</div>');
  h.push('');
  h.push('<!-- 编辑/新建模态框 -->');
  h.push('<div class="modal-overlay" id="modalOverlay">');
  h.push('  <div class="modal">');
  h.push('    <h2 id="modalTitle">新建备忘录</h2>');
  h.push('    <input type="hidden" id="editMemoId">');
  h.push('    <div class="field">');
  h.push('      <label for="memoTitle">标题</label>');
  h.push('      <input id="memoTitle" type="text" placeholder="输入标题">');
  h.push('    </div>');
  h.push('    <div class="field">');
  h.push('      <label for="memoContent">内容</label>');
  h.push('      <textarea id="memoContent" placeholder="输入内容..."></textarea>');
  h.push('      <div class="char-count" id="charCount">0 / 20000</div>');
  h.push('    </div>');
  h.push('    <div class="field">');
  h.push('      <label for="memoFolder">分类</label>');
  h.push('      <select id="memoFolder">');
  h.push('        <option value="">无分类</option>');
  h.push('      </select>');
  h.push('    </div>');
  h.push('    <div class="modal-btns">');
  h.push('      <button class="btn-delete-inline" id="deleteMemoBtn" style="display:none;">删除</button>');
  h.push('      <button class="btn-cancel" id="cancelBtn">取消</button>');
  h.push('      <button class="btn-save" id="saveBtn">保存</button>');
  h.push('    </div>');
  h.push('  </div>');
  h.push('</div>');
  h.push('');
  h.push('<!-- 文件夹模态框 -->');
  h.push('<div class="modal-overlay folder-modal" id="folderModal">');
  h.push('  <div class="modal">');
  h.push('    <h2 id="folderModalTitle">新建分类</h2>');
  h.push('    <input type="hidden" id="editFolderId">');
  h.push('    <div class="field">');
  h.push('      <label for="folderName">分类名称</label>');
  h.push('      <input id="folderName" type="text" placeholder="输入分类名称" maxlength="50">');
  h.push('    </div>');
  h.push('    <div class="modal-btns">');
  h.push('      <button class="btn-cancel" id="folderCancelBtn">取消</button>');
  h.push('      <button class="btn-save" id="folderSaveBtn">保存</button>');
  h.push('    </div>');
  h.push('  </div>');
  h.push('</div>');
  h.push('');
  h.push('<script>');
  h.push('(function(){');
  h.push('// ── 初始化 ───');
  h.push('var currentUser = "";');
  h.push('var memosCache = [];');
  h.push('var foldersCache = [];');
  h.push('var currentFolder = "all";');
  h.push('var searchQuery = "";');
  h.push('var isSaving = false;');
  h.push('');
  h.push('async function init() {');
  h.push('  try {');
  h.push('    var res = await fetch("/api/me");');
  h.push('    if (res.ok) {');
  h.push('      var data = await res.json();');
  h.push('      currentUser = data.username;');
  h.push('      document.getElementById("usernameDisplay").textContent = currentUser;');
  h.push('      await Promise.all([loadFolders(), loadMemos()]);');
  h.push('    } else {');
  h.push('      window.location.href = "/";');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    window.location.href = "/";');
  h.push('  }');
  h.push('}');
  h.push('');
  h.push('// ── 加载文件夹列表 ───');
  h.push('async function loadFolders() {');
  h.push('  try {');
  h.push('    var res = await fetch("/api/folders");');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    foldersCache = await res.json();');
  h.push('    renderFolderList();');
  h.push('  } catch(e) {}');
  h.push('}');
  h.push('');
  h.push('function renderFolderList() {');
  h.push('  var list = document.getElementById("folderList");');
  h.push('  list.innerHTML = foldersCache.map(function(f) {');
  h.push('    var count = memosCache.filter(function(m) { return m.folderId === f.id; }).length;');
    h.push('    return "<div class=\\"folder-item\\" data-folder=\\"" + f.id + "\\" draggable=\\"false\\">" +');
    h.push('      "<span class=\\"folder-icon\\">📁</span>" +');
    h.push('      "<span class=\\"folder-name\\">" + escapeHtml(f.name) + "</span>" +');
    h.push('      "<span class=\\"folder-count\\">" + count + "</span>" +');
    h.push('      "<span class=\\"folder-actions\\">" +');
    h.push('      "<button title=\\"重命名\\" data-rename=\\"" + f.id + "\\">✏️</button>" +');
    h.push('      "<button title=\\"删除\\" data-del=\\"" + f.id + "\\">🗑️</button>" +');
  h.push('      "</span>" +');
  h.push('      "</div>";');
  h.push('  }).join("");');
  h.push('  // 高亮当前选中');
  h.push('  list.querySelectorAll(".folder-item").forEach(function(el) {');
  h.push('    if (el.dataset.folder === currentFolder) el.classList.add("active");');
  h.push('  });');
  h.push('  list.querySelectorAll("[data-rename]").forEach(function(btn) {');
  h.push('    btn.addEventListener("click", function(e) { e.stopPropagation(); openRenameFolder(btn.dataset.rename); });');
  h.push('  });');
  h.push('  list.querySelectorAll("[data-del]").forEach(function(btn) {');
  h.push('    btn.addEventListener("click", function(e) { e.stopPropagation(); deleteFolder(btn.dataset.del); });');
  h.push('  });');
  h.push('  // 文件夹点击过滤');
  h.push('  list.querySelectorAll(".folder-item").forEach(function(el) {');
  h.push('    el.addEventListener("click", function() { selectFolder(el.dataset.folder); });');
  h.push('  });');
  h.push('  // 文件夹作为拖拽目标');
  h.push('  list.querySelectorAll(".folder-item").forEach(function(el) {');
  h.push('    el.addEventListener("dragover", function(e) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; el.classList.add("drag-over"); });');
  h.push('    el.addEventListener("dragleave", function() { el.classList.remove("drag-over"); });');
  h.push('    el.addEventListener("drop", function(e) { e.preventDefault(); el.classList.remove("drag-over"); var memoId = e.dataTransfer.getData("text/memo-id"); if (memoId) moveMemoToFolder(memoId, el.dataset.folder); });');
  h.push('  });');
  h.push('  updateFolderSelect();');
  h.push('}');
  h.push('async function loadMemos() {');
  h.push('  try {');
  h.push('    var res = await fetch("/api/memos");');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    memosCache = await res.json();');
  h.push('    renderMemoList();');
  h.push('  } catch(e) {');
  h.push('    document.getElementById("memoList").innerHTML = "<div class=\\"empty\\">加载失败，请刷新页面</div>";');
  h.push('  }');
h.push('}');
h.push('');
  h.push('function renderMemoList() {');
  h.push('  var container = document.getElementById("memoList");');
  h.push('  var q = searchQuery.trim().toLowerCase();');
  h.push('  var filtered = memosCache;');
  h.push('  if (currentFolder === "none") {');
  h.push('    filtered = memosCache.filter(function(m) { return !m.folderId; });');
  h.push('  } else if (currentFolder !== "all") {');
  h.push('    filtered = memosCache.filter(function(m) { return m.folderId === currentFolder; });');
  h.push('  }');
  h.push('  if (q) {');
  h.push('    filtered = filtered.filter(function(m) { return (m.title||"").toLowerCase().indexOf(q) !== -1 || (m.content||"").toLowerCase().indexOf(q) !== -1; });');
  h.push('  }');
  h.push('  if (filtered.length === 0) {');
  h.push('    container.innerHTML = "<div class=\\"empty\\">还没有备忘录，点击右上角「新建」开始</div>";');
  h.push('    return;');
  h.push('  }');
  h.push('  container.innerHTML = filtered.map(function(m) {');
  h.push('    var date = new Date(m.updatedAt).toLocaleString("zh-CN");');
  h.push('    var card = "<div class=\\"memo-card\\" draggable=\\"true\\" data-memo-id=\\"" + m.id + "\\">";');
  h.push('    var folderName = "";');
  h.push('    if (m.folderId) {');
  h.push('      var f = foldersCache.find(function(f) { return f.id === m.folderId; });');
  h.push('      if (f) folderName = "<span class=\\"memo-folder\\">📁 " + escapeHtml(f.name) + "</span>";');
  h.push('    }');
  h.push('    card += "<h3>" + escapeHtml(m.title || "(无标题)") + folderName + "</h3>";');
  h.push('    if (m.content) {');
  h.push('      card += "<p>" + escapeHtml(m.content) + "</p>";');
  h.push('    } else {');
  h.push('      card += "<p style=\\"color:#ccc;\\">无内容</p>";');
  h.push('    }');
  h.push('    card += "<div class=\\"time\\">更新于 " + date + "</div>";');
  h.push('    card += "<div class=\\"card-actions\\">";');
  h.push('    card += "<button title=\\"编辑\\" data-edit=\\"" + m.id + "\\">\u270F\uFE0F</button>";');
  h.push('    card += "<button title=\\"复制\\" data-copy=\\"" + m.id + "\\">\uD83D\uDCCB</button>";');
  h.push('    card += "<button title=\\"删除\\" data-delete=\\"" + m.id + "\\">\uD83D\uDDD1\uFE0F</button>";');
  h.push('    card += "</div>";');
  h.push('    card += "</div>";');
  h.push('    return card;');
  h.push('  }).join("");');
  h.push('  container.querySelectorAll("[data-edit]").forEach(function(btn) {');
  h.push('    btn.addEventListener("click", function() { openEditModal(btn.dataset.edit); });');
  h.push('  });');
  h.push('  container.querySelectorAll("[data-delete]").forEach(function(btn) {');
  h.push('    btn.addEventListener("click", function() { deleteMemoDirect(btn.dataset.delete); });');
  h.push('  });');
  h.push('  container.querySelectorAll("[data-copy]").forEach(function(btn) {');
  h.push('    btn.addEventListener("click", function() { copyMemoContent(btn.dataset.copy); });');
  h.push('  });');
  h.push('  // 拖拽支持');
  h.push('  container.querySelectorAll(".memo-card[draggable]").forEach(function(card) {');
  h.push('    card.addEventListener("dragstart", function(e) {');
  h.push('      e.dataTransfer.setData("text/memo-id", card.dataset.memoId);');
  h.push('      card.classList.add("dragging");');
  h.push('    });');
  h.push('    card.addEventListener("dragend", function() {');
  h.push('      card.classList.remove("dragging");');
  h.push('    });');
  h.push('  });');
  h.push('  // 未分类（sidebar空白）作为拖拽目标');
  h.push('  var sidebar = document.getElementById("folderSidebar");');
  h.push('  sidebar.addEventListener("dragover", function(e) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; sidebar.classList.add("drag-over"); });');
  h.push('  sidebar.addEventListener("dragleave", function(e) {');
  h.push('    if (!sidebar.contains(e.relatedTarget)) sidebar.classList.remove("drag-over");');
  h.push('  });');
  h.push('  sidebar.addEventListener("drop", function(e) {');
  h.push('    e.preventDefault();');
  h.push('    sidebar.classList.remove("drag-over");');
  h.push('    var memoId = e.dataTransfer.getData("text/memo-id");');
  h.push('    var target = e.target.closest("[data-folder]");');
  h.push('    if (target) return; // 由 folder-item 处理');
  h.push('    if (memoId) moveMemoToFolder(memoId, null);');
  h.push('  });');
  h.push('  updateFolderCounts();');
  h.push('}');
h.push('');
h.push('function escapeHtml(text) {');
  h.push('  var div = document.createElement("div");');
  h.push('  div.textContent = text;');
  h.push('  return div.innerHTML;');
  h.push('}');
  h.push('');
  h.push('// ── Toast 提示 ───');
  h.push('function toast(msg) {');
  h.push('  var el = document.createElement("div");');
  h.push('  el.className = "toast";');
  h.push('  el.textContent = msg;');
  h.push('  document.body.appendChild(el);');
  h.push('  setTimeout(function() {');
  h.push('    el.classList.add("leave");');
  h.push('    setTimeout(function() { el.remove(); }, 200);');
  h.push('  }, 2500);');
  h.push('}');
  h.push('');
  h.push('// ── 模态框 ───');
  h.push('var modalOverlay = document.getElementById("modalOverlay");');
  h.push('var modalTitle = document.getElementById("modalTitle");');
  h.push('var editMemoId = document.getElementById("editMemoId");');
  h.push('var memoTitle = document.getElementById("memoTitle");');
  h.push('var memoContent = document.getElementById("memoContent");');
  h.push('var memoFolder = document.getElementById("memoFolder");');
  h.push('var deleteBtn = document.getElementById("deleteMemoBtn");');
  h.push('var charCount = document.getElementById("charCount");');
  h.push('');
  h.push('function updateCharCount() {');
  h.push('  var len = memoContent.value.length;');
  h.push('  charCount.textContent = len + " / 20000";');
  h.push('  charCount.classList.toggle("warning", len > 19000);');
  h.push('}');
  h.push('');
  h.push('function autoResizeTextarea() {');
  h.push('  memoContent.style.height = "auto";');
  h.push('  memoContent.style.height = Math.min(memoContent.scrollHeight, 500) + "px";');
  h.push('}');
  h.push('');
  h.push('memoContent.addEventListener("input", function() {');
  h.push('  updateCharCount();');
  h.push('  autoResizeTextarea();');
  h.push('});');
  h.push('');
  h.push('function openNewModal() {');
  h.push('  modalTitle.textContent = "新建备忘录";');
  h.push('  editMemoId.value = "";');
  h.push('  memoTitle.value = "";');
  h.push('  memoContent.value = "";');
  h.push('  memoFolder.value = (currentFolder !== "all" && currentFolder !== "none") ? currentFolder : "";');
  h.push('  deleteBtn.style.display = "none";');
  h.push('  modalOverlay.classList.add("active");');
  h.push('  updateCharCount();');
  h.push('  autoResizeTextarea();');
  h.push('  memoTitle.focus();');
  h.push('}');
  h.push('');
  h.push('async function openEditModal(id) {');
  h.push('  modalTitle.textContent = "编辑备忘录";');
  h.push('  editMemoId.value = id;');
  h.push('  deleteBtn.style.display = "inline-block";');
  h.push('  var memos = memosCache;');
  h.push('  if (memos.length === 0) {');
  h.push('    try {');
  h.push('      var res = await fetch("/api/memos");');
  h.push('      if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('      if (res.ok) { memos = await res.json(); memosCache = memos; }');
  h.push('      else { toast("加载失败，请重试"); closeModal(); loadMemos(); return; }');
  h.push('    } catch(e) { toast("网络错误，请重试"); closeModal(); loadMemos(); return; }');
  h.push('  }');
  h.push('  var memo = memos.find(function(m) { return m.id === id; });');
  h.push('  if (memo) {');
  h.push('    memoTitle.value = memo.title;');
  h.push('    memoContent.value = memo.content;');
  h.push('    memoFolder.value = memo.folderId || "";');
  h.push('  } else {');
  h.push('    toast("该备忘录不存在或已被删除");');
  h.push('    closeModal();');
  h.push('    loadMemos();');
  h.push('    return;');
  h.push('  }');
  h.push('  modalOverlay.classList.add("active");');
  h.push('  updateCharCount();');
  h.push('  autoResizeTextarea();');
  h.push('  memoTitle.focus();');
  h.push('}');
  h.push('');
  h.push('function closeModal() {');
  h.push('  modalOverlay.classList.remove("active");');
  h.push('}');
  h.push('');
  h.push('async function saveMemo() {');
  h.push('  if (isSaving) return;');
  h.push('  var id = editMemoId.value;');
  h.push('  var title = memoTitle.value.trim();');
  h.push('  var content = memoContent.value.trim();');
  h.push('  if (!title && !content) {');
  h.push('    toast("请至少填写标题或内容");');
  h.push('    return;');
  h.push('  }');
  h.push('  var saveBtn = document.getElementById("saveBtn");');
  h.push('  var originalText = saveBtn.textContent;');
  h.push('  isSaving = true;');
  h.push('  saveBtn.disabled = true;');
  h.push('  saveBtn.textContent = "保存中...";');
  h.push('  try {');
  h.push('    var res;');
  h.push('    if (id) {');
  h.push('      res = await fetch("/api/memos/" + id, {');
  h.push('        method: "PUT",');
  h.push('        headers: { "Content-Type": "application/json" },');
  h.push('        body: JSON.stringify({ title: title, content: content, folderId: memoFolder.value || null })');
  h.push('      });');
  h.push('    } else {');
  h.push('      res = await fetch("/api/memos", {');
  h.push('        method: "POST",');
  h.push('        headers: { "Content-Type": "application/json" },');
  h.push('        body: JSON.stringify({ title: title, content: content, folderId: memoFolder.value || null })');
  h.push('      });');
  h.push('    }');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (res.ok) {');
  h.push('      var memo = await res.json();');
  h.push('      if (id) {');
h.push('        for (var i = 0; i < memosCache.length; i++) {');
h.push('          if (memosCache[i].id === id) {');
h.push('            memosCache[i] = memo;');
h.push('            break;');
h.push('          }');
h.push('        }');
h.push('        memosCache.sort(function(a,b){ return b.updatedAt - a.updatedAt; });');
  h.push('      } else {');
h.push('        memosCache.push(memo);');
h.push('        memosCache.sort(function(a,b){ return b.updatedAt - a.updatedAt; });');
h.push('      }');
h.push('      closeModal();');
h.push('      renderMemoList();');
h.push('    } else {');
  h.push('      var err = await res.json();');
  h.push('      toast(err.error || "保存失败");');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    toast("网络错误");');
  h.push('  } finally {');
  h.push('    isSaving = false;');
  h.push('    saveBtn.disabled = false;');
  h.push('    saveBtn.textContent = originalText;');
  h.push('  }');
  h.push('}');
  h.push('');
  h.push('async function deleteMemoDirect(id) {');
  h.push('  if (!confirm("确定要删除这条备忘录吗？")) return;');
  h.push('  try {');
  h.push('    var res = await fetch("/api/memos/" + id, { method: "DELETE" });');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (res.ok) {');
  h.push('      memosCache = memosCache.filter(function(m) { return m.id !== id; });');
  h.push('      renderMemoList();');
  h.push('    } else {');
  h.push('      toast("删除失败");');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    toast("网络错误");');
  h.push('  }');
  h.push('}');
  h.push('');
  h.push('function copyMemoContent(id) {');
  h.push('  var memo = memosCache.find(function(m) { return m.id === id; });');
  h.push('  if (!memo) { toast("备忘录不存在"); return; }');
  h.push('  var text = (memo.title || "") + "\\n" + (memo.content || "");');
  h.push('  navigator.clipboard.writeText(text).then(function() {');
  h.push('    toast("已复制到剪贴板");');
  h.push('  }, function() {');
  h.push('    toast("复制失败，请手动复制");');
  h.push('  });');
  h.push('}');
  h.push('');
  h.push('// ── 文件夹操作 ───');
  h.push('function selectFolder(id) {');
  h.push('  currentFolder = id;');
  h.push('  // 更新 sidebar 高亮');
  h.push('  document.querySelectorAll("[data-folder]").forEach(function(el) {');
  h.push('    el.classList.toggle("active", el.dataset.folder === id);');
  h.push('  });');
  h.push('  renderMemoList();');
  h.push('}');
  h.push('');
  h.push('function updateFolderCounts() {');
  h.push('  var list = document.getElementById("folderList");');
  h.push('  if (!list) return;');
  h.push('  list.querySelectorAll(".folder-item").forEach(function(el) {');
  h.push('    var fid = el.dataset.folder;');
  h.push('    var count = memosCache.filter(function(m) { return m.folderId === fid; }).length;');
  h.push('    var countEl = el.querySelector(".folder-count");');
  h.push('    if (countEl) countEl.textContent = count;');
  h.push('  });');
  h.push('}');
  h.push('');
  h.push('async function moveMemoToFolder(memoId, folderId) {');
  h.push('  try {');
  h.push('    var res = await fetch("/api/memos/" + memoId + "/folder", {');
  h.push('      method: "PUT",');
  h.push('      headers: { "Content-Type": "application/json" },');
  h.push('      body: JSON.stringify({ folderId: folderId })');
  h.push('    });');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (res.ok) {');
  h.push('      var memo = await res.json();');
  h.push('      for (var i = 0; i < memosCache.length; i++) {');
  h.push('        if (memosCache[i].id === memoId) { memosCache[i] = memo; break; }');
  h.push('      }');
  h.push('      renderMemoList();');
  h.push('      renderFolderList();');
  h.push('    } else { toast("移动失败"); }');
  h.push('  } catch(e) { toast("网络错误"); }');
  h.push('}');
  h.push('');
  h.push('function openNewFolder() {');
  h.push('  document.getElementById("folderModalTitle").textContent = "新建分类";');
  h.push('  document.getElementById("editFolderId").value = "";');
  h.push('  document.getElementById("folderName").value = "";');
  h.push('  document.getElementById("folderModal").classList.add("active");');
  h.push('  document.getElementById("folderName").focus();');
  h.push('}');
  h.push('');
  h.push('function openRenameFolder(id) {');
  h.push('  var folder = foldersCache.find(function(f) { return f.id === id; });');
  h.push('  if (!folder) return;');
  h.push('  document.getElementById("folderModalTitle").textContent = "重命名分类";');
  h.push('  document.getElementById("editFolderId").value = id;');
  h.push('  document.getElementById("folderName").value = folder.name;');
  h.push('  document.getElementById("folderModal").classList.add("active");');
  h.push('  document.getElementById("folderName").focus();');
  h.push('}');
  h.push('');
  h.push('async function saveFolder() {');
  h.push('  var id = document.getElementById("editFolderId").value;');
  h.push('  var name = document.getElementById("folderName").value.trim();');
  h.push('  if (!name) { toast("请输入分类名称"); return; }');
  h.push('  try {');
  h.push('    var res;');
  h.push('    if (id) {');
  h.push('      res = await fetch("/api/folders/" + id, {');
  h.push('        method: "PUT",');
  h.push('        headers: { "Content-Type": "application/json" },');
  h.push('        body: JSON.stringify({ name: name })');
  h.push('      });');
  h.push('    } else {');
  h.push('      res = await fetch("/api/folders", {');
  h.push('        method: "POST",');
  h.push('        headers: { "Content-Type": "application/json" },');
  h.push('        body: JSON.stringify({ name: name })');
  h.push('      });');
  h.push('    }');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (res.ok) {');
  h.push('      document.getElementById("folderModal").classList.remove("active");');
  h.push('      var folder = await res.json();');
  h.push('      if (id) {');
  h.push('        for (var i = 0; i < foldersCache.length; i++) {');
  h.push('          if (foldersCache[i].id === id) { foldersCache[i] = folder; break; }');
  h.push('        }');
  h.push('      } else {');
  h.push('        foldersCache.push(folder);');
  h.push('        foldersCache.sort(function(a,b){ return a.createdAt - b.createdAt; });');
  h.push('      }');
  h.push('      renderFolderList();');
  h.push('    } else {');
  h.push('      var err = await res.json();');
  h.push('      toast(err.error || "操作失败");');
  h.push('    }');
  h.push('  } catch(e) { toast("网络错误"); }');
  h.push('}');
  h.push('');
  h.push('async function deleteFolder(id) {');
  h.push('  if (!confirm("确定要删除这个分类吗？\\n备忘录不会被删除，但会移出此分类。")) return;');
  h.push('  try {');
  h.push('    var res = await fetch("/api/folders/" + id, { method: "DELETE" });');
  h.push('    if (res.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (res.ok) {');
  h.push('      if (currentFolder === id) selectFolder("all");');
  h.push('      loadFolders();');
  h.push('      loadMemos();');
  h.push('    } else { toast("删除失败"); }');
  h.push('  } catch(e) { toast("网络错误"); }');
  h.push('}');
  h.push('');
  h.push('function updateFolderSelect() {');
  h.push('  var select = memoFolder;');
  h.push('  if (!select) return;');
  h.push('  var value = select.value;');
  h.push('  select.innerHTML = "<option value=\\"\\">无分类</option>";');
  h.push('  foldersCache.forEach(function(f) {');
  h.push('    var opt = document.createElement("option");');
  h.push('    opt.value = f.id;');
  h.push('    opt.textContent = f.name;');
  h.push('    select.appendChild(opt);');
  h.push('  });');
  h.push('  select.value = value;');
  h.push('}');
  h.push('');
  h.push('// ── 事件绑定 ───');
  h.push('document.getElementById("newMemoBtn").addEventListener("click", openNewModal);');
  h.push('document.getElementById("cancelBtn").addEventListener("click", closeModal);');
  h.push('document.getElementById("addFolderBtn").addEventListener("click", openNewFolder);');
  h.push('document.getElementById("folderCancelBtn").addEventListener("click", function() {');
  h.push('  document.getElementById("folderModal").classList.remove("active");');
  h.push('});');
  h.push('document.getElementById("folderSaveBtn").addEventListener("click", saveFolder);');
  h.push('// 侧边栏「所有备忘录」和「未分类」点击');
  h.push('document.querySelectorAll("[data-folder=\\"all\\"],[data-folder=\\"none\\"]").forEach(function(el) {');
  h.push('  el.addEventListener("click", function() { selectFolder(el.dataset.folder); });');
  h.push('});');
  h.push('document.getElementById("folderName").addEventListener("keydown", function(e) {');
  h.push('  if (e.key === "Enter") saveFolder();');
  h.push('});');
  h.push('modalOverlay.addEventListener("click", function(e) {');
  h.push('  if (e.target === modalOverlay) closeModal();');
  h.push('});');
  h.push('document.getElementById("saveBtn").addEventListener("click", saveMemo);');
  h.push('document.getElementById("deleteMemoBtn").addEventListener("click", async function() {');
  h.push('  var id = editMemoId.value;');
  h.push('  if (!id || !confirm("确定要删除这条备忘录吗？")) return;');
  h.push('  try {');
  h.push('    var r = await fetch("/api/memos/" + id, { method: "DELETE" });');
  h.push('    if (r.status === 401) { window.location.href = "/"; return; }');
  h.push('    if (r.ok) { memosCache = memosCache.filter(function(m) { return m.id !== id; }); closeModal(); renderMemoList(); }');
  h.push('    else toast("删除失败");');
  h.push('  } catch(e) { toast("网络错误"); }');
  h.push('});');
  h.push('document.getElementById("logoutBtn").addEventListener("click", function() {');
  h.push('  fetch("/api/logout", { method: "POST" }).then(function() {');
  h.push('    window.location.href = "/";');
  h.push('  }, function() {');
  h.push('    window.location.href = "/";');
  h.push('  });');
  h.push('});');
  h.push('');
  h.push('// 键盘快捷键');
  h.push('document.addEventListener("keydown", function(e) {');
  h.push('  if (e.key === "Escape") {');
  h.push('    if (modalOverlay.classList.contains("active")) closeModal();');
  h.push('    if (document.getElementById("folderModal").classList.contains("active")) {');
  h.push('      document.getElementById("folderModal").classList.remove("active");');
  h.push('    }');
  h.push('  }');
  h.push('  if ((e.ctrlKey || e.metaKey) && e.key === "s" && modalOverlay.classList.contains("active")) {');
  h.push('    e.preventDefault();');
  h.push('    saveMemo();');
  h.push('  }');
  h.push('});');
  h.push('');
  h.push('// 深色模式');
  h.push('(function(){');
  h.push('  var theme = localStorage.getItem("theme") || "light";');
  h.push('  if (theme === "dark") {');
  h.push('    document.documentElement.setAttribute("data-theme", "dark");');
  h.push('    document.getElementById("themeToggle").textContent = "\u2600\uFE0F";');
  h.push('  }');
  h.push('  document.getElementById("themeToggle").addEventListener("click", function() {');
  h.push('    var current = document.documentElement.getAttribute("data-theme");');
  h.push('    if (current === "dark") {');
  h.push('      document.documentElement.removeAttribute("data-theme");');
  h.push('      localStorage.setItem("theme", "light");');
  h.push('      this.textContent = "\uD83C\uDF19";');
  h.push('    } else {');
  h.push('      document.documentElement.setAttribute("data-theme", "dark");');
  h.push('      localStorage.setItem("theme", "dark");');
  h.push('      this.textContent = "\u2600\uFE0F";');
  h.push('    }');
  h.push('  });');
  h.push('})();');
  h.push('');
  h.push('// 边栏折叠');
  h.push('(function(){');
  h.push('  var sidebar = document.getElementById("folderSidebar");');
  h.push('  var toggle = document.getElementById("sidebarToggle");');
  h.push('  if (sidebar && toggle) {');
  h.push('    var collapsed = localStorage.getItem("sidebarCollapsed") === "true";');
  h.push('    if (collapsed) {');
  h.push('      sidebar.classList.add("collapsed");');
  h.push('      toggle.textContent = "\u25B6";');
  h.push('      toggle.title = "展开边栏";');
  h.push('    }');
  h.push('    toggle.addEventListener("click", function() {');
  h.push('      var isCollapsed = sidebar.classList.toggle("collapsed");');
  h.push('      toggle.textContent = isCollapsed ? "\u25B6" : "\u25C0";');
  h.push('      toggle.title = isCollapsed ? "展开边栏" : "折叠边栏";');
  h.push('      localStorage.setItem("sidebarCollapsed", isCollapsed);');
  h.push('    });');
  h.push('  }');
  h.push('})();');
  h.push('');
  h.push('// 搜索');
  h.push('(function(){');
  h.push('  var input = document.getElementById("searchInput");');
  h.push('  if (!input) return;');
  h.push('  var timer;');
  h.push('  input.addEventListener("input", function() {');
  h.push('    clearTimeout(timer);');
  h.push('    timer = setTimeout(function() {');
  h.push('      searchQuery = input.value;');
  h.push('      renderMemoList();');
  h.push('    }, 200);');
  h.push('  });');
  h.push('})();');
  h.push('');
  h.push('init();');
  h.push('})();');
  h.push('</script>');
  h.push('</body>');
  h.push('</html>');

  return new Response(h.join('\n'), {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      ...securityHeaders(),
    },
  });
}
