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
// Value: JSON { id, title, content, createdAt, updatedAt }

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
  if (!userMatch | !passMatch) {
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
  const headers = { 'Content-Type': 'application/json', ...extraHeaders };
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
    for (const key of list.keys) {
      const raw = await env.MEMOS_KV.get(key.name);
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
  return json(memos, 200, { 'Cache-Control': 'no-store' });
}

async function handleCreateMemo(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  
  const { title, content } = body;
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

// ── 安全响应头 ──────────────────────────────────────────────────
function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
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
  h.push('  * { margin: 0; padding: 0; box-sizing: border-box; }');
  h.push('  body {');
  h.push('    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;');
  h.push('    background: #f5f6fa;');
  h.push('    color: #333;');
  h.push('    min-height: 100vh;');
  h.push('  }');
  h.push('  .header {');
  h.push('    background: #fff;');
  h.push('    border-bottom: 1px solid #e0e0e0;');
  h.push('    padding: 14px 20px;');
  h.push('    display: flex;');
  h.push('    justify-content: space-between;');
  h.push('    align-items: center;');
  h.push('    position: sticky;');
  h.push('    top: 0;');
  h.push('    z-index: 10;');
  h.push('  }');
  h.push('  .header h1 { font-size: 20px; }');
  h.push('  .header .actions { display: flex; gap: 10px; align-items: center; }');
  h.push('  .header .user { color: #888; font-size: 14px; }');
  h.push('  .header button {');
  h.push('    padding: 7px 16px;');
  h.push('    border: none;');
  h.push('    border-radius: 6px;');
  h.push('    font-size: 13px;');
  h.push('    cursor: pointer;');
  h.push('    font-weight: 500;');
  h.push('  }');
  h.push('  .btn-new { background: #667eea; color: #fff; }');
  h.push('  .btn-new:hover { background: #5a6fd6; }');
  h.push('  .btn-logout { background: #eee; color: #555; }');
  h.push('  .btn-logout:hover { background: #ddd; }');
  h.push('  .container {');
  h.push('    max-width: 900px;');
  h.push('    margin: 24px auto;');
  h.push('    padding: 0 16px;');
  h.push('  }');
  h.push('  .memo-card {');
  h.push('    background: #fff;');
  h.push('    border-radius: 12px;');
  h.push('    padding: 20px;');
  h.push('    margin-bottom: 14px;');
  h.push('    box-shadow: 0 2px 8px rgba(0,0,0,0.05);');
  h.push('    transition: box-shadow 0.2s;');
  h.push('    position: relative;');
  h.push('  }');
  h.push('  .memo-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.1); }');
  h.push('  .memo-card h3 { margin-bottom: 8px; font-size: 17px; color: #222; }');
  h.push('  .memo-card p { color: #555; font-size: 14px; line-height: 1.6; white-space: pre-wrap; }');
  h.push('  .memo-card .time { color: #aaa; font-size: 12px; margin-top: 10px; }');
  h.push('  .memo-card .card-actions {');
  h.push('    position: absolute;');
  h.push('    top: 16px;');
  h.push('    right: 16px;');
  h.push('    display: flex;');
  h.push('    gap: 6px;');
  h.push('  }');
  h.push('  .card-actions button {');
  h.push('    background: none;');
  h.push('    border: none;');
  h.push('    font-size: 16px;');
  h.push('    cursor: pointer;');
  h.push('    padding: 4px 6px;');
  h.push('    border-radius: 4px;');
  h.push('    color: #888;');
  h.push('    transition: background 0.2s;');
  h.push('  }');
  h.push('  .card-actions button:hover { background: #f0f0f0; color: #333; }');
  h.push('  .empty { text-align: center; color: #aaa; padding: 60px 0; font-size: 15px; }');
  h.push('  .modal-overlay {');
  h.push('    display: none;');
  h.push('    position: fixed;');
  h.push('    top: 0; left: 0; right: 0; bottom: 0;');
  h.push('    background: rgba(0,0,0,0.4);');
  h.push('    z-index: 100;');
  h.push('    align-items: center;');
  h.push('    justify-content: center;');
  h.push('  }');
  h.push('  .modal-overlay.active { display: flex; }');
  h.push('  .modal {');
  h.push('    background: #fff;');
  h.push('    border-radius: 14px;');
  h.push('    padding: 28px 24px;');
  h.push('    width: 90%;');
  h.push('    max-width: 600px;');
  h.push('    box-shadow: 0 20px 50px rgba(0,0,0,0.2);');
  h.push('  }');
  h.push('  .modal h2 { margin-bottom: 18px; font-size: 18px; }');
  h.push('  .modal .field { margin-bottom: 14px; }');
  h.push('  .modal .field label { display: block; margin-bottom: 5px; font-size: 13px; color: #666; font-weight: 500; }');
  h.push('  .modal .field input,');
  h.push('  .modal .field textarea {');
  h.push('    width: 100%;');
  h.push('    padding: 10px 12px;');
  h.push('    border: 1px solid #ddd;');
  h.push('    border-radius: 8px;');
  h.push('    font-size: 14px;');
  h.push('    font-family: inherit;');
  h.push('  }');
  h.push('  .modal .field textarea { resize: vertical; min-height: 160px; max-height: 500px; }');
  h.push('  .modal .field input:focus,');
  h.push('  .modal .field textarea:focus { outline: none; border-color: #667eea; }');
  h.push('  .char-count { text-align: right; font-size: 12px; color: #aaa; margin-top: 4px; }');
  h.push('  .char-count.warning { color: #e74c3c; }');
  h.push('  .modal .modal-btns { display: flex; gap: 10px; justify-content: flex-end; margin-top: 8px; }');
  h.push('  .modal .modal-btns button {');
  h.push('    padding: 9px 20px;');
  h.push('    border: none;');
  h.push('    border-radius: 6px;');
  h.push('    font-size: 14px;');
  h.push('    cursor: pointer;');
  h.push('    font-weight: 500;');
  h.push('  }');
  h.push('  .btn-save { background: #667eea; color: #fff; }');
  h.push('  .btn-save:hover { background: #5a6fd6; }');
  h.push('  .btn-cancel { background: #eee; color: #555; }');
  h.push('  .btn-cancel:hover { background: #ddd; }');
  h.push('  .btn-delete-inline { background: #e74c3c; color: #fff; margin-right: auto; }');
  h.push('  .btn-delete-inline:hover { background: #c0392b; }');
  h.push('  .memo-card h3, .memo-card p { overflow-wrap: break-word; word-break: break-word; }');
  h.push('  .btn-theme { background: none; border: 1px solid #ddd; color: #888; font-size: 16px; cursor: pointer; padding: 4px 8px; border-radius: 6px; line-height: 1; }');
  h.push('  .btn-theme:hover { background: #f0f0f0; }');
  h.push('  [data-theme="dark"] .btn-theme { border-color: #3a3a5a; color: #909090; }');
  h.push('  [data-theme="dark"] .btn-theme:hover { background: #2a2a4a; }');
  h.push('  [data-theme="dark"] body { background: #1a1a2e; color: #e0e0e0; }');
  h.push('  [data-theme="dark"] .header { background: #16213e; border-color: #2a2a4a; }');
  h.push('  [data-theme="dark"] .header h1 { color: #e0e0e0; }');
  h.push('  [data-theme="dark"] .header .user { color: #909090; }');
  h.push('  [data-theme="dark"] .btn-logout { background: #2a2a4a; color: #b0b0b0; }');
  h.push('  [data-theme="dark"] .btn-logout:hover { background: #3a3a5a; }');
  h.push('  [data-theme="dark"] .memo-card { background: #16213e; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }');
  h.push('  [data-theme="dark"] .memo-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.5); }');
  h.push('  [data-theme="dark"] .memo-card h3 { color: #e0e0e0; }');
  h.push('  [data-theme="dark"] .memo-card p { color: #b0b0b0; }');
  h.push('  [data-theme="dark"] .memo-card .time { color: #707070; }');
  h.push('  [data-theme="dark"] .card-actions button { color: #909090; }');
  h.push('  [data-theme="dark"] .card-actions button:hover { background: #2a2a4a; color: #e0e0e0; }');
  h.push('  [data-theme="dark"] .modal { background: #16213e; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }');
  h.push('  [data-theme="dark"] .modal h2 { color: #e0e0e0; }');
  h.push('  [data-theme="dark"] .modal .field label { color: #b0b0b0; }');
  h.push('  [data-theme="dark"] .modal .field input,');
  h.push('  [data-theme="dark"] .modal .field textarea { background: #1a1a2e; color: #e0e0e0; border-color: #3a3a5a; }');
  h.push('  [data-theme="dark"] .modal .field input:focus,');
  h.push('  [data-theme="dark"] .modal .field textarea:focus { border-color: #667eea; }');
  h.push('  [data-theme="dark"] .btn-cancel { background: #2a2a4a; color: #b0b0b0; }');
  h.push('  [data-theme="dark"] .btn-cancel:hover { background: #3a3a5a; }');
  h.push('  [data-theme="dark"] .char-count { color: #707070; }');
  h.push('  [data-theme="dark"] .empty { color: #707070; }');
  h.push('  [data-theme="dark"] .modal-overlay { background: rgba(0,0,0,0.7); }');
  h.push('</style>');
  h.push('</head>');
  h.push('<body>');
  h.push('<div class="header">');
  h.push('  <h1>\u{1F4DD} 我的备忘录</h1>');
  h.push('  <div class="actions">');
  h.push('    <span class="user" id="usernameDisplay"></span>');
  h.push('    <button class="btn-new" id="newMemoBtn">\u{FF0B}</button>');
  h.push('    <button class="btn-theme" id="themeToggle" title="切换深色模式">🌙</button>');
  h.push('    <button class="btn-logout" id="logoutBtn">退出</button>');
  h.push('  </div>');
  h.push('</div>');
  h.push('<div class="container" id="memoList"></div>');
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
  h.push('    <div class="modal-btns">');
  h.push('      <button class="btn-delete-inline" id="deleteMemoBtn" style="display:none;">删除</button>');
  h.push('      <button class="btn-cancel" id="cancelBtn">取消</button>');
  h.push('      <button class="btn-save" id="saveBtn">保存</button>');
  h.push('    </div>');
  h.push('  </div>');
  h.push('</div>');
  h.push('');
  h.push('<script>');
  h.push('(function(){');
  h.push('// ── 初始化 ───');
  h.push('var currentUser = "";');
  h.push('var memosCache = [];');
  h.push('var isSaving = false;');
  h.push('');
  h.push('async function init() {');
  h.push('  try {');
  h.push('    var res = await fetch("/api/me");');
  h.push('    if (res.ok) {');
  h.push('      var data = await res.json();');
  h.push('      currentUser = data.username;');
  h.push('      document.getElementById("usernameDisplay").textContent = currentUser;');
  h.push('      loadMemos();');
  h.push('    } else {');
  h.push('      window.location.href = "/";');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    window.location.href = "/";');
  h.push('  }');
  h.push('}');
  h.push('');
  h.push('// ── 加载备忘录列表 ───');
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
h.push('  if (memosCache.length === 0) {');
h.push('    container.innerHTML = "<div class=\\"empty\\">还没有备忘录，点击右上角「新建」开始</div>";');
h.push('    return;');
h.push('  }');
h.push('  container.innerHTML = memosCache.map(function(m) {');
h.push('    var date = new Date(m.updatedAt).toLocaleString("zh-CN");');
h.push('    var card = "<div class=\\"memo-card\\">";');
h.push('    card += "<h3>" + escapeHtml(m.title || "(无标题)") + "</h3>";');
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
h.push('}');
h.push('');
h.push('function escapeHtml(text) {');
  h.push('  var div = document.createElement("div");');
  h.push('  div.textContent = text;');
  h.push('  return div.innerHTML;');
  h.push('}');
  h.push('');
  h.push('// ── 模态框 ───');
  h.push('var modalOverlay = document.getElementById("modalOverlay");');
  h.push('var modalTitle = document.getElementById("modalTitle");');
  h.push('var editMemoId = document.getElementById("editMemoId");');
  h.push('var memoTitle = document.getElementById("memoTitle");');
  h.push('var memoContent = document.getElementById("memoContent");');
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
  h.push('      else { alert("加载失败，请重试"); closeModal(); loadMemos(); return; }');
  h.push('    } catch(e) { alert("网络错误，请重试"); closeModal(); loadMemos(); return; }');
  h.push('  }');
  h.push('  var memo = memos.find(function(m) { return m.id === id; });');
  h.push('  if (memo) {');
  h.push('    memoTitle.value = memo.title;');
  h.push('    memoContent.value = memo.content;');
  h.push('  } else {');
  h.push('    alert("该备忘录不存在或已被删除");');
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
  h.push('    alert("请至少填写标题或内容");');
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
  h.push('        body: JSON.stringify({ title: title, content: content })');
  h.push('      });');
  h.push('    } else {');
  h.push('      res = await fetch("/api/memos", {');
  h.push('        method: "POST",');
  h.push('        headers: { "Content-Type": "application/json" },');
  h.push('        body: JSON.stringify({ title: title, content: content })');
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
h.push('      } else {');
h.push('        memosCache.push(memo);');
h.push('        memosCache.sort(function(a,b){ return b.updatedAt - a.updatedAt; });');
h.push('      }');
h.push('      closeModal();');
h.push('      renderMemoList();');
h.push('    } else {');
  h.push('      var err = await res.json();');
  h.push('      alert(err.error || "保存失败");');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    alert("网络错误");');
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
  h.push('      alert("删除失败");');
  h.push('    }');
  h.push('  } catch(e) {');
  h.push('    alert("网络错误");');
  h.push('  }');
  h.push('}');
  h.push('');
  h.push('function copyMemoContent(id) {');
  h.push('  var memo = memosCache.find(function(m) { return m.id === id; });');
  h.push('  if (!memo) { alert("备忘录不存在"); return; }');
  h.push('  var text = (memo.title || "") + "\\n" + (memo.content || "");');
  h.push('  navigator.clipboard.writeText(text).then(function() {');
  h.push('    alert("已复制到剪贴板");');
  h.push('  }, function() {');
  h.push('    alert("复制失败，请手动复制");');
  h.push('  });');
  h.push('}');
  h.push('');
  h.push('// ── 事件绑定 ───');
  h.push('document.getElementById("newMemoBtn").addEventListener("click", openNewModal);');
  h.push('document.getElementById("cancelBtn").addEventListener("click", closeModal);');
  h.push('modalOverlay.addEventListener("click", function(e) {');
  h.push('  if (e.target === modalOverlay) closeModal();');
  h.push('});');
  h.push('document.getElementById("saveBtn").addEventListener("click", saveMemo);');
  h.push('document.getElementById("deleteMemoBtn").addEventListener("click", function() {');
  h.push('  var id = editMemoId.value;');
  h.push('  if (id && confirm("确定要删除这条备忘录吗？")) {');
  h.push('    fetch("/api/memos/" + id, { method: "DELETE" }).then(function(r) {');
  h.push('      if (r.status === 401) { window.location.href = "/"; return; }');
  h.push('      if (r.ok) { memosCache = memosCache.filter(function(m) { return m.id !== id; }); closeModal(); renderMemoList(); }');
  h.push('      else alert("删除失败");');
  h.push('    });');
  h.push('  }');
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
  h.push('  if (e.key === "Escape" && modalOverlay.classList.contains("active")) {');
  h.push('    closeModal();');
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
