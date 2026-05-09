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
  let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  if (options.path) cookie += `; Path=${options.path}`;
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
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

async function createSessionToken(username, secret) {
  const payload = `${username}:${Date.now()}`;
  const sig = await hmacSha256(payload, secret);
  return `${payload}:${sig}`;
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
        if (method === 'PUT') return handleUpdateMemo(request, memoId, env);
        if (method === 'DELETE') return handleDeleteMemo(memoId, env);
      }

      if (path === '/api/logout' && method === 'POST') {
        return handleLogout();
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
  const rateLimitKey = `ratelimit:login:${clientIP}`;
  let attempts = 0;
  try {
    const rawAttempts = await env.MEMOS_KV.get(rateLimitKey);
    if (rawAttempts) attempts = parseInt(rawAttempts, 10);
  } catch { /* 获取失败时允许继续 */ }
  if (attempts >= 5) {
    return json({ error: 'Too many login attempts. Please try again later.' }, 429);
  }

  if (username !== env.USERNAME || password !== env.PASSWORD) {
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
  const cookie = serializeCookie('cf_memo_session', token, {
    httpOnly: true,
    secure: true,
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

function handleLogout() {
  const cookie = serializeCookie('cf_memo_session', '', {
    httpOnly: true,
    secure: true,
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
  const list = await env.MEMOS_KV.list({ prefix: 'memo:' });
  const memos = [];
  for (const key of list.keys) {
    const raw = await env.MEMOS_KV.get(key.name);
    if (raw) {
      try {
        memos.push(JSON.parse(raw));
      } catch { /* 忽略损坏数据 */ }
    }
  }
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

  await env.MEMOS_KV.put(`memo:${memo.id}`, JSON.stringify(memo));
  return json(memo, 201);
}

async function handleUpdateMemo(request, memoId, env) {
  // 验证 memoId 格式
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) {
    return json({ error: 'Invalid memo id' }, 400);
  }
  // 先检查是否存在
  const existing = await env.MEMOS_KV.get(`memo:${memoId}`);
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

  const old = JSON.parse(existing);
  const updated = {
    ...old,
    title: body.title !== undefined ? body.title.trim() : old.title,
    content: body.content !== undefined ? body.content.trim() : old.content,
    updatedAt: Date.now(),
  };

  await env.MEMOS_KV.put(`memo:${memoId}`, JSON.stringify(updated));
  return json(updated);
}

async function handleDeleteMemo(memoId, env) {
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(memoId)) {
    return json({ error: 'Invalid memo id' }, 400);
  }
  const existing = await env.MEMOS_KV.get(`memo:${memoId}`);
  if (!existing) {
    return json({ error: 'Memo not found' }, 404);
  }
  await env.MEMOS_KV.delete(`memo:${memoId}`);
  return json({ ok: true });
}

// ── HTML 页面 ─────────────────────────────────────────────────────

function serveLoginPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>备忘录 - 登录</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .login-box {
    background: #fff;
    border-radius: 16px;
    padding: 40px 32px;
    width: 90%;
    max-width: 400px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.15);
  }
  h1 { text-align: center; color: #333; margin-bottom: 28px; font-size: 24px; }
  .field { margin-bottom: 18px; }
  .field label { display: block; margin-bottom: 6px; color: #555; font-size: 14px; font-weight: 500; }
  .field input {
    width: 100%;
    padding: 12px 14px;
    border: 1px solid #ddd;
    border-radius: 8px;
    font-size: 15px;
    transition: border-color 0.2s;
  }
  .field input:focus { outline: none; border-color: #667eea; }
  button {
    width: 100%;
    padding: 13px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
  }
  button:hover { opacity: 0.9; }
  button:active { opacity: 0.8; }
  .error { color: #e74c3c; text-align: center; margin-top: 12px; font-size: 14px; display: none; }
</style>
</head>
<body>
<div class="login-box">
  <h1>📝 备忘录登录</h1>
  <div class="field">
    <label for="username">用户名</label>
    <input id="username" type="text" placeholder="请输入用户名" autocomplete="username" autofocus>
  </div>
  <div class="field">
    <label for="password">密码</label>
    <input id="password" type="password" placeholder="请输入密码" autocomplete="current-password">
  </div>
  <button id="loginBtn">登 录</button>
  <div class="error" id="error"></div>
</div>
<script>
const errorEl = document.getElementById('error');
document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  if (!username || !password) {
    errorEl.textContent = '请输入用户名和密码';
    errorEl.style.display = 'block';
    return;
  }
  errorEl.style.display = 'none';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      window.location.href = '/';
    } else {
      errorEl.textContent = data.error || '登录失败';
      errorEl.style.display = 'block';
    }
  } catch {
    errorEl.textContent = '网络错误，请重试';
    errorEl.style.display = 'block';
  }
});
document.getElementById('password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('loginBtn').click();
});
</script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
      'Permissions-Policy': 'interest-cohort=()',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    },
  });
}

function serveAppPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>备忘录</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f5f6fa;
    color: #333;
    min-height: 100vh;
  }
  .header {
    background: #fff;
    border-bottom: 1px solid #e0e0e0;
    padding: 14px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .header h1 { font-size: 20px; }
  .header .actions { display: flex; gap: 10px; align-items: center; }
  .header .user { color: #888; font-size: 14px; }
  .header button {
    padding: 7px 16px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
  }
  .btn-new { background: #667eea; color: #fff; }
  .btn-new:hover { background: #5a6fd6; }
  .btn-logout { background: #eee; color: #555; }
  .btn-logout:hover { background: #ddd; }
  .container {
    max-width: 720px;
    margin: 24px auto;
    padding: 0 16px;
  }
  .memo-card {
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 14px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    transition: box-shadow 0.2s;
    position: relative;
  }
  .memo-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.1); }
  .memo-card h3 { margin-bottom: 8px; font-size: 17px; color: #222; }
  .memo-card p { color: #555; font-size: 14px; line-height: 1.6; white-space: pre-wrap; }
  .memo-card .time { color: #aaa; font-size: 12px; margin-top: 10px; }
  .memo-card .card-actions {
    position: absolute;
    top: 16px;
    right: 16px;
    display: flex;
    gap: 6px;
  }
  .card-actions button {
    background: none;
    border: none;
    font-size: 16px;
    cursor: pointer;
    padding: 4px 6px;
    border-radius: 4px;
    color: #888;
    transition: background 0.2s;
  }
  .card-actions button:hover { background: #f0f0f0; color: #333; }
  .empty { text-align: center; color: #aaa; padding: 60px 0; font-size: 15px; }
  
  /* Modal */
  .modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.4);
    z-index: 100;
    align-items: center;
    justify-content: center;
  }
  .modal-overlay.active { display: flex; }
  .modal {
    background: #fff;
    border-radius: 14px;
    padding: 28px 24px;
    width: 90%;
    max-width: 480px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.2);
  }
  .modal h2 { margin-bottom: 18px; font-size: 18px; }
  .modal .field { margin-bottom: 14px; }
  .modal .field label { display: block; margin-bottom: 5px; font-size: 13px; color: #666; font-weight: 500; }
  .modal .field input,
  .modal .field textarea {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #ddd;
    border-radius: 8px;
    font-size: 14px;
    font-family: inherit;
  }
  .modal .field textarea { resize: vertical; min-height: 100px; }
  .modal .field input:focus,
  .modal .field textarea:focus { outline: none; border-color: #667eea; }
  .modal .modal-btns { display: flex; gap: 10px; justify-content: flex-end; margin-top: 8px; }
  .modal .modal-btns button {
    padding: 9px 20px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    cursor: pointer;
    font-weight: 500;
  }
  .btn-save { background: #667eea; color: #fff; }
  .btn-save:hover { background: #5a6fd6; }
  .btn-cancel { background: #eee; color: #555; }
  .btn-cancel:hover { background: #ddd; }
  .btn-delete-inline { background: #e74c3c; color: #fff; margin-right: auto; }
  .btn-delete-inline:hover { background: #c0392b; }
</style>
</head>
<body>
<div class="header">
  <h1>📝 我的备忘录</h1>
  <div class="actions">
    <span class="user" id="usernameDisplay"></span>
    <button class="btn-new" id="newMemoBtn">＋ 新建</button>
    <button class="btn-logout" id="logoutBtn">退出</button>
  </div>
</div>
<div class="container" id="memoList"></div>

<!-- 编辑/新建模态框 -->
<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <h2 id="modalTitle">新建备忘录</h2>
    <input type="hidden" id="editMemoId">
    <div class="field">
      <label for="memoTitle">标题</label>
      <input id="memoTitle" type="text" placeholder="输入标题">
    </div>
    <div class="field">
      <label for="memoContent">内容</label>
      <textarea id="memoContent" placeholder="输入内容..."></textarea>
    </div>
    <div class="modal-btns">
      <button class="btn-delete-inline" id="deleteMemoBtn" style="display:none;">删除</button>
      <button class="btn-cancel" id="cancelBtn">取消</button>
      <button class="btn-save" id="saveBtn">保存</button>
    </div>
  </div>
</div>

<script>
// ── 初始化 ──────────────────────────────────
let currentUser = '';

async function init() {
  try {
    const res = await fetch('/api/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.username;
      document.getElementById('usernameDisplay').textContent = currentUser;
      loadMemos();
    } else {
      window.location.href = '/';
    }
  } catch {
    window.location.href = '/';
  }
}

// ── 加载备忘录列表 ──────────────────────────
async function loadMemos() {
  const container = document.getElementById('memoList');
  try {
    const res = await fetch('/api/memos');
    if (res.status === 401) { window.location.href = '/'; return; }
    const memos = await res.json();
    if (memos.length === 0) {
      container.innerHTML = '<div class="empty">还没有备忘录，点击右上角「新建」开始</div>';
      return;
    }
    container.innerHTML = memos.map(m => {
      const date = new Date(m.updatedAt).toLocaleString('zh-CN');
      return \`<div class="memo-card">
        <h3>\${escapeHtml(m.title || '(无标题)')}</h3>
        \${m.content ? '<p>' + escapeHtml(m.content) + '</p>' : '<p style="color:#ccc;">无内容</p>'}
        <div class="time">更新于 \${date}</div>
        <div class="card-actions">
          <button title="编辑" data-edit="\${m.id}">✏️</button>
          <button title="删除" data-delete="\${m.id}">🗑️</button>
        </div>
      </div>\`;
    }).join('');
    
    // 绑定事件
    container.querySelectorAll('[data-edit]').forEach(btn => {
      btn.addEventListener('click', () => openEditModal(btn.dataset.edit));
    });
    container.querySelectorAll('[data-delete]').forEach(btn => {
      btn.addEventListener('click', () => deleteMemoDirect(btn.dataset.delete));
    });
  } catch {
    container.innerHTML = '<div class="empty">加载失败，请刷新页面</div>';
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ── 模态框 ──────────────────────────────────
const modalOverlay = document.getElementById('modalOverlay');
const modalTitle = document.getElementById('modalTitle');
const editMemoId = document.getElementById('editMemoId');
const memoTitle = document.getElementById('memoTitle');
const memoContent = document.getElementById('memoContent');
const deleteBtn = document.getElementById('deleteMemoBtn');

function openNewModal() {
  modalTitle.textContent = '新建备忘录';
  editMemoId.value = '';
  memoTitle.value = '';
  memoContent.value = '';
  deleteBtn.style.display = 'none';
  modalOverlay.classList.add('active');
  memoTitle.focus();
}

async function openEditModal(id) {
  modalTitle.textContent = '编辑备忘录';
  editMemoId.value = id;
  deleteBtn.style.display = 'inline-block';
  try {
    const res = await fetch('/api/memos');
    if (res.ok) {
      const memos = await res.json();
      const memo = memos.find(m => m.id === id);
      if (memo) {
        memoTitle.value = memo.title;
        memoContent.value = memo.content;
      }
    }
  } catch { /* 忽略 */ }
  modalOverlay.classList.add('active');
  memoTitle.focus();
}

function closeModal() {
  modalOverlay.classList.remove('active');
}

async function saveMemo() {
  const id = editMemoId.value;
  const title = memoTitle.value.trim();
  const content = memoContent.value.trim();
  
  if (!title && !content) {
    alert('请至少填写标题或内容');
    return;
  }

  try {
    let res;
    if (id) {
      res = await fetch('/api/memos/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, content }),
      });
    } else {
      res = await fetch('/api/memos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, content }),
      });
    }
    if (res.ok) {
      closeModal();
      loadMemos();
    } else {
      const err = await res.json();
      alert(err.error || '保存失败');
    }
  } catch {
    alert('网络错误');
  }
}

async function deleteMemoDirect(id) {
  if (!confirm('确定要删除这条备忘录吗？')) return;
  try {
    const res = await fetch('/api/memos/' + id, { method: 'DELETE' });
    if (res.ok) {
      loadMemos();
    } else {
      alert('删除失败');
    }
  } catch {
    alert('网络错误');
  }
}

// ── 事件绑定 ────────────────────────────────
document.getElementById('newMemoBtn').addEventListener('click', openNewModal);
document.getElementById('cancelBtn').addEventListener('click', closeModal);
modalOverlay.addEventListener('click', (e) => {
  if (e.target === modalOverlay) closeModal();
});
document.getElementById('saveBtn').addEventListener('click', saveMemo);
document.getElementById('deleteBtn').addEventListener('click', () => {
  const id = editMemoId.value;
  if (id && confirm('确定要删除这条备忘录吗？')) {
    fetch('/api/memos/' + id, { method: 'DELETE' }).then(r => {
      if (r.ok) { closeModal(); loadMemos(); }
      else alert('删除失败');
    });
  }
});
document.getElementById('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
});

// 键盘快捷键
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && modalOverlay.classList.contains('active')) {
    closeModal();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 's' && modalOverlay.classList.contains('active')) {
    e.preventDefault();
    saveMemo();
  }
});

init();
</script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
      'Permissions-Policy': 'interest-cohort=()',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    },
  });
}
