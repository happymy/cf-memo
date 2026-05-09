# 📝 CF Memo - Cloudflare Worker 备忘录应用

基于 Cloudflare Worker + KV 的轻量级备忘录应用，通过预设环境变量实现单用户登录认证。

## 功能特性

- **预设账号登录** — 通过环境变量 `USERNAME` / `PASSWORD` 登录，无需注册流程
- **安全会话管理** — 基于 Web Crypto HMAC-SHA256 的 Session 令牌，24 小时有效期
- **备忘录 CRUD** — 新建、编辑、删除、列表展示，数据持久化到 Cloudflare KV
- **纯内嵌前端** — 单页应用，无需额外静态资源托管，登录/主界面合并在一个 Worker 中
- **安全防护** — Cookie 标记 `HttpOnly; Secure; SameSite=Lax`，前端 XSS 转义

## 项目结构

```
cf-memo/
├── README.md          # 本文件
├── wrangler.toml      # Cloudflare Worker 部署配置
└── src/
    └── index.js       # Worker 全部逻辑 (路由/认证/CRUD/HTML)
```

## 快速开始

### 1. 安装 Wrangler CLI

```bash
npm install -g wrangler
wrangler login
```

### 2. 创建 KV 命名空间

```bash
cd cf-memo
wrangler kv namespace create MEMOS_KV
```

记录输出中的 `id`，将其填入 `wrangler.toml` 的 `kv_namespaces[0].id` 字段：

```toml
kv_namespaces = [
  { binding = "MEMOS_KV", id = "你的KV_ID" }
]
```

### 3. 设置环境变量（生产环境）

使用 `wrangler secret` 安全存储敏感信息：

```bash
wrangler secret put USERNAME
# 输入: admin (或其他自定义用户名)

wrangler secret put PASSWORD
# 输入: 你的密码

wrangler secret put SESSION_SECRET
# 输入: 一个随机长字符串，用于 HMAC 签名
```

> ⚠️ **不要**在 `wrangler.toml` 的 `[vars]` 中硬编码生产环境密钥。

### 4. 本地开发（可选）

若需本地测试，可临时取消 `wrangler.toml` 中 `[vars]` 下的注释：

```toml
[vars]
USERNAME = "admin"
PASSWORD = "test123"
SESSION_SECRET = "dev-secret-change-me"
```

```bash
wrangler dev
```

访问 `http://localhost:8787` 即可看到登录页面。

### 5. 部署到 Cloudflare

```bash
wrangler deploy
```

## API 接口

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/api/login` | ❌ | 登录，body: `{ username, password }` |
| `POST` | `/api/logout` | ✅ | 登出，清除 Session Cookie |
| `GET` | `/api/me` | ✅ | 获取当前登录用户信息 |
| `GET` | `/api/memos` | ✅ | 获取所有备忘录列表 |
| `POST` | `/api/memos` | ✅ | 新建备忘录，body: `{ title, content }` |
| `PUT` | `/api/memos/:id` | ✅ | 更新指定备忘录 |
| `DELETE` | `/api/memos/:id` | ✅ | 删除指定备忘录 |

> 未认证请求返回 `401 Unauthorized`；未登录用户访问页面会看到登录界面。

## 技术实现

- **运行时**: Cloudflare Workers (ES Modules)
- **存储**: Cloudflare KV (键名格式 `memo:<UUID>`)
- **认证**: 自定义 Session 令牌 = `用户名:时间戳:HMAC-SHA256签名`，无外部依赖
- **前端**: 原生 HTML/CSS/JS，无框架，支持键盘快捷键（`Esc` 关闭模态框，`Ctrl+S` 保存）

## 许可证

MIT
