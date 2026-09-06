# 📝 CF Memo - Cloudflare Worker 备忘录应用

基于 Cloudflare Worker + KV 的轻量级备忘录应用，通过预设环境变量实现单用户登录认证。

## 功能特性

- **预设账号登录** — 通过环境变量 `USERNAME` / `PASSWORD` 登录，无需注册流程
- **安全会话管理** — 基于 Web Crypto HMAC-SHA256 的 Session 令牌，24 小时有效期
- **备忘录 CRUD** — 新建、编辑、删除、列表展示，数据持久化到 Cloudflare KV
- **文件夹分类** — 创建/重命名/删除文件夹，支持批量分类（多选），拖拽移动备忘录到文件夹
- **星标收藏** — 标记重要备忘录，快速筛选星标条目
- **折叠/展开** — 长文摘要截断（码点安全），展开状态按条目持久化到 KV
- **隐藏备忘录** — 用 `HIDDEN_PASSWORD` 加密隐藏，正文以 AES-GCM 加密存储，需额外密码进入隐藏视图
- **公开分享** — 生成分享链接，支持取消分享，分享页自动跟随系统深色模式
- **批量操作** — 批量选中后一键分享/取消分享/删除
- **实时搜索** — 按标题和内容关键字过滤备忘录，列表无结果时提示会包含当前搜索词
- **列表展示优化** — 点击卡片任意位置即可打开编辑；列表接口与前端请求均使用 `Cache-Control: no-store`，避免浏览器缓存导致空列表或陈旧数据
- **深色模式** — 手动切换，偏好持久化
- **键盘快捷键** — `Ctrl+S` / `Enter` 保存，`Esc` 关闭弹窗
- **纯内嵌前端** — 单页应用，无需额外静态资源托管，登录/主界面合并在一个 Worker 中
- **安全防护** — Cookie 标记 `HttpOnly; Secure; SameSite=Lax`，前端 XSS 转义

## 项目结构

```
cf-memo/
├── README.md          # 本文件
├── package.json       # 脚本与开发依赖（vitest / wrangler）
├── wrangler.toml      # Cloudflare Worker 部署配置（已填 KV id）
├── src/
│   └── index.js       # Worker 全部逻辑 (路由/认证/CRUD/HTML)
└── test/
    └── index.test.js  # Vitest 测试
```

## 快速开始

### 1. 安装依赖

```bash
npm install
```

wrangler CLI 通过本地依赖提供，使用 `npx wrangler ...`（或 `npm run`）。

### 2. KV 命名空间（首次部署时执行一次）

```bash
npx wrangler login
npx wrangler kv namespace create MEMOS_KV
```

将输出的 `id` 填入 `wrangler.toml` 的 `kv_namespaces[0].id`（当前文件已含线上实例 id）：

```toml
kv_namespaces = [
  { binding = "MEMOS_KV", id = "你的KV_ID" }
]
```

### 3. 设置环境变量（生产环境）

使用 `npx wrangler secret` 安全存储敏感信息：

```bash
npx wrangler secret put USERNAME
# 输入: admin (或其他自定义用户名)

npx wrangler secret put PASSWORD
# 输入: 你的密码

npx wrangler secret put SESSION_SECRET
# 输入: 一个随机长字符串，用于 HMAC 签名
```

启用隐藏备忘录功能时，额外设置：

```bash
npx wrangler secret put HIDDEN_PASSWORD
# 输入: 隐藏视图的独立访问密码

npx wrangler secret put MEMO_ENCRYPT_KEY
# 输入: 32 字节密钥的 Base64 编码（AES-GCM 加密隐藏备忘录正文）
# 生成: openssl rand -base64 32
```

> ⚠️ **不要**在 `wrangler.toml` 的 `[vars]` 中硬编码生产环境密钥。

### 4. 本地开发

本地运行默认读取项目根目录的 `.dev.vars`（已 gitignore，不进版本库）。参考 `.env` 示例创建：

```toml
# .dev.vars
USERNAME = "admin"
PASSWORD = "memo2024"
SESSION_SECRET = "dev-secret-change-me"
HIDDEN_PASSWORD = "hidden-memo-password"          # 可选
MEMO_ENCRYPT_KEY = "base64-encoded-32-byte-key"   # 可选，即 `openssl rand -base64 32` 的输出
```

> MEMO_ENCRYPT_KEY 由 `openssl rand -base64 32` 生成，`wrangler secret put` 与 `.dev.vars` 中填同一字符串。

```bash
npx wrangler dev
```

访问 `http://localhost:8787` 即可看到登录页面。

### 5. 部署到 Cloudflare

```bash
npm run deploy   # 等价于: npx wrangler deploy
```

### 6. 运行测试

```bash
npm test         # 等价于: npx vitest
```

## API 接口

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/api/login` | ❌ | 登录，body: `{ username, password }` |
| `POST` | `/api/logout` | ✅ | 登出，清除 Session Cookie |
| `GET` | `/api/me` | ✅ | 获取当前登录用户信息 |
| `GET` | `/api/memos` | ✅ | 获取所有备忘录列表，`?view=hidden` 返回隐藏备忘录 |
| `POST` | `/api/memos` | ✅ | 新建备忘录，body: `{ title, content, folderIds? }` |
| `PUT` | `/api/memos/:id` | ✅ | 更新指定备忘录，body: `{ title, content, folderIds?, shareToken? }` |
| `DELETE` | `/api/memos/:id` | ✅ | 删除指定备忘录 |
| `PUT` | `/api/memos/:id/hidden` | ✅ | 切换备忘录隐藏状态 |
| `GET` | `/api/folders` | ✅ | 获取所有文件夹列表 |
| `POST` | `/api/folders` | ✅ | 新建文件夹，body: `{ name }` |
| `PUT` | `/api/folders/:id` | ✅ | 重命名文件夹 |
| `DELETE` | `/api/folders/:id` | ✅ | 删除文件夹（同时清除其下备忘录的 folderIds） |
| `POST` | `/api/hidden-auth` | ✅ | 验证隐藏密码，创建隐藏视图会话 Cookie `cf_memo_hidden` |
| `POST` | `/api/hidden-logout` | ✅ | 退出隐藏视图 |
| `GET` | `/api/hidden-memos` | ✅ | 读取所有隐藏备忘录（内部路由，需隐藏会话） |
| `POST` | `/api/hidden-memos` | ✅ | 新建隐藏备忘录，body: `{ title, content }` |
| `PUT` | `/api/hidden-memos/:id` | ✅ | 更新隐藏备忘录，body: `{ title, content }` |
| `DELETE` | `/api/hidden-memos/:id` | ✅ | 删除隐藏备忘录 |
| `PUT` | `/api/memos/:id/folder` | ✅ | 移动备忘录到指定文件夹，body: `{ folderId }`（旧版单分类接口） |
| `PUT` | `/api/memos/:id/star` | ✅ | 切换星标状态 |
| `POST` | `/api/memos/:id/share` | ✅ | 开启分享，返回 `{ url, shareToken }` |
| `DELETE` | `/api/memos/:id/share` | ✅ | 取消分享 |
| `PUT` | `/api/memos/:id/expand` | ✅ | 设置展开状态，body: `{ expanded }`，返回 `{ ok, expanded }` |
| `GET` | `/share/:token` | ❌ | 公开分享页面（无需认证） |

   > 未认证请求返回 `401 Unauthorized`；未登录用户访问页面会看到登录界面。

## 技术实现

- **运行时**: Cloudflare Workers (ES Modules)
- **存储**: Cloudflare KV（`memo:<UUID>` 存储普通备忘录，`sc:<UUID>` 存储隐藏/分享/星标等加密备忘录，`folder:<UUID>` 存储文件夹，`share:<token>` 记录分享映射，`expand:<memoId>` 存储展开状态）
- **认证**: 自定义 Session 令牌 = `用户名:时间戳:HMAC-SHA256签名`，无外部依赖；隐藏视图另设密码，隐藏会话 Cookie 独立存储
- **加密**: 隐藏备忘录正文使用 Web Crypto `AES-GCM` 加密（密钥来自 `MEMO_ENCRYPT_KEY`），数据库层面额外防护
- **缓存**: 列表接口返回 `Cache-Control: no-store`，前端所有列表请求显式禁用缓存，避免浏览器 HTTP 缓存导致空列表/陈旧数据
- **前端**: 原生 HTML/CSS/JS，无框架，侧边栏按文件夹筛选，支持拖拽分类、切换芯片选分类、键盘快捷键；点击卡片任意位置打开编辑
- **测试**: Vitest + 模拟 KV 环境，41 个测试覆盖核心接口

## 版本历史

| 版本 | 说明 |
|------|------|
| `V1.1.4` | 备忘录折叠/展开功能，展开状态按条目持久化 KV；编辑/星标/移动分类保留展开状态；展开接口校验 memo 存在性 |
| `V1.1.3` | 搜索无结果提示覆盖全部分类；「打开编辑」兜底请求统一 no-store 缓存策略 |
| `V1.1.2` | 完善 wrangler.toml 配置说明与 vars 示例 |
| `V1.1.1` | 修复列表空显示与点击条目无法打开 |
| `V1.1.0` | 添加 emoji favicon |
| `V1.0.9` | 弹窗背景滚动与桌面端左右独立滚动 |

## 许可证

MIT
