import { SELF, reset, env } from "cloudflare:test";
import { describe, it, expect, afterEach } from "vitest";

const BASE = "http://localhost";
const CRED = { username: "admin", password: "memo2024" };

async function login() {
  const res = await SELF.fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(CRED),
  });
  const cookie = res.headers.get("Set-Cookie");
  return { res, cookie };
}

async function authedFetch(path, opts) {
  const { cookie } = await login();
  const headers = { ...opts?.headers, Cookie: cookie };
  return SELF.fetch(`${BASE}${path}`, { ...opts, headers });
}

// 已登录 + 已通过隐藏密码验证（携带 cf_memo_session + cf_memo_hidden 双 cookie）
async function hiddenAuthFetch(path, opts) {
  const { cookie: session } = await login();
  const hauth = await SELF.fetch(`${BASE}/api/hidden-auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: session },
    body: JSON.stringify({ password: "hidden2026" }),
  });
  expect(hauth.status).toBe(200);
  const hiddenCookie = hauth.headers.get("Set-Cookie");
  const headers = { ...opts?.headers, Cookie: `${session}; ${hiddenCookie}` };
  return SELF.fetch(`${BASE}${path}`, { ...opts, headers });
}

afterEach(async () => {
  await reset();
});

// ── Auth ───
describe("Auth", () => {
  it("拒绝无认证请求", async () => {
    const res = await SELF.fetch(`${BASE}/api/memos`);
    expect(res.status).toBe(401);
  });

  it("正确凭据返回 200", async () => {
    const { res } = await login();
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.username).toBe("admin");
  });

  it("错误密码返回 401", async () => {
    const res = await SELF.fetch(`${BASE}/api/login`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  it("空用户名返回 400", async () => {
    const res = await SELF.fetch(`${BASE}/api/login`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "", password: "x" }),
    });
    expect(res.status).toBe(400);
  });

  it("登录速率限制 5 次后触发", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await SELF.fetch(`${BASE}/api/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "admin", password: "wrong" }),
      });
      expect(res.status).toBe(401);
    }
    const res = await SELF.fetch(`${BASE}/api/login`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(CRED),
    });
    expect(res.status).toBe(429);
  });

  it("/api/me 返回当前用户", async () => {
    const { cookie } = await login();
    const res = await SELF.fetch(`${BASE}/api/me`, { headers: { Cookie: cookie } });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.username).toBe("admin");
  });
});

// ── Memo CRUD ───
describe("Memo CRUD", () => {
  it("创建备忘录", async () => {
    const res = await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Test", content: "Hello" }),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.title).toBe("Test");
    expect(data.content).toBe("Hello");
  });

  it("列表返回已创建的备忘录", async () => {
    await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "A" }),
    });
    const res = await authedFetch("/api/memos");
    expect(res.status).toBe(200);
    const list = await res.json();
    expect(list.length).toBe(1);
    expect(list[0].title).toBe("A");
  });

  it("更新备忘录", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Old", content: "x" }),
    })).json();
    const res = await authedFetch(`/api/memos/${created.id}`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "New", content: "y" }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.title).toBe("New");
    expect(data.content).toBe("y");
  });

  it("删除备忘录", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Del" }),
    })).json();
    const del = await authedFetch(`/api/memos/${created.id}`, { method: "DELETE" });
    expect(del.status).toBe(200);
    const list = await (await authedFetch("/api/memos")).json();
    expect(list.length).toBe(0);
  });

  it("创建时缺失 title 返回 400", async () => {
    const res = await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("获取不存在的备忘录返回 404", async () => {
    const res = await authedFetch("/api/memos/nonexistent123");
    expect(res.status).toBe(404);
  });

  it("标题超过 500 字符返回 400", async () => {
    const res = await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "x".repeat(501), content: "ok" }),
    });
    expect(res.status).toBe(400);
  });
});

// ── 分享 ───
describe("Share", () => {
  it("分享已创建的备忘录", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "共享", content: "test" }),
    })).json();
    const res = await authedFetch(`/api/memos/${created.id}/share`, { method: "POST" });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.shareToken).toBeTruthy();
    expect(data.url).toContain("/share/");
  });

  it("分享后可通过链接访问", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "公开", content: "hello world" }),
    })).json();
    const share = await (await authedFetch(`/api/memos/${created.id}/share`, { method: "POST" })).json();
    const res = await SELF.fetch(`${BASE}${share.url}`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("公开");
    expect(text).toContain("hello world");
  });

  it("取消分享后链接失效", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "取消", content: "gone" }),
    })).json();
    const share = await (await authedFetch(`/api/memos/${created.id}/share`, { method: "POST" })).json();
    const del = await authedFetch(`/api/memos/${created.id}/share`, { method: "DELETE" });
    expect(del.status).toBe(200);
    const res = await SELF.fetch(`${BASE}${share.url}`);
    expect(res.status).toBe(404);
  });
});

// ── 文件夹 ───
describe("Folders", () => {
  it("创建文件夹", async () => {
    const res = await authedFetch("/api/folders", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "工作" }),
    });
    expect(res.status).toBe(201);
  });

  it("列表返回已创建的文件夹", async () => {
    await authedFetch("/api/folders", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "个人" }),
    });
    const res = await authedFetch("/api/folders");
    expect(res.status).toBe(200);
    const list = await res.json();
    expect(list.length).toBe(1);
    expect(list[0].name).toBe("个人");
  });
});

// ── 星标 ───
describe("Star", () => {
  it("星标切换后 starred 字段翻转", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "星标测试" }),
    })).json();
    const res = await authedFetch(`/api/memos/${created.id}/star`, { method: "PUT" });
    expect(res.status).toBe(200);
    const starred = await res.json();
    expect(starred.starred).toBe(true);
    const res2 = await authedFetch(`/api/memos/${created.id}/star`, { method: "PUT" });
    const unstarred = await res2.json();
    expect(unstarred.starred).toBe(false);
  });

  it("星标备忘录在列表中 starred 为 true", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "重要" }),
    })).json();
    await authedFetch(`/api/memos/${created.id}/star`, { method: "PUT" });
    const list = await (await authedFetch("/api/memos")).json();
    const m = list.find(x => x.id === created.id);
    expect(m.starred).toBe(true);
  });
});

describe("Expand/Collapse", () => {
  it("默认折叠，切换后 expanded 翻转并持久化到列表", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "折叠测试" }),
    })).json();
    let list = await (await authedFetch("/api/memos")).json();
    expect(list.find(x => x.id === created.id).expanded).toBe(false);

    const res = await authedFetch(`/api/memos/${created.id}/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: true })
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.expanded).toBe(true);

    list = await (await authedFetch("/api/memos")).json();
    expect(list.find(x => x.id === created.id).expanded).toBe(true);

    await authedFetch(`/api/memos/${created.id}/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: false })
    });
    list = await (await authedFetch("/api/memos")).json();
    expect(list.find(x => x.id === created.id).expanded).toBe(false);
  });

  it("隐藏备忘录的 expanded 状态同样持久化", async () => {
    const created = await (await hiddenAuthFetch("/api/hidden-memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "隐藏折叠" }),
    })).json();
    await authedFetch(`/api/memos/${created.id}/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: true })
    });
    const list = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(list.find(x => x.id === created.id).expanded).toBe(true);
  });

  it("expanded 非布尔值返回 400，删除 memo 后不残留展开状态", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "清理测试" }),
    })).json();
    await authedFetch(`/api/memos/${created.id}/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: true })
    });
    const bad = await authedFetch(`/api/memos/${created.id}/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: "yes" })
    });
    expect(bad.status).toBe(400);

    const missing = await authedFetch(`/api/memos/nonexistent_id/expand`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ expanded: true })
    });
    expect(missing.status).toBe(404);

    await authedFetch(`/api/memos/${created.id}`, { method: "DELETE" });
    const fresh = await (await authedFetch("/api/memos?t=" + Date.now())).json();
    expect(fresh.find(x => x.id === created.id)).toBeUndefined();
  });
});

// ── 隐藏备忘录 ───
describe("Hidden Memo", () => {
  async function createHidden(title, content) {
    const res = await hiddenAuthFetch("/api/hidden-memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, content }),
    });
    expect(res.status).toBe(201);
    return res.json();
  }

  it("无隐藏授权时 view=hidden 返回 403", async () => {
    const res = await authedFetch("/api/memos?view=hidden");
    expect(res.status).toBe(403);
  });

  it("隐藏密码错误返回 401", async () => {
    const { cookie } = await login();
    const res = await SELF.fetch(`${BASE}/api/hidden-auth`, {
      method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({ password: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  it("创建隐藏备忘录返回 hidden:true", async () => {
    const m = await createHidden("机密", "绝密内容");
    expect(m.hidden).toBe(true);
    expect(m.id).toBeTruthy();
  });

  it("KV 中存储的是密文而非明文", async () => {
    const m = await createHidden("绝密标题XYZ", "绝密内容ABC");
    const raw = await env.MEMOS_KV.get("sc:" + m.id);
    expect(raw).toBeTruthy();
    expect(raw).not.toContain("绝密标题XYZ");
    expect(raw).not.toContain("绝密内容ABC");
  });

  it("普通列表不包含隐藏备忘录", async () => {
    await createHidden("隐藏项", "secret");
    const list = await (await authedFetch("/api/memos")).json();
    expect(list.length).toBe(0);
  });

  it("view=hidden 列表返回解密后的明文", async () => {
    await createHidden("机密", "内容可见");
    const res = await hiddenAuthFetch("/api/memos?view=hidden");
    expect(res.status).toBe(200);
    const list = await res.json();
    expect(list.length).toBe(1);
    expect(list[0].title).toBe("机密");
    expect(list[0].content).toBe("内容可见");
  });

  it("获取单个隐藏备忘录", async () => {
    const m = await createHidden("single", "body");
    const res = await hiddenAuthFetch(`/api/hidden-memos/${m.id}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.title).toBe("single");
  });

  it("更新隐藏备忘录", async () => {
    const m = await createHidden("旧", "x");
    const res = await hiddenAuthFetch(`/api/hidden-memos/${m.id}`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "新", content: "y" }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.title).toBe("新");
    expect(data.content).toBe("y");
    const list = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(list.length).toBe(1);
    expect(list[0].title).toBe("新");
  });

  it("删除隐藏备忘录", async () => {
    const m = await createHidden("删除", "x");
    const del = await hiddenAuthFetch(`/api/hidden-memos/${m.id}`, { method: "DELETE" });
    expect(del.status).toBe(200);
    const list = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(list.length).toBe(0);
  });

  it("普通接口无法读写隐藏备忘录", async () => {
    const m = await createHidden("隔离", "x");
    const get = await authedFetch(`/api/memos/${m.id}`);
    expect(get.status).toBe(404);
    const del = await authedFetch(`/api/memos/${m.id}`, { method: "DELETE" });
    expect(del.status).toBe(404);
  });

  it("篡改密文后返回 500", async () => {
    const m = await createHidden("tamper", "x");
    const raw = await env.MEMOS_KV.get("sc:" + m.id);
    await env.MEMOS_KV.put("sc:" + m.id, raw.slice(0, -4) + "AAAA");
    const res = await hiddenAuthFetch(`/api/hidden-memos/${m.id}`);
    expect(res.status).toBe(500);
  });

  it("应用页面包含「隐藏」侧边栏入口", async () => {
    const res = await authedFetch("/");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('data-folder="hidden"');
    expect(html).toContain("隐藏");
  });

  it("无隐藏授权时无法将普通备忘录隐藏（403）", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "H0", content: "x" }),
    })).json();
    const res = await authedFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: true }),
    });
    expect(res.status).toBe(403);
  });

  it("将普通备忘录隐藏后移出普通列表并保留分类", async () => {
    const folder = await (await authedFetch("/api/folders", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "工作" }),
    })).json();
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "H1", content: "hidden body", folderIds: [folder.id] }),
    })).json();
    const res = await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: true }),
    });
    expect(res.status).toBe(200);
    const memos = await (await authedFetch("/api/memos")).json();
    expect(memos.length).toBe(0);
    const hidden = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(hidden.length).toBe(1);
    expect(hidden[0].title).toBe("H1");
    expect(hidden[0].folderIds).toEqual([folder.id]);
  });

  it("隐藏后分享令牌被清除，分享链接失效", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "share", content: "x" }),
    })).json();
    const share = await (await authedFetch(`/api/memos/${created.id}/share`, { method: "POST" })).json();
    await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: true }),
    });
    const hidden = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(hidden[0].shareToken).toBeUndefined();
    const page = await SELF.fetch(`${BASE}/share/${share.shareToken}`);
    expect(page.status).toBe(404);
  });

  it("取消隐藏后恢复正常列表并保留分类", async () => {
    const folder = await (await authedFetch("/api/folders", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "工作" }),
    })).json();
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "U", content: "x", folderIds: [folder.id] }),
    })).json();
    await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: true }),
    });
    const res2 = await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: false }),
    });
    expect(res2.status).toBe(200);
    const memos = await (await authedFetch("/api/memos")).json();
    expect(memos.length).toBe(1);
    expect(memos[0].title).toBe("U");
    expect(memos[0].folderIds).toEqual([folder.id]);
    const hidden = await (await hiddenAuthFetch("/api/memos?view=hidden")).json();
    expect(hidden.length).toBe(0);
  });

  it("取消隐藏后旧分享链接不会复活，分享持久失效", async () => {
    const created = await (await authedFetch("/api/memos", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "revive", content: "x" }),
    })).json();
    const share = await (await authedFetch(`/api/memos/${created.id}/share`, { method: "POST" })).json();
    await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: true }),
    });
    await hiddenAuthFetch(`/api/memos/${created.id}/hidden`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hidden: false }),
    });
    const page = await SELF.fetch(`${BASE}/share/${share.shareToken}`);
    expect(page.status).toBe(404);
  });

  it("未登录直接调用隐藏授权接口被拒绝", async () => {
    const res = await SELF.fetch(`${BASE}/api/hidden-auth`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "hidden2026" }),
    });
    expect(res.status).toBe(401);
  });
});
