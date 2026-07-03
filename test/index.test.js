import { SELF, reset } from "cloudflare:test";
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
