// 工单分派草稿保留回归测试的公共辅助：
// - 启动/停止随仓库提交的 case-dock 服务（临时数据目录、随机端口）
// - 通过登记接口准备工单
// - 驱动系统 Chrome 打开页面、查看工单详情
// - 在浏览器侧拦截分派请求：先挂起，待用户在等待期间完成编辑后，
//   再选择放行（真实服务处理）、返回失败状态或直接中断（模拟无法连接）
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import puppeteer from "puppeteer-core";

export const ROOT = path.resolve(import.meta.dirname, "..");
export const BIN = path.join(ROOT, "case-dock");
export const CHROME =
  process.env.CHROME_BIN || process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/google-chrome";

// ---- case-dock 服务 ----

export async function startServer() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "casedock-test-"));
  const proc = spawn(
    BIN,
    ["serve", "--host", "127.0.0.1", "--port", "0", "--data-dir", dir],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let base = "";
  let started = false;
  proc.stdout.on("data", (d) => {
    const m = /listening on (http:\/\/\S+)/.exec(String(d));
    if (m && !started) {
      started = true;
      base = m[1].replace(/\s+$/, "");
    }
  });
  let stderr = "";
  proc.stderr.on("data", (d) => {
    stderr += String(d);
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("服务启动超时\n" + stderr)), 10_000);
    proc.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`服务提前退出，退出码 ${code}\n${stderr}`));
    });
    const check = setInterval(() => {
      if (base) {
        clearInterval(check);
        clearTimeout(timer);
        resolve();
      }
    }, 20);
  });
  return {
    base,
    dir,
    async stop() {
      proc.kill("SIGTERM");
      await once(proc, "exit").catch(() => {});
      await rm(dir, { recursive: true, force: true });
    },
  };
}

// ---- 接口辅助 ----

let ticketSeq = 0;

export async function createTicket(base, opts = {}) {
  ticketSeq += 1;
  const payload = {
    description: opts.description ?? `回归测试工单 ${process.pid}-${ticketSeq}`,
    contactName: opts.contactName ?? "联系人甲",
    contactInfo: opts.contactInfo ?? "010-88886666",
    source: opts.source ?? "电话",
    category: opts.category ?? "账号",
    priority: opts.priority ?? "高",
    attachmentNote: opts.attachmentNote ?? "",
    orderNumber: opts.orderNumber ?? "",
    ...(opts.fields || {}),
    submitId:
      opts.submitId ??
      `test-sub-${process.pid}-${ticketSeq}-${Math.random().toString(36).slice(2, 8)}`,
  };
  const resp = await fetch(`${base}/api/tickets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(`登记工单失败：HTTP ${resp.status} ${JSON.stringify(data)}`);
  return data;
}

export async function getTicket(base, id) {
  const resp = await fetch(`${base}/api/tickets`);
  const data = await resp.json();
  const t = data.tickets.find((t) => t.id === id);
  if (!t) return null;
  // 从未分派过的工单，接口返回 assignments 为 null（Go nil 切片），统一为空数组。
  t.assignments = Array.isArray(t.assignments) ? t.assignments : [];
  return t;
}

let opSeq = 0;

// 绕过页面直接调用分派接口，用于准备“已有负责人”的前置状态。
export async function assignViaApi(base, id, assignee) {
  opSeq += 1;
  const resp = await fetch(`${base}/api/tickets/${id}/assignment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      assignee,
      operationId: `api-op-${process.pid}-${opSeq}-${Math.random().toString(36).slice(2, 8)}`,
    }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(`接口分派失败：HTTP ${resp.status} ${JSON.stringify(data)}`);
  return data;
}

// 页面展示的最近处理时间精度（与 page.go 的 fmtTime 保持一致）。
export function fmtMinute(s) {
  return String(s || "").replace("T", " ").slice(0, 16);
}

// ---- 浏览器 ----

export async function launchBrowser() {
  return puppeteer.launch({
    executablePath: CHROME,
    headless: process.env.HEADFUL ? false : true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
  });
}

export async function openApp(browser, base) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  await page.goto(base, { waitUntil: "networkidle0" });
  // 列表初次加载结束：出现表格或空状态占位。
  await page.waitForSelector("#list-area table, #list-area .empty", { timeout: 5_000 });
  return page;
}

// 重新加载页面并等待列表渲染（用例通过接口准备数据后调用）。
export async function reloadApp(page) {
  await page.reload({ waitUntil: "networkidle0" });
  await page.waitForSelector("#list-area table", { timeout: 5_000 });
}

// 打开列表中指定工单的详情。
export async function openDetail(page, ticketId) {
  await page.evaluate((id) => {
    const row = [...document.querySelectorAll("#list-area table tbody tr")].find(
      (r) => r.cells[0].textContent.trim() === id,
    );
    if (!row) throw new Error("列表中找不到工单 " + id);
    row.querySelector("button[data-i]").click();
  }, ticketId);
  await page.waitForSelector("#assign-form", { timeout: 5_000 });
}

// ---- 分派请求闸门：等待期间先挂起，再由测试决定结果 ----

export function installAssignGate(page) {
  const held = [];
  let holding = false;

  page.on("request", (req) => {
    let pathname = req.url();
    try {
      pathname = new URL(req.url()).pathname;
    } catch {
      // 保持原始 URL 文本参与判断
    }
    const isAssign = req.method() === "POST" && /\/assignment\/?$/.test(pathname);
    if (!isAssign || !holding) {
      void req.continue();
      return;
    }
    let body = {};
    try {
      body = JSON.parse(req.postData() || "{}");
    } catch {
      // 请求体不是 JSON 时保留原始文本
      body = { raw: req.postData() };
    }
    held.push({ req, body });
  });

  async function settle(target, apply) {
    const item = typeof target === "number" ? held[target] : held.shift();
    if (!item) throw new Error("没有挂起中的分派请求");
    const idx = held.indexOf(item);
    if (idx >= 0) held.splice(idx, 1);
    return apply(item.req);
  }

  return {
    async enable() {
      await page.setRequestInterception(true);
    },
    hold() {
      holding = true;
    },
    releaseAll() {
      holding = false;
    },
    pending() {
      return held.length;
    },
    heldAt(i) {
      return held[i]?.body;
    },
    async waitForPending(n = 1, timeout = 3_000) {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        if (held.length >= n) return;
        await new Promise((r) => setTimeout(r, 15));
      }
      throw new Error(`等待挂起的分派请求超时（已有 ${held.length}，期望 ${n}）`);
    },
    release(target = 0) {
      return settle(target, (req) => req.continue());
    },
    fail(target = 0, status = 500, error = "unable to save assignment") {
      return settle(target, (req) =>
        req.respond({
          status,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({ error }),
        }),
      );
    },
    abort(target = 0) {
      return settle(target, (req) => req.abort());
    },
  };
}

// ---- 详情页操作 ----

// 用真实键盘事件写入负责人（会触发页面的 input 监听），并点击提交。
export async function submitAssignment(page, rawValue) {
  await page.evaluate(() => {
    const i = document.getElementById("f-assignee");
    i.focus();
    i.select();
  });
  await page.keyboard.press("Delete");
  if (rawValue) await page.keyboard.type(rawValue, { delay: 5 });
  await page.click("#assign-btn");
}

// 等待期间改动输入框（模拟用户继续填写），全部走真实键盘以产生 input 事件。
// mode=replace 先全选再键入；mode=append 直接在当前内容后追加。
export async function editAssignee(page, rawValue, mode = "replace") {
  await page.focus("#f-assignee");
  if (mode === "replace") {
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.keyboard.press("Delete");
  }
  if (rawValue) await page.keyboard.type(rawValue, { delay: 5 });
}

// 用真实键盘清空输入框（触发 input 事件）。
export async function clearAssignee(page) {
  await page.evaluate(() => {
    const i = document.getElementById("f-assignee");
    i.focus();
    i.select();
  });
  await page.keyboard.press("Backspace");
}

export async function waitForButtonWaiting(page) {
  await page.waitForFunction(
    () => {
      const b = document.getElementById("assign-btn");
      return b && b.disabled && b.textContent.includes("正在分派");
    },
    { timeout: 3_000 },
  );
}

export async function waitForButtonIdle(page, timeout = 5_000) {
  await page.waitForFunction(
    () => {
      const b = document.getElementById("assign-btn");
      return b && !b.disabled && b.textContent.trim() === "提交分派";
    },
    { timeout },
  );
}

export async function waitForNoticeKind(page, kind, timeout = 5_000) {
  await page.waitForFunction(
    (k) => {
      const n = document.getElementById("assign-notice");
      if (!n) return false;
      if (k === "any") return n.classList.contains("ok") || n.classList.contains("err");
      return n.classList.contains(k);
    },
    { timeout },
    kind,
  );
}

export async function getNotice(page) {
  return page.$eval("#assign-notice", (n) => ({
    kind: n.classList.contains("ok") ? "ok" : n.classList.contains("err") ? "err" : "",
    text: n.textContent,
  }));
}

export async function getInputValue(page) {
  return page.$eval("#f-assignee", (i) => i.value);
}

export async function getButton(page) {
  return page.$eval("#assign-btn", (b) => ({
    disabled: b.disabled,
    text: b.textContent.trim(),
  }));
}

// 详情中的字段（按 dt 文案取 dd）、分派记录与空记录占位。
export async function getDetail(page) {
  return page.evaluate(() => {
    const out = { fields: {}, history: [], historyEmpty: false };
    document.querySelectorAll("#detail dl dt").forEach((dt) => {
      out.fields[dt.textContent.trim()] = dt.nextElementSibling.textContent.trim();
    });
    out.history = [...document.querySelectorAll(".assign-history li")].map((li) =>
      li.textContent.replace(/\s+/g, " ").trim(),
    );
    out.historyEmpty = !!document.querySelector("#detail .assign-history .empty");
    return out;
  });
}

// 列表中指定工单的负责人与最近处理时间两列。
export async function getListRow(page, ticketId) {
  return page.evaluate((id) => {
    const row = [...document.querySelectorAll("#list-area table tbody tr")].find(
      (r) => r.cells[0].textContent.trim() === id,
    );
    if (!row) return null;
    return {
      id: row.cells[0].textContent.trim(),
      status: row.cells[4].textContent.trim(),
      assignee: row.cells[5].textContent.trim(),
      updated: row.cells[6].textContent.trim(),
    };
  }, ticketId);
}

// 点击提交按钮（用于校验失败、不发出请求的场景）。
export async function clickAssign(page) {
  await page.click("#assign-btn");
}

// 断言后续一段时间内没有新的分派请求（不自动二次分派/重试）。
export async function assertNoAssignmentSoon(gate, label, ms = 400) {
  await new Promise((r) => setTimeout(r, ms));
  if (gate.pending() !== 0) {
    throw new Error(`${label}：不应再发出分派请求，但检测到 ${gate.pending()} 个挂起请求`);
  }
}
