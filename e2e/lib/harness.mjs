// E2E 回归测试公共设施：
// - 启动真实的 Go 服务（随机端口、临时数据目录）；
// - 启动一个同源 Node HTTP 代理，浏览器只访问代理：普通接口原样转发，
//   分派接口可被门控（挂起后再决定放行成功 / 返回失败 / 中断连接），
//   从而确定性地复现“提交后等待结果期间继续填写”的场景。
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const here = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(here, "..", "..");
const binDir = path.join(here, "..", ".cache");
const binPath = path.join(binDir, "case-dock");

let built = false;
// ensureBinary 用当前源码构建测试用二进制；每个测试进程只构建一次。
export function ensureBinary() {
  if (built) return;
  fs.mkdirSync(binDir, { recursive: true });
  execFileSync("go", ["build", "-o", binPath, "."], { cwd: repoRoot, stdio: "inherit" });
  built = true;
}

const CHROME = process.env.CHROME_BIN || "/usr/bin/google-chrome";

export async function launchBrowser() {
  ensureBinary();
  return puppeteer.launch({
    executablePath: CHROME,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--no-first-run",
    ],
  });
}

function listenFree(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

// startGoServer 以临时数据目录启动真实服务，--port 0 让内核分配端口，
// 从启动日志解析实际端口。
async function startGoServer() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "casedock-e2e-"));
  const proc = spawn(binPath, ["serve", "--host", "127.0.0.1", "--port", "0", "--data-dir", dataDir], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const upstream = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("server start timeout")), 10000);
    proc.stdout.on("data", (chunk) => {
      const m = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(String(chunk));
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
    proc.on("exit", (code) => reject(new Error("server exited early with code " + code)));
  });
  return {
    upstream,
    async close() {
      proc.kill("SIGTERM");
      await new Promise((r) => proc.on("exit", r)).catch(() => {});
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

const HOP_HEADERS = new Set(["host", "connection", "content-length", "proxy-connection"]);

// startProxy 在随机端口启动同源反向代理。分派 POST 统一进入门控队列，
// 由测试代码决定每个挂起请求的去向；其他请求一律转发到真实服务。
async function startProxy(upstream) {
  const held = []; // 挂起的分派请求：{req, res, body}
  const waiters = [];
  const arrivals = []; // 所有到达过的分派请求（放行后也保留），按到达顺序
  let assignCount = 0;

  function pump() {
    while (waiters.length && held.length >= waiters[0].need) {
      const w = waiters.shift();
      w.resolve();
    }
  }

  async function forward(item) {
    const url = new URL(item.req.url, upstream);
    const headers = {};
    for (const [k, v] of Object.entries(item.req.headers)) {
      if (!HOP_HEADERS.has(k.toLowerCase())) headers[k] = v;
    }
    const upstreamResp = await fetch(url, {
      method: item.req.method,
      headers,
      body: item.body || undefined,
    });
    const respHeaders = {};
    upstreamResp.headers.forEach((v, k) => {
      if (!HOP_HEADERS.has(k.toLowerCase())) respHeaders[k] = v;
    });
    item.res.writeHead(upstreamResp.status, respHeaders);
    const buf = Buffer.from(await upstreamResp.arrayBuffer());
    item.res.end(buf);
    return { status: upstreamResp.status, body: JSON.parse(buf.toString("utf8") || "null") };
  }

  const server = http.createServer((req, res) => {
    if (req.method === "POST" && /\/api\/tickets\/[^/]+\/assignment$/.test(req.url)) {
      assignCount += 1;
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const item = { req, res, body: Buffer.concat(chunks).toString("utf8") };
        held.push(item);
        arrivals.push({ url: req.url, body: item.body });
        pump();
      });
      res.on("error", () => {});
      return;
    }
    // 非分派请求：原样转发。
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      try {
        const body = Buffer.concat(chunks);
        const url = new URL(req.url, upstream);
        const headers = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (!HOP_HEADERS.has(k.toLowerCase())) headers[k] = v;
        }
        const upstreamResp = await fetch(url, {
          method: req.method,
          headers,
          body: body.length ? body : undefined,
        });
        const respHeaders = {};
        upstreamResp.headers.forEach((v, k) => {
          if (!HOP_HEADERS.has(k.toLowerCase())) respHeaders[k] = v;
        });
        res.writeHead(upstreamResp.status, respHeaders);
        res.end(Buffer.from(await upstreamResp.arrayBuffer()));
      } catch (err) {
        if (!res.headersSent) res.writeHead(502);
        res.end(String(err));
      }
    });
  });
  server.on("clientError", (_err, socket) => socket.destroy());
  // 记录所有连接，关闭代理时强制销毁：测试侧 fetch 与浏览器的 keep-alive
  // 空闲连接会让 server.close() 一直等待，必须显式断开。
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await listenFree(server);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  return {
    base,
    // waitForHeld 等待 n 个分派请求被门控挂起（说明页面已处于等待结果状态）。
    waitForHeld(n = 1) {
      return new Promise((resolve) => {
        if (held.length >= n) return resolve();
        waiters.push({ need: n, resolve });
        pump();
      });
    },
    heldCount() {
      return held.length;
    },
    // arrivals 返回所有到达过的分派请求（含已放行的），按到达顺序解析。
    arrivals() {
      return arrivals.map((a) => {
        let body = {};
        try { body = JSON.parse(a.body); } catch { /* 保留空对象 */ }
        const m = /\/api\/tickets\/([^/]+)\/assignment/.exec(a.url);
        return { ticketId: decodeURIComponent(m?.[1] || ""), assignee: body.assignee, operationId: body.operationId };
      });
    },
    heldBody(index = 0) {
      return JSON.parse(held[index]?.body || "{}");
    },
    // releaseNext 放行最早挂起的分派请求：
    //  - 'forward'：转发到真实服务（默认）；
    //  - {status, error}：由代理直接回失败响应（如保存失败 500）；
    //  - 'destroy'：直接中断连接，模拟无法连接服务。
    async releaseNext(action = "forward") {
      const item = held.shift();
      if (action === "destroy") {
        // 模拟“无法连接服务”：先写入无法解析的响应字节再断开。
        // 直接 RST 会让 Chrome 在收到任何响应字节前自动重试同一个 POST；
        // 写入非法 HTTP 字节后浏览器立即判定为网络错误（ERR_INVALID_HTTP_RESPONSE），
        // fetch 进入 catch 且不会重试，语义等同服务不可达。
        const socket = item.res.socket;
        if (socket) {
          socket.write("X\r\n\r\n");
          socket.end();
          socket.destroy();
        } else {
          item.res.destroy();
        }
        return null;
      }
      if (action === "forward") {
        return forward(item);
      }
      const payload = JSON.stringify({ error: action.error || "unable to save assignment" });
      item.res.writeHead(action.status || 500, { "Content-Type": "application/json; charset=utf-8" });
      item.res.end(payload);
      return null;
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((r) => server.close(r));
    },
  };
}

// createHarness 为单个测试准备：真实服务 + 门控代理 + 独立浏览器标签页。
export async function createHarness(browser) {
  const go = await startGoServer();
  let proxy;
  try {
    proxy = await startProxy(go.upstream);
  } catch (err) {
    await go.close();
    throw err;
  }
  const page = await browser.newPage();
  await page.setCacheEnabled(false);
  return {
    base: proxy.base,
    upstream: go.upstream, // 直连真实服务，供测试做前置数据准备（不经过分派门控）
    page,
    proxy,
    async close() {
      await page.close().catch(() => {});
      await proxy.close().catch(() => {});
      await go.close().catch(() => {});
    },
  };
}
