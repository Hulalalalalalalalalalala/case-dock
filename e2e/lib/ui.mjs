// 页面驱动与状态读取：所有测试通过真实浏览器操作页面，不直接调用页面内部函数。
import assert from "node:assert/strict";

let seq = 0;
function uniq(prefix) {
  seq += 1;
  return `${prefix}-${process.pid}-${Date.now().toString(36)}-${seq}`;
}

// registerTicket 通过公开的登记接口建一张工单，返回接口确认的工单数据。
export async function registerTicket(h, overrides = {}) {
  const payload = {
    description: `回归测试问题 ${uniq("desc")}`,
    contactName: "张三",
    contactInfo: "010-88886666",
    source: "电话",
    category: "账号",
    priority: "高",
    orderNumber: "007788",
    attachmentNote: "",
    submitId: uniq("sub"),
    ...overrides,
  };
  const resp = await fetch(`${h.base}/api/tickets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  assert.equal(resp.status, 201, `登记工单应成功，实际 HTTP ${resp.status}`);
  return resp.json();
}

// waitListLoaded 等待首页列表结束首次加载。
export async function waitListLoaded(h) {
  await h.page.waitForFunction(
    () => !document.querySelector("#list-area").textContent.includes("正在加载"),
  );
}

// openApp 打开首页并等待列表加载完成。
export async function openApp(h) {
  await h.page.goto(h.base + "/", { waitUntil: "domcontentloaded" });
  await waitListLoaded(h);
}

// openDetail 点击指定工单所在行的“查看”按钮，打开详情。
export async function openDetail(h, ticketId) {
  const clicked = await h.page.evaluate((id) => {
    const rows = [...document.querySelectorAll("#list-area tbody tr")];
    for (const tr of rows) {
      if (tr.querySelector("td")?.textContent === id) {
        tr.querySelector("button[data-i]").click();
        return true;
      }
    }
    return false;
  }, ticketId);
  assert.ok(clicked, `列表中应能找到工单 ${ticketId}`);
  await h.page.waitForSelector("#detail.open #assign-form", { visible: true });
}

// closeDetail 点击详情中的“关闭”按钮。
export async function closeDetail(h) {
  await h.page.click("#detail .close");
}

// registerViaForm 通过页面登记表单提交一张新工单，触发成功后对列表的重新读取；
// 等待新工单出现在列表中（说明本次读取与合并已完成），返回新工单编号。
export async function registerViaForm(h, description) {
  await h.page.evaluate((desc) => {
    document.getElementById("f-description").value = desc;
    document.getElementById("f-contactName").value = "张三";
    document.getElementById("f-contactInfo").value = "010-88886666";
    document.getElementById("f-source").value = "电话";
    document.getElementById("f-category").value = "账号";
    document.getElementById("f-priority").value = "普通";
  }, description);
  await h.page.click("#submit-btn");
  await h.page.waitForFunction(() =>
    document.getElementById("form-notice").classList.contains("ok"),
  );
  const noticeText = await h.page.$eval("#form-notice", (n) => n.textContent);
  const m = /编号：(TKT-\d+)/.exec(noticeText);
  assert.ok(m, `登记成功提示应包含新工单编号，实际：${noticeText}`);
  await waitForRow(h, m[1], "未分派"); // 列表重新读取与合并已完成
  return m[1];
}

// setAssignee 以派发 input 事件的方式写入负责人输入框（含首尾空白时按原样写入）。
export async function setAssignee(h, value) {
  await h.page.focus("#f-assignee");
  await h.page.$eval(
    "#f-assignee",
    (el, v) => {
      el.value = v;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    value,
  );
}

// clickAssign 点击“提交分派”，由调用方随后在代理处等待请求被挂起。
export async function clickAssign(h) {
  await h.page.click("#assign-btn");
}

// submitAndWaitHeld 组合动作：点击提交并等待请求到达代理门控（页面进入等待状态）。
export async function submitAndWaitHeld(h) {
  await clickAssign(h);
  await h.proxy.waitForHeld();
  // 同步确认按钮的等待状态。
  const btn = await buttonState(h);
  assert.equal(btn.disabled, true, "等待分派结果期间提交按钮应禁用");
  assert.equal(btn.text, "正在分派…");
}

export async function buttonState(h) {
  return h.page.$eval("#assign-btn", (b) => ({ disabled: b.disabled, text: b.textContent.trim() }));
}

// readState 读取列表、详情、分派表单与提示的当前展示内容。
export async function readState(h) {
  return h.page.evaluate(() => {
    const rows = [...document.querySelectorAll("#list-area tbody tr")].map((tr) => {
      const td = [...tr.querySelectorAll("td")].map((c) => c.textContent);
      return { id: td[0], status: td[4], assignee: td[5], updated: td[6] };
    });
    const fields = {};
    document.querySelectorAll("#detail dl dt").forEach((dt) => {
      fields[dt.textContent] = dt.nextElementSibling.textContent;
    });
    const hist = [...document.querySelectorAll(".assign-list li")].map((li) => li.textContent.replace(/\s+/g, " ").trim());
    const emptyHistory = document.querySelector(".assign-history .empty")?.textContent || null;
    const n = document.getElementById("assign-notice");
    return {
      rows,
      detailOpen: document.getElementById("detail").classList.contains("open"),
      fields,
      history: hist,
      emptyHistory,
      input: document.getElementById("f-assignee").value,
      notice: { kind: n.classList.contains("ok") ? "ok" : n.classList.contains("err") ? "err" : "", text: n.textContent },
      button: (() => {
        const b = document.getElementById("assign-btn");
        return { disabled: b.disabled, text: b.textContent.trim() };
      })(),
    };
  });
}

// rowOf / detailOf / apiTicket 提供按工单编号读取视图与接口数据的快捷方式。
export function rowOf(state, id) {
  const row = state.rows.find((r) => r.id === id);
  assert.ok(row, `列表应展示工单 ${id}`);
  return row;
}

export async function apiTicket(h, id) {
  const resp = await fetch(`${h.base}/api/tickets`);
  const data = await resp.json();
  const t = data.tickets.find((x) => x.id === id);
  assert.ok(t, `接口应返回工单 ${id}`);
  return t;
}

export function fmtMinute(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(s || "");
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}` : s || "";
}

// waitSettled 等待一次分派请求收尾：提示已出现且按钮恢复可用。
export async function waitSettled(h) {
  await h.page.waitForFunction(() => {
    const b = document.getElementById("assign-btn");
    const n = document.getElementById("assign-notice");
    return !b.disabled && (n.classList.contains("ok") || n.classList.contains("err"));
  });
  return readState(h);
}

// waitQuiet 确认一段时间内没有新的分派请求发出（用于断言不会自动二次分派）。
export async function waitQuiet(h, ms = 600) {
  await new Promise((r) => setTimeout(r, ms));
  return h.proxy.heldCount();
}

// waitForRow 等待列表中指定工单展示出期望的负责人（分派成功后的列表刷新是异步的）。
export async function waitForRow(h, id, assignee) {
  await h.page.waitForFunction(
    ({ id, assignee }) => {
      const row = [...document.querySelectorAll("#list-area tbody tr")].find(
        (tr) => tr.querySelector("td")?.textContent === id,
      );
      return row && row.querySelectorAll("td")[5].textContent === assignee;
    },
    { timeout: 10000 },
    { id, assignee },
  );
}
