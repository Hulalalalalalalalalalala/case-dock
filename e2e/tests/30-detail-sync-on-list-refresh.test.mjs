import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import {
  registerTicket, openApp, openDetail, setAssignee, submitAndWaitHeld,
  waitSettled, readState, rowOf, fmtMinute, waitForRow,
} from "../lib/ui.mjs";

const browser = await launchBrowser();
after(async () => browser.close());

// 每次测试使用独立的真实服务（独立数据目录）与独立标签页。
async function setup() {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h);
  await openApp(h);
  return { h, ticket };
}

// assignDirect 直连真实服务分派工单（不经过门控），模拟另一页面的转交。
async function assignDirect(h, ticketId, assignee, opId) {
  const resp = await fetch(`${h.upstream}/api/tickets/${ticketId}/assignment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ assignee, operationId: opId }),
  });
  assert.equal(resp.status, 200, "直接分派应成功");
  return resp.json();
}

// registerViaForm 通过页面登记表单提交一张新工单，触发成功后对列表的重新读取；
// 等待新工单出现在列表中（说明本次读取与合并已完成），返回新工单编号。
async function registerViaForm(h, description) {
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

test("同步-1：列表刷新后，已打开详情同步显示另一页面转交后的负责人、最近处理时间与分派记录", async () => {
  const { h, ticket } = await setup();
  try {
    await openDetail(h, ticket.id);
    const before = await readState(h);
    assert.equal(before.fields["负责人"], "未分派");
    assert.equal(before.emptyHistory, "暂无分派记录。");

    // 另一页面把工单转交给王芳（本页面尚未感知）。
    const assigned = await assignDirect(h, ticket.id, "王芳", "other-page-op-1");
    const serverTicket = assigned.ticket;

    // 本页面登记一张新工单，成功后重新读取列表。
    const newId = await registerViaForm(h, "列表刷新触发工单");

    const s = await readState(h);
    // 详情仍停留在用户正在查看的同一张工单，不被新登记工单取代。
    assert.equal(s.detailOpen, true);
    assert.equal(s.fields["编号"], ticket.id);
    // 详情与列表行展示同一份内容：新负责人、最近处理时间与分派记录。
    assert.equal(s.fields["负责人"], "王芳");
    assert.equal(s.fields["最近处理时间"], fmtMinute(serverTicket.updatedAt));
    assert.equal(s.history.length, 1);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    const row = rowOf(s, ticket.id);
    assert.equal(row.assignee, "王芳");
    assert.equal(row.updated, fmtMinute(serverTicket.updatedAt));
    // 新登记工单按现有顺序进入列表，且未被自动打开为详情。
    assert.ok(s.rows.some((r) => r.id === newId), "新登记工单应进入列表");
    assert.equal(s.rows[0].id, newId, "新工单应排在列表最前");
  } finally {
    await h.close();
  }
});

test("同步-2：列表刷新同步详情时，负责人草稿（含首尾空白）与现有提示不被覆盖", async () => {
  const { h, ticket } = await setup();
  try {
    await openDetail(h, ticket.id);
    // 先留下一条校验失败提示，再填写带首尾空白的草稿。
    await h.page.click("#assign-btn");
    const blocked = await readState(h);
    assert.equal(blocked.notice.kind, "err");
    assert.match(blocked.notice.text, /请填写负责人/);
    await setAssignee(h, "  李静  ");

    await assignDirect(h, ticket.id, "王芳", "other-page-op-2");
    await registerViaForm(h, "刷新时保留草稿");

    const s = await readState(h);
    // 详情取值已同步，但草稿与提示原样保留。
    assert.equal(s.fields["负责人"], "王芳");
    assert.equal(s.input, "  李静  ", "列表读取不能清除或填回负责人草稿");
    assert.equal(s.notice.kind, "err", "现有提示不应被列表读取覆盖");
    assert.match(s.notice.text, /请填写负责人/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
  } finally {
    await h.close();
  }
});

test("同步-3：分派请求未结束时列表刷新，按钮保持正在分派，请求结束后按已有行为恢复", async () => {
  const { h, ticket } = await setup();
  try {
    await openDetail(h, ticket.id);
    await setAssignee(h, "赵强");
    await submitAndWaitHeld(h);

    // 分派请求被挂起期间，登记新工单触发列表重新读取。
    const newId = await registerViaForm(h, "分派等待期间刷新列表");
    const during = await readState(h);
    assert.deepEqual(during.button, { disabled: true, text: "正在分派…" },
      "分派未结束时列表刷新不能恢复提交按钮");
    assert.equal(during.input, "赵强", "等待期间输入内容不被列表读取改动");
    assert.ok(during.rows.some((r) => r.id === newId));

    // 原请求结束后按已有行为恢复：成功提示、清空输入、按钮可用。
    const resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, true);
    const s = await waitSettled(h);
    assert.equal(s.fields["负责人"], "赵强");
    assert.equal(s.input, "");
    assert.equal(s.notice.kind, "ok");
    assert.equal(s.notice.text, "分派成功，负责人：赵强");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
  } finally {
    await h.close();
  }
});

test("同步-4：详情已关闭时，列表更新不会重新打开详情", async () => {
  const { h, ticket } = await setup();
  try {
    await openDetail(h, ticket.id);
    await h.page.click("#detail .close");
    const closed = await readState(h);
    assert.equal(closed.detailOpen, false);

    await assignDirect(h, ticket.id, "王芳", "other-page-op-4");
    await registerViaForm(h, "关闭详情后刷新列表");

    const s = await readState(h);
    assert.equal(s.detailOpen, false, "列表更新不能重新打开已关闭的详情");
    // 列表行仍正常显示另一页面转交后的负责人。
    assert.equal(rowOf(s, ticket.id).assignee, "王芳");
  } finally {
    await h.close();
  }
});
