import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import {
  registerTicket, openApp, openDetail, setAssignee, submitAndWaitHeld,
  waitSettled, readState, rowOf, apiTicket, fmtMinute, waitForRow, waitQuiet,
} from "../lib/ui.mjs";

const browser = await launchBrowser();
after(async () => browser.close());

// 每次测试使用独立的真实服务（独立数据目录）与独立标签页。
async function setup() {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h);
  await openApp(h);
  await openDetail(h, ticket.id);
  return { h, ticket };
}

// assignDirect 直连真实服务分派工单（不经过门控），模拟另一页面的转交。
async function assignDirect(h, ticketId, assignee, opId) {
  const resp = await fetch(`${h.upstream}/api/tickets/${ticketId}/assignment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ assignee, operationId: opId }),
  });
  assert.equal(resp.status, 200, "另一页面的直接转交应成功");
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

// markListRender 在当前列表 tbody 上打标记；迟到响应处理时会重渲染列表，
// 标记随之消失，可据此确定性等待响应处理完成（无可见变化的场景也适用）。
async function markListRender(h) {
  await h.page.$eval("#list-area tbody", (tb) => tb.setAttribute("data-gen", "x"));
}
async function waitListRerendered(h) {
  await h.page.waitForFunction(
    () => !document.querySelector("#list-area tbody")?.hasAttribute("data-gen"),
  );
}

test("旧响应-1：王芳分派成功但响应迟到，期间工单已被另一页面转交给李静——显示保留李静与完整记录，提示区分本次结果与当前状态", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);

    // 服务端已保存王芳这次分派，但响应暂不回到页面。
    const wang = await h.proxy.releaseNext("withhold");
    assert.equal(wang.body.changed, true, "王芳分派在服务端应实际成功");
    assert.equal(wang.body.ticket.assignee, "王芳");

    // 另一页面随即将工单转交给李静（本页面只能在稍后的列表读取中感知）。
    const li = await assignDirect(h, ticket.id, "李静", "other-page-li");
    assert.ok(li.ticket.updatedAt > wang.body.ticket.updatedAt, "后一次转交时间应更晚");

    // 登记另一张工单触发列表重新读取：页面先看到李静与完整的两次分派记录。
    const newId = await registerViaForm(h, "旧响应场景中新登记工单");
    await waitForRow(h, ticket.id, "李静");
    const before = await readState(h);
    assert.equal(before.fields["负责人"], "李静");
    assert.equal(before.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt));
    assert.equal(before.history.length, 2);
    assert.match(before.history[0], /^未分派 → 王芳 /);
    assert.match(before.history[1], /^王芳 → 李静 /);

    // 王芳那次分派的成功响应迟到：不得把展示退回王芳。
    await markListRender(h);
    h.proxy.deliverNextResponse();
    const s = await waitSettled(h);

    assert.equal(s.fields["负责人"], "李静", "详情负责人必须保留后一次转交的李静");
    assert.equal(s.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt),
      "最近处理时间保留后一次转交的时间");
    assert.equal(s.history.length, 2, "分派记录一条都不能少");
    assert.match(s.history[0], /^未分派 → 王芳 /, "记录按原有发生顺序展示");
    assert.match(s.history[1], /^王芳 → 李静 /);
    const row = rowOf(s, ticket.id);
    assert.equal(row.assignee, "李静", "列表与详情显示一致的负责人");
    assert.equal(row.updated, fmtMinute(li.ticket.updatedAt));

    // 提示区分本次操作结果与工单当前状态：本次曾分派给王芳，当前负责人是李静。
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /分派成功，本次曾分派给：王芳/);
    assert.match(s.notice.text, /已被转交，当前负责人为：李静/);
    assert.ok(!/本次实际分派给：李静/.test(s.notice.text), "不能把李静描述成本次提交的分派目标");
    assert.ok(!/负责人：王芳/.test(s.notice.text), "不能提示当前负责人仍是王芳");
    assert.ok(!/仍为：王芳/.test(s.notice.text), "不能提示当前负责人仍是王芳");

    // 等待期间没有编辑过：成功后照常清空输入，按钮恢复。
    assert.equal(s.input, "");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    // 不依据旧响应再次执行分派；新登记工单仍按现有顺序留在列表最前。
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "旧响应处理后不应自动发出分派请求");
    const arrivals = h.proxy.arrivals();
    assert.equal(arrivals.length, 1);
    assert.equal(arrivals[0].assignee, "王芳");
    assert.equal(s.rows[0].id, newId, "新登记工单仍排在列表最前");

    // 服务端工单同样以李静为当前负责人，两次分派记录完整。
    const persisted = await apiTicket(h, ticket.id);
    assert.equal(persisted.assignee, "李静");
    assert.equal(persisted.updatedAt, li.ticket.updatedAt);
    assert.equal(persisted.assignments.length, 2);
  } finally {
    await h.close();
  }
});

test("旧响应-2：迟到响应到达前改过下一次负责人草稿——展示不退回，草稿（含首尾空白）原样保留且不自动提交", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext("withhold");
    await assignDirect(h, ticket.id, "李静", "other-page-li-2");
    const newId = await registerViaForm(h, "旧响应草稿场景");
    await waitForRow(h, ticket.id, "李静");

    // 等待结果期间填写下一次负责人（含首尾空白），属于尚未提交的草稿。
    await setAssignee(h, "  周敏  ");

    await markListRender(h);
    h.proxy.deliverNextResponse();
    const s = await waitSettled(h);

    assert.equal(s.fields["负责人"], "李静");
    assert.equal(rowOf(s, ticket.id).assignee, "李静");
    assert.equal(s.history.length, 2);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.match(s.history[1], /^王芳 → 李静 /);

    assert.equal(s.input, "  周敏  ", "下一次负责人草稿原样保留，包括首尾空白");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /本次曾分派给：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.match(s.notice.text, /输入框中的当前内容尚未提交，已原样保留（包括首尾空白）/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "草稿不能被旧响应自动提交");
    assert.equal(h.proxy.arrivals().length, 1);
    assert.ok(s.rows.some((r) => r.id === newId));
  } finally {
    await h.close();
  }
});

test("旧响应-3：迟到响应到达前主动清空过输入——提示当前为空且未提交，展示仍为李静", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext("withhold");
    await assignDirect(h, ticket.id, "李静", "other-page-li-3");
    await registerViaForm(h, "旧响应清空场景");
    await waitForRow(h, ticket.id, "李静");

    await setAssignee(h, ""); // 等待期间主动清空

    await markListRender(h);
    h.proxy.deliverNextResponse();
    const s = await waitSettled(h);

    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.history.length, 2);
    assert.equal(s.input, "", "主动清空属于编辑，不能填回王芳或李静");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /本次曾分派给：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.match(s.notice.text, /清空了输入框，当前内容为空且尚未提交/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    assert.equal(h.proxy.arrivals().length, 1);
  } finally {
    await h.close();
  }
});

test("旧响应-4：等待期间关闭详情——迟到结果只更新所属工单的列表，不重新打开详情", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext("withhold");
    const li = await assignDirect(h, ticket.id, "李静", "other-page-li-4");
    await registerViaForm(h, "关闭详情后的旧响应场景");
    await waitForRow(h, ticket.id, "李静");

    // 结果到达前关闭详情。
    await h.page.click("#detail .close");
    assert.equal((await readState(h)).detailOpen, false);

    await markListRender(h);
    h.proxy.deliverNextResponse();
    await waitListRerendered(h);
    await waitQuiet(h);

    const s = await readState(h);
    assert.equal(s.detailOpen, false, "迟到结果不能重新打开详情");
    const row = rowOf(s, ticket.id);
    assert.equal(row.assignee, "李静", "列表仍保留后一次转交结果");
    assert.equal(row.updated, fmtMinute(li.ticket.updatedAt));
    assert.equal(h.proxy.arrivals().length, 1, "不应补发任何分派请求");
  } finally {
    await h.close();
  }
});

test("旧响应-5：等待期间切换到另一张工单——结果只归所属工单，不改写另一张工单的输入与提示", async () => {
  const h = await createHarness(browser);
  const ticketA = await registerTicket(h, { description: "被转交的工单 A" });
  const ticketB = await registerTicket(h, { description: "正在填写的工单 B" });
  await openApp(h);
  try {
    await openDetail(h, ticketA.id);
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext("withhold");
    await assignDirect(h, ticketA.id, "李静", "other-page-li-5");
    await registerViaForm(h, "切换工单时的旧响应场景");
    await waitForRow(h, ticketA.id, "李静");

    // 等待 A 的结果期间切换到工单 B，并在 B 上留下校验提示与草稿。
    await openDetail(h, ticketB.id);
    await h.page.click("#assign-btn"); // 空输入：校验失败提示属于工单 B
    const blocked = await readState(h);
    assert.equal(blocked.notice.kind, "err");
    assert.match(blocked.notice.text, /请填写负责人/);
    await setAssignee(h, "  陈昊  ");

    await markListRender(h);
    h.proxy.deliverNextResponse(); // A 的迟到成功响应
    await waitListRerendered(h);
    await waitQuiet(h);

    const s = await readState(h);
    // 详情仍停留在 B，A 的结果不打扰 B 的任何内容。
    assert.equal(s.detailOpen, true);
    assert.equal(s.fields["编号"], ticketB.id);
    assert.equal(s.fields["负责人"], "未分派");
    assert.equal(s.input, "  陈昊  ", "另一张工单的草稿不能被改写");
    assert.equal(s.notice.kind, "err", "另一张工单的提示不能被覆盖");
    assert.match(s.notice.text, /请填写负责人/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    // A 的列表内容仍为后一次转交结果。
    assert.equal(rowOf(s, ticketA.id).assignee, "李静");
    assert.equal(h.proxy.arrivals().length, 1, "陈昊草稿不能被自动提交");
  } finally {
    await h.close();
  }
});

test("旧响应-6：迟到的是“负责人未变化”响应、期间工单已转交——仍显示李静，提示说明提交时未变与当前负责人", async () => {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h);
  // 先由另一页面把工单分派给王芳，作为提交时的当前负责人。
  const seeded = await assignDirect(h, ticket.id, "王芳", "seed-wang");
  await openApp(h);
  try {
    await openDetail(h, ticket.id);
    // 提交与当前负责人相同的王芳：服务端返回 changed=false，响应暂不回页面。
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    const same = await h.proxy.releaseNext("withhold");
    assert.equal(same.body.changed, false);
    assert.equal(same.body.ticket.assignee, "王芳");
    assert.equal(same.body.ticket.updatedAt, seeded.ticket.updatedAt, "负责人未变化不刷新时间");

    // 随后工单被转交给李静并被列表读取感知。
    const li = await assignDirect(h, ticket.id, "李静", "other-page-li-6");
    await registerViaForm(h, "未变化响应迟到场景");
    await waitForRow(h, ticket.id, "李静");

    await markListRender(h);
    h.proxy.deliverNextResponse();
    const s = await waitSettled(h);

    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt));
    assert.equal(s.history.length, 2);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.match(s.history[1], /^王芳 → 李静 /);
    assert.equal(rowOf(s, ticket.id).assignee, "李静");
    assert.equal(s.input, "", "等待期间未编辑，成功后照常清空输入");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /提交的负责人与当时的负责人相同，提交时负责人未变化，当时为：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    assert.equal(h.proxy.arrivals().length, 1);
  } finally {
    await h.close();
  }
});
