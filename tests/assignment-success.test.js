// 分派成功后的“已提交操作”与“未提交草稿”隔离回归测试。
//
// 关注点：
//  1. 等待分派结果期间继续修改负责人输入，旧请求成功时：
//     列表/详情只显示服务确认的负责人、最近处理时间与分派记录；
//     输入框保留返回时的原始草稿（含首尾空白），不会被自动二次分派。
//  2. “保留草稿”以等待期间确实发生过编辑为准：主动清空、仅改动首尾空白都算编辑。
//  3. 等待期间完全没有编辑时，沿用成功后清空输入的既有行为。
//  4. 提交的负责人与当前负责人相同：成功但不新增分派记录、不刷新最近处理时间，
//     草稿保留规则与实际变化时一致。
import { test, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  startServer,
  launchBrowser,
  openApp,
  createTicket,
  getTicket,
  assignViaApi,
  openDetail,
  reloadApp,
  installAssignGate,
  submitAssignment,
  editAssignee,
  clearAssignee,
  waitForButtonWaiting,
  waitForButtonIdle,
  waitForNoticeKind,
  getNotice,
  getInputValue,
  getDetail,
  getListRow,
  clickAssign,
  assertNoAssignmentSoon,
  fmtMinute,
} from "./helpers.js";

let server;
let browser;

before(async () => {
  server = await startServer();
  browser = await launchBrowser();
});

after(async () => {
  await browser.close();
  await server.stop();
});

let page;
let gate;

beforeEach(async () => {
  page = await openApp(browser, server.base);
  gate = installAssignGate(page);
  await gate.enable();
});

afterEach(async () => {
  gate.releaseAll();
  await page.close();
});

// 打开一张工单并挂起分派请求，返回接口侧的初始工单快照。
async function prepare(ticketOpts = {}) {
  const ticket = await createTicket(server.base, ticketOpts);
  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();
  return ticket;
}

test("等待期间改成另一个名字：旧请求成功后只确认已提交的负责人，草稿原样保留且不会自动再次分派", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "  王芳  ");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  // 请求体提交的是去除首尾空白后的负责人。
  assert.equal(gate.heldAt(0).assignee, "王芳");

  // 等待期间用户继续填写另一个名字（含首尾空白）。
  await editAssignee(page, "  李强  ");
  assert.equal(await getInputValue(page), "  李强  ");
  // 等待期间按钮始终不可用，不能并发提交第二次。
  const buttonWhileWaiting = await page.$eval("#assign-btn", (b) => ({
    disabled: b.disabled,
    text: b.textContent.trim(),
  }));
  assert.equal(buttonWhileWaiting.disabled, true);
  assert.match(buttonWhileWaiting.text, /正在分派/);

  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);

  // 成功提示先讲清这次实际分派给谁，再说明输入框内容尚未提交。
  const notice = await getNotice(page);
  assert.equal(notice.kind, "ok");
  assert.match(notice.text, /分派成功/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /尚未提交/);
  assert.match(notice.text, /原样保留/);
  // 不能把草稿名字描述成已分派。
  assert.doesNotMatch(notice.text, /分派给[:：]?\s*李强/);

  // 输入框保留返回时的原始内容，包括首尾空白；不会被成功结果填回或清空。
  assert.equal(await getInputValue(page), "  李强  ");

  // 详情只显示服务确认的实际负责人、最近处理时间与分派记录。
  const serverTicket = await getTicket(server.base, ticket.id);
  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], "王芳");
  assert.equal(detail.fields["最近处理时间"], fmtMinute(serverTicket.updatedAt));
  assert.deepEqual(detail.history, [
    `未分派 → 王芳 ${fmtMinute(serverTicket.updatedAt)}`,
  ]);
  assert.equal(detail.historyEmpty, false);
  assert.ok(!detail.history.some((h) => h.includes("李强")));

  // 列表同步显示已确认的负责人与最近处理时间。
  const row = await getListRow(page, ticket.id);
  assert.equal(row.assignee, "王芳");
  assert.equal(row.updated, fmtMinute(serverTicket.updatedAt));

  // 接口侧只落地了已提交的那次分派，草稿名字从未被提交。
  assert.equal(serverTicket.assignee, "王芳");
  assert.equal(serverTicket.assignments.length, 1);
  assert.equal(serverTicket.assignments[0].to, "王芳");

  // 不会自动把后来填写的名字再次分派：没有新请求，按钮已交还用户。
  await assertNoAssignmentSoon(gate, "成功返回后");
  assert.equal(gate.pending(), 0);
});

test("保留的草稿只有用户主动再次提交时才生效，且按一次新分派处理", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  const firstOpId = gate.heldAt(0).operationId;
  await editAssignee(page, "李强");
  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  assert.equal(await getInputValue(page), "李强");
  await assertNoAssignmentSoon(gate, "成功返回后");

  // 用户确认草稿后主动提交：产生第二次请求，使用新的操作标识。
  await clickAssign(page);
  await gate.waitForPending(1);
  assert.notEqual(gate.heldAt(0).operationId, firstOpId);

  // 第二次请求在用户点击之前并不存在（没有自动重发）。
  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);

  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.assignee, "李强");
  assert.equal(serverTicket.assignments.length, 2);
  assert.deepEqual(
    serverTicket.assignments.map((a) => [a.from, a.to]),
    [
      ["未分派", "王芳"],
      ["王芳", "李强"],
    ],
  );
  // 第二次提交等待期间没有编辑：沿用成功后清空输入的既有行为。
  assert.equal(await getInputValue(page), "");
  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], "李强");
  assert.equal(detail.history.length, 2);
});

test("等待期间主动清空：成功后保留空草稿并提示为空且未提交，再分派前必须填写有效负责人", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await clearAssignee(page);
  assert.equal(await getInputValue(page), "");
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.match(notice.text, /分派成功/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /清空/);
  assert.match(notice.text, /为空且尚未提交/);
  // 空草稿原样保留，不用刚提交的负责人填回。
  assert.equal(await getInputValue(page), "");

  const serverTicket = await getTicket(server.base, ticket.id);
  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], "王芳");
  assert.deepEqual(detail.history, [
    `未分派 → 王芳 ${fmtMinute(serverTicket.updatedAt)}`,
  ]);

  // 空内容不能再次分派：被前端校验拦截，不发请求，按钮仍可用。
  await clickAssign(page);
  let n = await getNotice(page);
  assert.equal(n.kind, "err");
  assert.match(n.text, /请填写负责人/);
  assert.equal(gate.pending(), 0);

  // 只有首尾空白同样无效。
  await editAssignee(page, "   ");
  await clickAssign(page);
  n = await getNotice(page);
  assert.match(n.text, /请填写负责人/);
  assert.equal(gate.pending(), 0);

  // 填写有效负责人后才能再次分派。
  await editAssignee(page, "赵六");
  await clickAssign(page);
  await gate.waitForPending(1);
  assert.equal(gate.heldAt(0).assignee, "赵六");
  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const finalTicket = await getTicket(server.base, ticket.id);
  assert.equal(finalTicket.assignee, "赵六");
  assert.equal(finalTicket.assignments.length, 2);
});

test("等待期间只增加首尾空白也算编辑：成功后不填回已提交负责人，保留带空白的草稿", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await editAssignee(page, "王芳 "); // 仅在末尾增加空白
  assert.equal(await getInputValue(page), "王芳 ");
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.match(notice.text, /尚未提交/);
  assert.match(notice.text, /原样保留/);
  // 输入保留尾部空白，既不是清空，也不是去空白后的已提交名字。
  assert.equal(await getInputValue(page), "王芳 ");

  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.assignee, "王芳");
  assert.equal(serverTicket.assignments.length, 1);
});

test("等待期间只删除首尾空白也算编辑：成功后保留无空白版本而非清空或填回", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "  王芳  ");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  assert.equal(gate.heldAt(0).assignee, "王芳");
  await editAssignee(page, "王芳"); // 仅删掉两端空白
  assert.equal(await getInputValue(page), "王芳");
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  // 走的是“草稿保留”分支，而不是无编辑时的清空分支。
  const notice = await getNotice(page);
  assert.match(notice.text, /尚未提交/);
  assert.equal(await getInputValue(page), "王芳");

  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.assignee, "王芳");
  assert.equal(serverTicket.assignments.length, 1);
});

test("等待期间完全没有改动：沿用成功后清空输入的既有行为", async () => {
  const ticket = await prepare();

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  // 不做任何编辑，直接放行。
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.equal(notice.kind, "ok");
  assert.equal(notice.text, "分派成功，负责人：王芳");
  // 无编辑：成功后清空输入。
  assert.equal(await getInputValue(page), "");

  const serverTicket = await getTicket(server.base, ticket.id);
  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], "王芳");
  assert.equal(detail.fields["最近处理时间"], fmtMinute(serverTicket.updatedAt));
  assert.deepEqual(detail.history, [
    `未分派 → 王芳 ${fmtMinute(serverTicket.updatedAt)}`,
  ]);
  const row = await getListRow(page, ticket.id);
  assert.equal(row.assignee, "王芳");
  assert.equal(row.updated, fmtMinute(serverTicket.updatedAt));
});

test("负责人与当前相同且等待中改名：仍成功但不新增记录、不刷新时间，草稿保留", async () => {
  // 前置：工单已经分派给王芳。
  const ticket = await createTicket(server.base);
  const before = await assignViaApi(server.base, ticket.id, "王芳");
  assert.equal(before.changed, true);
  const updatedAt0 = before.ticket.updatedAt;

  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();
  await submitAssignment(page, "王芳"); // 与当前负责人相同
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await editAssignee(page, "李强");
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.match(notice.text, /负责人未变化/);
  assert.match(notice.text, /仍为[:：]?\s*王芳/);
  assert.match(notice.text, /尚未提交/);
  assert.equal(await getInputValue(page), "李强");

  // 详情仍显示原负责人、原最近处理时间，分派记录不新增。
  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], "王芳");
  assert.equal(detail.fields["最近处理时间"], fmtMinute(updatedAt0));
  assert.deepEqual(detail.history, [`未分派 → 王芳 ${fmtMinute(updatedAt0)}`]);
  const row = await getListRow(page, ticket.id);
  assert.equal(row.assignee, "王芳");
  assert.equal(row.updated, fmtMinute(updatedAt0));

  // 接口侧时间与记录均未变化。
  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.assignee, "王芳");
  assert.equal(serverTicket.updatedAt, updatedAt0);
  assert.equal(serverTicket.assignments.length, 1);

  await assertNoAssignmentSoon(gate, "相同负责人成功后");
});

test("负责人与当前相同且等待中清空：不新增记录、不刷新时间，空草稿保留并说明为空未提交", async () => {
  const ticket = await createTicket(server.base);
  const before = await assignViaApi(server.base, ticket.id, "王芳");
  const updatedAt0 = before.ticket.updatedAt;

  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();
  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await clearAssignee(page);
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.match(notice.text, /负责人未变化/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /为空且尚未提交/);
  assert.equal(await getInputValue(page), "");

  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.updatedAt, updatedAt0);
  assert.equal(serverTicket.assignments.length, 1);
});

test("负责人与当前相同且等待中未编辑：成功提示未变化并清空输入，不新增记录、不刷新时间", async () => {
  const ticket = await createTicket(server.base);
  const before = await assignViaApi(server.base, ticket.id, "王芳");
  const updatedAt0 = before.ticket.updatedAt;

  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();
  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await gate.release();

  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const notice = await getNotice(page);
  assert.equal(notice.text, "负责人未变化");
  assert.equal(await getInputValue(page), "");

  const serverTicket = await getTicket(server.base, ticket.id);
  assert.equal(serverTicket.assignee, "王芳");
  assert.equal(serverTicket.updatedAt, updatedAt0);
  assert.equal(serverTicket.assignments.length, 1);
  const detail = await getDetail(page);
  assert.equal(detail.fields["最近处理时间"], fmtMinute(updatedAt0));
  assert.deepEqual(detail.history, [`未分派 → 王芳 ${fmtMinute(updatedAt0)}`]);
});
