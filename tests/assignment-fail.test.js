// 分派失败后的隔离与可恢复性回归测试。
//
// 关注点：
//  1. 收到保存失败响应（HTTP 500）或无法连接服务时，此前提交的分派绝不能被提示成成功。
//  2. 提示要区分：失败的是“此前提交的负责人”，输入框里只是尚未提交的内容。
//  3. 等待期间后来填写或清空的输入按返回时当前内容原样保留；按钮恢复可用。
//  4. 列表与详情中的负责人、最近处理时间、分派记录不能根据失败结果改写。
//  5. 不自动重试：重试只能由用户主动点击发起；未成功的操作标识沿用，可修正后重试。
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

async function prepare() {
  const ticket = await createTicket(server.base);
  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();
  return ticket;
}

// 失败后数据层面不应发生任何分派：接口、详情、列表三处一致保持旧状态。
async function assertDataUnchanged(ticketId, expectedAssignee, expectedUpdatedAt, recordCount) {
  const serverTicket = await getTicket(server.base, ticketId);
  assert.equal(serverTicket.assignee, expectedAssignee);
  assert.equal(serverTicket.updatedAt, expectedUpdatedAt);
  assert.equal(serverTicket.assignments.length, recordCount);

  const detail = await getDetail(page);
  assert.equal(detail.fields["负责人"], expectedAssignee);
  assert.equal(detail.fields["最近处理时间"], fmtMinute(expectedUpdatedAt));
  assert.equal(detail.history.length, recordCount);

  const row = await getListRow(page, ticketId);
  assert.equal(row.assignee, expectedAssignee);
  assert.equal(row.updated, fmtMinute(expectedUpdatedAt));
  return { serverTicket, detail };
}

test("保存失败且等待期间改过名：失败只归属于此前提交的负责人，草稿保留、数据不改写、不自动重试", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  const firstOpId = gate.heldAt(0).operationId;
  await editAssignee(page, "李强");
  assert.equal(await getInputValue(page), "李强");

  await gate.fail(0, 500, "unable to save assignment");
  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  // 失败提示：明确失败的是此前提交给“王芳”的那次分派，保留服务端错误的业务含义，
  // 并说明输入框里只是尚未提交的内容；绝不能出现成功表述或把草稿名字卷进来。
  const notice = await getNotice(page);
  assert.equal(notice.kind, "err");
  assert.match(notice.text, /此前提交给/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /HTTP 500/);
  assert.match(notice.text, /unable to save assignment/);
  assert.match(notice.text, /尚未提交/);
  assert.match(notice.text, /保留/);
  assert.doesNotMatch(notice.text, /成功/);
  assert.ok(!notice.text.includes("李强"), "草稿名字不应出现在失败归属提示中");

  // 草稿原样保留，按钮交还用户。
  assert.equal(await getInputValue(page), "李强");

  // 数据三处一致，保持分派前状态。
  const { detail } = await assertDataUnchanged(
    ticket.id,
    "未分派",
    initial.updatedAt,
    0,
  );
  assert.equal(detail.historyEmpty, true);

  // 不自动重试：没有新请求发出。
  await assertNoAssignmentSoon(gate, "保存失败后");

  // 重试只能由用户主动发起；未成功的操作标识沿用。
  await clickAssign(page);
  await gate.waitForPending(1);
  assert.equal(gate.heldAt(0).operationId, firstOpId);
  assert.equal(gate.heldAt(0).assignee, "李强");
  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);

  const after = await getTicket(server.base, ticket.id);
  assert.equal(after.assignee, "李强");
  assert.equal(after.assignments.length, 1);
  assert.deepEqual(after.assignments.map((a) => [a.from, a.to]), [["未分派", "李强"]]);
});

test("无法连接服务且等待期间改过名：按失败处理，草稿保留、数据不改写、不自动重试", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await editAssignee(page, "李强");

  await gate.abort(); // 连接直接中断，浏览器收不到响应
  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  const notice = await getNotice(page);
  assert.equal(notice.kind, "err");
  assert.match(notice.text, /此前提交给/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /无法连接服务/);
  assert.match(notice.text, /尚未提交/);
  assert.doesNotMatch(notice.text, /成功/);
  assert.ok(!notice.text.includes("李强"));

  assert.equal(await getInputValue(page), "李强");
  await assertDataUnchanged(ticket.id, "未分派", initial.updatedAt, 0);
  await assertNoAssignmentSoon(gate, "连接失败后");
});

test("保存失败且等待期间清空：空内容原样保留，数据不改写；恢复后须重新填写有效负责人", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await clearAssignee(page);
  assert.equal(await getInputValue(page), "");

  await gate.fail(0, 500, "unable to save assignment");
  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  const notice = await getNotice(page);
  assert.match(notice.text, /此前提交给/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /HTTP 500/);
  assert.match(notice.text, /尚未提交/);
  assert.doesNotMatch(notice.text, /成功/);

  // 清空的结果原样保留，不用已提交或已确认的负责人填回。
  assert.equal(await getInputValue(page), "");
  await assertDataUnchanged(ticket.id, "未分派", initial.updatedAt, 0);

  // 空内容无法再次分派：前端校验拦截，不发请求。
  await clickAssign(page);
  assert.match((await getNotice(page)).text, /请填写负责人/);
  assert.equal(gate.pending(), 0);

  // 填入有效负责人后由用户主动重试才发请求。
  await editAssignee(page, "赵六");
  await clickAssign(page);
  await gate.waitForPending(1);
  assert.equal(gate.heldAt(0).assignee, "赵六");
  await gate.release();
  await waitForNoticeKind(page, "ok");
  const after = await getTicket(server.base, ticket.id);
  assert.equal(after.assignee, "赵六");
  assert.equal(after.assignments.length, 1);
});

test("保存失败且等待期间未编辑：沿用既有失败提示，已填写内容保留，用户主动重试后成功", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  const firstOpId = gate.heldAt(0).operationId;
  await gate.fail(0, 500, "unable to save assignment");

  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  // 无编辑时沿用既有的单主体失败文案。
  const notice = await getNotice(page);
  assert.equal(notice.text, "分派失败（HTTP 500）：unable to save assignment\n填写内容已保留，请重试。");
  assert.doesNotMatch(notice.text, /成功/);
  // 已填写内容保留在输入框。
  assert.equal(await getInputValue(page), "王芳");
  await assertDataUnchanged(ticket.id, "未分派", initial.updatedAt, 0);
  await assertNoAssignmentSoon(gate, "保存失败后");

  // 用户主动重试：沿用同一操作标识，这次放行成功。
  await clickAssign(page);
  await gate.waitForPending(1);
  assert.equal(gate.heldAt(0).operationId, firstOpId);
  assert.equal(gate.heldAt(0).assignee, "王芳");
  await gate.release();
  await waitForNoticeKind(page, "ok");
  await waitForButtonIdle(page);
  const after = await getTicket(server.base, ticket.id);
  assert.equal(after.assignee, "王芳");
  assert.equal(after.assignments.length, 1);
});

test("无法连接服务且等待期间未编辑：沿用既有提示与已填写内容，不自动重试", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await gate.abort();

  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);
  assert.equal(
    (await getNotice(page)).text,
    "分派失败：无法连接服务。填写内容已保留，请稍后重试。",
  );
  assert.equal(await getInputValue(page), "王芳");
  await assertDataUnchanged(ticket.id, "未分派", initial.updatedAt, 0);
  await assertNoAssignmentSoon(gate, "连接失败后");
});

test("无法连接服务且等待期间清空：空内容原样保留，数据不改写", async () => {
  const ticket = await prepare();
  const initial = await getTicket(server.base, ticket.id);

  await submitAssignment(page, "王芳");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await clearAssignee(page);

  await gate.abort();
  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  const notice = await getNotice(page);
  assert.match(notice.text, /此前提交给/);
  assert.match(notice.text, /王芳/);
  assert.match(notice.text, /无法连接服务/);
  assert.match(notice.text, /尚未提交/);
  assert.doesNotMatch(notice.text, /成功/);
  assert.equal(await getInputValue(page), "");
  await assertDataUnchanged(ticket.id, "未分派", initial.updatedAt, 0);
  await assertNoAssignmentSoon(gate, "连接失败后");
});

test("转交保存失败：已有负责人、最近处理时间与分派记录均保持旧值，草稿不受影响", async () => {
  // 前置：工单已分派给王芳，存在一条分派记录与处理时间。
  const ticket = await createTicket(server.base);
  const before = await assignViaApi(server.base, ticket.id, "王芳");
  const updatedAt0 = before.ticket.updatedAt;

  await reloadApp(page);
  await openDetail(page, ticket.id);
  gate.hold();

  await submitAssignment(page, "李强");
  await waitForButtonWaiting(page);
  await gate.waitForPending(1);
  await editAssignee(page, "  赵六 "); // 等待中又改成草稿（含首尾空白）

  await gate.fail(0, 500, "unable to save assignment");
  await waitForNoticeKind(page, "err");
  await waitForButtonIdle(page);

  const notice = await getNotice(page);
  assert.match(notice.text, /此前提交给/);
  assert.match(notice.text, /李强/); // 失败的是此前提交的“李强”
  assert.match(notice.text, /HTTP 500/);
  assert.match(notice.text, /尚未提交/);
  assert.ok(!notice.text.includes("赵六"), "草稿名字不应被当作失败的分派对象");

  // 草稿（含首尾空白）保留。
  assert.equal(await getInputValue(page), "  赵六 ");

  // 旧负责人、旧时间、旧记录在三处都不被失败结果改写。
  const { detail } = await assertDataUnchanged(ticket.id, "王芳", updatedAt0, 1);
  assert.deepEqual(detail.history, [`未分派 → 王芳 ${fmtMinute(updatedAt0)}`]);

  await assertNoAssignmentSoon(gate, "转交失败后");
});
