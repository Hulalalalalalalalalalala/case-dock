import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import {
  registerTicket, openApp, openDetail, closeDetail, setAssignee, submitAndWaitHeld,
  waitSettled, readState, rowOf, apiTicket, fmtMinute, waitQuiet,
  registerViaForm,
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

// assignDirect 直连真实服务分派/转交工单（不经过门控），模拟另一页面的操作。
async function assignDirect(h, ticketId, assignee, opId) {
  const resp = await fetch(`${h.upstream}/api/tickets/${ticketId}/assignment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ assignee, operationId: opId }),
  });
  assert.equal(resp.status, 200, "直接分派应成功");
  return resp.json();
}

test("旧响应-1：王芳分派已被服务保存、响应迟到前工单已被另一页面转交给李静；迟到成功后仍显示李静、后一次时间与完整两次记录", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);

    // 转发给真实服务：王芳分派已保存成功，但响应先扣在代理处不回页面。
    const wang = await h.proxy.parkNext();
    assert.equal(wang.changed, true);
    assert.equal(wang.ticket.assignee, "王芳");
    assert.equal(wang.ticket.assignments.length, 1);
    const wangUpdated = wang.ticket.updatedAt;

    // 另一页面在此期间把同一工单转交给李静。
    const li = await assignDirect(h, ticket.id, "李静", "other-page-transfer");
    assert.equal(li.ticket.assignee, "李静");
    assert.ok(li.ticket.updatedAt > wangUpdated, "后一次转交时间应更晚");

    // 登记另一张工单触发列表重新读取：页面此时已看到李静及完整两次分派记录。
    const newId = await registerViaForm(h, "旧响应返回前的新工单");
    let s = await readState(h);
    assert.equal(s.fields["负责人"], "李静", "重新读取后详情应显示后一次转交的负责人");
    assert.equal(s.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt));
    assert.equal(s.history.length, 2);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.match(s.history[1], /^王芳 → 李静 /);
    assert.equal(rowOf(s, ticket.id).assignee, "李静");
    assert.deepEqual(s.button, { disabled: true, text: "正在分派…" }, "王芳响应未返回前按钮仍处于等待状态");
    assert.ok(s.rows.some((r) => r.id === newId), "新登记工单按现有顺序留在列表中");

    // 王芳那次的成功响应迟到：不得把显示退回王芳。
    h.proxy.deliverParked();
    s = await waitSettled(h);
    assert.equal(s.fields["负责人"], "李静", "旧成功响应不能退回当前负责人");
    assert.equal(s.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt), "最近处理时间保留后一次转交的时间");
    assert.equal(s.history.length, 2, "分派记录按发生顺序完整展示，不少掉后一次记录");
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.match(s.history[1], /^王芳 → 李静 /);
    const row = rowOf(s, ticket.id);
    assert.equal(row.assignee, "李静", "列表与详情中的同一张工单显示一致");
    assert.equal(row.updated, fmtMinute(li.ticket.updatedAt));

    // 提示区分本次操作结果与工单当前状态：曾分派给王芳，当前负责人是李静。
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /分派成功，本次曾分派给：王芳/);
    assert.match(s.notice.text, /该工单随后已转交给他人，当前负责人为：李静/);
    assert.ok(!/本次实际分派给：李静/.test(s.notice.text), "不能把李静描述成本次提交的分派目标");
    assert.ok(!/负责人[：:]\s*王芳\s*。?\s*$/.test(s.notice.text), "不能在结尾提示当前负责人仍是王芳");
    // 等待期间没有编辑输入：成功后照常清空，按钮恢复。
    assert.equal(s.input, "");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    // 不依据旧响应再次执行分派；服务端工单没有被退回。
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "旧响应处理后不应自动发出第二次分派");
    assert.equal(h.proxy.arrivals().length, 1);
    const persisted = await apiTicket(h, ticket.id);
    assert.equal(persisted.assignee, "李静");
    assert.equal(persisted.updatedAt, li.ticket.updatedAt);
    assert.equal(persisted.assignments.length, 2);
  } finally {
    await h.close();
  }
});

test("旧响应-2：旧成功返回前已转交，且等待期间改过下一次负责人——草稿原样保留，提示同时说明王芳与李静", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.parkNext();
    await assignDirect(h, ticket.id, "李静", "other-page-transfer-2");

    // 等待结果期间填写下一次负责人（含首尾空白），再通过登记触发列表重新读取。
    await setAssignee(h, "  赵磊  ");
    await registerViaForm(h, "旧响应与草稿并存");

    h.proxy.deliverParked();
    const s = await waitSettled(h);
    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.history.length, 2);
    assert.equal(s.input, "  赵磊  ", "等待期间填写的下一次负责人仍是未提交草稿，原样保留");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /本次曾分派给：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.match(s.notice.text, /输入框中的当前内容尚未提交，已原样保留（包括首尾空白）/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    assert.equal(h.proxy.arrivals().length, 1, "草稿不能被旧响应自动提交");
    assert.equal((await waitQuiet(h)), 0);
    const persisted = await apiTicket(h, ticket.id);
    assert.equal(persisted.assignee, "李静");
  } finally {
    await h.close();
  }
});

test("旧响应-3：旧成功返回前已转交，等待期间清空了草稿——提示为空且未提交，空内容不能再分派", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.parkNext();
    await assignDirect(h, ticket.id, "李静", "other-page-transfer-3");
    await setAssignee(h, ""); // 等待期间主动清空
    await registerViaForm(h, "旧响应与清空草稿");

    h.proxy.deliverParked();
    const s = await waitSettled(h);
    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.input, "");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /本次曾分派给：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.match(s.notice.text, /清空了输入框，当前内容为空且尚未提交/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    // 空内容仍被前端拦截，不发新请求。
    await h.page.click("#assign-btn");
    const blocked = await readState(h);
    assert.equal(blocked.notice.kind, "err");
    assert.match(blocked.notice.text, /请填写负责人/);
    assert.equal(h.proxy.arrivals().length, 1);
  } finally {
    await h.close();
  }
});

test("旧响应-4：等待期间关闭详情——迟到结果只更新所属工单列表，不重新打开详情", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.parkNext();
    await assignDirect(h, ticket.id, "李静", "other-page-transfer-4");
    await registerViaForm(h, "关闭详情后的迟到响应");

    await closeDetail(h);
    let s = await readState(h);
    assert.equal(s.detailOpen, false);

    h.proxy.deliverParked();
    await waitQuiet(h); // 详情已关闭，通过固定静默期确认迟到结果处理完毕
    s = await readState(h);
    assert.equal(s.detailOpen, false, "迟到结果不能重新打开详情");
    assert.equal(rowOf(s, ticket.id).assignee, "李静", "列表仍显示后一次转交的负责人");

    // 再打开该工单：负责人与两次分派记录完整。
    await openDetail(h, ticket.id);
    s = await readState(h);
    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.history.length, 2);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.match(s.history[1], /^王芳 → 李静 /);
  } finally {
    await h.close();
  }
});

test("旧响应-5：等待期间切换到另一张工单——迟到结果不改写另一张工单的输入与提示", async () => {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h, { description: "旧响应所属工单" });
  const other = await registerTicket(h, { description: "等待期间切换查看的工单" });
  await openApp(h);
  await openDetail(h, ticket.id);
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.parkNext();
    await assignDirect(h, ticket.id, "李静", "other-page-transfer-5");
    await registerViaForm(h, "切换工单前登记的新工单");

    // 切换到另一张工单，制造一条既有提示与一个草稿。
    await openDetail(h, other.id);
    await h.page.click("#assign-btn");
    let otherState = await readState(h);
    assert.equal(otherState.notice.kind, "err");
    assert.match(otherState.notice.text, /请填写负责人/);
    await setAssignee(h, "  陈晨  ");

    h.proxy.deliverParked();
    await waitQuiet(h);
    const s = await readState(h);
    assert.equal(s.detailOpen, true);
    assert.equal(s.fields["编号"], other.id, "详情仍停留在另一张工单，不被旧结果带回原工单");
    assert.equal(s.input, "  陈晨  ", "另一张工单的草稿不被改写");
    assert.equal(s.notice.kind, "err", "另一张工单的提示不被覆盖");
    assert.match(s.notice.text, /请填写负责人/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    // 原工单在列表中仍是李静。
    assert.equal(rowOf(s, ticket.id).assignee, "李静");

    // 再打开原工单核对内容完整。
    await openDetail(h, ticket.id);
    const back = await readState(h);
    assert.equal(back.fields["负责人"], "李静");
    assert.equal(back.history.length, 2);
    assert.equal(h.proxy.arrivals().length, 1, "迟到结果不触发任何新分派");
  } finally {
    await h.close();
  }
});

test("旧响应-6：响应虽经扣压迟到、但期间没有后续转交——正常分派成功的现有行为不变", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    const wang = await h.proxy.parkNext();
    assert.equal(wang.changed, true);

    h.proxy.deliverParked();
    const s = await waitSettled(h);
    assert.equal(s.input, "", "没有后续转交、等待期间也未编辑：照常清空输入");
    assert.equal(s.notice.text, "分派成功，负责人：王芳", "沿用普通成功提示，不出现随后转交措辞");
    assert.equal(s.fields["负责人"], "王芳");
    assert.equal(s.fields["最近处理时间"], fmtMinute(wang.ticket.updatedAt));
    assert.equal(s.history.length, 1);
    assert.match(s.history[0], /^未分派 → 王芳 /);
    assert.equal(rowOf(s, ticket.id).assignee, "王芳");
  } finally {
    await h.close();
  }
});

test("旧响应-7：迟到的是负责人未变化的成功响应、期间工单已被转交——仍区分本次未变化与当前负责人", async () => {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h);
  // 先由另一页面把工单分派给王芳。
  const seeded = await assignDirect(h, ticket.id, "王芳", "seed-wang");
  await openApp(h);
  await openDetail(h, ticket.id);
  try {
    // 本页面提交与当前负责人相同的王芳：changed=false，响应扣压期间被转交给李静。
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    const same = await h.proxy.parkNext();
    assert.equal(same.changed, false);
    assert.equal(same.ticket.assignee, "王芳");
    assert.equal(same.ticket.updatedAt, seeded.ticket.updatedAt, "负责人未变化时时间不刷新");
    const li = await assignDirect(h, ticket.id, "李静", "other-page-transfer-7");
    await registerViaForm(h, "未变化响应迟到");

    h.proxy.deliverParked();
    const s = await waitSettled(h);
    assert.equal(s.fields["负责人"], "李静");
    assert.equal(s.fields["最近处理时间"], fmtMinute(li.ticket.updatedAt));
    assert.equal(s.history.length, 2, "转交记录完整，不被未变化响应撤回");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /提交的负责人与当时的负责人相同，本次负责人未变化，当时负责人为：王芳/);
    assert.match(s.notice.text, /当前负责人为：李静/);
    assert.equal(s.input, "");
  } finally {
    await h.close();
  }
});
