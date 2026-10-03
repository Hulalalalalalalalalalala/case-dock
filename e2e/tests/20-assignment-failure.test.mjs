import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import {
  registerTicket, openApp, openDetail, setAssignee, submitAndWaitHeld,
  waitSettled, readState, rowOf, apiTicket, fmtMinute, waitQuiet,
} from "../lib/ui.mjs";

const browser = await launchBrowser();
after(async () => browser.close());

async function setup(seedAssignee) {
  const h = await createHarness(browser);
  const ticket = await registerTicket(h);
  let seededAt = ticket.updatedAt;
  if (seedAssignee) {
    // 直连真实服务预置当前负责人，不经过门控。
    const resp = await fetch(`${h.upstream}/api/tickets/${ticket.id}/assignment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assignee: seedAssignee, operationId: "seed-op-1" }),
    });
    assert.equal(resp.status, 200);
    const body = await resp.json();
    seededAt = body.ticket.updatedAt;
  }
  await openApp(h);
  await openDetail(h, ticket.id);
  return { h, ticket, seededAt };
}

// assertUnchanged 核对列表、详情与接口中的负责人、处理时间、分派记录均未被失败结果改写。
async function assertUnchanged(h, ticket, assignee, updatedAt, recordCount) {
  const s = await readState(h);
  assert.equal(s.fields["负责人"], assignee);
  assert.equal(s.fields["最近处理时间"], fmtMinute(updatedAt));
  assert.equal(s.history.length, recordCount);
  const row = rowOf(s, ticket.id);
  assert.equal(row.assignee, assignee);
  assert.equal(row.updated, fmtMinute(updatedAt));
  const persisted = await apiTicket(h, ticket.id);
  assert.equal(persisted.assignee, assignee);
  assert.equal(persisted.updatedAt, updatedAt);
  assert.equal((persisted.assignments || []).length, recordCount);
  return s;
}

test("失败-1：保存失败响应（500），等待期间改过输入——不提示成功，记录不改写，草稿保留，重试须用户主动发起", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    const opFirst = h.proxy.heldBody().operationId;
    await setAssignee(h, "李静"); // 等待期间改填另一个名字

    await h.proxy.releaseNext({ status: 500, error: "unable to save assignment" });
    const s = await waitSettled(h);

    // 此前提交的分派不能被提示成成功；失败要明确指向此前提交的负责人。
    assert.equal(s.notice.kind, "err");
    assert.ok(!/成功/.test(s.notice.text), "失败提示中不应出现成功措辞");
    assert.match(s.notice.text, /此前提交给“王芳”的分派失败（HTTP 500）/);
    assert.match(s.notice.text, /unable to save assignment/);
    assert.match(s.notice.text, /输入框中尚未提交的内容已原样保留/);
    // 当前输入只是未提交的草稿，按当前内容保留。
    assert.equal(s.input, "李静");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);
    // 不自动重试。
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0);
    assert.equal(h.proxy.arrivals().length, 1);

    // 用户主动提交草稿后重试才真正分派；失败后操作标识保持不变可供重试，
    // 但这里提交的是新草稿，沿用页面当前操作标识不应影响成功。
    await submitAndWaitHeld(h);
    const arrivals = h.proxy.arrivals();
    assert.equal(arrivals.length, 2);
    assert.equal(arrivals[1].assignee, "李静");
    assert.equal(arrivals[0].operationId, opFirst);
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.fields["负责人"], "李静");
    assert.equal(s2.history.length, 1);
    assert.match(s2.history[0], /^未分派 → 李静 /);
  } finally {
    await h.close();
  }
});

test("失败-2：保存失败响应（500），等待期间未编辑——已填内容保留，用户可自行重试成功", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext({ status: 500, error: "unable to save assignment" });
    const s = await waitSettled(h);

    assert.equal(s.notice.kind, "err");
    assert.match(s.notice.text, /^分派失败（HTTP 500）/);
    assert.match(s.notice.text, /填写内容已保留，请重试/);
    assert.equal(s.input, "王芳", "未编辑时保留提交时填写的内容");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);
    assert.equal(h.proxy.arrivals().length, 1);

    // 由用户主动重试，成功后记录才落库。
    await submitAndWaitHeld(h);
    assert.equal(h.proxy.arrivals().length, 2);
    assert.equal(h.proxy.arrivals()[1].assignee, "王芳");
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.input, "", "重试等待期间未编辑，成功后清空输入");
    assert.equal(s2.fields["负责人"], "王芳");
    assert.equal(s2.history.length, 1);
  } finally {
    await h.close();
  }
});

test("失败-3：无法连接服务，等待期间改过输入——失败仅属于此前的提交，草稿保留，记录不改写", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await setAssignee(h, "  李静  "); // 等待期间改填，含首尾空白

    await h.proxy.releaseNext("destroy"); // 直接中断连接
    const s = await waitSettled(h);

    assert.equal(s.notice.kind, "err");
    assert.ok(!/成功/.test(s.notice.text));
    assert.match(s.notice.text, /此前提交给“王芳”的分派失败：无法连接服务/);
    assert.match(s.notice.text, /输入框中尚未提交的内容已原样保留/);
    assert.equal(s.input, "  李静  ", "草稿（含首尾空白）原样保留");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "断连后不得自动重试");
    assert.equal(h.proxy.arrivals().length, 1);
  } finally {
    await h.close();
  }
});

test("失败-4：无法连接服务，等待期间清空——提示当前草稿未提交，空内容不能直接再分派", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "赵强");
    await submitAndWaitHeld(h);
    await setAssignee(h, "");
    await h.proxy.releaseNext("destroy");
    const s = await waitSettled(h);

    assert.equal(s.notice.kind, "err");
    assert.match(s.notice.text, /此前提交给“赵强”的分派失败：无法连接服务/);
    assert.match(s.notice.text, /尚未提交的内容已原样保留/);
    assert.equal(s.input, "");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);

    // 空内容仍须先填写有效负责人，前端拦截且不发请求。
    await h.page.click("#assign-btn");
    const blocked = await readState(h);
    assert.equal(blocked.notice.kind, "err");
    assert.match(blocked.notice.text, /请填写负责人/);
    assert.equal(h.proxy.arrivals().length, 1);

    // 用户重新填写并主动重试，分派成功。
    await setAssignee(h, "赵强");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.fields["负责人"], "赵强");
    assert.equal(s2.history.length, 1);
  } finally {
    await h.close();
  }
});

test("失败-5：保存失败响应不得改写已有负责人、处理时间与分派记录；随后用户主动重试才追加转交记录", async () => {
  const { h, ticket, seededAt } = await setup("高翔");
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await setAssignee(h, "李静"); // 等待期间又改了主意
    await h.proxy.releaseNext({ status: 500, error: "unable to save assignment" });
    const s = await waitSettled(h);

    assert.equal(s.notice.kind, "err");
    assert.match(s.notice.text, /此前提交给“王芳”的分派失败/);
    assert.equal(s.input, "李静");
    // 已有处理结果不能根据失败响应改写。
    await assertUnchanged(h, ticket, "高翔", seededAt, 1);
    assert.match(s.history[0], /^未分派 → 高翔 /);
    assert.equal(h.proxy.arrivals().length, 1);

    // 用户确认后主动提交草稿李静，才发生一次转交并刷新时间与记录。
    await submitAndWaitHeld(h);
    assert.equal(h.proxy.arrivals()[1].assignee, "李静");
    const resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, true);
    const s2 = await waitSettled(h);
    assert.equal(s2.fields["负责人"], "李静");
    assert.ok(resp.body.ticket.updatedAt > seededAt, "成功的重试应刷新最近处理时间");
    assert.equal(s2.fields["最近处理时间"], fmtMinute(resp.body.ticket.updatedAt));
    assert.equal(s2.history.length, 2);
    assert.match(s2.history[1], /^高翔 → 李静 /);
  } finally {
    await h.close();
  }
});

test("失败-6：无法连接服务，等待期间未编辑——不能提示成功，已填内容保留，用户自行重试", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    // 等待期间不改动输入。
    await h.proxy.releaseNext("destroy");
    const s = await waitSettled(h);

    assert.equal(s.notice.kind, "err", "断连绝不能被提示成成功");
    assert.equal(s.notice.text, "分派失败：无法连接服务。填写内容已保留，请稍后重试。");
    assert.equal(s.input, "王芳", "已填内容原样保留");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "断连后不得自动重试");
    assert.equal(h.proxy.arrivals().length, 1);

    // 用户主动重试后成功。
    await submitAndWaitHeld(h);
    assert.equal(h.proxy.arrivals()[1].assignee, "王芳");
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.fields["负责人"], "王芳");
    assert.equal(s2.history.length, 1);
  } finally {
    await h.close();
  }
});

test("失败-7：校验类错误（400）保留既有业务提示含义与填写内容，不自动重试", async () => {  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    await h.proxy.releaseNext({ status: 400, error: "missing or empty required field: assignee" });
    const s = await waitSettled(h);
    assert.equal(s.notice.kind, "err");
    assert.match(s.notice.text, /^输入错误：missing or empty required field: assignee/);
    assert.match(s.notice.text, /填写内容已保留，可修改后重试/);
    assert.equal(s.input, "王芳");
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });
    await assertUnchanged(h, ticket, "未分派", ticket.updatedAt, 0);
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0);
    assert.equal(h.proxy.arrivals().length, 1);
  } finally {
    await h.close();
  }
});
