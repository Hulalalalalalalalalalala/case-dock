import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import {
  registerTicket, openApp, openDetail, setAssignee, submitAndWaitHeld,
  waitSettled, readState, rowOf, apiTicket, fmtMinute, waitForRow, waitQuiet,
  waitListLoaded,
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

test("成功-1：等待期间改成另一个名字，结果只更新已提交的分派，草稿（含首尾空白）原样保留且不自动二次分派", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "王芳");
    await submitAndWaitHeld(h);
    const held = h.proxy.heldBody();
    assert.equal(held.assignee, "王芳");
    assert.ok(held.operationId, "提交应携带非空操作标识");

    // 等待结果期间把输入改成另一个名字，保留首尾空白。
    await setAssignee(h, "  李静  ");

    const resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, true, "首次分派负责人应实际变化");
    const serverTicket = resp.body.ticket;

    const s = await waitSettled(h);

    // 列表显示服务确认的实际负责人与最近处理时间，而不是草稿。
    const row = rowOf(s, ticket.id);
    assert.equal(row.assignee, "王芳");
    assert.equal(row.updated, fmtMinute(serverTicket.updatedAt));
    // 详情同样显示服务确认的负责人、最近处理时间与分派记录。
    assert.equal(s.fields["负责人"], "王芳");
    assert.equal(s.fields["最近处理时间"], fmtMinute(serverTicket.updatedAt));
    assert.equal(s.history.length, 1);
    assert.match(s.history[0], /^未分派 → 王芳 /);

    // 输入框保留返回时的原始内容，包括首尾空白；不被已分派负责人填回。
    assert.equal(s.input, "  李静  ");
    // 成功提示先讲清实际分派给谁，再说明输入框内容尚未提交。
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /分派成功，本次实际分派给：王芳/);
    assert.match(s.notice.text, /输入框中的当前内容尚未提交，已原样保留（包括首尾空白）/);
    // 按钮恢复可用，由用户决定是否继续提交。
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    // 不能自动把后来填写的名字再次分派：服务端只收到王芳那次请求。
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "等待结束后不应自动发出第二次分派");
    const arrivals = h.proxy.arrivals();
    assert.equal(arrivals.length, 1);
    assert.equal(arrivals[0].assignee, "王芳");
    const persisted = await apiTicket(h, ticket.id);
    assert.equal(persisted.assignee, "王芳");
    assert.equal(persisted.assignments.length, 1);

    // 用户主动再次提交草稿（输入框中仍是“  李静  ”）：新名字正常分派；
    // 此次等待期间未再编辑，成功后按现有行为清空输入。
    await submitAndWaitHeld(h);
    const second = h.proxy.arrivals();
    assert.equal(second.length, 2);
    assert.equal(second[1].assignee, "李静", "再次提交按去除首尾空白后的负责人发送");
    assert.notEqual(second[1].operationId, second[0].operationId, "成功后的下一次分派应使用新操作标识");
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.input, "", "等待期间未编辑，成功后应沿用清空输入的现有行为");
    assert.equal(s2.fields["负责人"], "李静");
    assert.equal(s2.history.length, 2);
    assert.match(s2.history[0], /^未分派 → 王芳 /);
    assert.match(s2.history[1], /^王芳 → 李静 /);
  } finally {
    await h.close();
  }
});

test("成功-2：等待期间主动清空输入，提示为空且未提交，恢复后仍须填写有效负责人才能再次分派", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "赵强");
    await submitAndWaitHeld(h);
    const opFirst = h.proxy.heldBody().operationId;

    await setAssignee(h, ""); // 等待期间主动清空

    const resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, true);
    const s = await waitSettled(h);

    assert.equal(s.fields["负责人"], "赵强");
    assert.equal(rowOf(s, ticket.id).assignee, "赵强");
    // 清空属于编辑：不能用刚提交的负责人填回输入。
    assert.equal(s.input, "");
    assert.equal(s.notice.kind, "ok");
    assert.match(s.notice.text, /分派成功，本次实际分派给：赵强/);
    assert.match(s.notice.text, /清空了输入框，当前内容为空且尚未提交/);
    assert.deepEqual(s.button, { disabled: false, text: "提交分派" });

    // 空内容不能再次分派：前端拦截且不发请求，按钮不会进入等待状态。
    await setAssignee(h, "");
    await h.page.click("#assign-btn");
    const blocked = await readState(h);
    assert.equal(blocked.notice.kind, "err");
    assert.match(blocked.notice.text, /请填写负责人/);
    assert.deepEqual(blocked.button, { disabled: false, text: "提交分派" });
    assert.equal(h.proxy.arrivals().length, 1, "空内容提交被拦截，不应发出分派请求");
    assert.equal(blocked.input, "");

    // 重新填写有效负责人后可再次分派，且使用新的操作标识。
    await setAssignee(h, "孙丽");
    await submitAndWaitHeld(h);
    const arrivals = h.proxy.arrivals();
    assert.equal(arrivals.length, 2);
    assert.equal(arrivals[1].assignee, "孙丽");
    assert.notEqual(arrivals[1].operationId, opFirst);
    await h.proxy.releaseNext("forward");
    const s2 = await waitSettled(h);
    assert.equal(s2.fields["负责人"], "孙丽");
    assert.equal(s2.history.length, 2);
  } finally {
    await h.close();
  }
});

test("成功-3：等待期间仅增删首尾空白仍算编辑，成功后不填回已提交负责人", async () => {
  // 3a：提交时无空白，等待期间只增加两端空白。
  {
    const { h, ticket } = await setup();
    try {
      await setAssignee(h, "周敏");
      await submitAndWaitHeld(h);
      await setAssignee(h, "  周敏  "); // 仅增加首尾空白
      const resp = await h.proxy.releaseNext("forward");
      assert.equal(resp.body.changed, true);
      const s = await waitSettled(h);
      assert.equal(s.fields["负责人"], "周敏");
      assert.equal(s.input, "  周敏  ", "仅增加空白也属于编辑，草稿原样保留");
      assert.match(s.notice.text, /分派成功，本次实际分派给：周敏/);
      assert.match(s.notice.text, /尚未提交，已原样保留（包括首尾空白）/);
      const persisted = await apiTicket(h, ticket.id);
      assert.equal(persisted.assignee, "周敏");
      assert.equal(persisted.assignments.length, 1);
    } finally {
      await h.close();
    }
  }
  // 3b：提交时带空白，等待期间只删除两端空白。
  {
    const { h, ticket } = await setup();
    try {
      await setAssignee(h, "  吴磊  ");
      await submitAndWaitHeld(h);
      assert.equal(h.proxy.heldBody().assignee, "吴磊", "页面发送去除首尾空白后的负责人");
      await setAssignee(h, "吴磊"); // 仅删除首尾空白
      const resp = await h.proxy.releaseNext("forward");
      assert.equal(resp.body.changed, true);
      const s = await waitSettled(h);
      assert.equal(s.fields["负责人"], "吴磊");
      assert.equal(s.input, "吴磊", "仅删除空白也属于编辑，不能被当作未编辑而清空");
      assert.equal(s.notice.kind, "ok");
      assert.match(s.notice.text, /分派成功，本次实际分派给：吴磊/);
      assert.match(s.notice.text, /尚未提交/);
    } finally {
      await h.close();
    }
  }
});

test("成功-4：等待期间完全没有改动输入时，沿用成功后清空输入的现有行为", async () => {
  const { h, ticket } = await setup();
  try {
    await setAssignee(h, "冯洁");
    await submitAndWaitHeld(h);
    // 等待期间不做任何输入操作。
    const resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, true);
    const s = await waitSettled(h);

    assert.equal(s.input, "", "未编辑时成功后应清空输入");
    assert.equal(s.notice.kind, "ok");
    assert.equal(s.notice.text, "分派成功，负责人：冯洁");
    assert.ok(!/尚未提交/.test(s.notice.text), "未编辑时不应出现草稿保留提示");
    assert.equal(s.fields["负责人"], "冯洁");
    assert.equal(rowOf(s, ticket.id).assignee, "冯洁");
    assert.match(s.history[0], /^未分派 → 冯洁 /);
    await waitForRow(h, ticket.id, "冯洁");
  } finally {
    await h.close();
  }
});

test("成功-5：提交与当前负责人相同仍成功，但不新增分派记录、不刷新最近处理时间，草稿规则一致", async () => {
  const { h, ticket } = await setup();
  try {
    // 先把工单分派给高翔，作为“当前负责人”（直连真实服务，不经过门控）。
    const seeded = await fetch(`${h.upstream}/api/tickets/${ticket.id}/assignment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assignee: "高翔", operationId: "seed-op-1" }),
    });
    assert.equal(seeded.status, 200);
    const seededBody = await seeded.json();
    assert.equal(seededBody.changed, true);
    const t0 = seededBody.ticket.updatedAt;

    await h.page.reload({ waitUntil: "domcontentloaded" });
    await waitListLoaded(h);
    await openDetail(h, ticket.id);

    // 5a：等待期间未编辑 → changed=false，输入清空，记录与时间不变。
    await setAssignee(h, "高翔");
    await submitAndWaitHeld(h);
    let resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, false);
    let s = await waitSettled(h);
    assert.equal(s.input, "");
    assert.equal(s.notice.text, "负责人未变化");
    assert.equal(s.fields["负责人"], "高翔");
    assert.equal(s.fields["最近处理时间"], fmtMinute(t0), "负责人相同时最近处理时间不应刷新");
    assert.equal(s.history.length, 1, "负责人相同时不应新增分派记录");
    assert.match(s.history[0], /^未分派 → 高翔 /);

    // 5b：等待期间改成另一个名字 → changed=false，草稿保留，后来名字不被自动分派。
    await setAssignee(h, "高翔");
    await submitAndWaitHeld(h);
    await setAssignee(h, "何琳");
    resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, false);
    s = await waitSettled(h);
    assert.equal(s.input, "何琳", "相同负责人分派期间的草稿同样保留");
    assert.match(s.notice.text, /提交的负责人与当前负责人相同，负责人未变化，仍为：高翔/);
    assert.match(s.notice.text, /输入框中的当前内容尚未提交/);
    assert.equal(s.fields["负责人"], "高翔");
    assert.equal(s.fields["最近处理时间"], fmtMinute(t0));
    assert.equal(s.history.length, 1);
    const heldAfter = await waitQuiet(h);
    assert.equal(heldAfter, 0, "不能自动把草稿名字再次分派");

    // 5c：等待期间清空 → changed=false，提示当前为空且未提交。
    await setAssignee(h, "高翔");
    await submitAndWaitHeld(h);
    await setAssignee(h, "");
    resp = await h.proxy.releaseNext("forward");
    assert.equal(resp.body.changed, false);
    s = await waitSettled(h);
    assert.equal(s.input, "");
    assert.match(s.notice.text, /负责人未变化，仍为：高翔/);
    assert.match(s.notice.text, /清空了输入框，当前内容为空且尚未提交/);
    assert.equal(s.fields["最近处理时间"], fmtMinute(t0));
    assert.equal(s.history.length, 1);

    // 接口侧最终核对：负责人仍为高翔，仅一条分派记录，时间停留在 t0。
    const persisted = await apiTicket(h, ticket.id);
    assert.equal(persisted.assignee, "高翔");
    assert.equal(persisted.updatedAt, t0);
    assert.equal(persisted.assignments.length, 1);
  } finally {
    await h.close();
  }
});
