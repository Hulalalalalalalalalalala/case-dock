import { test, after } from "node:test";
import assert from "node:assert/strict";
import { launchBrowser, createHarness } from "../lib/harness.mjs";
import { registerTicket, openApp, openDetail, readState } from "../lib/ui.mjs";

const browser = await launchBrowser();
after(async () => browser.close());

test("冒烟：页面可打开、可登记、详情显示未分派", async () => {
  const h = await createHarness(browser);
  try {
    const t = await registerTicket(h);
    await openApp(h);
    await openDetail(h, t.id);
    const s = await readState(h);
    assert.equal(s.fields["负责人"], "未分派");
    assert.equal(s.emptyHistory, "暂无分派记录。");
  } finally {
    await h.close();
  }
});
