package main

// page 是首页的全部内容。页面所有用户输入都以文本节点方式渲染，
// 不拼进 HTML，避免填写内容被当作页面代码执行。
const page = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CaseDock · 客服工单登记</title>
<style>
:root{color-scheme:light}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.7;color:#1f2933}
h1{font-size:1.5rem;margin-bottom:.2rem}
h2{font-size:1.15rem;margin-top:2rem}
a{color:#175b9c}
form{border:1px solid #d8dee4;border-radius:.6rem;padding:1.2rem 1.4rem;background:#fafbfc}
label{display:block;margin:.7rem 0 .2rem;font-weight:600}
.req{color:#c0392b}
.opt{font-weight:400;color:#6b7280;font-size:.85rem}
input[type=text],textarea,select{width:100%;box-sizing:border-box;padding:.45rem .55rem;border:1px solid #c2c8d0;border-radius:.35rem;font:inherit;background:#fff}
textarea{resize:vertical;min-height:5.5rem}
.row{display:flex;gap:1rem;flex-wrap:wrap}
.row>div{flex:1;min-width:12rem}
.actions{margin-top:1.1rem;display:flex;gap:.8rem;align-items:center}
button{font:inherit;padding:.5rem 1.2rem;border-radius:.35rem;border:1px solid #175b9c;background:#175b9c;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#175b9c}
.notice{margin-top:1rem;padding:.7rem 1rem;border-radius:.35rem;display:none;white-space:pre-wrap}
.notice.ok{display:block;background:#e8f5ec;border:1px solid #9ccaa8;color:#1d6b35}
.notice.err{display:block;background:#fdecea;border:1px solid #f1b0a8;color:#a6372d;white-space:normal}
table{border-collapse:collapse;width:100%;margin-top:.5rem;font-size:.95rem}
th,td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid #e4e7eb;vertical-align:top}
th{background:#f3f5f7}
td.summary{max-width:18rem}
.empty{color:#6b7280;padding:1rem 0}
.list-err{color:#a6372d}
.dialog{display:none;border:1px solid #d8dee4;border-radius:.6rem;padding:1.1rem 1.4rem;background:#fafbfc;margin-top:1rem}
.dialog.open{display:block}
.dialog h3{margin:.2rem 0 1rem}
dl{display:grid;grid-template-columns:7rem 1fr;gap:.35rem .8rem;margin:0}
dt{font-weight:600;color:#52606d}
dd{margin:0;white-space:pre-wrap;word-break:break-word;min-width:0}
.close{float:right}
.dialog h4{font-size:1rem;margin:1.2rem 0 .4rem}
.assign-list{margin:.2rem 0;padding-left:1.2rem}
.assign-list li{margin:.15rem 0}
.assign-time{color:#6b7280;font-size:.85rem}
#assign-form{margin-top:.3rem}
.tag{display:inline-block;padding:.05rem .5rem;border-radius:1rem;background:#eef2f6;font-size:.85rem}
.prio-紧急{background:#fdecea;color:#a6372d}
.prio-高{background:#fdf2e3;color:#9a5b13}
.prio-普通{background:#eef2f6;color:#33414e}
.prio-低{background:#e8f5ec;color:#1d6b35}
</style>
</head>
<body>
<h1>CaseDock 客服工单登记</h1>
<p>登记客户服务请求，提交后生成唯一工单编号。</p>

<h2>新建工单</h2>
<form id="ticket-form" novalidate>
  <label for="f-description">问题描述 <span class="req">*</span></label>
  <textarea id="f-description" name="description" placeholder="请描述客户遇到的问题，可保留换行"></textarea>

  <div class="row">
    <div>
      <label for="f-contactName">联系人 <span class="req">*</span></label>
      <input type="text" id="f-contactName" autocomplete="name">
    </div>
    <div>
      <label for="f-contactInfo">联系方式 <span class="req">*</span></label>
      <input type="text" id="f-contactInfo" placeholder="电话、邮箱或其他，前导零会保留">
    </div>
  </div>

  <div class="row">
    <div>
      <label for="f-source">来源 <span class="req">*</span></label>
      <select id="f-source">
        <option value="">请选择</option>
        <option value="在线">在线</option>
        <option value="电话">电话</option>
        <option value="邮件">邮件</option>
      </select>
    </div>
    <div>
      <label for="f-category">类别 <span class="req">*</span></label>
      <input type="text" id="f-category" placeholder="如：配送、退款、技术问题">
    </div>
    <div>
      <label for="f-priority">优先级 <span class="req">*</span></label>
      <select id="f-priority">
        <option value="">请选择</option>
        <option value="低">低</option>
        <option value="普通">普通</option>
        <option value="高">高</option>
        <option value="紧急">紧急</option>
      </select>
    </div>
  </div>

  <label for="f-orderNumber">关联订单号 <span class="opt">（选填，仅保存文字）</span></label>
  <input type="text" id="f-orderNumber" inputmode="text" placeholder="如：007788，前导零会保留">

  <label for="f-attachmentNote">附件说明 <span class="opt">（选填，仅保存文字，不上传文件）</span></label>
  <textarea id="f-attachmentNote" placeholder="可记录附件名称、数量等说明，可保留换行"></textarea>

  <div class="actions">
    <button type="submit" id="submit-btn">提交登记</button>
    <button type="button" class="secondary" id="reset-btn">清空重填</button>
  </div>
  <div id="form-notice" class="notice" role="alert"></div>
</form>

<h2>工单列表</h2>
<div id="list-area">
  <p class="empty">正在加载工单…</p>
</div>

<div id="detail" class="dialog" aria-hidden="true"></div>

<p style="margin-top:2rem"><a href="/api/tickets">工单列表接口</a> · <a href="/health">服务状态</a></p>

<script>
(function(){
  "use strict";
  var SOURCES = ["在线","电话","邮件"];
  var PRIORITIES = ["低","普通","高","紧急"];

  var form = document.getElementById("ticket-form");
  var fields = {
    description: document.getElementById("f-description"),
    contactName: document.getElementById("f-contactName"),
    contactInfo: document.getElementById("f-contactInfo"),
    source: document.getElementById("f-source"),
    category: document.getElementById("f-category"),
    priority: document.getElementById("f-priority"),
    orderNumber: document.getElementById("f-orderNumber"),
    attachmentNote: document.getElementById("f-attachmentNote")
  };
  var notice = document.getElementById("form-notice");
  var submitBtn = document.getElementById("submit-btn");

  // 本次登记的提交标识：未成功时保持不变，可修正内容后重试；
  // 成功后或用户主动开始新登记时重新生成。
  var submitId = newSubmitId();
  // 登记版本：每次“清空重填”递增。提交时记下当时的版本，
  // 请求结束时版本已变，说明等待期间用户开始了另一份登记，
  // 该结果只属于清空重填之前的那次提交，不能改动当前表单。
  var draftVersion = 0;
  // 进行中的登记请求：同一时间至多一个（提交按钮在等待期间禁用）。
  // 等待期间任一登记字段被改动时 edited 置为 true，使返回结果只处理
  // 发出请求时的那份登记，不波及等待期间继续填写的内容。
  var pendingSubmit = null;
  form.addEventListener("input", function(){
    if (pendingSubmit) pendingSubmit.edited = true;
  });
  form.addEventListener("change", function(){
    if (pendingSubmit) pendingSubmit.edited = true;
  });
  function newSubmitId(){
    if (window.crypto && window.crypto.getRandomValues) {
      var b = new Uint8Array(16);
      window.crypto.getRandomValues(b);
      var hex = "";
      for (var i=0;i<b.length;i++){ hex += ("0"+b[i].toString(16)).slice(-2); }
      return "sub-" + hex;
    }
    return "sub-" + Date.now().toString(36) + "-" + Math.floor(Math.random()*1e9).toString(36);
  }

  function setNotice(kind, text){
    notice.className = "notice " + kind;
    notice.textContent = text; // 以文本节点显示，不执行其中的页面代码
  }
  function clearNotice(){
    notice.className = "notice";
    notice.textContent = "";
  }

  // 与后端一致的校验：去除首尾空白后必填项必须有内容，选项必须合法。
  function collectAndValidate(){
    var payload = {
      description: fields.description.value.trim(),
      contactName: fields.contactName.value.trim(),
      contactInfo: fields.contactInfo.value.trim(),
      source: fields.source.value.trim(),
      category: fields.category.value.trim(),
      priority: fields.priority.value.trim(),
      orderNumber: fields.orderNumber.value.trim(),
      attachmentNote: fields.attachmentNote.value.trim(),
      submitId: submitId
    };
    var missing = [];
    if (!payload.description) missing.push("问题描述");
    if (!payload.contactName) missing.push("联系人");
    if (!payload.contactInfo) missing.push("联系方式");
    if (!payload.category) missing.push("类别");
    if (missing.length) {
      return {error: "请填写必填项：" + missing.join("、")};
    }
    if (SOURCES.indexOf(payload.source) === -1) {
      return {error: "来源必须是：在线、电话、邮件"};
    }
    if (PRIORITIES.indexOf(payload.priority) === -1) {
      return {error: "优先级必须是：低、普通、高、紧急"};
    }
    return {payload: payload};
  }

  form.addEventListener("submit", function(ev){
    ev.preventDefault();
    clearNotice();
    var result = collectAndValidate();
    if (result.error) {
      setNotice("err", result.error); // 校验失败，填写内容原样保留
      return;
    }
    submitBtn.disabled = true;
    // 结果只归属于提交时的这份登记：版本在提交时固定，等待期间
    // 用户“清空重填”会使版本变化；用户继续修改任一登记字段会使
    // edited 置位。两种情况下结果都不清空、不填回、不改动当前表单内容。
    var submittedVersion = draftVersion;
    pendingSubmit = {edited: false};
    function draftReplaced(){
      return draftVersion !== submittedVersion;
    }
    function draftEdited(){
      return !draftReplaced() && pendingSubmit && pendingSubmit.edited;
    }
    fetch("/api/tickets", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(result.payload)
    }).then(function(resp){
      return resp.json().catch(function(){ return {}; }).then(function(data){
        return {status: resp.status, data: data};
      });
    }).then(function(r){
      if (draftReplaced()) {
        // 等待期间用户已清空重填：结果属于清空重填之前的那次提交，
        // 只提示与更新列表，不清空、不填回、不改动当前新登记。
        if (r.status === 200 || r.status === 201) {
          var staleMsg = "清空重填之前的那次提交已登记成功，工单编号：" + r.data.id +
            "。\n当前这份登记尚未提交，填写内容已保留。";
          if (r.status === 200) {
            staleMsg = "清空重填之前的那次提交此前已登记成功，返回原工单，编号：" + r.data.id +
              "。\n当前这份登记尚未提交，填写内容已保留。";
          }
          setNotice("ok", staleMsg);
          loadTickets(); // 旧提交成功的工单仍应进入列表
        } else if (r.status === 409) {
          setNotice("err", "清空重填之前的那次提交出现提交标识冲突：" +
            (r.data.error || "同一提交标识对应了不同内容") +
            "\n记录未改动。该冲突与当前这份登记无关，当前内容尚未提交，可继续填写后提交。");
        } else {
          setNotice("err", "清空重填之前的那次提交失败（HTTP " + r.status + "）：" +
            (r.data.error || "未知错误") +
            "\n该失败与当前这份登记无关，当前内容尚未提交，可继续填写后提交。");
        }
        return;
      }
      if (r.status === 200 || r.status === 201) {
        var msg = "登记成功，新工单编号：" + r.data.id;
        if (r.status === 200) {
          msg = "该提交此前已登记成功，返回原工单，编号：" + r.data.id;
        }
        loadTickets();
        if (draftEdited()) {
          // 等待期间用户继续修改过：之前的提交照常登记并进入列表，
          // 但当前表单是一份尚未提交的新登记，保留返回时的全部当前值，
          // 不清空、不填回旧请求的内容，并换用新的提交标识，
          // 下次提交按新登记处理，不自动再次提交。
          submitId = newSubmitId();
          setNotice("ok", msg +
            "。\n您在等待结果期间修改的内容尚未提交，已按当前填写原样保留，请确认后再次提交。");
        } else {
          setNotice("ok", msg);
          form.reset();
          submitId = newSubmitId(); // 开始另一份登记使用新标识
        }
      } else if (draftEdited()) {
        // 请求失败属于此前发出的那次提交；当前内容是返回时表单里的内容，
        // 原样保留并恢复提交按钮，用户可继续修改后重试。
        if (r.status === 409) {
          setNotice("err", "此前的提交出现提交标识冲突：" +
            (r.data.error || "同一提交标识对应了不同内容") +
            "\n记录未改动，该结果不代表当前内容已保存。当前填写已保留；可改回原内容沿用原标识重试，或按“清空重填”开始另一份登记。");
        } else {
          setNotice("err", "此前的提交失败（HTTP " + r.status + "）：" +
            (r.data.error || "未知错误") +
            "\n当前填写已保留，可继续修改后重试。");
        }
      } else if (r.status === 409) {
        setNotice("err", "提交标识冲突：" + (r.data.error || "同一提交标识对应了不同内容") +
          "\n记录未改动。可改回原内容重试，或按“清空重填”开始另一份登记。");
      } else {
        setNotice("err", "登记失败（HTTP " + r.status + "）：" + (r.data.error || "未知错误") +
          "\n填写内容已保留，请修改后重试。");
      }
    }).catch(function(){
      if (draftReplaced()) {
        setNotice("err", "清空重填之前的那次提交失败：无法连接服务。" +
          "\n该失败与当前这份登记无关，当前内容尚未提交，可继续填写后提交。");
      } else if (draftEdited()) {
        setNotice("err", "此前的提交失败：无法连接服务。当前填写已保留，可继续修改后重试。");
      } else {
        setNotice("err", "登记失败：无法连接服务。填写内容已保留，请稍后重试。");
      }
    }).finally(function(){
      pendingSubmit = null;
      // 无论结果归属哪份登记，旧请求结束后提交按钮都恢复正常。
      submitBtn.disabled = false;
    });
  });

  document.getElementById("reset-btn").addEventListener("click", function(){
    form.reset();
    clearNotice();
    submitId = newSubmitId(); // 放弃当前未成功的填写，按另一份登记处理
    draftVersion += 1; // 进行中的旧请求结果不再属于当前这份登记
  });

  // ---- 列表与详情 ----
  var listArea = document.getElementById("list-area");
  var detail = document.getElementById("detail");
  var loaded = [];
  // confirmed 保存分派接口已确认成功的工单最新状态（工单编号 -> 工单）。
  // 列表读取可能始于分派成功之前，其旧响应不得撤回已确认的处理结果：
  // 合并时同一工单保留最近处理时间较新的一方，读取追平或更新后该记录即可丢弃。
  var confirmed = {};

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, function(c){
      return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
    });
  }
  function fmtTime(s){
    var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(s || "");
    if (m) return m[1]+"-"+m[2]+"-"+m[3]+" "+m[4]+":"+m[5];
    return s || "";
  }
  function summary(t){
    var line = (t.description || "").replace(/\s+$/,"");
    var nl = line.indexOf("\n");
    if (nl !== -1) line = line.slice(0, nl);
    if (line.length > 60) line = line.slice(0, 60) + "…";
    return line;
  }

  function renderList(){
    if (!loaded.length) {
      listArea.innerHTML = '<p class="empty">还没有工单记录。可在上方表单登记第一张工单。</p>';
      return;
    }
    var html = '<table><thead><tr>' +
      "<th>编号</th><th>问题摘要</th><th>来源</th><th>优先级</th><th>状态</th><th>负责人</th><th>最近处理时间</th><th></th>" +
      "</tr></thead><tbody>";
    loaded.forEach(function(t, i){
      html += "<tr>" +
        "<td>" + escapeHtml(t.id) + "</td>" +
        "<td class=\"summary\">" + escapeHtml(summary(t)) + "</td>" +
        "<td>" + escapeHtml(t.source) + "</td>" +
        "<td><span class=\"tag prio-" + escapeHtml(t.priority) + "\">" + escapeHtml(t.priority) + "</span></td>" +
        "<td>" + escapeHtml(t.status) + "</td>" +
        "<td>" + escapeHtml(t.assignee) + "</td>" +
        "<td>" + escapeHtml(fmtTime(t.updatedAt)) + "</td>" +
        "<td><button type=\"button\" class=\"secondary\" data-i=\"" + i + "\">查看</button></td>" +
      "</tr>";
    });
    html += "</tbody></table>";
    listArea.innerHTML = html;
  }

  listArea.addEventListener("click", function(ev){
    var btn = ev.target.closest("button[data-i]");
    if (!btn) return;
    showDetail(loaded[Number(btn.getAttribute("data-i"))]);
  });

  function row(k){
    return '<dt>' + escapeHtml(k) + '</dt><dd></dd>';
  }
  var current = null;      // 详情中正在查看的工单
  var assignOpId = null;   // 当前详情本次分派操作的标识：未成功时保持不变可重试，成功后重新生成
  var assignPending = {};  // 工单编号 -> 等待结果的分派请求数，结果只归属于提交时的工单
  // assignEdited 记录某工单在等待分派结果期间负责人输入框是否被改动过
  // （含主动清空、仅增删首尾空白）：以标记而非当前取值判断，
  // 这样“清空后等待”不会被误当成从未编辑。
  var assignEdited = {};   // 工单编号 -> 等待结果期间输入是否被改动

  function setAssignNotice(kind, text){
    var n = document.getElementById("assign-notice");
    if (!n) return;
    n.className = "notice " + kind;
    n.textContent = text; // 以文本节点显示，不执行其中的页面代码
  }

  function showDetail(t){
    current = t;
    assignOpId = newSubmitId(); // 每次打开详情开始一次新的分派操作
    detail.innerHTML =
      '<button type="button" class="secondary close">关闭</button>' +
      "<h3>工单详情</h3><dl>" +
      row("编号") + row("状态") + row("负责人") +
      row("优先级") + row("来源") + row("类别") +
      row("问题描述") + row("联系人") + row("联系方式") +
      row("关联订单号") + row("附件说明") +
      row("创建时间") + row("最近处理时间") +
      "</dl>" +
      "<h4>分派记录</h4>" +
      '<div class="assign-history"></div>' +
      "<h4>分派负责人</h4>" +
      '<form id="assign-form" novalidate>' +
      '<input type="text" id="f-assignee" placeholder="填写负责人姓名" autocomplete="off">' +
      '<div class="actions"><button type="submit" id="assign-btn">提交分派</button></div>' +
      '<div id="assign-notice" class="notice" role="alert"></div>' +
      "</form>";
    fillDetail(t);
    // 每次打开详情重置该工单的“等待期间已编辑”标记，并在本次详情的
    // 输入框上监听改动：等待结果期间的任何编辑只代表下一次操作的草稿。
    delete assignEdited[t.id];
    document.getElementById("f-assignee").addEventListener("input", function(){
      if (assignPending[t.id]) assignEdited[t.id] = true;
    });
    if (assignPending[t.id]) {
      // 重新打开时该工单仍有分派在等待结果，保持提交中的按钮状态
      var pendingBtn = document.getElementById("assign-btn");
      pendingBtn.disabled = true;
      pendingBtn.textContent = "正在分派…";
    }
    detail.classList.add("open");
    detail.setAttribute("aria-hidden","false");
    detail.scrollIntoView({behavior:"smooth", block:"nearest"});
  }

  // fillDetail 只更新详情中的取值与分派记录，不动分派表单与提示。
  function fillDetail(t){
    var map = {
      "编号": t.id, "状态": t.status, "负责人": t.assignee,
      "优先级": t.priority, "来源": t.source, "类别": t.category,
      "问题描述": t.description, "联系人": t.contactName, "联系方式": t.contactInfo,
      "关联订单号": t.orderNumber || "（无）", "附件说明": t.attachmentNote || "（无）",
      "创建时间": fmtTime(t.createdAt), "最近处理时间": fmtTime(t.updatedAt)
    };
    var dts = detail.querySelectorAll("dl dt");
    for (var i=0;i<dts.length;i++){
      // 以文本节点写入，换行由 CSS white-space:pre-wrap 保留
      dts[i].nextElementSibling.textContent = map[dts[i].textContent];
    }
    var hist = detail.querySelector(".assign-history");
    var recs = Array.isArray(t.assignments) ? t.assignments : [];
    if (!recs.length) {
      hist.innerHTML = '<p class="empty">暂无分派记录。</p>';
      return;
    }
    var html = '<ul class="assign-list">';
    recs.forEach(function(rec){ // 按发生顺序展示，姓名按普通文字显示
      html += "<li>" + escapeHtml(rec.from) + " → " + escapeHtml(rec.to) +
        ' <span class="assign-time">' + escapeHtml(fmtTime(rec.at)) + "</span></li>";
    });
    html += "</ul>";
    hist.innerHTML = html;
  }

  detail.addEventListener("submit", function(ev){
    if (!ev.target || ev.target.id !== "assign-form") return;
    ev.preventDefault();
    if (!current) return;
    var input = document.getElementById("f-assignee");
    var btn = document.getElementById("assign-btn");
    var assignee = input.value.trim();
    if (!assignee) {
      setAssignNotice("err", "请填写负责人。");
      return;
    }
    if (assignee === "未分派") {
      setAssignNotice("err", "负责人不能填写“未分派”。");
      return;
    }
    // 结果只归属于提交时的工单：编号与操作标识在提交时固定，
    // 之后关闭详情或查看其他工单都不改变本次请求的去向与结果的归属。
    var ticketId = current.id;
    var opId = assignOpId;
    // 本次分派以点击提交时的负责人为准；重新跟踪等待期间对输入框的改动。
    assignEdited[ticketId] = false;
    setAssignNotice("", "");
    btn.disabled = true;
    btn.textContent = "正在分派…";
    assignPending[ticketId] = (assignPending[ticketId] || 0) + 1;
    // 只有详情仍打开且仍在查看提交时的工单，结果才能更新详情、表单与按钮；
    // 否则结果只落到列表数据上，不打扰当前正在查看或填写的另一张工单。
    function viewingThis(){
      return detail.classList.contains("open") && current && current.id === ticketId;
    }
    fetch("/api/tickets/" + encodeURIComponent(ticketId) + "/assignment", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({assignee: assignee, operationId: opId})
    }).then(function(resp){
      return resp.json().catch(function(){ return {}; }).then(function(data){
        return {status: resp.status, data: data};
      });
    }).then(function(r){
      if (r.status === 200 && r.data && r.data.ticket) {
        var nt = r.data.ticket;
        confirmed[nt.id] = nt; // 已确认成功的结果，旧列表响应不得将其退回
        for (var i=0;i<loaded.length;i++){ // 列表立即显示新负责人与本次处理时间
          if (loaded[i].id === nt.id) { loaded[i] = nt; break; }
        }
        renderList();
        if (!viewingThis()) return; // 已关闭或切换查看对象：详情保持原样
        current = nt;
        fillDetail(nt);
        assignOpId = newSubmitId(); // 本次操作已成功，下一次分派使用新标识
        var fAssignee = document.getElementById("f-assignee");
        if (assignEdited[ticketId]) {
          // 等待期间改动过输入（含主动清空、仅改动首尾空白）：不写回本次
          // 请求的负责人，保留返回时输入框里的当前内容，它属于尚未提交的
          // 下一次分派；提示先讲清这次实际分派给了谁。
          var keptMsg = r.data.changed
            ? "分派成功，本次实际分派给：" + nt.assignee + "。"
            : "提交的负责人与当前负责人相同，负责人未变化，仍为：" + nt.assignee + "。";
          if (fAssignee.value.trim() === "") {
            keptMsg += "\n您在等待结果期间清空了输入框，当前内容为空且尚未提交；按钮已恢复，可重新填写后再分派。";
          } else {
            keptMsg += "\n输入框中的当前内容尚未提交，已原样保留（包括首尾空白）；按钮已恢复，请确认后再次提交分派。";
          }
          setAssignNotice("ok", keptMsg);
        } else {
          // 等待期间没有编辑过：成功后照常清空输入并恢复提交按钮。
          fAssignee.value = "";
          setAssignNotice("ok", r.data.changed ? "分派成功，负责人：" + nt.assignee : "负责人未变化");
        }
      } else if (!viewingThis()) {
        return; // 失败提示只属于提交时的工单，不覆盖另一张工单的提示
      } else if (r.status === 400) {
        setAssignNotice("err", "输入错误：" + (r.data.error || "请检查填写内容") +
          "\n填写内容已保留，可修改后重试。");
      } else if (r.status === 404) {
        setAssignNotice("err", "工单不存在：" + (r.data.error || ticketId) +
          "\n请刷新列表后重试。");
      } else if (r.status === 409) {
        setAssignNotice("err", "操作标识冲突：" + (r.data.error || "同一操作标识对应了不同负责人") +
          "\n记录未改动。请关闭详情后重新打开再分派。");
      } else if (assignEdited[ticketId]) {
        // 其他接口错误属于此前发出的那次分派；不能把输入框里后来填写的
        // 负责人描述成已分派。当前输入原样保留，由用户决定是否再次提交。
        setAssignNotice("err", "此前提交给“" + assignee + "”的分派失败（HTTP " + r.status + "）：" +
          (r.data.error || "未知错误") +
          "\n输入框中尚未提交的内容已原样保留，请确认后再次提交。");
      } else {
        setAssignNotice("err", "分派失败（HTTP " + r.status + "）：" + (r.data.error || "未知错误") +
          "\n填写内容已保留，请重试。");
      }
    }).catch(function(){
      if (!viewingThis()) return;
      if (assignEdited[ticketId]) {
        // 断网同样只针对此前发出的请求：当前（含等待期间改动的）输入原样保留。
        setAssignNotice("err", "此前提交给“" + assignee + "”的分派失败：无法连接服务。" +
          "输入框中尚未提交的内容已原样保留，请稍后确认后再提交。");
      } else {
        setAssignNotice("err", "分派失败：无法连接服务。填写内容已保留，请稍后重试。");
      }
    }).finally(function(){
      assignPending[ticketId] -= 1;
      if (assignPending[ticketId] <= 0) delete assignPending[ticketId];
      if (!viewingThis() || assignPending[ticketId]) return; // 不解除其他工单自己等待结果的状态
      var b = document.getElementById("assign-btn");
      if (b) {
        b.disabled = false;
        b.textContent = "提交分派";
      }
    });
  });
  detail.addEventListener("click", function(ev){
    if (ev.target.classList.contains("close")) {
      detail.classList.remove("open");
      detail.setAttribute("aria-hidden","true");
    }
  });

  function loadTickets(){
    return fetch("/api/tickets", {headers:{"Accept":"application/json"}})
      .then(function(resp){
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        return resp.json();
      })
      .then(function(data){
        var arr = Array.isArray(data.tickets) ? data.tickets : [];
        // 与已确认成功的分派结果合并：本次读取可能始于分派之前，
        // 其旧内容不能撤回已确认的负责人、最近处理时间与分派记录。
        // 时间格式固定宽度、可按字符串比较；同一工单取较新的一方。
        // 新登记的工单仍随本次读取进入列表，已确认但本次缺失的工单也保留。
        var merged = false;
        for (var id in confirmed) {
          var c = confirmed[id];
          var idx = -1;
          for (var i=0;i<arr.length;i++){ if (arr[i].id === id) { idx = i; break; } }
          if (idx === -1) {
            arr.push(c); // 读取开始于分派前而未包含该工单：仍应留在列表中
            merged = true;
          } else if (String(c.updatedAt) > String(arr[idx].updatedAt)) {
            arr[idx] = c; // 列表内容较旧：保留已确认的处理结果
          } else {
            delete confirmed[id]; // 列表已追平或更新，确认记录不再需要
          }
        }
        if (merged) {
          // 补入缺失工单后恢复与服务端一致的排列：创建时间从新到旧。
          arr.sort(function(a, b){
            if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? 1 : -1;
            return a.id < b.id ? 1 : -1;
          });
        }
        loaded = arr; // 只有读取成功才替换，失败时保留原列表
        renderList();
      })
      .catch(function(err){
        // 读取失败不用空列表覆盖已有记录
        if (!loaded.length) {
          listArea.innerHTML = '<p class="empty list-err">工单列表读取失败（' +
            escapeHtml(err.message) + '），暂未显示任何记录，请稍后刷新重试。</p>';
        } else {
          listArea.insertAdjacentHTML("beforeend",
            '<p class="list-err">刷新失败：继续显示此前读取到的 ' + loaded.length + ' 条记录。</p>');
        }
      });
  }

  loadTickets();
})();
</script>
</body>
</html>`
