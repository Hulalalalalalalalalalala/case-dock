package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const product = "CaseDock"
const resourceName = "tickets"

const page = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CaseDock · 客服工单与知识服务</title>
<style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.7}
a{color:#175b9c}
h2{margin-top:2rem}
form{display:flex;flex-direction:column;gap:.75rem;margin:1rem 0}
label{display:flex;flex-direction:column;gap:.25rem;font-weight:600}
input,select,textarea{font:inherit;padding:.5rem;border:1px solid #ccc;border-radius:4px}
textarea{min-height:5rem;resize:vertical}
button{font:inherit;padding:.5rem 1rem;background:#175b9c;color:#fff;border:0;border-radius:4px;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
.error{color:#b00020;font-weight:600}
.success{color:#1a7f37;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th,td{text-align:left;padding:.5rem;border-bottom:1px solid #eee;vertical-align:top}
th{font-weight:600}
tr[data-idx]{cursor:pointer}
tr[data-idx]:hover{background:#f5f8fc}
.summary{max-width:20rem}
.empty{color:#666}
#ticket-detail{margin-top:1rem}
.detail-row{margin:.5rem 0}
.detail-row strong{display:block}
.detail-row pre{white-space:pre-wrap;word-break:break-word;margin:.25rem 0 0;font:inherit;background:#f7f7f7;padding:.5rem;border-radius:4px}
</style>
</head>
<body>
<main>
<h1>CaseDock</h1>
<p>客服工单与知识服务</p>

<h2>登记工单</h2>
<form id="ticket-form">
  <label>问题描述<textarea name="description" required></textarea></label>
  <label>联系人<input name="contact" required></label>
  <label>联系方式<input name="contactInfo" required></label>
  <label>来源
    <select name="source">
      <option value="在线">在线</option>
      <option value="电话">电话</option>
      <option value="邮件">邮件</option>
    </select>
  </label>
  <label>类别<input name="category" required placeholder="如：账户问题"></label>
  <label>优先级
    <select name="priority">
      <option value="低">低</option>
      <option value="普通" selected>普通</option>
      <option value="高">高</option>
      <option value="紧急">紧急</option>
    </select>
  </label>
  <label>附件说明（可选）<textarea name="attachment"></textarea></label>
  <label>关联订单号（可选）<input name="orderNo"></label>
  <button type="submit">提交登记</button>
</form>
<div id="form-message"></div>

<h2>工单列表</h2>
<div id="ticket-list"><p class="empty">加载中…</p></div>
<div id="ticket-detail"></div>

<p><a href="/api/tickets">查看工单列表接口</a> · <a href="/health">服务状态</a></p>
</main>

<script>
(function(){
  var form = document.getElementById('ticket-form');
  var msg = document.getElementById('form-message');
  var listEl = document.getElementById('ticket-list');
  var detailEl = document.getElementById('ticket-detail');
  var ticketsCache = [];
  var submitId = newSubmitId();

  function newSubmitId(){
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c){
      var r = Math.random()*16|0, v = c === 'x' ? r : (r&0x3|0x8);
      return v.toString(16);
    });
  }

  function esc(s){
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function summary(t){
    var line = (t.description || '').split('\n')[0];
    if (line.length > 50) line = line.slice(0, 50) + '…';
    return line;
  }

  function fmtTime(ts){
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d)) return String(ts);
    return d.toLocaleString('zh-CN');
  }

  function renderList(tickets){
    ticketsCache = tickets || [];
    if (ticketsCache.length === 0){
      listEl.innerHTML = '<p class="empty">还没有工单记录。</p>';
      detailEl.innerHTML = '';
      return;
    }
    var html = '<table><thead><tr><th>编号</th><th>摘要</th><th>状态</th><th>负责人</th><th>最近处理时间</th></tr></thead><tbody>';
    ticketsCache.forEach(function(t, i){
      html += '<tr data-idx="' + i + '"><td>' + esc(t.id) + '</td><td class="summary">' + esc(summary(t)) + '</td><td>' + esc(t.status) + '</td><td>' + esc(t.assignee) + '</td><td>' + esc(fmtTime(t.updatedAt)) + '</td></tr>';
    });
    html += '</tbody></table>';
    listEl.innerHTML = html;
    var rows = listEl.querySelectorAll('tr[data-idx]');
    for (var i = 0; i < rows.length; i++){
      rows[i].addEventListener('click', function(){
        var t = ticketsCache[Number(this.getAttribute('data-idx'))];
        showDetail(t);
      });
    }
  }

  function showDetail(t){
    var fields = [
      ['工单编号', t.id],
      ['问题描述', t.description],
      ['联系人', t.contact],
      ['联系方式', t.contactInfo],
      ['来源', t.source],
      ['类别', t.category],
      ['优先级', t.priority],
      ['附件说明', t.attachment],
      ['关联订单号', t.orderNo],
      ['状态', t.status],
      ['负责人', t.assignee],
      ['创建时间', fmtTime(t.createdAt)],
      ['最近处理时间', fmtTime(t.updatedAt)]
    ];
    var html = '<h3>工单详情</h3>';
    fields.forEach(function(f){
      html += '<div class="detail-row"><strong>' + esc(f[0]) + '</strong><pre>' + esc(f[1] == null ? '' : f[1]) + '</pre></div>';
    });
    detailEl.innerHTML = html;
  }

  function loadList(){
    fetch('/api/tickets')
      .then(function(r){ return r.json(); })
      .then(function(data){ renderList(data.tickets); })
      .catch(function(){ listEl.innerHTML = '<p class="empty">加载失败。</p>'; });
  }

  form.addEventListener('submit', function(e){
    e.preventDefault();
    msg.textContent = '';
    var btn = form.querySelector('button');
    btn.disabled = true;
    var payload = {
      submitId: submitId,
      description: form.description.value,
      contact: form.contact.value,
      contactInfo: form.contactInfo.value,
      source: form.source.value,
      category: form.category.value,
      priority: form.priority.value,
      attachment: form.attachment.value,
      orderNo: form.orderNo.value
    };
    fetch('/api/tickets', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(function(r){
      return r.json().then(function(data){ return {status: r.status, data: data}; });
    }).then(function(res){
      if (res.status === 200 || res.status === 201){
        msg.innerHTML = '<p class="success">登记成功，工单编号：' + esc(res.data.id) + '</p>';
        form.reset();
        submitId = newSubmitId();
        loadList();
      } else {
        msg.innerHTML = '<p class="error">登记失败：' + esc(res.data.error || '未知错误') + '</p>';
      }
    }).catch(function(){
      msg.innerHTML = '<p class="error">登记失败：网络错误</p>';
    }).finally(function(){
      btn.disabled = false;
    });
  });

  loadList();
})();
</script>
</body>
</html>`

// Ticket is a customer service work order.
type Ticket struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Contact     string    `json:"contact"`
	ContactInfo string    `json:"contactInfo"`
	Source      string    `json:"source"`
	Category    string    `json:"category"`
	Priority    string    `json:"priority"`
	Attachment  string    `json:"attachment"`
	OrderNo     string    `json:"orderNo"`
	Status      string    `json:"status"`
	Assignee    string    `json:"assignee"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ticketRequest is the incoming JSON body for POST /api/tickets.
type ticketRequest struct {
	SubmitID    string `json:"submitId"`
	Description string `json:"description"`
	Contact     string `json:"contact"`
	ContactInfo string `json:"contactInfo"`
	Source      string `json:"source"`
	Category    string `json:"category"`
	Priority    string `json:"priority"`
	Attachment  string `json:"attachment"`
	OrderNo     string `json:"orderNo"`
}

// store holds tickets and submit identifiers, persisted to a data file.
type store struct {
	mu          sync.Mutex
	file        string
	tickets     []Ticket
	submissions map[string]string // submitID -> ticketID
}

// loadStore reads the data file. A missing file yields an empty store.
// A present but unparseable file returns an error so callers never
// silently overwrite data with an empty list.
func loadStore(file string) (*store, error) {
	s := &store{file: file, submissions: map[string]string{}}
	raw, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var data struct {
		Tickets     []Ticket          `json:"tickets"`
		Submissions map[string]string `json:"submissions"`
	}
	if err := json.Unmarshal(raw, &data); err == nil && data.Tickets != nil {
		s.tickets = data.Tickets
		s.submissions = data.Submissions
		if s.submissions == nil {
			s.submissions = map[string]string{}
		}
		return s, nil
	}
	// Legacy format: a bare JSON array of tickets.
	var tickets []Ticket
	if err := json.Unmarshal(raw, &tickets); err != nil {
		return nil, err
	}
	s.tickets = tickets
	return s, nil
}

// save writes the store atomically via a temp file and rename.
func (s *store) save() error {
	data := struct {
		Tickets     []Ticket          `json:"tickets"`
		Submissions map[string]string `json:"submissions"`
	}{s.tickets, s.submissions}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.file)
}

var validSources = map[string]bool{"在线": true, "电话": true, "邮件": true}
var validPriorities = map[string]bool{"低": true, "普通": true, "高": true, "紧急": true}

// normalize trims surrounding whitespace from every text field.
// Newlines inside description and attachment are preserved.
func normalize(req *ticketRequest) ticketRequest {
	return ticketRequest{
		SubmitID:    strings.TrimSpace(req.SubmitID),
		Description: strings.TrimSpace(req.Description),
		Contact:     strings.TrimSpace(req.Contact),
		ContactInfo: strings.TrimSpace(req.ContactInfo),
		Source:      strings.TrimSpace(req.Source),
		Category:    strings.TrimSpace(req.Category),
		Priority:    strings.TrimSpace(req.Priority),
		Attachment:  strings.TrimSpace(req.Attachment),
		OrderNo:     strings.TrimSpace(req.OrderNo),
	}
}

// validate returns a distinct error message for each rule, or "" if valid.
func validate(n ticketRequest) string {
	if n.SubmitID == "" {
		return "submit identifier is required"
	}
	if n.Description == "" {
		return "description is required"
	}
	if n.Contact == "" {
		return "contact is required"
	}
	if n.ContactInfo == "" {
		return "contact info is required"
	}
	if n.Source == "" {
		return "source is required"
	}
	if !validSources[n.Source] {
		return "source must be one of: 在线, 电话, 邮件"
	}
	if n.Category == "" {
		return "category is required"
	}
	if n.Priority == "" {
		return "priority is required"
	}
	if !validPriorities[n.Priority] {
		return "priority must be one of: 低, 普通, 高, 紧急"
	}
	return ""
}

// sameContent compares the normalized text fields of a stored ticket
// against a normalized request.
func sameContent(t Ticket, n ticketRequest) bool {
	return t.Description == n.Description &&
		t.Contact == n.Contact &&
		t.ContactInfo == n.ContactInfo &&
		t.Source == n.Source &&
		t.Category == n.Category &&
		t.Priority == n.Priority &&
		t.Attachment == n.Attachment &&
		t.OrderNo == n.OrderNo
}

// newTicketID generates a unique identifier that does not repeat across
// restarts: a date prefix plus 16 random hex characters.
func newTicketID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "T" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return "T-" + time.Now().UTC().Format("20060102") + "-" + hex.EncodeToString(b)
}

// create validates and persists a new ticket. It returns the ticket,
// an HTTP status code, and an error message. A replay with the same
// submit identifier and content returns the original ticket; a replay
// with different content returns 409 without modifying records.
func (s *store) create(req ticketRequest) (Ticket, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := normalize(&req)
	if msg := validate(n); msg != "" {
		return Ticket{}, http.StatusBadRequest, msg
	}

	if ticketID, ok := s.submissions[n.SubmitID]; ok {
		for _, t := range s.tickets {
			if t.ID == ticketID {
				if sameContent(t, n) {
					return t, http.StatusOK, ""
				}
				return Ticket{}, http.StatusConflict, "submit identifier conflict: content differs from the original submission"
			}
		}
		return Ticket{}, http.StatusConflict, "submit identifier conflict: original ticket not found"
	}

	now := time.Now().UTC()
	t := Ticket{
		ID:          newTicketID(),
		Description: n.Description,
		Contact:     n.Contact,
		ContactInfo: n.ContactInfo,
		Source:      n.Source,
		Category:    n.Category,
		Priority:    n.Priority,
		Attachment:  n.Attachment,
		OrderNo:     n.OrderNo,
		Status:      "待处理",
		Assignee:    "未分派",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.tickets = append(s.tickets, t)
	s.submissions[n.SubmitID] = t.ID
	if err := s.save(); err != nil {
		s.tickets = s.tickets[:len(s.tickets)-1]
		delete(s.submissions, n.SubmitID)
		return Ticket{}, http.StatusInternalServerError, "unable to save tickets: " + err.Error()
	}
	return t, http.StatusCreated, ""
}

// list returns tickets sorted by creation time, newest first.
func (s *store) list() []Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Ticket, len(s.tickets))
	copy(out, s.tickets)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func run() error {
	if len(os.Args) < 2 {
		printHelp()
		return errors.New("expected serve or --help")
	}
	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		printHelp()
		return nil
	}
	if os.Args[1] != "serve" {
		return errors.New("expected serve or --help")
	}
	args := flag.NewFlagSet("case-dock serve", flag.ContinueOnError)
	args.SetOutput(os.Stdout)
	host := args.String("host", "127.0.0.1", "address to bind")
	port := args.Int("port", 8080, "port to bind; 0 selects an available port")
	data := args.String("data-dir", "data", "directory for local records")
	if err := args.Parse(os.Args[2:]); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if args.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if *port < 0 || *port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	dataFile := filepath.Join(*data, "tickets.json")
	st, err := loadStore(dataFile)
	if err != nil {
		return fmt.Errorf("unable to read tickets: %w", err)
	}

	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.Path
		switch route {
		case "/":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, page)
		case "/health":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			respond(w, http.StatusOK, map[string]string{"status": "ok", "product": product})
		case "/api/tickets":
			switch r.Method {
			case http.MethodGet:
				respond(w, http.StatusOK, map[string]any{resourceName: st.list()})
			case http.MethodPost:
				var req ticketRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					respond(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
					return
				}
				t, status, msg := st.create(req)
				if msg != "" {
					respond(w, status, map[string]string{"error": msg})
					return
				}
				respond(w, status, t)
			default:
				w.Header().Set("Allow", "GET, POST")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			}
		default:
			respond(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	listener, err := net.Listen("tcp", net.JoinHostPort(*host, fmt.Sprint(*port)))
	if err != nil {
		return err
	}
	fmt.Printf("%s listening on http://%s\n", product, listener.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 1)
	go func() { failures <- server.Serve(listener) }()
	select {
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func printHelp() {
	fmt.Println("CaseDock - 客服工单与知识服务")
	fmt.Println("Usage: go run . serve [--host ADDRESS] [--port PORT] [--data-dir DIRECTORY]")
	fmt.Println("       go run . --help")
	fmt.Println("Defaults: --host 127.0.0.1 --port 8080 --data-dir data")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
