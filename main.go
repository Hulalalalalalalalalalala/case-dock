package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// timeLayout 使用固定宽度的小数位，保证字符串按时间先后可比较。
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// validSources / validPriorities 是页面与接口共用的合法选项。
var validSources = []string{"在线", "电话", "邮件"}
var validPriorities = []string{"低", "普通", "高", "紧急"}

// ticketInput 是登记接口接收的字段，全部按文字处理。
type ticketInput struct {
	Description    string `json:"description"`
	ContactName    string `json:"contactName"`
	ContactInfo    string `json:"contactInfo"`
	Source         string `json:"source"`
	Category       string `json:"category"`
	Priority       string `json:"priority"`
	AttachmentNote string `json:"attachmentNote"`
	OrderNumber    string `json:"orderNumber"`
	SubmitID       string `json:"submitId"`
}

// unassigned 是登记后尚未分派时的负责人占位文字，不能作为负责人填写。
const unassigned = "未分派"

// assignmentInput 是分派接口接收的字段，负责人按文字处理。
type assignmentInput struct {
	Assignee    string `json:"assignee"`
	OperationID string `json:"operationId"`
}

// assignment 是一次负责人实际变化的分派记录。
type assignment struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   string `json:"at"`
}

// ticket 是保存并返回的工单记录。
type ticket struct {
	ID             string       `json:"id"`
	Description    string       `json:"description"`
	ContactName    string       `json:"contactName"`
	ContactInfo    string       `json:"contactInfo"`
	Source         string       `json:"source"`
	Category       string       `json:"category"`
	Priority       string       `json:"priority"`
	AttachmentNote string       `json:"attachmentNote"`
	OrderNumber    string       `json:"orderNumber"`
	Status         string       `json:"status"`
	Assignee       string       `json:"assignee"`
	CreatedAt      string       `json:"createdAt"`
	UpdatedAt      string       `json:"updatedAt"`
	Assignments    []assignment `json:"assignments"`
}

// storeFile 是磁盘上的持久化结构。submitIds 与 tickets 按位置一一对应。
type storeFile struct {
	Seq       int      `json:"seq"`
	Tickets   []ticket `json:"tickets"`
	SubmitIDs []string `json:"submitIds"`
	// AssignOperations 记录每张工单已成功的分派操作标识及其负责人：
	// 工单编号 -> operationId -> 去除首尾空白后的负责人。
	AssignOperations map[string]map[string]string `json:"assignOperations,omitempty"`
}

// ticketStore 持久化工单与已成功的提交标识，所有方法并发安全。
type ticketStore struct {
	mu        sync.Mutex
	path      string
	seq       int
	tickets   []ticket
	bySubmit  map[string]int               // submitId -> tickets 下标
	assignOps map[string]map[string]string // 工单编号 -> operationId -> assignee
}

func loadStore(path string) (*ticketStore, error) {
	s := &ticketStore{path: path, tickets: []ticket{}, bySubmit: map[string]int{}, assignOps: map[string]map[string]string{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data storeFile
	if err := json.Unmarshal(raw, &data); err != nil {
		// 兼容旧版本的纯数组文件 []。
		var legacy []ticket
		if legacyErr := json.Unmarshal(raw, &legacy); legacyErr != nil {
			return nil, err
		}
		data.Tickets = legacy
	}
	if data.Tickets != nil {
		s.tickets = data.Tickets
	}
	s.seq = data.Seq
	for i, t := range s.tickets {
		// 编号是重启后不重复的最终依据；旧数据缺少 seq 时从编号恢复。
		var n int
		if _, scanErr := fmt.Sscanf(t.ID, "TKT-%d", &n); scanErr == nil && n > s.seq {
			s.seq = n
		}
		if i < len(data.SubmitIDs) && data.SubmitIDs[i] != "" {
			s.bySubmit[data.SubmitIDs[i]] = i
		}
	}
	for id, ops := range data.AssignOperations {
		if len(ops) > 0 {
			s.assignOps[id] = ops
		}
	}
	return s, nil
}

// persistLocked 将当前数据原子写入磁盘，调用方须持有 s.mu。
func (s *ticketStore) persistLocked() error {
	ids := make([]string, len(s.tickets))
	for id, i := range s.bySubmit {
		if i >= 0 && i < len(ids) {
			ids[i] = id
		}
	}
	data := storeFile{Seq: s.seq, Tickets: s.tickets, SubmitIDs: ids, AssignOperations: s.assignOps}
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

var errConflict = errors.New("submit id reused with different content")

// create 校验后的数据登记为工单。同一提交标识、相同内容为幂等重放，
// 返回已有工单且 replay=true；同一标识不同内容返回 errConflict 且不改数据。
func (s *ticketStore) create(in ticketInput) (t ticket, replay bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.bySubmit[in.SubmitID]; ok {
		existing := s.tickets[idx]
		if sameTicketContent(existing, in) {
			return existing, true, nil
		}
		return ticket{}, false, errConflict
	}
	s.seq++
	now := time.Now().Format(timeLayout)
	t = ticket{
		ID:             fmt.Sprintf("TKT-%06d", s.seq),
		Description:    in.Description,
		ContactName:    in.ContactName,
		ContactInfo:    in.ContactInfo,
		Source:         in.Source,
		Category:       in.Category,
		Priority:       in.Priority,
		AttachmentNote: in.AttachmentNote,
		OrderNumber:    in.OrderNumber,
		Status:         "待处理",
		Assignee:       unassigned,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.tickets = append(s.tickets, t)
	s.bySubmit[in.SubmitID] = len(s.tickets) - 1
	if err := s.persistLocked(); err != nil {
		// 保存失败：回滚内存中的本次变更，登记不算完成。
		delete(s.bySubmit, in.SubmitID)
		s.tickets = s.tickets[:len(s.tickets)-1]
		s.seq--
		return ticket{}, false, err
	}
	return t, false, nil
}

var errNotFound = errors.New("ticket not found")
var errAssignConflict = errors.New("operation id reused with a different assignee")

// assign 将工单负责人分派或转交给 in.Assignee。changed 表示负责人是否实际变化。
// 同一工单内同一操作标识：提交相同负责人为幂等重放，返回当前工单且不做任何修改
// （即使工单后来已转交给别人，也不会被改回）；提交不同负责人返回 errAssignConflict。
// 负责人与当前相同视为成功但不追加记录、不刷新最近处理时间，操作标识仍会记录。
func (s *ticketStore) assign(id string, in assignmentInput) (t ticket, changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, tk := range s.tickets {
		if tk.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ticket{}, false, errNotFound
	}
	ops := s.assignOps[id]
	if prev, ok := ops[in.OperationID]; ok {
		if prev == in.Assignee {
			// 幂等重放：返回当前工单，不修改负责人、时间或记录。
			return s.tickets[idx], false, nil
		}
		return ticket{}, false, errAssignConflict
	}
	if ops == nil {
		ops = map[string]string{}
	}
	ops[in.OperationID] = in.Assignee

	cur := s.tickets[idx]
	if cur.Assignee == in.Assignee {
		// 负责人未变化：只记录操作标识，不追加分派记录、不刷新最近处理时间。
		s.assignOps[id] = ops
		if err := s.persistLocked(); err != nil {
			delete(ops, in.OperationID)
			return ticket{}, false, err
		}
		return cur, false, nil
	}

	now := time.Now().Format(timeLayout)
	updated := cur
	updated.Assignments = append(append([]assignment{}, cur.Assignments...), assignment{From: cur.Assignee, To: in.Assignee, At: now})
	updated.Assignee = in.Assignee
	updated.UpdatedAt = now
	s.tickets[idx] = updated
	s.assignOps[id] = ops
	if err := s.persistLocked(); err != nil {
		// 保存失败：回滚内存中的本次变更，分派不算完成。
		delete(ops, in.OperationID)
		s.tickets[idx] = cur
		return ticket{}, false, err
	}
	return updated, true, nil
}

// list 返回按创建时间从新到旧排列的工单副本。
func (s *ticketStore) list() []ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ticket, len(s.tickets))
	copy(out, s.tickets)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// sameTicketContent 按文字处理规则比较已有工单与本次提交（提交标识除外）。
func sameTicketContent(t ticket, in ticketInput) bool {
	return t.Description == in.Description &&
		t.ContactName == in.ContactName &&
		t.ContactInfo == in.ContactInfo &&
		t.Source == in.Source &&
		t.Category == in.Category &&
		t.Priority == in.Priority &&
		t.AttachmentNote == in.AttachmentNote &&
		t.OrderNumber == in.OrderNumber
}

// validateInput 按页面与接口一致的规则校验，并对文字字段去除首尾空白。
// 描述与附件说明只去除整体首尾空白，正文内部换行保留。
func validateInput(in *ticketInput) error {
	in.Description = strings.TrimSpace(in.Description)
	in.ContactName = strings.TrimSpace(in.ContactName)
	in.ContactInfo = strings.TrimSpace(in.ContactInfo)
	in.Source = strings.TrimSpace(in.Source)
	in.Category = strings.TrimSpace(in.Category)
	in.Priority = strings.TrimSpace(in.Priority)
	in.AttachmentNote = strings.TrimSpace(in.AttachmentNote)
	// 联系方式与订单号始终是字符串，不做数字转换，前导零不会丢失。
	in.OrderNumber = strings.TrimSpace(in.OrderNumber)
	in.SubmitID = strings.TrimSpace(in.SubmitID)

	var missing []string
	for _, f := range []struct{ name, value string }{
		{"description", in.Description},
		{"contactName", in.ContactName},
		{"contactInfo", in.ContactInfo},
		{"category", in.Category},
		{"submitId", in.SubmitID},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing or empty required fields: %s", strings.Join(missing, ", "))
	}
	if !oneOf(in.Source, validSources) {
		return fmt.Errorf("invalid source: %q; allowed: %s", in.Source, strings.Join(validSources, "/"))
	}
	if !oneOf(in.Priority, validPriorities) {
		return fmt.Errorf("invalid priority: %q; allowed: %s", in.Priority, strings.Join(validPriorities, "/"))
	}
	return nil
}

// validateAssignment 校验分派请求，并对文字字段去除首尾空白。
// 负责人去空白后必须有内容，且不能是占位文字“未分派”；操作标识必须非空。
func validateAssignment(in *assignmentInput) error {
	in.Assignee = strings.TrimSpace(in.Assignee)
	in.OperationID = strings.TrimSpace(in.OperationID)
	if in.Assignee == "" {
		return errors.New("missing or empty required field: assignee")
	}
	if in.Assignee == unassigned {
		return fmt.Errorf("invalid assignee: %q is reserved and cannot be used", unassigned)
	}
	if in.OperationID == "" {
		return errors.New("missing or empty required field: operationId")
	}
	return nil
}

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func newSubmitID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand 失败极不可能发生；退回纳秒时间戳仍能给出非空标识。
		return fmt.Sprintf("sub-%d", time.Now().UnixNano())
	}
	return "sub-" + hex.EncodeToString(b)
}

func respond(w http.ResponseWriter, status int, allow string, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
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
	if _, err := os.Stat(dataFile); errors.Is(err, os.ErrNotExist) {
		buf, err := json.MarshalIndent(storeFile{Seq: 0, Tickets: []ticket{}, SubmitIDs: []string{}}, "", "  ")
		if err != nil {
			return err
		}
		buf = append(buf, '\n')
		if err := os.WriteFile(dataFile, buf, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	store, err := loadStore(dataFile)
	if err != nil {
		return fmt.Errorf("load %s: %w", dataFile, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			respond(w, http.StatusNotFound, "", map[string]string{"error": "not found"})
			return
		}
		if r.Method != http.MethodGet {
			respond(w, http.StatusMethodNotAllowed, "GET", map[string]string{"error": "method not allowed"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respond(w, http.StatusMethodNotAllowed, "GET", map[string]string{"error": "method not allowed"})
			return
		}
		respond(w, http.StatusOK, "", map[string]string{"status": "ok", "product": product})
	})
	mux.HandleFunc("/api/tickets", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			tickets := store.list()
			respond(w, http.StatusOK, "", map[string]any{resourceName: tickets})
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				respond(w, http.StatusBadRequest, "", map[string]string{"error": "unable to read request body"})
				return
			}
			dec := json.NewDecoder(bytes.NewReader(body))
			var in ticketInput
			if decErr := dec.Decode(&in); decErr != nil {
				if errors.Is(decErr, io.EOF) {
					decErr = errors.New("request body is empty")
				}
				respond(w, http.StatusBadRequest, "", map[string]string{"error": "invalid JSON: " + decErr.Error()})
				return
			}
			var tail json.RawMessage
			if decErr := dec.Decode(&tail); !errors.Is(decErr, io.EOF) {
				respond(w, http.StatusBadRequest, "", map[string]string{"error": "invalid JSON: trailing data after the JSON object"})
				return
			}
			if err := validateInput(&in); err != nil {
				respond(w, http.StatusBadRequest, "", map[string]string{"error": err.Error()})
				return
			}
			t, replay, err := store.create(in)
			if errors.Is(err, errConflict) {
				respond(w, http.StatusConflict, "", map[string]string{"error": "submit id was already used with different content"})
				return
			}
			if err != nil {
				respond(w, http.StatusInternalServerError, "", map[string]string{"error": "unable to save ticket"})
				return
			}
			status := http.StatusCreated
			if replay {
				status = http.StatusOK
			}
			respond(w, status, "", t)
		default:
			respond(w, http.StatusMethodNotAllowed, "GET, POST", map[string]string{"error": "method not allowed"})
		}
	})
	mux.HandleFunc("/api/tickets/{id}/assignment", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respond(w, http.StatusMethodNotAllowed, "POST", map[string]string{"error": "method not allowed"})
			return
		}
		id := r.PathValue("id")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			respond(w, http.StatusBadRequest, "", map[string]string{"error": "unable to read request body"})
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		var in assignmentInput
		if decErr := dec.Decode(&in); decErr != nil {
			if errors.Is(decErr, io.EOF) {
				decErr = errors.New("request body is empty")
			}
			respond(w, http.StatusBadRequest, "", map[string]string{"error": "invalid JSON: " + decErr.Error()})
			return
		}
		var tail json.RawMessage
		if decErr := dec.Decode(&tail); !errors.Is(decErr, io.EOF) {
			respond(w, http.StatusBadRequest, "", map[string]string{"error": "invalid JSON: trailing data after the JSON object"})
			return
		}
		if err := validateAssignment(&in); err != nil {
			respond(w, http.StatusBadRequest, "", map[string]string{"error": err.Error()})
			return
		}
		t, changed, err := store.assign(id, in)
		if errors.Is(err, errNotFound) {
			respond(w, http.StatusNotFound, "", map[string]string{"error": "ticket not found: " + id})
			return
		}
		if errors.Is(err, errAssignConflict) {
			respond(w, http.StatusConflict, "", map[string]string{"error": "operation id was already used with a different assignee"})
			return
		}
		if err != nil {
			respond(w, http.StatusInternalServerError, "", map[string]string{"error": "unable to save assignment"})
			return
		}
		respond(w, http.StatusOK, "", map[string]any{"ticket": t, "changed": changed})
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
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
