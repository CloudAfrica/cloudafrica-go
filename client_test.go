package cloudafrica

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeClock) Sleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.sleeps...)
}

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) (*Client, *fakeClock, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	clk := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	c, err := New(srv.URL, StaticToken("cak_test_secret"), opts...)
	if err != nil {
		t.Fatal(err)
	}
	c.now = clk.Now
	c.sleep = clk.Sleep
	c.jitter = func(time.Duration) time.Duration { return 0 }
	return c, clk, srv
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"type":%q,"title":"t","status":%d,"detail":%q}`, typ, status, detail)
}

func createKey(c *Client) (*CreateSshKeyResponse, error) {
	return c.API.CreateSshKeyWithResponse(context.Background(),
		&CreateSshKeyParams{}, PublicCreateSshKeyRequest{Name: "n", PublicKey: "k"})
}

func TestAuthAndUserAgent(t *testing.T) {
	var auth, ua string
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth, ua = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}, WithUserAgent("ca/1.2.3"))
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer cak_test_secret" {
		t.Errorf("Authorization = %q", auth)
	}
	if ua != "ca/1.2.3 cloudafrica-go/"+Version {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestIdempotencyKeyReusedAcrossRetriesAndFreshPerWrite(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	var bodies []string
	var calls int32
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b := new(strings.Builder)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		bodies = append(bodies, b.String())
		mu.Unlock()
		// First two attempts of every write fail transiently.
		if atomic.AddInt32(&calls, 1)%3 != 0 {
			problem(w, http.StatusServiceUnavailable, "https://x/problems/unavailable", "later")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	for i := 0; i < 2; i++ {
		resp, err := createKey(c)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode() != http.StatusCreated {
			t.Fatalf("status = %d", resp.StatusCode())
		}
	}
	if len(keys) != 6 {
		t.Fatalf("expected 6 requests, got %d", len(keys))
	}
	if keys[0] == "" {
		t.Fatal("no Idempotency-Key sent")
	}
	if keys[0] != keys[1] || keys[1] != keys[2] {
		t.Errorf("write 1 keys differ across retries: %v", keys[:3])
	}
	if keys[3] != keys[4] || keys[4] != keys[5] {
		t.Errorf("write 2 keys differ across retries: %v", keys[3:])
	}
	if keys[0] == keys[3] {
		t.Errorf("two logical writes shared key %q", keys[0])
	}
	for i, b := range bodies {
		if !strings.Contains(b, `"publicKey":"k"`) {
			t.Errorf("attempt %d body not re-sent: %q", i, b)
		}
	}
}

func TestReadsCarryNoIdempotencyKey(t *testing.T) {
	var got string
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("GET carried Idempotency-Key %q", got)
	}
}

func TestRetry429WaitsForResetCapped(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&calls, 1) {
		case 1: // reset 45 s ahead, unix seconds
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Unix(1_800_000_000, 0).Add(45*time.Second).Unix()))
			problem(w, http.StatusTooManyRequests, "https://x/problems/rate-limited", "slow")
		case 2: // absurd reset is capped at 60 s
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Unix(1_800_000_000, 0).Add(time.Hour).Unix()))
			problem(w, http.StatusTooManyRequests, "https://x/problems/rate-limited", "slow")
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	})
	resp, err := c.API.ListSshKeysWithResponse(context.Background(), nil)
	if err != nil || resp.StatusCode() != 200 {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	s := clk.Sleeps()
	if len(s) != 2 || s[0] != 45*time.Second || s[1] != 60*time.Second {
		t.Errorf("sleeps = %v, want [45s 60s]", s)
	}
}

func TestRetry503ThenGiveUp(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		problem(w, http.StatusServiceUnavailable, "https://x/problems/unavailable", "down")
	})
	resp, err := c.API.ListSshKeysWithResponse(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 503 {
		t.Errorf("status = %d", resp.StatusCode())
	}
	if calls != int32(defaultMaxRetries+1) {
		t.Errorf("calls = %d, want %d", calls, defaultMaxRetries+1)
	}
	s := clk.Sleeps()
	if len(s) != defaultMaxRetries || s[0] != 500*time.Millisecond || s[1] != time.Second {
		t.Errorf("backoff sleeps = %v", s)
	}
	if e := CheckResponse(resp.HTTPResponse, resp.Body); !IsSlug(e, "unavailable") {
		t.Errorf("final body not decodable: %v", e)
	}
}

func TestConflictRetriedOnlyForIdempotencyInProgress(t *testing.T) {
	var calls int32
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			problem(w, http.StatusConflict, "https://x/problems/idempotency-in-progress", "first still running")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	resp, err := createKey(c)
	if err != nil || resp.StatusCode() != 201 || calls != 2 {
		t.Fatalf("resp=%v err=%v calls=%d", resp, err, calls)
	}

	calls = 0
	c2, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		problem(w, http.StatusConflict, "https://x/problems/name-taken", "already exists")
	})
	resp, err = createKey(c2)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("other 409 was retried: %d calls", calls)
	}
	if e := CheckResponse(resp.HTTPResponse, resp.Body); !IsConflict(e) || !IsSlug(e, "name-taken") {
		t.Errorf("err = %v", e)
	}
}

func TestResourceNotReadyRetriedAfterRetryAfter(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 3 {
			w.Header().Set("Retry-After", "7")
			problem(w, http.StatusConflict, "https://x/errors/resource-not-ready", "still being set up")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	resp, err := createKey(c)
	if err != nil || resp.StatusCode() != 201 || calls != 4 {
		t.Fatalf("resp=%v err=%v calls=%d", resp, err, calls)
	}
	s := clk.Sleeps()
	if len(s) != 3 || s[0] != 7*time.Second || s[2] != 7*time.Second {
		t.Errorf("sleeps = %v, want 3 x 7s", s)
	}
}

func TestResourceNotReadyHasItsOwnBudget(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		problem(w, http.StatusConflict, "https://x/errors/resource-not-ready", "still being set up")
	})
	resp, err := createKey(c)
	if err != nil {
		t.Fatal(err)
	}
	if calls != int32(defaultNotReadyRetries+1) {
		t.Errorf("calls = %d, want %d", calls, defaultNotReadyRetries+1)
	}
	if s := clk.Sleeps(); len(s) == 0 || s[0] != backoffCap {
		t.Errorf("no Retry-After: sleeps = %v, want %s each", s, backoffCap)
	}
	if e := CheckResponse(resp.HTTPResponse, resp.Body); !IsSlug(e, "resource-not-ready") {
		t.Errorf("final err = %v", e)
	}
}

func TestRetryAfterClamped(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": time.Second, "30": 30 * time.Second, "3600": maxRateLimitWait} {
		d, ok := retryAfter(&http.Response{Header: http.Header{"Retry-After": {in}}})
		if !ok || d != want {
			t.Errorf("Retry-After %s = %s %v, want %s", in, d, ok, want)
		}
	}
	for _, in := range []string{"", "-1", "Wed, 21 Oct 2026 07:28:00 GMT"} {
		if _, ok := retryAfter(&http.Response{Header: http.Header{"Retry-After": {in}}}); ok {
			t.Errorf("Retry-After %q parsed", in)
		}
	}
}

func TestOther4xxNotRetried(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 422} {
		var calls int32
		c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			problem(w, status, "https://x/problems/nope", "no")
		})
		if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("status %d retried: %d calls", status, calls)
		}
	}
}

func TestRetryStopsAtContextDeadline(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("X-RateLimit-Reset", "60")
		problem(w, http.StatusTooManyRequests, "https://x/problems/rate-limited", "slow")
	})
	// The guard compares the fake clock against a real deadline, so both
	// start from the wall clock: the deadline is live whenever the test runs.
	clk.now = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.API.ListSshKeysWithResponse(ctx, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
	if calls != 1 || len(clk.Sleeps()) != 0 {
		t.Errorf("calls=%d sleeps=%v, want one call and no sleep", calls, clk.Sleeps())
	}
}

func TestRateLimitResetForms(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name, header string
		want         time.Duration
	}{
		{"absent", "", 500 * time.Millisecond},
		{"unparseable", "abc", 500 * time.Millisecond},
		{"negative", "-5", 500 * time.Millisecond},
		{"relative seconds", "30", 30 * time.Second},
		{"unix in the past", fmt.Sprint(base.Add(-time.Minute).Unix()), time.Second},
		{"unix ahead", fmt.Sprint(base.Add(10 * time.Second).Unix()), 10 * time.Second},
	} {
		var calls int32
		c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&calls, 1) == 1 {
				if tc.header != "" {
					w.Header().Set("X-RateLimit-Reset", tc.header)
				}
				problem(w, http.StatusTooManyRequests, "https://x/problems/rate-limited", "slow")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		})
		if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if s := clk.Sleeps(); len(s) != 1 || s[0] != tc.want {
			t.Errorf("%s: sleeps = %v, want [%s]", tc.name, s, tc.want)
		}
	}
}

func TestProblemDecodingAndHelpers(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"type":"https://api.example.com/problems/limit-reached","title":"Limit reached",
"status":422,"detail":"VM cap","instance":"/v1/vms","requestId":"req-1","traceId":"tr-1",
"violations":[{"field":"name","code":"blank","message":"must not be blank"}],
"key":"VM","scope":"account","limit":10,"used":10,"unknownFuture":{"a":1}}`))
	})
	resp, err := c.API.GetVpcWithResponse(context.Background(), "v1")
	if err != nil {
		t.Fatal(err)
	}
	err = CheckResponse(resp.HTTPResponse, resp.Body)
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("not an APIError: %v", err)
	}
	if ae.Status != 422 || ae.Slug() != "limit-reached" || ae.Detail != "VM cap" || ae.RequestID != "req-1" ||
		ae.TraceID != "tr-1" || ae.Instance != "/v1/vms" || ae.Key != "VM" || ae.Scope != "account" ||
		ae.Limit != 10 || ae.Used != 10 || len(ae.Violations) != 1 || ae.Violations[0].Field != "name" {
		t.Errorf("decoded = %+v", ae)
	}
	if !IsSlug(err, "limit-reached") || IsSlug(err, "other") || IsNotFound(err) || IsConflict(err) {
		t.Error("helpers misclassify")
	}
	wrapped := fmt.Errorf("creating: %w", err)
	if !IsSlug(wrapped, "limit-reached") {
		t.Error("IsSlug does not unwrap")
	}
	if !strings.Contains(err.Error(), "limit-reached") || !strings.Contains(err.Error(), "must not be blank") {
		t.Errorf("Error() = %q", err.Error())
	}
	if IsNotFound(nil) || IsSlug(nil, "x") {
		t.Error("nil error classified")
	}
}

func TestCheckResponseNonProblemBody(t *testing.T) {
	err := CheckResponse(&http.Response{StatusCode: 404}, []byte("<html>nope</html>"))
	if !IsNotFound(err) {
		t.Errorf("err = %v", err)
	}
	if CheckResponse(&http.Response{StatusCode: 202}, nil) != nil {
		t.Error("2xx produced an error")
	}
}

func TestAPIErrorStatusIsTheWireStatus(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusNotFound}
	err := CheckResponse(resp, []byte(`{"type":"https://x/problems/not-found","status":500}`))
	if !IsNotFound(err) {
		t.Errorf("err = %v, want the wire 404 to win over the body's status", err)
	}
}

func TestUnknownFieldsAndEnumValuesTolerated(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"r1","direction":"sideways","action":"QUARANTINE","brandNew":[1,2]}],"nextCursor":null}`))
	})
	resp, err := c.API.ListVpcFirewallRulesWithResponse(context.Background(), "v1")
	if err != nil || resp.JSON200 == nil || resp.JSON200.Data == nil || len(*resp.JSON200.Data) != 1 {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	r := (*resp.JSON200.Data)[0]
	if r.Direction == nil || string(*r.Direction) != "sideways" {
		t.Errorf("unknown enum value not preserved: %+v", r.Direction)
	}
	if r.Direction.Valid() {
		t.Error("unknown enum reported valid")
	}
}

func opJSON(id, state string, extra string) string {
	return fmt.Sprintf(`{"id":%q,"kind":"vm.create","state":%q%s}`, id, state, extra)
}

func TestWaitForOperationComplete(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		state := []string{"pending", "running", "complete"}[min(int(atomic.AddInt32(&calls, 1))-1, 2)]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON("op-1", state, `,"future":true`)))
	})
	op, err := c.WaitForOperation(context.Background(), OperationPath("op-1"))
	if err != nil {
		t.Fatal(err)
	}
	if *op.State != "complete" || calls != 3 {
		t.Errorf("state=%s calls=%d", *op.State, calls)
	}
	s := clk.Sleeps()
	if len(s) != 2 || s[0] != 1500*time.Millisecond || s[1] != 2250*time.Millisecond {
		t.Errorf("poll sleeps = %v", s)
	}
}

func TestPollBackoffCapped(t *testing.T) {
	var calls int32
	c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		state := "running"
		if atomic.AddInt32(&calls, 1) > 8 {
			state = "complete"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON("op", state, "")))
	})
	c.jitter = func(d time.Duration) time.Duration { return d } // worst case: full jitter
	if _, err := c.WaitForOperation(context.Background(), OperationPath("op")); err != nil {
		t.Fatal(err)
	}
	for _, d := range clk.Sleeps() {
		if d > pollCap {
			t.Errorf("poll sleep %s exceeds cap", d)
		}
	}
	if s := clk.Sleeps(); s[0] != pollStart {
		t.Errorf("first poll sleep = %s, want %s", s[0], pollStart)
	}
}

func TestWaitForOperationFailedAndCancelled(t *testing.T) {
	for _, state := range []string{"failed", "cancelled"} {
		c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(opJSON("op-9", state, `,"error":{"kind":"quota","message":"no capacity"}`)))
		})
		op, err := c.WaitForOperation(context.Background(), OperationPath("op-9"))
		var oe *OperationError
		if !errors.As(err, &oe) {
			t.Fatalf("%s: err = %v", state, err)
		}
		if oe.Kind != "quota" || oe.Message != "no capacity" || oe.State != state || oe.ID != "op-9" {
			t.Errorf("%s: %+v", state, oe)
		}
		if op == nil || *op.State != state {
			t.Errorf("%s: operation not returned", state)
		}
		if !strings.Contains(err.Error(), "quota") || !strings.Contains(err.Error(), "no capacity") {
			t.Errorf("message lacks kind/message: %v", err)
		}
	}
}

func TestWaitForOperation404WhileWaitingIsHardError(t *testing.T) {
	var calls int32
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(opJSON("op-1", "running", "")))
			return
		}
		problem(w, http.StatusNotFound, "https://x/problems/not-found", "gone")
	})
	op, err := c.WaitForOperation(context.Background(), OperationPath("op-1"))
	if op != nil || !IsNotFound(err) {
		t.Errorf("op=%v err=%v", op, err)
	}
}

func TestWaitForOperationSlashedIdIsNotEscaped(t *testing.T) {
	const id = "temporal:default/wf-1/run-1"
	var reqURI, rawPath, path string
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		reqURI, rawPath, path = r.RequestURI, r.URL.RawPath, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON(id, "complete", "")))
	})
	for _, loc := range []string{OperationPath(id), "/v1/operations/" + id} {
		if _, err := c.WaitForOperation(context.Background(), loc); err != nil {
			t.Fatal(err)
		}
		if reqURI != "/v1/operations/"+id {
			t.Errorf("RequestURI = %q", reqURI)
		}
		if strings.Contains(strings.ToLower(reqURI+rawPath), "%2f") || path != "/v1/operations/"+id {
			t.Errorf("id escaped: uri=%q raw=%q path=%q", reqURI, rawPath, path)
		}
	}
}

func TestWaitForOperationAbsoluteLocation(t *testing.T) {
	c, _, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON("op-1", "complete", "")))
	})
	if _, err := c.WaitForOperation(context.Background(), srv.URL+"/v1/operations/op-1"); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForOperationRefusesAnotherOrigin(t *testing.T) {
	var foreign int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&foreign, 1)
	}))
	defer other.Close()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := c.WaitForOperation(context.Background(), other.URL+"/v1/operations/op-1"); err == nil ||
		!strings.Contains(err.Error(), "not the configured endpoint") {
		t.Errorf("err = %v", err)
	}
	if foreign != 0 {
		t.Errorf("foreign origin received %d requests", foreign)
	}
}

func TestRedirectToAnotherOriginCarriesNoToken(t *testing.T) {
	var foreignAuth []string
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		foreignAuth = append(foreignAuth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer other.Close()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/ssh-keys", http.StatusFound)
	})
	_, err := c.API.ListSshKeysWithResponse(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "not the configured endpoint") {
		t.Errorf("err = %v", err)
	}
	if len(foreignAuth) != 0 {
		t.Errorf("foreign origin received requests with Authorization %q", foreignAuth)
	}
}

func TestRedirectWithinTheEndpointKeepsTheToken(t *testing.T) {
	var auth string
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/moved" {
			http.Redirect(w, r, "/moved", http.StatusFound)
			return
		}
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer cak_test_secret" {
		t.Errorf("Authorization after same-origin redirect = %q", auth)
	}
}

func TestOriginOfDropsDefaultPorts(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.example.com:443/x": "https://api.example.com",
		"http://h:80":                   "http://h",
		"https://h:8443":                "https://h:8443",
		"http://h:443":                  "http://h:443",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := originOf(u); got != want {
			t.Errorf("originOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWaitForOperationUnexpectedStateIsAnError(t *testing.T) {
	for _, body := range []string{`{}`, opJSON("op-1", "weird", "")} {
		var calls int32
		c, clk, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // bounds a regression to a poll loop
		_, err := c.WaitForOperation(ctx, OperationPath("op-1"))
		cancel()
		if err == nil || !strings.Contains(err.Error(), "unexpected state") {
			t.Errorf("%s: err = %v", body, err)
		}
		if calls != 1 || len(clk.Sleeps()) != 0 {
			t.Errorf("%s: calls=%d sleeps=%v, want one poll", body, calls, clk.Sleeps())
		}
	}
}

func TestWaitForOperationStateIsCaseInsensitive(t *testing.T) {
	var calls int32
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		state := []string{"PENDING", "Running", "COMPLETE"}[min(int(atomic.AddInt32(&calls, 1))-1, 2)]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON("op-1", state, "")))
	})
	if _, err := c.WaitForOperation(context.Background(), OperationPath("op-1")); err != nil || calls != 3 {
		t.Errorf("err=%v calls=%d", err, calls)
	}
	c2, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"Failed"}`))
	})
	var oe *OperationError
	if _, err := c2.WaitForOperation(context.Background(), OperationPath("op-7")); !errors.As(err, &oe) ||
		oe.State != "failed" || oe.ID != OperationPath("op-7") {
		t.Errorf("err = %v (id falls back to loc when the body has none)", err)
	}
}

func TestWaitForOperationUndecodableBody(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<html>`))
	})
	if _, err := c.WaitForOperation(context.Background(), OperationPath("op-1")); err == nil ||
		!strings.Contains(err.Error(), "decoding operation") {
		t.Errorf("err = %v", err)
	}
}

func TestWaitForOperationCancelledMidPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON("op-1", "running", "")))
	})
	c.sleep = sleepCtx
	if _, err := c.WaitForOperation(ctx, OperationPath("op-1")); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestConcurrencyCap(t *testing.T) {
	for _, limit := range []int{0, 2} { // 0 => default of 4
		var cur, peak int32
		c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&cur, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			atomic.AddInt32(&cur, -1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}, WithConcurrency(limit))
		want := int32(defaultConcurrency)
		if limit > 0 {
			want = int32(limit)
		}
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if peak > want {
			t.Errorf("limit %d: peak in-flight %d > %d", limit, peak, want)
		}
		if peak < want {
			t.Errorf("limit %d: peak in-flight %d never reached %d", limit, peak, want)
		}
	}
}

func TestNewValidation(t *testing.T) {
	for _, tc := range []struct {
		ep string
		ts TokenSource
	}{
		{"", StaticToken("t")}, {"api.example.com", StaticToken("t")}, {"https://x", nil},
	} {
		if _, err := New(tc.ep, tc.ts); err == nil {
			t.Errorf("New(%q, %v) accepted", tc.ep, tc.ts)
		}
	}
}

func TestDefaultUserAgent(t *testing.T) {
	var ua string
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if ua != "cloudafrica-go/"+Version {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestTokenSourceAskedOnEveryAttempt(t *testing.T) {
	var calls, asked int32
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if atomic.AddInt32(&calls, 1) == 1 {
			problem(w, 503, "about:blank", "busy")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	ts := TokenSourceFunc(func(context.Context) (string, error) {
		return fmt.Sprintf("tok-%d", atomic.AddInt32(&asked, 1)), nil
	})
	c, err := New(srv.URL, ts)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "Bearer tok-1" || seen[1] != "Bearer tok-2" {
		t.Errorf("Authorization per attempt = %v", seen)
	}
}

func TestTokenSourceErrorStopsTheRequest(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	t.Cleanup(srv.Close)
	sentinel := errors.New("refresh refused")
	c, err := New(srv.URL, TokenSourceFunc(func(context.Context) (string, error) { return "", sentinel }))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.API.ListSshKeysWithResponse(context.Background(), nil)
	if !errors.Is(err, sentinel) || calls != 0 {
		t.Errorf("err=%v calls=%d", err, calls)
	}
}

func TestStaticTokenRejectsEmpty(t *testing.T) {
	if _, err := StaticToken("").Token(context.Background()); err == nil {
		t.Error("empty static token accepted")
	}
	if _, err := New("https://x", StaticToken("")); err == nil || !strings.Contains(err.Error(), "token is empty") {
		t.Errorf("New with an empty static token: err = %v", err)
	}
}

func TestWithTransportNilKeepsTheDefault(t *testing.T) {
	c, err := New("https://x", StaticToken("t"), WithTransport(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.base != http.DefaultTransport {
		t.Errorf("base = %v", c.base)
	}
}

func TestCallerIdempotencyKeyKeptAcrossRetries(t *testing.T) {
	var keys []string
	var mu sync.Mutex
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		n := len(keys)
		mu.Unlock()
		if n == 1 {
			problem(w, http.StatusServiceUnavailable, "https://x/problems/unavailable", "down")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	_, err := c.API.CreateSshKeyWithResponse(context.Background(),
		&CreateSshKeyParams{IdempotencyKey: "caller-key-1"}, PublicCreateSshKeyRequest{Name: "n", PublicKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "caller-key-1" || keys[1] != "caller-key-1" {
		t.Errorf("keys = %q, want the caller's key on both attempts", keys)
	}
}

func TestIdempotencyKeyByMethod(t *testing.T) {
	var got string
	c, _, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
	})
	for method, want := range map[string]bool{
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
		http.MethodGet: false, http.MethodHead: false,
	} {
		req, err := http.NewRequest(method, srv.URL+"/v1/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if (got != "") != want {
			t.Errorf("%s: Idempotency-Key = %q, want present=%v", method, got, want)
		}
	}
}

type failingTransport struct{ fails int32 }

func (f *failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if atomic.AddInt32(&f.fails, -1) >= 0 {
		return nil, errors.New("connection reset")
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestTransportErrorReleasesTheSlot(t *testing.T) {
	ft := &failingTransport{fails: 3}
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}, WithConcurrency(1), WithTransport(ft))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if _, err := c.API.ListSshKeysWithResponse(ctx, nil); err == nil {
			t.Fatalf("attempt %d: want the transport error", i)
		}
	}
	if _, err := c.API.ListSshKeysWithResponse(ctx, nil); err != nil {
		t.Errorf("after transport errors: %v (a leaked slot blocks until the deadline)", err)
	}
}

func TestSlotHeldUntilBodyClosed(t *testing.T) {
	c, _, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, WithConcurrency(1))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/x", nil)
	held, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.API.ListSshKeysWithResponse(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second request while the body is open: err = %v, want deadline exceeded", err)
	}
	closed := make(chan struct{})
	go func() {
		_ = held.Body.Close()
		_ = held.Body.Close() // a second Close must not release a slot it does not hold
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the body twice blocked: the second Close tried to release a slot")
	}
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if tr, ok := c.http.Transport.(*transport); !ok || len(tr.sem) != 0 {
		t.Error("slot still held after the body was closed")
	}
}

type truncatedConflict struct{}

func (truncatedConflict) RoundTrip(r *http.Request) (*http.Response, error) {
	body := io.MultiReader(strings.NewReader(`{"type":"https://x/problems/idempot`), errReader{errors.New("connection reset")})
	return &http.Response{StatusCode: http.StatusConflict, Header: http.Header{}, Body: io.NopCloser(body), Request: r}, nil
}

func TestConflictBodyReadErrorReachesTheCaller(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {}, WithTransport(truncatedConflict{}))
	if _, err := c.API.ListSshKeysWithResponse(context.Background(), nil); err == nil ||
		!strings.Contains(err.Error(), "connection reset") {
		t.Errorf("err = %v, want the body read error", err)
	}
}

func TestTokenFetchedOnlyOnceASlotIsHeld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	var calls atomic.Int32
	ts := TokenSourceFunc(func(context.Context) (string, error) {
		calls.Add(1)
		return "cak_test_secret", nil
	})
	c, err := New(srv.URL, ts, WithConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/x", nil)
	held, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.API.ListSshKeysWithResponse(context.Background(), nil)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("token calls while the queued request waits for a slot = %d, want 1", n)
	}
	_ = held.Body.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued request did not run after the slot was released")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("token calls = %d, want 2", n)
	}
}

func TestTokenErrorReleasesTheSlot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	var calls atomic.Int32
	ts := TokenSourceFunc(func(context.Context) (string, error) {
		if calls.Add(1) == 1 {
			return "", errors.New("refresh failed")
		}
		return "cak_test_secret", nil
	})
	c, err := New(srv.URL, ts, WithConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.API.ListSshKeysWithResponse(ctx, nil); err == nil || !strings.Contains(err.Error(), "refresh failed") {
		t.Fatalf("err = %v, want the token error", err)
	}
	if _, err := c.API.ListSshKeysWithResponse(ctx, nil); err != nil {
		t.Errorf("after a token error: %v (a leaked slot blocks until the deadline)", err)
	}
}
