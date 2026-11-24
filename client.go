// Package cloudafrica is a Go client for the CloudAfrica public API.
//
// The request/response types and the per-operation methods are generated
// (client.gen.go) from the pinned openapi.json; this file adds what generation
// cannot: authentication, idempotency keys, retries, a concurrency cap,
// problem+json errors and operation polling.
package cloudafrica

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

//go:generate go tool -modfile=tools/go.mod oapi-codegen --config oapi-codegen.yaml openapi.json

const (
	defaultConcurrency = 4
	defaultMaxRetries  = 5
	// defaultNotReadyRetries bounds resource-not-ready retries separately:
	// the platform's sync interval outlasts the transient budget, and the API
	// asks clients to cap them because the refusal can persist.
	defaultNotReadyRetries = 20

	backoffBase = 1 * time.Second
	backoffCap  = 30 * time.Second
	// maxRateLimitWait caps any server-directed wait (a 429's
	// X-RateLimit-Reset, a resource-not-ready Retry-After). X-RateLimit-Reset
	// is always about one minute ahead, whatever the window's real state.
	maxRateLimitWait = 60 * time.Second

	pollStart = 2 * time.Second
	pollCap   = 10 * time.Second

	idempotencyInProgress = "idempotency-in-progress"
	resourceNotReady      = "resource-not-ready"
	maxProblemBody        = 1 << 20
)

// Operation is an asynchronous operation as returned by GET /v1/operations/{id}.
type Operation = PublicOperationDto

// Client talks to the CloudAfrica API. API exposes the generated calls; they
// all go through the retrying, key-stamping transport.
type Client struct {
	API *ClientWithResponses

	endpoint string
	origin   string
	http     *http.Client
	base     http.RoundTripper
	product  string
	conc     int
	retries  int
	notReady int

	// Injectable for tests.
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithConcurrency sets the maximum number of in-flight requests (default 4).
func WithConcurrency(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.conc = n
		}
	}
}

// WithUserAgent prepends product (e.g. "ca/0.1.0") to the User-Agent, which
// otherwise is "cloudafrica-go/<Version>".
func WithUserAgent(product string) Option {
	return func(c *Client) { c.product = strings.TrimSpace(product) }
}

// WithTransport sets the underlying RoundTripper (default http.DefaultTransport;
// nil keeps the default).
func WithTransport(rt http.RoundTripper) Option {
	return func(c *Client) {
		if rt != nil {
			c.base = rt
		}
	}
}

// New builds a client for endpoint (e.g. https://api.cloudafrica.net,
// without /v1). Every request, retries included, takes its bearer credential
// from ts. The client sends requests only to endpoint's scheme and host: a
// redirect or operation Location naming another origin is refused, so the
// credential never leaves it.
func New(endpoint string, ts TokenSource, opts ...Option) (*Client, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return nil, errors.New("cloudafrica: endpoint is required")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("cloudafrica: endpoint %q must start with http:// or https://", endpoint)
	}
	if ts == nil {
		return nil, errors.New("cloudafrica: token source is required")
	}
	if st, ok := ts.(staticToken); ok && st == "" {
		return nil, errors.New("cloudafrica: token is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("cloudafrica: endpoint %q is not a URL with a host", endpoint)
	}
	c := &Client{
		endpoint: endpoint,
		origin:   originOf(u),
		base:     http.DefaultTransport,
		conc:     defaultConcurrency,
		retries:  defaultMaxRetries,
		notReady: defaultNotReadyRetries,
		now:      time.Now,
		sleep:    sleepCtx,
		jitter:   func(d time.Duration) time.Duration { return time.Duration(rand.Int64N(int64(d) + 1)) },
	}
	for _, o := range opts {
		o(c)
	}
	ua := "cloudafrica-go/" + Version
	if c.product != "" {
		ua = c.product + " " + ua
	}
	c.http = &http.Client{Transport: &transport{
		c:   c,
		ts:  ts,
		ua:  ua,
		sem: make(chan struct{}, c.conc),
	}}
	api, err := NewClientWithResponses(endpoint, WithHTTPClient(c.http))
	if err != nil {
		return nil, err
	}
	c.API = api
	return c, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// originOf is scheme://host with the scheme's default port dropped.
func originOf(u *url.URL) string {
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (scheme == "https" && strings.HasSuffix(host, ":443")) || (scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	return scheme + "://" + host
}

// transport stamps auth, User-Agent and Idempotency-Key, caps concurrency and
// retries per the API's contract.
type transport struct {
	c   *Client
	ts  TokenSource
	ua  string
	sem chan struct{}
}

// mintsCredential reports whether req mints a short-lived URL or token, the
// routes that must not carry an Idempotency-Key.
func mintsCredential(req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	p := req.URL.Path
	switch {
	case strings.HasPrefix(p, "/v1/buckets/"):
		return strings.HasSuffix(p, "/objects/download-url") || strings.HasSuffix(p, "/objects/upload-url")
	case strings.HasPrefix(p, "/v1/kubernetes/clusters/"):
		return strings.HasSuffix(p, "/token")
	}
	return false
}

func isWrite(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if o := originOf(req.URL); o != t.c.origin {
		return nil, fmt.Errorf("cloudafrica: refusing request to %s: not the configured endpoint %s", o, t.c.origin)
	}

	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	// One key per logical write, shared by every retry of it. Not on a mint:
	// the API replays an empty 200 for a repeated key, so a retry after a lost
	// reply would return no URL or token. Minting again without a key is safe.
	key := req.Header.Get("Idempotency-Key")
	if key == "" && isWrite(req.Method) && !mintsCredential(req) {
		key = uuid.NewString()
	}

	var attempt, notReady int
	for {
		// Take the slot before the token, so a request queued behind the cap
		// does not send a token fetched before it waited.
		select {
		case t.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		token, err := t.ts.Token(ctx)
		if err != nil {
			<-t.sem
			return nil, fmt.Errorf("cloudafrica: token: %w", err)
		}
		r := req.Clone(ctx)
		if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("User-Agent", t.ua)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}

		resp, err := t.c.base.RoundTrip(r)
		if err != nil {
			<-t.sem
			return nil, err
		}

		wait, class := t.retryDelay(resp, attempt)
		exhausted := false
		switch class {
		case retryTransient:
			exhausted = attempt >= t.c.retries
			attempt++
		case retryNotReady:
			exhausted = notReady >= t.c.notReady
			notReady++
		}
		if class == retryNone || exhausted {
			resp.Body = &releaseBody{ReadCloser: resp.Body, release: func() { <-t.sem }}
			return resp, nil
		}
		// The slot is freed while we wait; a deadline that cannot outlast the
		// wait ends the call now rather than after a futile sleep.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProblemBody))
		_ = resp.Body.Close()
		<-t.sem
		if dl, ok := ctx.Deadline(); ok && t.c.now().Add(wait).After(dl) {
			return nil, fmt.Errorf("cloudafrica: giving up after HTTP %d: retry in %s would pass the context deadline: %w",
				resp.StatusCode, wait.Round(time.Millisecond), context.DeadlineExceeded)
		}
		if err := t.c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

type retryClass int

const (
	retryNone retryClass = iota
	retryTransient
	retryNotReady
)

// retryDelay decides whether resp warrants a retry, from which budget, and how
// long to wait. It leaves resp.Body readable.
func (t *transport) retryDelay(resp *http.Response, attempt int) (time.Duration, retryClass) {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		if d, ok := t.rateLimitWait(resp); ok {
			return d, retryTransient
		}
		return t.backoff(attempt), retryTransient
	case http.StatusServiceUnavailable:
		return t.backoff(attempt), retryTransient
	case http.StatusConflict:
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxProblemBody))
		_ = resp.Body.Close()
		if err != nil {
			// Hand the caller the bytes read and then the read error, not a
			// truncated body that looks complete.
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), errReader{err}))
			return 0, retryNone
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		var p problemWire
		if json.Unmarshal(data, &p) != nil {
			return 0, retryNone
		}
		switch {
		case strings.HasSuffix(p.Type, idempotencyInProgress):
			return t.backoff(attempt), retryTransient
		case strings.HasSuffix(p.Type, resourceNotReady):
			if d, ok := retryAfter(resp); ok {
				return d, retryNotReady
			}
			return backoffCap, retryNotReady
		}
	}
	return 0, retryNone
}

// retryAfter reads a delta-seconds Retry-After, clamped to 1s..maxRateLimitWait.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
	if err != nil || n < 0 {
		return 0, false
	}
	return min(max(time.Duration(n)*time.Second, time.Second), maxRateLimitWait), true
}

// rateLimitWait reads X-RateLimit-Reset: unix seconds, or seconds from now.
func (t *transport) rateLimitWait(resp *http.Response) (time.Duration, bool) {
	v := strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset"))
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	var d time.Duration
	if n > 1_000_000_000 {
		d = time.Unix(n, 0).Sub(t.c.now())
	} else {
		d = time.Duration(n) * time.Second
	}
	if d < time.Second {
		d = time.Second
	}
	return min(d, maxRateLimitWait), true
}

// backoff is exponential with equal jitter: half fixed, half random.
func (t *transport) backoff(attempt int) time.Duration {
	d := backoffBase << min(attempt, 10)
	d = min(d, backoffCap)
	return d/2 + t.c.jitter(d/2)
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// FieldViolation is one field-level validation failure.
type FieldViolation struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type problemWire struct {
	Type       string           `json:"type"`
	Title      string           `json:"title"`
	Status     int              `json:"status"`
	Detail     string           `json:"detail"`
	Instance   string           `json:"instance"`
	RequestID  string           `json:"requestId"`
	TraceID    string           `json:"traceId"`
	Violations []FieldViolation `json:"violations"`
	Key        string           `json:"key"`
	Scope      string           `json:"scope"`
	Limit      int64            `json:"limit"`
	Used       int64            `json:"used"`
}

// APIError is an application/problem+json error response.
type APIError struct {
	Type       string
	Title      string
	Status     int
	Detail     string
	Instance   string
	RequestID  string
	TraceID    string
	Violations []FieldViolation
	Key        string
	Scope      string
	Limit      int64
	Used       int64
}

// Slug is the last path segment of Type, e.g. "limit-reached".
func (e *APIError) Slug() string {
	t := strings.TrimRight(e.Type, "/")
	if i := strings.LastIndex(t, "/"); i >= 0 {
		return t[i+1:]
	}
	return t
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d", e.Status)
	if s := e.Slug(); s != "" && s != "about:blank" {
		fmt.Fprintf(&b, " %s", s)
	}
	if e.Title != "" {
		fmt.Fprintf(&b, ": %s", e.Title)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Detail)
	}
	for _, v := range e.Violations {
		msg := v.Message
		if msg == "" {
			msg = v.Code
		}
		fmt.Fprintf(&b, "; %s: %s", v.Field, msg)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request %s)", e.RequestID)
	}
	return b.String()
}

// CheckResponse returns nil for a status below 400, otherwise an *APIError
// decoded from body (a problem+json document; a body that is not one still
// yields an APIError carrying the HTTP status).
func CheckResponse(resp *http.Response, body []byte) error {
	if resp == nil || resp.StatusCode < 400 {
		return nil
	}
	var p problemWire
	_ = json.Unmarshal(body, &p) // not JSON: fall back to the status alone
	// Status is the wire status, which the transport's retries also key on.
	e := &APIError{
		Type: p.Type, Title: p.Title, Status: resp.StatusCode, Detail: p.Detail, Instance: p.Instance,
		RequestID: p.RequestID, TraceID: p.TraceID, Violations: p.Violations,
		Key: p.Key, Scope: p.Scope, Limit: p.Limit, Used: p.Used,
	}
	if e.Title == "" && e.Detail == "" && p.Type == "" {
		e.Title = http.StatusText(resp.StatusCode)
	}
	return e
}

// IsNotFound reports whether err is an API 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// IsConflict reports whether err is an API 409.
func IsConflict(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

// IsSlug reports whether err is an API error whose problem type slug is slug.
func IsSlug(err error, slug string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Slug() == slug
}

// OperationError is returned by WaitForOperation for a failed or cancelled operation.
type OperationError struct {
	ID      string
	State   string
	Kind    string
	Message string
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("operation %s %s: %s: %s", e.ID, e.State, e.Kind, e.Message)
}

// OperationPath is the request path for an operation id.
func OperationPath(operationID string) string {
	return "/v1/operations/" + operationID
}

// WaitForOperation polls loc while the operation is pending or running, and
// returns once it is complete, failed or cancelled. loc is the 202's Location
// header or OperationPath(id). A path is joined onto the endpoint verbatim
// (operation ids contain "/" and must not be escaped); an absolute URL is used
// as given and must name the endpoint's origin. A failed or cancelled
// operation returns the operation together with an *OperationError. An error
// response (a 404, for example) ends the wait with an *APIError; a state
// other than the five documented ones ends it with an error naming the state.
func (c *Client) WaitForOperation(ctx context.Context, loc string) (*Operation, error) {
	target := loc
	if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
		target = c.endpoint + "/" + strings.TrimLeft(loc, "/")
	}
	delay := pollStart
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if err := CheckResponse(resp, data); err != nil {
			return nil, err
		}
		var op Operation
		if err := json.Unmarshal(data, &op); err != nil {
			return nil, fmt.Errorf("cloudafrica: decoding operation from %s: %w", loc, err)
		}
		state := ""
		if op.State != nil {
			state = strings.ToLower(*op.State)
		}
		switch state {
		case "complete":
			return &op, nil
		case "pending", "running":
		case "failed", "cancelled":
			oe := &OperationError{ID: loc, State: state}
			if op.Id != nil {
				oe.ID = *op.Id
			}
			if op.Error != nil {
				oe.Kind = deref(op.Error.Kind)
				oe.Message = deref(op.Error.Message)
			}
			return &op, oe
		default:
			return &op, fmt.Errorf("cloudafrica: operation %s has unexpected state %q", loc, state)
		}
		// 0.75d..d: jittered, and never beyond pollCap.
		wait := delay*3/4 + c.jitter(delay/4)
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
		delay = min(delay*3/2, pollCap)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
