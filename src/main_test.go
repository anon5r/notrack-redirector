package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestIsTrackerURL(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://px.a8.net/svt/ejp?a8mat=abc", true},
		{"https://px.a8.net/other", false},
		{"https://hb.afl.rakuten.co.jp/ichiba/abc.def/", true},
		{"https://ck.jp.ap.valuecommerce.com/servlet/referral?sid=1", true},
		{"https://t.afi-b.com/anything", true},
		{"https://evil.example/svt/ejp?a8mat=abc", false},
		{"https://px.a8.net.evil.example/svt/ejp", false},
		{"javascript:alert(1)", false},
	}
	for _, c := range cases {
		if got := isTrackerURL(mustParse(t, c.raw)); got != c.want {
			t.Errorf("isTrackerURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestTargetURL(t *testing.T) {
	cases := []struct {
		name           string
		host           string
		target         string
		forwardedProto string
		want           string
		wantErr        error
	}{
		{
			name:           "X-Forwarded-Proto があればそのスキームを引き継ぐ",
			host:           "px.a8.net",
			target:         "/svt/ejp?a8mat=abc",
			forwardedProto: "https",
			want:           "https://px.a8.net/svt/ejp?a8mat=abc",
		},
		{
			name:   "DNS 付け替え運用ではリクエストホストが対象になる",
			host:   "px.a8.net",
			target: "/svt/ejp?a8mat=abc",
			want:   "http://px.a8.net/svt/ejp?a8mat=abc",
		},
		{
			// パラメータに任意の URL を仕込んでも destination には使われない。
			name:   "パラメータの URL は対象決定に影響しない",
			host:   "px.a8.net",
			target: "/svt/ejp?a8mat=https%3A%2F%2Fphishing.example%2F",
			want:   "http://px.a8.net/svt/ejp?a8mat=https%3A%2F%2Fphishing.example%2F",
		},
		{
			name:    "allowlist 外のホストは対象外",
			host:    "redirector.example",
			target:  "/?url=https://phishing.example/",
			wantErr: errNotTracker,
		},
		{
			name:   "明示エンドポイントは allowlist 済みの URL を受け付ける",
			host:   "redirector.example",
			target: resolveEndpoint + "?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc",
			want:   "https://px.a8.net/svt/ejp?a8mat=abc",
		},
		{
			name:    "明示エンドポイントも allowlist 外は拒否する",
			host:    "redirector.example",
			target:  resolveEndpoint + "?u=https%3A%2F%2Fphishing.example%2F",
			wantErr: errNotTracker,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, c.target, nil)
			r.Host = c.host
			if c.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", c.forwardedProto)
			}

			got, err := targetURL(r)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != c.want {
				t.Errorf("targetURL = %q, want %q", got.String(), c.want)
			}
		})
	}
}

func TestValidateHopURL(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/",
		"http://localhost/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
		"http://[::1]/",
		"file:///etc/passwd",
		"https://printer.local/",
	}
	for _, raw := range blocked {
		if err := validateHopURL(mustParse(t, raw)); err == nil {
			t.Errorf("validateHopURL(%q) = nil, want error", raw)
		}
	}

	allowed := []string{"https://example.com/item", "http://93.184.216.34/"}
	for _, raw := range allowed {
		if err := validateHopURL(mustParse(t, raw)); err != nil {
			t.Errorf("validateHopURL(%q) = %v, want nil", raw, err)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		"127.0.0.1":       false,
		"10.1.2.3":        false,
		"172.16.0.1":      false,
		"192.168.1.1":     false,
		"169.254.169.254": false,
		"100.64.0.1":      false,
		"192.0.0.1":       false,
		"::1":             false,
		"fd00::1":         false,
	}
	for raw, want := range cases {
		if got := isPublicIP(net.ParseIP(raw)); got != want {
			t.Errorf("isPublicIP(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestStripTrackingParams(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{
			"https://example.com/p?id=1&utm_source=a8&gclid=xyz",
			"https://example.com/p?id=1",
		},
		{
			"https://www.amazon.co.jp/dp/B0000?tag=aff-22&linkCode=osi&psc=1",
			"https://www.amazon.co.jp/dp/B0000",
		},
		{
			"https://item.rakuten.co.jp/shop/item/?scid=af_link&l-id=top",
			"https://item.rakuten.co.jp/shop/item/",
		},
		{
			// ホスト固有パラメータは他ホストでは消さない。
			"https://example.com/search?tag=go&ref=top",
			"https://example.com/search?ref=top&tag=go",
		},
		{
			"https://example.com/p",
			"https://example.com/p",
		},
	}
	for _, c := range cases {
		got := stripTrackingParams(mustParse(t, c.raw)).String()
		if got != c.want {
			t.Errorf("stripTrackingParams(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestParseHostMap(t *testing.T) {
	got := parseHostMap(" PX.A8.NET=203.0.113.10 , broken , hb.afl.rakuten.co.jp=203.0.113.11 ")
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (%v)", len(got), got)
	}
	if got["px.a8.net"] != "203.0.113.10" {
		t.Errorf("px.a8.net = %q", got["px.a8.net"])
	}
	if got["hb.afl.rakuten.co.jp"] != "203.0.113.11" {
		t.Errorf("hb.afl.rakuten.co.jp = %q", got["hb.afl.rakuten.co.jp"])
	}
}

// newTestClient は上流にテストサーバーを使うためのクライアントを生成する。
func newTestClient(t *testing.T, hostMap string) *http.Client {
	t.Helper()
	t.Setenv(envUpstreamHostMap, hostMap)
	t.Setenv(envAllowPrivate, "1")
	return newUpstreamClient()
}

func TestResolveDestinationFollowsUpstreamOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/svt/ejp":
			// パラメータの値ではなく上流が返す Location が採用されること。
			http.Redirect(w, r, "http://example.com/hop", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, "http://example.com/final?id=1&utm_source=a8", http.StatusFound)
		case "/final":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	addr := strings.TrimPrefix(upstream.URL, "http://")
	client := newTestClient(t, "px.a8.net="+addr+",example.com="+addr)

	target := mustParse(t, "http://px.a8.net/svt/ejp?a8mat=https://phishing.example/")
	result, err := resolveDestination(client, target)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if len(result.Hops) != 2 {
		t.Errorf("hops = %v, want 2 entries", result.Hops)
	}

	got := stripTrackingParams(result.Final).String()
	want := "http://example.com/final?id=1"
	if got != want {
		t.Errorf("destination = %q, want %q", got, want)
	}
}

func TestResolveDestinationBlocksInternalHop(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer upstream.Close()

	client := newTestClient(t, "px.a8.net="+strings.TrimPrefix(upstream.URL, "http://"))

	_, err := resolveDestination(client, mustParse(t, "http://px.a8.net/svt/ejp"))
	if !errors.Is(err, errBlockedAddress) {
		t.Fatalf("err = %v, want errBlockedAddress", err)
	}
}

func TestResolveDestinationStopsAtHopLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/loop", http.StatusFound)
	}))
	defer upstream.Close()

	addr := strings.TrimPrefix(upstream.URL, "http://")
	client := newTestClient(t, "px.a8.net="+addr+",example.com="+addr)

	_, err := resolveDestination(client, mustParse(t, "http://px.a8.net/svt/ejp"))
	if !errors.Is(err, errTooManyHops) {
		t.Fatalf("err = %v, want errTooManyHops", err)
	}
}

func TestResolveDestinationRejectsNonRedirectingUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := newTestClient(t, "px.a8.net="+strings.TrimPrefix(upstream.URL, "http://"))

	_, err := resolveDestination(client, mustParse(t, "http://px.a8.net/svt/ejp"))
	if !errors.Is(err, errNoDestination) {
		t.Fatalf("err = %v, want errNoDestination", err)
	}
}

// newStubUpstream は /svt/ejp -> /final のリダイレクトを返すテスト用の上流。
func newStubUpstream(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/svt/ejp":
			http.Redirect(w, r, "http://example.com/final?id=1&utm_source=a8", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(upstream.Close)

	addr := strings.TrimPrefix(upstream.URL, "http://")
	return upstream, newTestClient(t, "px.a8.net="+addr+",example.com="+addr)
}

func doRequest(t *testing.T, client *http.Client, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = "redirector.example"
	w := httptest.NewRecorder()
	redirector(client, w, r)
	return w
}

func TestHandleIndexShowsForm(t *testing.T) {
	_, client := newStubUpstream(t)

	w := doRequest(t, client, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`name="u"`, "notrack-redirector", "px.a8.net"} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestHandleIndexShowsDestinationWithoutRedirecting(t *testing.T) {
	_, client := newStubUpstream(t)

	w := doRequest(t, client, "/?u=http%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty (must not redirect)", loc)
	}

	body := w.Body.String()
	if !strings.Contains(body, "http://example.com/final?id=1") {
		t.Errorf("destination is missing from body")
	}
	if strings.Contains(body, "utm_source") {
		t.Errorf("tracking parameter survived into the page")
	}
	if !strings.Contains(body, `rel="noreferrer noopener"`) {
		t.Errorf(`new tab link must carry rel="noreferrer noopener"`)
	}
}

func TestHandleIndexRejectsUnsupportedURL(t *testing.T) {
	_, client := newStubUpstream(t)

	w := doRequest(t, client, "/?u=https%3A%2F%2Fphishing.example%2F")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "対応していないサービス") {
		t.Errorf("error message is missing from body")
	}
}

func TestHandleAPI(t *testing.T) {
	_, client := newStubUpstream(t)

	w := doRequest(t, client, apiEndpoint+"?u=http%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var got apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got.Destination != "http://example.com/final?id=1" {
		t.Errorf("destination = %q", got.Destination)
	}
	if len(got.Hops) != 1 {
		t.Errorf("hops = %v, want 1 entry", got.Hops)
	}

	bad := doRequest(t, client, apiEndpoint+"?u=https%3A%2F%2Fphishing.example%2F")
	if bad.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", bad.Code)
	}
}

func TestTrackerHostRequestStillRedirects(t *testing.T) {
	_, client := newStubUpstream(t)

	r := httptest.NewRequest(http.MethodGet, "/svt/ejp?a8mat=abc", nil)
	r.Host = "px.a8.net"
	w := httptest.NewRecorder()
	redirector(client, w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "http://example.com/final?id=1" {
		t.Errorf("Location = %q", got)
	}
}

func TestHandleIndexEscapesInput(t *testing.T) {
	_, client := newStubUpstream(t)

	w := doRequest(t, client, "/?u=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("input was not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("escaped input is missing from body")
	}
}
