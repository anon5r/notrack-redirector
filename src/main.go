// Anti-Tracking URL Redirector
//
// アフィリエイト / トラッキング用の中継 URL を受け取り、サーバー側で実際の
// リダイレクト先を解決したうえで、トラッキング用パラメータを除去した URL へ
// ブラウザをリダイレクトする。
//
// セキュリティ方針:
//   - リダイレクト先は「クエリパラメータに書かれた URL」ではなく、必ず
//     サーバー側で上流サービスを辿った結果から決定する。
//   - 解決結果を表示するだけの経路 (トップページと /api/resolve) は任意の
//     ホストを受け付ける。302 を返さないため、他人に「開くだけで飛ぶリンク」
//     を送れず、オープンリダイレクタ (フィッシング踏み台) にはならない。
//   - 302 を返す経路 (/-/resolve と DNS 付け替え運用) だけは trackerRules の
//     allowlist に限定する。ここを任意ホストに開くと踏み台になる。
//   - 接続先が内部ネットワークでないことを検証する (SSRF 対策)。
//
// トップページ (自ドメインの "/") は URL 入力フォームを提供する。こちらは
// リダイレクトせず解決結果の URL を表示するだけなので、遷移先にこのサービスの
// URL が Referer として残らない。
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	defaultListenAddr = ":9000"
	maxRedirectHops   = 8
	upstreamTimeout   = 8 * time.Second
	dialTimeout       = 3 * time.Second
	maxDrainBytes     = 64 * 1024

	loopGuardHeader = "X-Notrack-Redirector"
	loopGuardValue  = "1"

	resolveEndpoint  = "/-/resolve"
	apiEndpoint      = "/api/resolve"
	trackersEndpoint = "/api/trackers"
	resolveParam     = "u"

	// uiCSP は共有 UI に付与する Content-Security-Policy。
	// スクリプトとスタイルは同一オリジンの静的ファイルだけを許可する。
	uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
		"img-src 'self'; manifest-src 'self'; connect-src 'self'; " +
		"form-action 'self'; base-uri 'none'"

	envListenAddr      = "LISTEN_ADDR"
	envUpstreamHostMap = "UPSTREAM_HOST_MAP"
	envAllowPrivate    = "ALLOW_PRIVATE_UPSTREAM"
)

var (
	errNotTracker     = errors.New("not a supported tracking url")
	errInvalidURL     = errors.New("invalid url")
	errTooManyHops    = errors.New("too many redirect hops")
	errBlockedAddress = errors.New("blocked upstream address")
	errLoopDetected   = errors.New("redirect loop back to this service")
)

//go:embed shared/rules.json
var rulesJSON []byte

// uiFS は Cloudflare Worker 実装と共有する静的 UI。
//
//go:embed shared/ui
var uiFS embed.FS

// sharedRules は src/shared/rules.json の構造。Cloudflare Worker 実装と
// 同じファイルを読み込むことで、ルールの定義を一箇所に保つ。
type sharedRules struct {
	Trackers []struct {
		Host  string   `json:"host"`
		Paths []string `json:"paths"`
	} `json:"trackers"`
	TrackingParamPrefixes []string `json:"trackingParamPrefixes"`
	TrackingParamNames    []string `json:"trackingParamNames"`
	HostTrackingParams    []struct {
		Suffix string   `json:"suffix"`
		Names  []string `json:"names"`
	} `json:"hostTrackingParams"`
}

// trackerRule は上流として接続を許可するトラッキングサービスを表す。
type trackerRule struct {
	// host はリクエストホスト / 上流ホストの完全一致条件。
	host string
	// paths は許可するパスの正規表現。空の場合は全パスを許可する。
	paths []*regexp.Regexp
}

// hostParamRule はホストを限定して除去するクエリパラメータの定義。
type hostParamRule struct {
	suffix string
	names  []string
}

var (
	// trackerRules は処理対象とするトラッキングサービスの allowlist。
	trackerRules []trackerRule
	// trackingParamPrefixes は前方一致で除去するクエリパラメータ。
	trackingParamPrefixes []string
	// trackingParamNames は完全一致で除去するクエリパラメータ。
	trackingParamNames map[string]struct{}
	// hostTrackingParams はホストごとに追加で除去するクエリパラメータ。
	hostTrackingParams []hostParamRule
)

// init は共有ルール定義を読み込む。定義が壊れている場合は起動させない。
func init() {
	var parsed sharedRules
	if err := json.Unmarshal(rulesJSON, &parsed); err != nil {
		panic(fmt.Sprintf("invalid shared/rules.json: %v", err))
	}

	trackerRules = make([]trackerRule, 0, len(parsed.Trackers))
	for _, tracker := range parsed.Trackers {
		rule := trackerRule{host: strings.ToLower(tracker.Host)}
		for _, pattern := range tracker.Paths {
			rule.paths = append(rule.paths, regexp.MustCompile(pattern))
		}
		trackerRules = append(trackerRules, rule)
	}

	trackingParamPrefixes = parsed.TrackingParamPrefixes

	trackingParamNames = make(map[string]struct{}, len(parsed.TrackingParamNames))
	for _, name := range parsed.TrackingParamNames {
		trackingParamNames[strings.ToLower(name)] = struct{}{}
	}

	hostTrackingParams = make([]hostParamRule, 0, len(parsed.HostTrackingParams))
	for _, entry := range parsed.HostTrackingParams {
		hostTrackingParams = append(hostTrackingParams, hostParamRule{
			suffix: strings.ToLower(entry.Suffix),
			names:  entry.Names,
		})
	}
}

func main() {
	addr := os.Getenv(envListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}

	client := newUpstreamClient()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirector(client, w, r)
	})

	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

// redirector はリクエストを経路ごとに振り分ける。
func redirector(client *http.Client, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 自分自身から出た上流リクエストが戻ってきた場合 (DNS 付け替え運用での
	// ループ) は、これ以上辿らずに打ち切る。
	if r.Header.Get(loopGuardHeader) == loopGuardValue {
		writeError(w, http.StatusLoopDetected, errLoopDetected)
		return
	}

	// DNS 付け替え運用: リクエストホスト自体がトラッキングサービス。
	if isTrackerHost(requestHost(r)) {
		handleRedirect(client, w, r)
		return
	}

	switch r.URL.Path {
	case apiEndpoint:
		handleAPI(client, w, r)
	case trackersEndpoint:
		handleTrackers(w)
	case resolveEndpoint:
		handleRedirect(client, w, r)
	default:
		uiHandler.ServeHTTP(w, r)
	}
}

// handleRedirect はトラッキング URL を解決し、解決結果へ 302 を返す。
func handleRedirect(client *http.Client, w http.ResponseWriter, r *http.Request) {
	target, err := targetURL(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errNotTracker) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	log.Printf("resolving: %s", target.Redacted())

	result, err := resolveDestination(client, target)
	if err != nil {
		log.Printf("resolve failed for %s: %v", target.Redacted(), err)
		writeError(w, upstreamStatus(err), err)
		return
	}

	clean := stripTrackingParams(result.Final)
	log.Printf("redirect: %s -> %s", target.Redacted(), clean.String())

	w.Header().Set("Location", clean.String())
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusFound)
}

// apiResponse は /api/resolve の応答。
type apiResponse struct {
	Original    string   `json:"original,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Hops        []string `json:"hops,omitempty"`
	Error       string   `json:"error,omitempty"`
	Code        string   `json:"code,omitempty"`
}

// handleAPI は解決結果を JSON で返す。
func handleAPI(client *http.Client, w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get(resolveParam))
	status := http.StatusOK
	body := apiResponse{Original: raw}

	if raw == "" {
		status = http.StatusBadRequest
		body.Error = fmt.Sprintf("missing %q parameter", resolveParam)
		body.Code = codeInvalidURL
	} else if result, err := lookup(client, raw); err != nil {
		status = resolveStatus(err)
		body.Error = err.Error()
		body.Code = errorCode(err)
	} else {
		body.Destination = stripTrackingParams(result.Final).String()
		body.Hops = hopLabels(result.Hops)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("json encoding failed: %v", err)
	}
}

// lookup は入力文字列を検証してから上流を解決する。
func lookup(client *http.Client, raw string) (*resolveResult, error) {
	target, err := parseResolvableURL(raw)
	if err != nil {
		return nil, err
	}
	log.Printf("resolving: %s", target.Redacted())

	result, err := resolveDestination(client, target)
	if err != nil {
		log.Printf("resolve failed for %s: %v", target.Redacted(), err)
		return nil, err
	}
	return result, nil
}

// parseResolvableURL は表示専用の経路で解決してよい URL かを検証する。
// allowlist は求めない代わりに、内部ネットワーク宛でないことを確認する。
func parseResolvableURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidURL, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("%w: %s", errInvalidURL, raw)
	}
	if err := validateHopURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// parseTrackerURL は 302 を返す経路のために、allowlist 済みの
// トラッキング URL として解釈する。
func parseTrackerURL(raw string) (*url.URL, error) {
	u, err := parseResolvableURL(raw)
	if err != nil {
		return nil, err
	}
	if !isTrackerURL(u) {
		return nil, errNotTracker
	}
	return u, nil
}

// エラーコード。画面に出す文言は src/shared/ui/app.js 側で管理する。
const (
	codeUnsupportedURL     = "unsupported_url"
	codeInvalidURL         = "invalid_url"
	codeBlockedDestination = "blocked_destination"
	codeTooManyHops        = "too_many_hops"
	codeUpstreamError      = "upstream_error"
)

// errorCode は解決時のエラーを API のエラーコードへ変換する。
func errorCode(err error) string {
	switch {
	case errors.Is(err, errNotTracker):
		return codeUnsupportedURL
	case errors.Is(err, errInvalidURL):
		return codeInvalidURL
	case errors.Is(err, errBlockedAddress):
		return codeBlockedDestination
	case errors.Is(err, errTooManyHops), errors.Is(err, errLoopDetected):
		return codeTooManyHops
	default:
		return codeUpstreamError
	}
}

// resolveStatus は解決時のエラーに対応する HTTP ステータスを返す。
func resolveStatus(err error) int {
	if errors.Is(err, errNotTracker) || errors.Is(err, errInvalidURL) {
		return http.StatusBadRequest
	}
	return upstreamStatus(err)
}

// hopLabels は経由地をスキーム・ホスト・パスだけの表記に落とす。
// 経路として必要なのは「どこを通ったか」であり、クエリに含まれるトラッキング
// 情報まで見せる必要はない。
func hopLabels(hops []*url.URL) []string {
	labels := make([]string, 0, len(hops))
	for _, hop := range hops {
		labels = append(labels, (&url.URL{Scheme: hop.Scheme, Host: hop.Host, Path: hop.Path}).String())
	}
	return labels
}

// handleTrackers は対応サービスの一覧を JSON で返す。画面の一覧表示に使う。
func handleTrackers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string][]string{"trackers": trackerHostNames()}); err != nil {
		log.Printf("json encoding failed: %v", err)
	}
}

// uiHandler は共有 UI を配信する。
var uiHandler = newUIHandler()

// newUIHandler は src/shared/ui の静的ファイルを配信するハンドラを返す。
// Cloudflare Worker 実装も同じファイルを配信する。
func newUIHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "shared/ui")
	if err != nil {
		panic(fmt.Sprintf("invalid embedded ui: %v", err))
	}
	// Go の既定の MIME テーブルには含まれないため明示する。
	if err := mime.AddExtensionType(".webmanifest", "application/manifest+json"); err != nil {
		panic(fmt.Sprintf("cannot register webmanifest mime type: %v", err))
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", uiCSP)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, r)
	})
}

// trackerHostNames は対応サービスのホスト名一覧を返す。
func trackerHostNames() []string {
	hosts := make([]string, 0, len(trackerRules))
	for _, rule := range trackerRules {
		hosts = append(hosts, rule.host)
	}
	return hosts
}

// targetURL は解決対象となるトラッキング URL を決定する。
//
// 受け付ける形は次の 2 つ。
//  1. DNS 付け替え運用: リクエストの Host 自体がトラッキングサービス
//  2. 明示エンドポイント: /-/resolve?u=<トラッキング URL>
func targetURL(r *http.Request) (*url.URL, error) {
	if r.URL.Path == resolveEndpoint {
		raw := r.URL.Query().Get(resolveParam)
		if raw == "" {
			return nil, fmt.Errorf("missing %q parameter", resolveParam)
		}
		return parseTrackerURL(raw)
	}

	u := &url.URL{
		Scheme:   requestScheme(r),
		Host:     requestHost(r),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	if !isTrackerURL(u) {
		return nil, errNotTracker
	}
	return u, nil
}

// requestScheme は受け取ったリクエストのスキームを推定する。
// 上流へは同じスキームで接続する。
func requestScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// isTrackerURL は URL が allowlist 済みのトラッキングサービスかを判定する。
func isTrackerURL(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, rule := range trackerRules {
		if rule.host != host {
			continue
		}
		if len(rule.paths) == 0 {
			return true
		}
		for _, p := range rule.paths {
			if p.MatchString(u.Path) {
				return true
			}
		}
	}
	return false
}

// isTrackerHost はホスト名だけで allowlist 判定する。DNS 付け替え運用の
// リクエストかどうかを見分けるために使う。
func isTrackerHost(host string) bool {
	for _, rule := range trackerRules {
		if rule.host == host {
			return true
		}
	}
	return false
}

// resolveResult は上流の解決結果を表す。
type resolveResult struct {
	// Final は最終的に到達した URL (トラッキングパラメータ除去前)。
	Final *url.URL
	// Hops は途中で辿った Location の一覧。
	Hops []*url.URL
}

// resolveDestination は上流のリダイレクトチェーンを辿り、最終 URL を返す。
// クエリパラメータに書かれた URL は一切信用せず、上流が実際に返す Location
// だけを根拠にする。
func resolveDestination(client *http.Client, target *url.URL) (*resolveResult, error) {
	current := target
	var hops []*url.URL

	for hop := 0; hop < maxRedirectHops; hop++ {
		req, err := http.NewRequest(http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		// 上流に対して利用者の情報を渡さない。
		req.Header.Set("User-Agent", "notrack-redirector/1.0")
		req.Header.Set("Accept", "*/*")
		req.Header.Set(loopGuardHeader, loopGuardValue)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		location := resp.Header.Get("Location")
		status := resp.StatusCode
		io.CopyN(io.Discard, resp.Body, maxDrainBytes)
		resp.Body.Close()

		if status < 300 || status > 399 || location == "" {
			// これ以上リダイレクトしない = ここが最終地点。
			// 一度もリダイレクトしなかった場合も、入力 URL からトラッキング
			// パラメータを取り除いた結果には意味があるため結果として返す。
			return &resolveResult{Final: current, Hops: hops}, nil
		}

		next, err := current.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("invalid Location header: %w", err)
		}
		if err := validateHopURL(next); err != nil {
			return nil, err
		}
		hops = append(hops, next)
		current = next
	}

	return nil, errTooManyHops
}

// validateHopURL はリダイレクト先として許容できる URL かを検証する。
func validateHopURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", errBlockedAddress, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: empty host", errBlockedAddress)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("%w: local host %q", errBlockedAddress, host)
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return fmt.Errorf("%w: non-public address %q", errBlockedAddress, host)
	}
	return nil
}

// isPublicIP は公衆インターネット上のアドレスかを判定する。
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 100.64.0.0/10 (CGNAT) と 169.254.0.0/16 のメタデータ経路を除外する。
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 {
			return false
		}
	}
	return true
}

// stripTrackingParams は URL からトラッキング用パラメータを除去する。
func stripTrackingParams(u *url.URL) *url.URL {
	clean := *u
	if clean.RawQuery == "" {
		return &clean
	}

	host := strings.ToLower(clean.Hostname())
	query := clean.Query()
	for name := range query {
		if isTrackingParam(host, name) {
			query.Del(name)
		}
	}
	clean.RawQuery = query.Encode()
	return &clean
}

func isTrackingParam(host, name string) bool {
	lower := strings.ToLower(name)
	if _, ok := trackingParamNames[lower]; ok {
		return true
	}
	for _, prefix := range trackingParamPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, entry := range hostTrackingParams {
		if !hostMatches(host, entry.suffix) {
			continue
		}
		for _, n := range entry.names {
			if strings.EqualFold(n, name) {
				return true
			}
		}
	}
	return false
}

func hostMatches(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// newUpstreamClient は上流取得用のクライアントを生成する。
// リダイレクトは自動追跡せず、ホップごとに検証する。
func newUpstreamClient() *http.Client {
	hostMap := parseHostMap(os.Getenv(envUpstreamHostMap))
	allowPrivate := os.Getenv(envAllowPrivate) == "1"

	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublicIP(ip) {
				return fmt.Errorf("%w: %s", errBlockedAddress, address)
			}
			return nil
		},
	}

	transport := &http.Transport{
		// プロキシ配下でも動作するよう、標準の環境変数を尊重する。
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if override, ok := hostMap[strings.ToLower(host)]; ok {
				// "host:port" 形式ならポートごと差し替える。
				if strings.Contains(override, ":") {
					addr = override
				} else {
					addr = net.JoinHostPort(override, port)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: upstreamTimeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   upstreamTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// parseHostMap は "host=addr,host=addr" 形式の上書き設定を解析する。
// addr は "192.0.2.1" または "192.0.2.1:8080" のいずれかを受け付ける。
// DNS をこのサービスへ向けている運用で、上流の実アドレスを指定するために使う。
func parseHostMap(raw string) map[string]string {
	result := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, addr, ok := strings.Cut(entry, "=")
		if !ok {
			log.Printf("ignoring malformed %s entry: %q", envUpstreamHostMap, entry)
			continue
		}
		result[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(addr)
	}
	return result
}

func upstreamStatus(err error) int {
	switch {
	case errors.Is(err, errBlockedAddress):
		return http.StatusForbidden
	case errors.Is(err, errTooManyHops), errors.Is(err, errLoopDetected):
		return http.StatusLoopDetected
	default:
		return http.StatusBadGateway
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d %s\n\n%v\n", status, http.StatusText(status), err)
}
