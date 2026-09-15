// Anti-Tracking URL Redirector
//
// アフィリエイト / トラッキング用の中継 URL を受け取り、サーバー側で実際の
// リダイレクト先を解決したうえで、トラッキング用パラメータを除去した URL へ
// ブラウザをリダイレクトする。
//
// セキュリティ方針:
//   - リダイレクト先は「クエリパラメータに書かれた URL」ではなく、必ず
//     サーバー側で上流サービスを辿った結果から決定する。これによりクエリ
//     パラメータを差し替えるだけのオープンリダイレクタ (フィッシング踏み台)
//     化を防ぐ。
//   - 上流として接続してよいホストは trackerRules の allowlist に限定する。
//   - 接続先 IP が内部ネットワークでないことを検証する (SSRF 対策)。
//
// トップページ (自ドメインの "/") は URL 入力フォームを提供する。こちらは
// リダイレクトせず解決結果の URL を表示するだけなので、遷移先にこのサービスの
// URL が Referer として残らない。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
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

	resolveEndpoint = "/-/resolve"
	apiEndpoint     = "/api/resolve"
	resolveParam    = "u"

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
	errNoDestination  = errors.New("no destination resolved")
)

// trackerRule は上流として接続を許可するトラッキングサービスを表す。
//
// 「誰でも任意の URL を登録できる」短縮 URL サービス (t.co, bit.ly など) は
// ここに追加してはならない。追加するとオープンリダイレクタ化する。
type trackerRule struct {
	// host はリクエストホスト / 上流ホストの完全一致条件。
	host string
	// paths は許可するパスの正規表現。空の場合は全パスを許可する。
	paths []*regexp.Regexp
}

var trackerRules = []trackerRule{
	{
		host:  "px.a8.net",
		paths: []*regexp.Regexp{regexp.MustCompile(`^/svt/`)},
	},
	{
		host: "hb.afl.rakuten.co.jp",
		paths: []*regexp.Regexp{
			regexp.MustCompile(`^/ichiba/[\w.\-]+`),
			regexp.MustCompile(`^/hgc/[\w.\-]+`),
			regexp.MustCompile(`^/hsc/[\w.\-]+`),
		},
	},
	{
		host:  "ck.jp.ap.valuecommerce.com",
		paths: []*regexp.Regexp{regexp.MustCompile(`^/servlet/referral`)},
	},
	{
		host:  "af.moshimo.com",
		paths: []*regexp.Regexp{regexp.MustCompile(`^/af/c/click`)},
	},
	{
		host:  "t.afi-b.com",
		paths: []*regexp.Regexp{regexp.MustCompile(`^/`)},
	},
	{
		host:  "click.linksynergy.com",
		paths: []*regexp.Regexp{regexp.MustCompile(`^/`)},
	},
}

// trackingParamPrefixes は前方一致で除去するクエリパラメータ。
var trackingParamPrefixes = []string{
	"utm_", "mtm_", "pk_", "piwik_", "matomo_", "hsa_", "vero_", "oly_",
	"trk_", "_bta_", "__hs", "ito_", "at_custom", "spm_",
}

// trackingParamNames は完全一致で除去するクエリパラメータ。
// "ref" / "pid" / "sid" / "cid" のように正規の機能パラメータと衝突しうる名前は
// ここには入れず、hostTrackingParams 側でホストを限定して扱う。
var trackingParamNames = map[string]struct{}{
	"gclid": {}, "gclsrc": {}, "dclid": {}, "gbraid": {}, "wbraid": {},
	"fbclid": {}, "msclkid": {}, "yclid": {}, "twclid": {}, "ttclid": {},
	"igshid": {}, "igsh": {}, "li_fat_id": {}, "rdt_cid": {}, "epik": {},
	"s_kwcid": {}, "ef_id": {}, "mkt_tok": {}, "wickedid": {}, "_openstat": {},
	"yadcid": {}, "yadid": {}, "_ga": {}, "_gl": {}, "__s": {},
	"mc_cid": {}, "mc_eid": {}, "ml_subscriber": {}, "ml_subscriber_hash": {},
	"fb_action_ids": {}, "fb_action_types": {}, "fb_source": {}, "fb_ref": {},
	"action_object_map": {}, "action_type_map": {}, "action_ref_map": {},
	"vc_lpp": {}, "a8": {}, "msockid": {},
}

// hostTrackingParams はホスト (サフィックス一致) ごとに追加で除去する
// パラメータ。汎用的に消すと壊れる名前をここで限定的に扱う。
var hostTrackingParams = []struct {
	suffix string
	names  []string
}{
	{"amazon.co.jp", []string{
		"tag", "linkCode", "linkId", "creative", "creativeASIN", "ascsubtag",
		"camp", "ref", "ref_", "psc", "qid", "sr", "sprefix", "crid",
		"dib", "dib_tag", "content-id", "_encoding", "th",
	}},
	{"amazon.com", []string{
		"tag", "linkCode", "linkId", "creative", "creativeASIN", "ascsubtag",
		"camp", "ref", "ref_", "psc", "qid", "sr", "sprefix", "crid",
		"dib", "dib_tag", "content-id", "_encoding", "th",
	}},
	{"rakuten.co.jp", []string{
		"scid", "sc2id", "iasid", "rafcid", "l-id", "l2-id", "trflg", "bk",
	}},
	{"yahoo.co.jp", []string{
		"sc_e", "sc_i", "mcr", "ei", "ark", "tpkgd",
	}},
	{"youtube.com", []string{"si", "feature", "kw"}},
	{"youtu.be", []string{"si", "feature"}},
	{"x.com", []string{"s", "t", "ref_src", "ref_url"}},
	{"twitter.com", []string{"s", "t", "ref_src", "ref_url"}},
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
	case "/":
		handleIndex(client, w, r)
	case apiEndpoint:
		handleAPI(client, w, r)
	case resolveEndpoint:
		handleRedirect(client, w, r)
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
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

// pageData はトップページのテンプレートに渡す値。
type pageData struct {
	Input       string
	Destination string
	Hops        []string
	Error       string
	Trackers    []string
}

// handleIndex は URL 入力フォームと解決結果を表示する。
// リダイレクトはせず、結果の URL を提示するだけに留める。
func handleIndex(client *http.Client, w http.ResponseWriter, r *http.Request) {
	data := pageData{Trackers: trackerHostNames()}
	status := http.StatusOK

	if raw := strings.TrimSpace(r.URL.Query().Get(resolveParam)); raw != "" {
		data.Input = raw
		result, err := lookup(client, raw)
		if err != nil {
			data.Error = userMessage(err)
			status = resolveStatus(err)
		} else {
			data.Destination = stripTrackingParams(result.Final).String()
			data.Hops = hopLabels(result.Hops)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'")
	w.WriteHeader(status)

	if err := indexTemplate.Execute(w, data); err != nil {
		log.Printf("template execution failed: %v", err)
	}
}

// apiResponse は /api/resolve の応答。
type apiResponse struct {
	Original    string   `json:"original,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Hops        []string `json:"hops,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// handleAPI は解決結果を JSON で返す。
func handleAPI(client *http.Client, w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get(resolveParam))
	status := http.StatusOK
	body := apiResponse{Original: raw}

	if raw == "" {
		status = http.StatusBadRequest
		body.Error = fmt.Sprintf("missing %q parameter", resolveParam)
	} else if result, err := lookup(client, raw); err != nil {
		status = resolveStatus(err)
		body.Error = err.Error()
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
	target, err := parseTrackerURL(raw)
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

// parseTrackerURL は入力文字列を allowlist 済みのトラッキング URL として解釈する。
// 利用者が入力した値に対する検証なので、失敗は 400 として扱う。
func parseTrackerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidURL, err)
	}
	if !isTrackerURL(u) {
		return nil, errNotTracker
	}
	return u, nil
}

// userMessage は利用者向けの日本語メッセージへ変換する。
func userMessage(err error) string {
	switch {
	case errors.Is(err, errNotTracker):
		return "対応していないサービスの URL です。下の対応サービス一覧を確認してください。"
	case errors.Is(err, errInvalidURL):
		return "URL の形式が正しくありません。"
	case errors.Is(err, errBlockedAddress):
		return "安全でないリダイレクト先が含まれていたため中断しました。"
	case errors.Is(err, errTooManyHops), errors.Is(err, errLoopDetected):
		return "リダイレクトが多すぎるため中断しました。"
	case errors.Is(err, errNoDestination):
		return "この URL はリダイレクトを返しませんでした。"
	default:
		return "リダイレクト先を取得できませんでした。時間をおいて再度試してください。"
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
			if hop == 0 {
				return nil, errNoDestination
			}
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

// indexTemplate はトップページの HTML。
// href は html/template の URL サニタイズを経由するため、http(s) 以外のスキームは
// 出力されない。すべてのリンクに rel="noreferrer" を付け、遷移先へこのページの
// URL が Referer として渡らないようにしている。
var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>notrack-redirector</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0 auto; padding: 2rem 1rem; max-width: 46rem; line-height: 1.7;
  font-family: system-ui, -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; }
h1 { font-size: 1.4rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; }
h3 { font-size: 1rem; }
form { display: flex; gap: .5rem; flex-wrap: wrap; margin: 1.5rem 0; }
input[type=url] { flex: 1 1 24rem; padding: .6rem .7rem; font: inherit;
  border: 1px solid currentColor; border-radius: .3rem; background: transparent; color: inherit; }
button, .action { padding: .6rem 1rem; font: inherit; cursor: pointer; text-decoration: none;
  border: 1px solid currentColor; border-radius: .3rem; background: transparent; color: inherit;
  display: inline-block; }
code { word-break: break-all; font-size: .95em; }
.result { border: 1px solid currentColor; border-radius: .4rem; padding: 1rem; }
.destination { padding: .7rem; border-radius: .3rem; background: rgba(127,127,127,.15); }
.actions { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
.note { font-size: .85rem; opacity: .75; }
.error { padding: .8rem 1rem; border-radius: .4rem; border: 1px solid #c0392b; color: #c0392b; }
ol, ul { padding-left: 1.4rem; }
</style>
</head>
<body>
<h1>notrack-redirector</h1>
<p>アフィリエイト / トラッキング URL を入力すると、サーバー側でリダイレクト先を解決し、
トラッキングパラメータを除いた URL を表示します。このページ自体はリダイレクトしません。</p>

<form method="get" action="/">
<input type="url" name="u" value="{{.Input}}" required autofocus
  placeholder="https://px.a8.net/svt/ejp?a8mat=...">
<button type="submit">解決する</button>
</form>

{{if .Error}}<p class="error">{{.Error}}</p>{{end}}

{{if .Destination}}
<section class="result">
<h2>リダイレクト先</h2>
<p class="destination"><code>{{.Destination}}</code></p>
<p class="actions">
<button type="button" id="copy" data-url="{{.Destination}}">URL をコピー</button>
<a class="action" href="{{.Destination}}" target="_blank" rel="noreferrer noopener">新しいタブで開く</a>
<a class="action" href="{{.Destination}}" rel="noreferrer">このタブで開く</a>
</p>
<p class="note">どちらのリンクにも <code>rel="noreferrer"</code> を付けているため、
遷移先にこのページの URL は送られません。「新しいタブで開く」は <code>noopener</code> も付与します。</p>
{{if .Hops}}
<h3>経路</h3>
<ol>{{range .Hops}}<li><code>{{.}}</code></li>{{end}}</ol>
{{end}}
</section>
{{end}}

<h2>対応サービス</h2>
<ul>{{range .Trackers}}<li><code>{{.}}</code></li>{{end}}</ul>
<p class="note">JSON で取得する場合は <code>/api/resolve?u=&lt;tracking url&gt;</code> を使用してください。</p>

<script>
const copyButton = document.getElementById("copy");
if (copyButton) {
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(copyButton.dataset.url);
      copyButton.textContent = "コピーしました";
    } catch {
      copyButton.textContent = "コピーできませんでした";
    }
  });
}
</script>
</body>
</html>
`))
