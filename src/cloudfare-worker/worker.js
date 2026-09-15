/**
 * Anti-Tracking URL Redirector (Cloudflare Workers)
 *
 * アフィリエイト / トラッキング用の中継 URL を受け取り、サーバー側で実際の
 * リダイレクト先を解決したうえで、トラッキング用パラメータを除去した URL へ
 * ブラウザをリダイレクトする。
 *
 * セキュリティ方針:
 *   - リダイレクト先は「クエリパラメータに書かれた URL」ではなく、必ず
 *     Worker 側で上流サービスを辿った結果から決定する。これによりクエリ
 *     パラメータを差し替えるだけのオープンリダイレクタ (フィッシング踏み台)
 *     化を防ぐ。
 *   - 上流として接続してよいホストは TRACKER_RULES の allowlist に限定する。
 *
 * トップページ (自ドメインの "/") は URL 入力フォームを提供する。こちらは
 * リダイレクトせず解決結果の URL を表示するだけなので、遷移先にこのサービスの
 * URL が Referer として残らない。
 *
 * src/main/main.go と同じポリシーを実装している。ルールを更新する場合は
 * 双方を同時に更新すること。
 */

const MAX_REDIRECT_HOPS = 8;
const UPSTREAM_TIMEOUT_MS = 8000;

const LOOP_GUARD_HEADER = "X-Notrack-Redirector";
const LOOP_GUARD_VALUE = "1";

const RESOLVE_ENDPOINT = "/-/resolve";
const API_ENDPOINT = "/api/resolve";
const RESOLVE_PARAM = "u";

/**
 * 上流として接続を許可するトラッキングサービス。
 *
 * 「誰でも任意の URL を登録できる」短縮 URL サービス (t.co, bit.ly など) は
 * ここに追加してはならない。追加するとオープンリダイレクタ化する。
 * paths が空配列の場合は当該ホストの全パスを許可する。
 */
const TRACKER_RULES = [
    { host: "px.a8.net", paths: [/^\/svt\//] },
    {
        host: "hb.afl.rakuten.co.jp",
        paths: [/^\/ichiba\/[\w.\-]+/, /^\/hgc\/[\w.\-]+/, /^\/hsc\/[\w.\-]+/],
    },
    { host: "ck.jp.ap.valuecommerce.com", paths: [/^\/servlet\/referral/] },
    { host: "af.moshimo.com", paths: [/^\/af\/c\/click/] },
    { host: "t.afi-b.com", paths: [] },
    { host: "click.linksynergy.com", paths: [] },
];

/** 前方一致で除去するクエリパラメータ。 */
const TRACKING_PARAM_PREFIXES = [
    "utm_", "mtm_", "pk_", "piwik_", "matomo_", "hsa_", "vero_", "oly_",
    "trk_", "_bta_", "__hs", "ito_", "at_custom", "spm_",
];

/**
 * 完全一致で除去するクエリパラメータ。
 * "ref" / "pid" / "sid" / "cid" のように正規の機能パラメータと衝突しうる名前は
 * ここには入れず、HOST_TRACKING_PARAMS 側でホストを限定して扱う。
 */
const TRACKING_PARAM_NAMES = new Set([
    "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
    "fbclid", "msclkid", "yclid", "twclid", "ttclid",
    "igshid", "igsh", "li_fat_id", "rdt_cid", "epik",
    "s_kwcid", "ef_id", "mkt_tok", "wickedid", "_openstat",
    "yadcid", "yadid", "_ga", "_gl", "__s",
    "mc_cid", "mc_eid", "ml_subscriber", "ml_subscriber_hash",
    "fb_action_ids", "fb_action_types", "fb_source", "fb_ref",
    "action_object_map", "action_type_map", "action_ref_map",
    "vc_lpp", "a8", "msockid",
]);

const AMAZON_PARAMS = [
    "tag", "linkcode", "linkid", "creative", "creativeasin", "ascsubtag",
    "camp", "ref", "ref_", "psc", "qid", "sr", "sprefix", "crid",
    "dib", "dib_tag", "content-id", "_encoding", "th",
];

/**
 * ホスト (サフィックス一致) ごとに追加で除去するパラメータ。
 * 汎用的に消すと壊れる名前をここで限定的に扱う。名前は小文字で保持する。
 */
const HOST_TRACKING_PARAMS = [
    { suffix: "amazon.co.jp", names: AMAZON_PARAMS },
    { suffix: "amazon.com", names: AMAZON_PARAMS },
    { suffix: "rakuten.co.jp", names: ["scid", "sc2id", "iasid", "rafcid", "l-id", "l2-id", "trflg", "bk"] },
    { suffix: "yahoo.co.jp", names: ["sc_e", "sc_i", "mcr", "ei", "ark", "tpkgd"] },
    { suffix: "youtube.com", names: ["si", "feature", "kw"] },
    { suffix: "youtu.be", names: ["si", "feature"] },
    { suffix: "x.com", names: ["s", "t", "ref_src", "ref_url"] },
    { suffix: "twitter.com", names: ["s", "t", "ref_src", "ref_url"] },
];

const DEFAULT_USER_MESSAGE = "リダイレクト先を取得できませんでした。時間をおいて再度試してください。";

class RedirectorError extends Error {
    /**
     * @param {string} message ログ / API 向けの英語メッセージ
     * @param {number} status HTTP ステータス
     * @param {string} [userMessage] 画面に表示する日本語メッセージ
     */
    constructor(message, status, userMessage) {
        super(message);
        this.status = status;
        this.userMessage = userMessage || DEFAULT_USER_MESSAGE;
    }
}

const MESSAGE_UNSUPPORTED = "対応していないサービスの URL です。下の対応サービス一覧を確認してください。";
const MESSAGE_INVALID_URL = "URL の形式が正しくありません。";
const MESSAGE_BLOCKED = "安全でないリダイレクト先が含まれていたため中断しました。";
const MESSAGE_TOO_MANY_HOPS = "リダイレクトが多すぎるため中断しました。";
const MESSAGE_NO_DESTINATION = "この URL はリダイレクトを返しませんでした。";

/** URL が allowlist 済みのトラッキングサービスかを判定する。 */
function isTrackerURL(url) {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return false;
    }
    const host = url.hostname.toLowerCase();
    return TRACKER_RULES.some((rule) => {
        if (rule.host !== host) {
            return false;
        }
        return rule.paths.length === 0 || rule.paths.some((p) => p.test(url.pathname));
    });
}

/**
 * ホスト名だけで allowlist 判定する。DNS / ルート付け替え運用のリクエストか
 * どうかを見分けるために使う。
 */
function isTrackerHost(host) {
    return TRACKER_RULES.some((rule) => rule.host === host.toLowerCase());
}

/**
 * 解決対象となるトラッキング URL を決定する。
 *
 * 受け付ける形は次の 2 つ。
 *   1. DNS / ルート付け替え運用: リクエストの Host 自体がトラッキングサービス
 *   2. 明示エンドポイント: /-/resolve?u=<トラッキング URL>
 */
function targetURL(requestURL) {
    if (requestURL.pathname === RESOLVE_ENDPOINT) {
        const raw = requestURL.searchParams.get(RESOLVE_PARAM);
        if (!raw) {
            throw new RedirectorError(`missing "${RESOLVE_PARAM}" parameter`, 400);
        }
        let parsed;
        try {
            parsed = new URL(raw);
        } catch {
            throw new RedirectorError(`invalid "${RESOLVE_PARAM}" parameter`, 400, MESSAGE_INVALID_URL);
        }
        if (!isTrackerURL(parsed)) {
            throw new RedirectorError("not a supported tracking url", 404, MESSAGE_UNSUPPORTED);
        }
        return parsed;
    }

    const target = new URL(requestURL.toString());
    target.protocol = "https:";
    if (!isTrackerURL(target)) {
        throw new RedirectorError("not a supported tracking url", 404, MESSAGE_UNSUPPORTED);
    }
    return target;
}

/** リダイレクト先として許容できる URL かを検証する。 */
function validateHopURL(url) {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new RedirectorError(`blocked upstream scheme "${url.protocol}"`, 403, MESSAGE_BLOCKED);
    }
    const host = url.hostname.toLowerCase();
    if (!host) {
        throw new RedirectorError("blocked upstream address: empty host", 403, MESSAGE_BLOCKED);
    }
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
        throw new RedirectorError(`blocked local host "${host}"`, 403, MESSAGE_BLOCKED);
    }
    if (isNonPublicAddress(host)) {
        throw new RedirectorError(`blocked non-public address "${host}"`, 403, MESSAGE_BLOCKED);
    }
}

/** ホスト名が内部ネットワーク向けの IP リテラルかを判定する。 */
function isNonPublicAddress(host) {
    if (host.startsWith("[")) {
        // IPv6 リテラル。ループバック / ULA / リンクローカルを拒否する。
        const inner = host.slice(1, -1).toLowerCase();
        return inner === "::1" || inner === "::" || /^f[cd]/.test(inner) || inner.startsWith("fe80");
    }

    const octets = host.split(".");
    if (octets.length !== 4 || !octets.every((o) => /^\d{1,3}$/.test(o))) {
        return false;
    }
    const [a, b] = octets.map(Number);
    if (octets.some((o) => Number(o) > 255)) {
        return true;
    }
    return (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0) ||
        a >= 224
    );
}

/**
 * 上流のリダイレクトチェーンを辿り、{ final, hops } を返す。
 * クエリパラメータに書かれた URL は一切信用せず、上流が実際に返す Location
 * だけを根拠にする。
 */
async function resolveDestination(target, hostMap) {
    let current = target;
    const hops = [];

    for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
        const requestURL = new URL(current.toString());
        const override = hostMap.get(requestURL.hostname.toLowerCase());
        if (override) {
            // "host" でも "host:port" でも受け付ける。
            requestURL.host = override;
        }

        let response;
        try {
            response = await fetch(requestURL.toString(), {
                method: "GET",
                redirect: "manual",
                headers: {
                    // 上流に対して利用者の情報を渡さない。
                    "User-Agent": "notrack-redirector/1.0",
                    Accept: "*/*",
                    [LOOP_GUARD_HEADER]: LOOP_GUARD_VALUE,
                },
                signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
            });
        } catch (err) {
            throw new RedirectorError(`upstream fetch failed: ${err}`, 502);
        }

        const location = response.headers.get("Location");
        const status = response.status;
        // ボディは利用しないので破棄する。
        if (response.body) {
            await response.body.cancel();
        }

        if (status < 300 || status > 399 || !location) {
            // これ以上リダイレクトしない = ここが最終地点。
            if (hop === 0) {
                throw new RedirectorError("no destination resolved", 502, MESSAGE_NO_DESTINATION);
            }
            return { final: current, hops };
        }

        let next;
        try {
            next = new URL(location, current);
        } catch {
            throw new RedirectorError("invalid Location header", 502);
        }
        validateHopURL(next);
        hops.push(next);
        current = next;
    }

    throw new RedirectorError("too many redirect hops", 508, MESSAGE_TOO_MANY_HOPS);
}

/** URL からトラッキング用パラメータを除去する。 */
function stripTrackingParams(url) {
    const clean = new URL(url.toString());
    if (!clean.search) {
        return clean;
    }

    const host = clean.hostname.toLowerCase();
    for (const name of [...clean.searchParams.keys()]) {
        if (isTrackingParam(host, name)) {
            clean.searchParams.delete(name);
        }
    }
    return clean;
}

function isTrackingParam(host, name) {
    const lower = name.toLowerCase();
    if (TRACKING_PARAM_NAMES.has(lower)) {
        return true;
    }
    if (TRACKING_PARAM_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
        return true;
    }
    return HOST_TRACKING_PARAMS.some(
        (entry) => hostMatches(host, entry.suffix) && entry.names.includes(lower),
    );
}

function hostMatches(host, suffix) {
    return host === suffix || host.endsWith(`.${suffix}`);
}

/**
 * "host=host,host=host:port" 形式の上書き設定を解析する。
 * DNS / ルートをこの Worker へ向けている運用で、上流の実ホストを指定して
 * ループを避けるために使う。
 */
function parseHostMap(raw) {
    const result = new Map();
    for (const entry of (raw || "").split(",")) {
        const trimmed = entry.trim();
        if (!trimmed) {
            continue;
        }
        const index = trimmed.indexOf("=");
        if (index < 0) {
            console.log(`ignoring malformed UPSTREAM_HOST_MAP entry: ${trimmed}`);
            continue;
        }
        result.set(
            trimmed.slice(0, index).trim().toLowerCase(),
            trimmed.slice(index + 1).trim(),
        );
    }
    return result;
}

function textResponse(body, status) {
    return new Response(body, {
        status,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
        },
    });
}

/**
 * 経由地をスキーム・ホスト・パスだけの表記に落とす。
 * 経路として必要なのは「どこを通ったか」であり、クエリに含まれるトラッキング
 * 情報まで見せる必要はない。
 */
function hopLabels(hops) {
    return hops.map((hop) => `${hop.protocol}//${hop.host}${hop.pathname}`);
}

/** 解決時のエラーに対応する HTTP ステータスを返す。 */
function resolveStatus(err) {
    return err instanceof RedirectorError ? err.status : 502;
}

/** 利用者向けの日本語メッセージへ変換する。 */
function userMessage(err) {
    return err instanceof RedirectorError ? err.userMessage : DEFAULT_USER_MESSAGE;
}

/**
 * 入力文字列を allowlist 済みのトラッキング URL として解釈する。
 * 利用者が入力した値に対する検証なので、失敗は 400 として扱う。
 */
function parseTrackerURL(raw) {
    let parsed;
    try {
        parsed = new URL(raw);
    } catch {
        throw new RedirectorError("invalid url", 400, MESSAGE_INVALID_URL);
    }
    if (!isTrackerURL(parsed)) {
        throw new RedirectorError("not a supported tracking url", 400, MESSAGE_UNSUPPORTED);
    }
    return parsed;
}

/** 入力文字列を検証してから上流を解決する。 */
async function lookup(raw, hostMap) {
    const target = parseTrackerURL(raw);
    console.log(`resolving: ${target.toString()}`);
    return resolveDestination(target, hostMap);
}

function escapeHTML(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

/**
 * トップページの HTML を組み立てる。
 * href に入るのは validateHopURL を通過した http(s) URL だけであり、
 * 利用者の入力値は value 属性としてエスケープしたうえで埋め込む。
 * すべてのリンクに rel="noreferrer" を付け、遷移先へこのページの URL が
 * Referer として渡らないようにしている。
 */
function renderIndex({ input = "", destination = "", hops = [], error = "" }) {
    const trackers = TRACKER_RULES.map((rule) => `<li><code>${escapeHTML(rule.host)}</code></li>`).join("");
    const errorBlock = error ? `<p class="error">${escapeHTML(error)}</p>` : "";
    const hopBlock = hops.length
        ? `<h3>経路</h3><ol>${hops.map((hop) => `<li><code>${escapeHTML(hop)}</code></li>`).join("")}</ol>`
        : "";
    const resultBlock = destination
        ? `<section class="result">
<h2>リダイレクト先</h2>
<p class="destination"><code>${escapeHTML(destination)}</code></p>
<p class="actions">
<button type="button" id="copy" data-url="${escapeHTML(destination)}">URL をコピー</button>
<a class="action" href="${escapeHTML(destination)}" target="_blank" rel="noreferrer noopener">新しいタブで開く</a>
<a class="action" href="${escapeHTML(destination)}" rel="noreferrer">このタブで開く</a>
</p>
<p class="note">どちらのリンクにも <code>rel="noreferrer"</code> を付けているため、
遷移先にこのページの URL は送られません。「新しいタブで開く」は <code>noopener</code> も付与します。</p>
${hopBlock}
</section>`
        : "";

    return `<!doctype html>
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
<input type="url" name="u" value="${escapeHTML(input)}" required autofocus
  placeholder="https://px.a8.net/svt/ejp?a8mat=...">
<button type="submit">解決する</button>
</form>

${errorBlock}
${resultBlock}

<h2>対応サービス</h2>
<ul>${trackers}</ul>
<p class="note">JSON で取得する場合は <code>${API_ENDPOINT}?u=&lt;tracking url&gt;</code> を使用してください。</p>

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
`;
}

function htmlResponse(body, status) {
    return new Response(body, {
        status,
        headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Content-Security-Policy":
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'",
        },
    });
}

/**
 * URL 入力フォームと解決結果を表示する。
 * リダイレクトはせず、結果の URL を提示するだけに留める。
 */
async function handleIndex(url, hostMap) {
    const raw = (url.searchParams.get(RESOLVE_PARAM) || "").trim();
    if (!raw) {
        return htmlResponse(renderIndex({}), 200);
    }

    try {
        const result = await lookup(raw, hostMap);
        return htmlResponse(
            renderIndex({
                input: raw,
                destination: stripTrackingParams(result.final).toString(),
                hops: hopLabels(result.hops),
            }),
            200,
        );
    } catch (err) {
        console.log(`resolve failed for ${raw}: ${err.message}`);
        return htmlResponse(renderIndex({ input: raw, error: userMessage(err) }), resolveStatus(err));
    }
}

/** 解決結果を JSON で返す。 */
async function handleAPI(url, hostMap) {
    const raw = (url.searchParams.get(RESOLVE_PARAM) || "").trim();
    const respond = (body, status) =>
        new Response(JSON.stringify(body) + "\n", {
            status,
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
        });

    if (!raw) {
        return respond({ error: `missing "${RESOLVE_PARAM}" parameter` }, 400);
    }

    try {
        const result = await lookup(raw, hostMap);
        return respond(
            {
                original: raw,
                destination: stripTrackingParams(result.final).toString(),
                hops: hopLabels(result.hops),
            },
            200,
        );
    } catch (err) {
        console.log(`resolve failed for ${raw}: ${err.message}`);
        return respond({ original: raw, error: err.message }, resolveStatus(err));
    }
}

/** トラッキング URL を解決し、解決結果へ 302 を返す。 */
async function handleRedirect(url, hostMap) {
    let target;
    try {
        target = targetURL(url);
    } catch (err) {
        return textResponse(`${resolveStatus(err)} ${err.message}\n`, resolveStatus(err));
    }

    console.log(`resolving: ${target.toString()}`);

    let result;
    try {
        result = await resolveDestination(target, hostMap);
    } catch (err) {
        console.log(`resolve failed for ${target.toString()}: ${err.message}`);
        return textResponse(`${resolveStatus(err)} ${err.message}\n`, resolveStatus(err));
    }

    const clean = stripTrackingParams(result.final);
    console.log(`redirect: ${target.toString()} -> ${clean.toString()}`);

    return new Response(null, {
        status: 302,
        headers: {
            Location: clean.toString(),
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex",
        },
    });
}

async function handleRequest(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
    }

    // 自分自身から出た上流リクエストが戻ってきた場合 (ルート付け替え運用での
    // ループ) は、これ以上辿らずに打ち切る。
    if (request.headers.get(LOOP_GUARD_HEADER) === LOOP_GUARD_VALUE) {
        return textResponse("508 Loop Detected\n\nredirect loop back to this service\n", 508);
    }

    const hostMap = parseHostMap(env && env.UPSTREAM_HOST_MAP);

    // ルート付け替え運用: リクエストホスト自体がトラッキングサービス。
    if (isTrackerHost(url.hostname)) {
        return handleRedirect(url, hostMap);
    }

    switch (url.pathname) {
        case "/":
            return handleIndex(url, hostMap);
        case API_ENDPOINT:
            return handleAPI(url, hostMap);
        case RESOLVE_ENDPOINT:
            return handleRedirect(url, hostMap);
        default:
            return textResponse("404 not found\n", 404);
    }
}

export default {
    async fetch(request, env) {
        return handleRequest(request, env);
    },
};

// テスト用。Workers ランタイムは default export のみを使用する。
export {
    RedirectorError,
    handleRequest,
    hopLabels,
    isNonPublicAddress,
    isTrackerHost,
    isTrackerURL,
    parseHostMap,
    resolveDestination,
    stripTrackingParams,
    targetURL,
    validateHopURL,
};
