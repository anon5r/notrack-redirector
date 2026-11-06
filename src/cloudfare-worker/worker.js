/**
 * Anti-Tracking URL Redirector (Cloudflare Workers)
 *
 * アフィリエイト / トラッキング用の中継 URL を受け取り、サーバー側で実際の
 * リダイレクト先を解決したうえで、トラッキング用パラメータを除去した URL へ
 * ブラウザをリダイレクトする。
 *
 * セキュリティ方針:
 *   - リダイレクト先は「クエリパラメータに書かれた URL」ではなく、必ず
 *     Worker 側で上流サービスを辿った結果から決定する。
 *   - 解決結果を表示するだけの経路 (トップページと /api/resolve) は任意の
 *     ホストを受け付ける。302 を返さないため、他人に「開くだけで飛ぶリンク」
 *     を送れず、オープンリダイレクタ (フィッシング踏み台) にはならない。
 *   - 302 を返す経路 (/-/resolve とルート付け替え運用) だけは TRACKER_RULES の
 *     allowlist に限定する。ここを任意ホストに開くと踏み台になる。
 *
 * トップページ (自ドメインの "/") は URL 入力フォームを提供する。こちらは
 * リダイレクトせず解決結果の URL を表示するだけなので、遷移先にこのサービスの
 * URL が Referer として残らない。
 *
 * allowlist と除去するパラメータの定義は src/shared/rules.mjs にある。
 */

import rules from "../shared/rules.mjs";

const MAX_REDIRECT_HOPS = 8;
const UPSTREAM_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 64 * 1024;

/**
 * この文字数以下の本文しか表示しないページを「中継用の空ページ」とみなす。
 * "Redirecting..." 程度の文言は許容しつつ、通常のページは対象外にする。
 */
const MAX_INTERSTITIAL_TEXT_LENGTH = 200;

const LOOP_GUARD_HEADER = "X-Notrack-Redirector";
const LOOP_GUARD_VALUE = "1";

const RESOLVE_ENDPOINT = "/-/resolve";
const API_ENDPOINT = "/api/resolve";
const TRACKERS_ENDPOINT = "/api/trackers";
const RESOLVE_PARAM = "u";

/**
 * Cloudflare Access のログイン画面。
 *
 * このサービスを Access の内側に置くと、セッション切れのリクエストは
 * ここへリダイレクトされる。CSP はリダイレクト先も検査するため、
 * 許可しておかないと再認証が始まらずページが動かなくなる。
 */
const ACCESS_LOGIN_ORIGIN = "https://*.cloudflareaccess.com";

/**
 * UI に付与する Content-Security-Policy。
 * スクリプトは同一オリジンの静的ファイルだけを許可する。
 */
const UI_CSP =
    "default-src 'none'; " +
    "script-src 'self'; " +
    "img-src 'self'; " +
    "base-uri 'none'; " +
    `style-src 'self' ${ACCESS_LOGIN_ORIGIN}; ` +
    `manifest-src 'self' ${ACCESS_LOGIN_ORIGIN}; ` +
    `connect-src 'self' ${ACCESS_LOGIN_ORIGIN}; ` +
    `form-action 'self' ${ACCESS_LOGIN_ORIGIN}`;

/**
 * ルール定義。ルールを変更する場合は src/shared/rules.mjs だけを編集すればよい。
 */
const TRACKER_RULES = rules.trackers.map((tracker) => ({
    host: tracker.host.toLowerCase(),
    paths: tracker.paths.map((pattern) => new RegExp(pattern)),
}));

/**
 * パラメータの除去ルールを実行時の形に変換する。
 * 名前は大文字小文字を区別しないため、すべて小文字にそろえる。
 */
function compileParamRules(category) {
    const lower = (list) => (list || []).map((value) => value.toLowerCase());
    const compileHost = (entry) => ({
        suffixes: lower(entry.suffixes),
        names: new Set(lower(entry.names)),
        prefixes: lower(entry.prefixes),
        pathPatterns: (entry.pathPatterns || []).map((pattern) => new RegExp(pattern, "gi")),
    });
    return {
        names: new Set(lower(category.names)),
        prefixes: lower(category.prefixes),
        hosts: (category.hosts || []).map(compileHost),
        markers: (category.markers || []).map((marker) => ({
            ...compileHost(marker),
            param: marker.param.toLowerCase(),
            pattern: new RegExp(marker.pattern, "i"),
        })),
    };
}

/** 計測用パラメータの除去ルール。 */
const TRACKING_RULES = compileParamRules(rules.tracking);

/** アフィリエイト / 紹介報酬用パラメータの除去ルール。 */
const AFFILIATE_RULES = compileParamRules(rules.affiliate);

/** 除去オプションの既定値。指定がなければ両方を除去する。 */
const DEFAULT_STRIP_OPTIONS = Object.freeze({ tracking: true, affiliate: true });

/** 除去オプションを無効にするクエリパラメータ。値が "0" のとき無効になる。 */
const STRIP_TRACKING_PARAM = "strip_tracking";
const STRIP_AFFILIATE_PARAM = "strip_affiliate";

/** エラーコード。画面に出す文言は src/shared/ui/app.js 側で管理する。 */
const CODE_UNSUPPORTED_URL = "unsupported_url";
const CODE_INVALID_URL = "invalid_url";
const CODE_BLOCKED_DESTINATION = "blocked_destination";
const CODE_TOO_MANY_HOPS = "too_many_hops";
const CODE_UPSTREAM_ERROR = "upstream_error";

class RedirectorError extends Error {
    /**
     * @param {string} message ログ / API 向けの英語メッセージ
     * @param {number} status HTTP ステータス
     * @param {string} [code] API のエラーコード
     */
    constructor(message, status, code) {
        super(message);
        this.status = status;
        this.code = code || CODE_UPSTREAM_ERROR;
    }
}

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
            throw new RedirectorError(`invalid "${RESOLVE_PARAM}" parameter`, 400, CODE_INVALID_URL);
        }
        if (!isTrackerURL(parsed)) {
            throw new RedirectorError("not a supported tracking url", 404, CODE_UNSUPPORTED_URL);
        }
        return parsed;
    }

    const target = new URL(requestURL.toString());
    target.protocol = "https:";
    if (!isTrackerURL(target)) {
        throw new RedirectorError("not a supported tracking url", 404, CODE_UNSUPPORTED_URL);
    }
    return target;
}

/** 本文を HTML として読むべきかを判定する。 */
function isHTMLContentType(value) {
    return String(value || "").toLowerCase().includes("text/html");
}

/** 本文を読まずに破棄する。 */
async function discardBody(response) {
    if (response.body) {
        await response.body.cancel();
    }
}

/**
 * 本文の先頭だけを読み取る。遷移先の指示はページ冒頭にあるため十分。
 * 上流の本文は大きさが分からないため、上限まで読んだら残りは破棄する。
 */
async function readBodyHead(response) {
    if (!response.body) {
        return "";
    }

    const reader = response.body.getReader();
    const buffer = new Uint8Array(MAX_BODY_BYTES);
    let size = 0;
    try {
        while (size < MAX_BODY_BYTES) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            const part = value.subarray(0, MAX_BODY_BYTES - size);
            buffer.set(part, size);
            size += part.length;
        }
    } finally {
        await reader.cancel();
    }
    return new TextDecoder().decode(buffer.subarray(0, size));
}

const META_TAG_PATTERN = /<meta\s[^>]*>/gis;
const META_ATTR_PATTERN = /([a-z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gis;

/**
 * HTML の meta refresh による遷移先を返す。
 *
 * HTTP リダイレクトではなく <meta http-equiv="refresh"> で遷移させる
 * トラッキングサービスがあるため、それも追跡の対象にする。
 * JavaScript による遷移は scriptRedirectTarget が条件付きで扱う。
 */
function metaRefreshTarget(html) {
    for (const [tag] of String(html).matchAll(META_TAG_PATTERN)) {
        let isRefresh = false;
        let content = "";

        for (const [, name, rawValue] of tag.matchAll(META_ATTR_PATTERN)) {
            const value = decodeHTMLEntities(rawValue.replace(/^["']|["']$/g, ""));
            if (name.toLowerCase() === "http-equiv") {
                isRefresh = value.trim().toLowerCase() === "refresh";
            } else if (name.toLowerCase() === "content") {
                content = value;
            }
        }

        if (isRefresh) {
            const target = parseRefreshContent(content);
            if (target) {
                return target;
            }
        }
    }
    return "";
}

/** URL に現れうる名前付き文字参照。 */
const HTML_NAMED_ENTITIES = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" };

/**
 * 属性値の文字参照を戻す。URL 中の "&" は "&amp;" と書かれるため、戻さないと
 * "amp;utm_source" のような別名のパラメータになり除去を逃れる。
 */
function decodeHTMLEntities(value) {
    return value.replace(/&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));/gi, (entity, decimal, hex, name) => {
        if (decimal || hex) {
            const code = decimal ? parseInt(decimal, 10) : parseInt(hex, 16);
            return code <= 0x10ffff ? String.fromCodePoint(code) : entity;
        }
        return HTML_NAMED_ENTITIES[name.toLowerCase()] ?? entity;
    });
}

/**
 * refresh の content 属性から URL を取り出す。
 * "0;url=https://..." と "0.0;https://..." のどちらの書き方も受け付ける。
 */
function parseRefreshContent(content) {
    const index = content.indexOf(";");
    if (index < 0) {
        return "";
    }
    let target = content.slice(index + 1).trim();
    if (target.slice(0, 4).toLowerCase() === "url=") {
        target = target.slice(4).trim();
    }
    return target.replace(/^["']|["']$/g, "");
}

const SCRIPT_BLOCK_PATTERN = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const SCRIPT_TYPE_PATTERN = /\btype\s*=\s*["']?([^"'\s>]+)/i;
const SCRIPT_SRC_PATTERN = /\bsrc\s*=/i;
const NON_VISIBLE_BLOCK_PATTERN = /<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi;

/**
 * location への文字列リテラルの代入、または location.replace / assign の呼び出し。
 * 例: location.href = "...", window.location = '...', top.location.replace("...")
 * 文字列の連結や変数など、宛先が静的に確定しないものは対象外。
 */
const SCRIPT_REDIRECT_PATTERN = new RegExp(
    String.raw`(?:^|[^\w$.])(?:(?:window|self|top|parent|document)\s*\.\s*)?location` +
        String.raw`(?:(?:\s*\.\s*href)?\s*=(?!=)|\s*\.\s*(?:replace|assign)\s*\()` +
        String.raw`\s*(["'])((?:\\.|(?!\1)[^\\\r\n])*)\1(?!\s*[+.[])`,
);

/** JavaScript の文字列リテラルのエスケープ (\/ \u0026 \x26 など) を戻す。 */
function unescapeScriptString(value) {
    return value.replace(
        /\\(?:u\{([0-9a-f]+)\}|u([0-9a-f]{4})|x([0-9a-f]{2})|([\s\S]))/gi,
        (_, codePoint, unicode, hex, char) => {
            const code = codePoint || unicode || hex;
            return code ? String.fromCodePoint(parseInt(code, 16)) : char;
        },
    );
}

/** ページが利用者に見せる本文の文字数を返す。 */
function visibleTextLength(html) {
    return html
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(NON_VISIBLE_BLOCK_PATTERN, " ")
        .replace(/<[^>]*>/g, " ")
        .replace(/\s+/g, " ")
        .trim().length;
}

/** インラインで実行される JavaScript の script 要素かを判定する。 */
function isInlineJavaScript(attributes) {
    if (SCRIPT_SRC_PATTERN.test(attributes)) {
        return false;
    }
    const type = (attributes.match(SCRIPT_TYPE_PATTERN) || [])[1];
    return !type || /javascript|ecmascript|^module$/i.test(type);
}

/**
 * 本文を持たず JavaScript で即座に遷移させる中継ページの遷移先を返す。
 *
 * スクリプトから宛先を推測すると誤検出を招くため、次をすべて満たす場合だけ
 * 遷移とみなす。
 *   - 表示される本文がほとんどない (通常のページではない)
 *   - インラインの script 要素内で location に文字列リテラルを渡している
 */
function scriptRedirectTarget(html) {
    const source = String(html);
    if (visibleTextLength(source) > MAX_INTERSTITIAL_TEXT_LENGTH) {
        return "";
    }

    for (const [, attributes, body] of source.matchAll(SCRIPT_BLOCK_PATTERN)) {
        if (!isInlineJavaScript(attributes)) {
            continue;
        }
        const match = body.match(SCRIPT_REDIRECT_PATTERN);
        if (match) {
            const target = unescapeScriptString(match[2]).trim();
            if (target) {
                return target;
            }
        }
    }
    return "";
}

/**
 * HTTP リダイレクト以外の応答から遷移先を探す。
 *
 * 200 を返しつつ実際には別ページへ送る中継ページがあるため、次の順に調べる。
 *   1. Refresh ヘッダ (本文が空の応答で使われる)
 *   2. <meta http-equiv="refresh">
 *   3. 中身のない成功応答ページの JavaScript による遷移
 */
async function documentRedirectTarget(response) {
    const refresh = parseRefreshContent(response.headers.get("Refresh") || "");
    if (refresh || !isHTMLContentType(response.headers.get("Content-Type"))) {
        await discardBody(response);
        return refresh;
    }

    const html = await readBodyHead(response);
    return metaRefreshTarget(html) || (response.ok ? scriptRedirectTarget(html) : "");
}

/** フラグメントを除いて同じページを指すかを判定する。 */
function isSameDocument(a, b) {
    const left = new URL(a.toString());
    const right = new URL(b.toString());
    left.hash = "";
    right.hash = "";
    return left.toString() === right.toString();
}

/** リダイレクト先として許容できる URL かを検証する。 */
function validateHopURL(url) {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new RedirectorError(`blocked upstream scheme "${url.protocol}"`, 403, CODE_BLOCKED_DESTINATION);
    }
    const host = url.hostname.toLowerCase();
    if (!host) {
        throw new RedirectorError("blocked upstream address: empty host", 403, CODE_BLOCKED_DESTINATION);
    }
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
        throw new RedirectorError(`blocked local host "${host}"`, 403, CODE_BLOCKED_DESTINATION);
    }
    if (isNonPublicAddress(host)) {
        throw new RedirectorError(`blocked non-public address "${host}"`, 403, CODE_BLOCKED_DESTINATION);
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

        const status = response.status;
        let location = response.headers.get("Location");
        const redirected = status >= 300 && status <= 399 && Boolean(location);

        // HTTP リダイレクトでない場合だけ、Refresh ヘッダや本文による遷移指示を探す。
        if (redirected) {
            await discardBody(response);
        } else {
            location = await documentRedirectTarget(response);
        }

        if (!location) {
            // これ以上リダイレクトしない = ここが最終地点。
            // 一度もリダイレクトしなかった場合も、入力 URL からトラッキング
            // パラメータを取り除いた結果には意味があるため結果として返す。
            return { final: current, hops };
        }

        let next;
        try {
            next = new URL(location, current);
        } catch {
            throw new RedirectorError("invalid redirect target", 502);
        }
        if (!redirected && isSameDocument(next, current)) {
            // 自分自身を再読み込みするだけの refresh は遷移ではない。
            return { final: current, hops };
        }
        validateHopURL(next);
        hops.push(next);
        current = next;
    }

    throw new RedirectorError("too many redirect hops", 508, CODE_TOO_MANY_HOPS);
}

/**
 * URL から計測用 / アフィリエイト用のパラメータを除去する。
 * どちらを除去するかは options で選ぶ。両方に当てはまるものはアフィリエイト
 * として扱うため、アフィリエイトを残す指定なら計測用でも残る。
 */
function stripParams(url, options = DEFAULT_STRIP_OPTIONS) {
    const clean = new URL(url.toString());
    const host = clean.hostname.toLowerCase();

    if (options.tracking) {
        clean.pathname = stripPath(host, clean.pathname, TRACKING_RULES);
    }
    if (options.affiliate) {
        clean.pathname = stripPath(host, clean.pathname, AFFILIATE_RULES);
    }
    if (!clean.search) {
        return clean;
    }

    const marked = markedAffiliateRules(host, clean.searchParams);
    for (const name of [...clean.searchParams.keys()]) {
        const kind = paramKind(host, name, marked);
        if ((kind === "affiliate" && options.affiliate) || (kind === "tracking" && options.tracking)) {
            clean.searchParams.delete(name);
        }
    }
    return clean;
}

/** パスに埋め込まれた計測情報 (Amazon の /ref=... など) を取り除く。 */
function stripPath(host, pathname, category) {
    let path = pathname;
    for (const entry of category.hosts) {
        if (entry.pathPatterns.length === 0 || !matchesAnyHost(host, entry.suffixes)) {
            continue;
        }
        for (const pattern of entry.pathPatterns) {
            path = path.replace(pattern, "");
        }
    }
    return path || "/";
}

/** パラメータの値からアフィリエイト経由と判断できたルールを返す。 */
function markedAffiliateRules(host, searchParams) {
    const values = new Map();
    for (const [name, value] of searchParams) {
        const lower = name.toLowerCase();
        values.set(lower, [...(values.get(lower) || []), value]);
    }
    return AFFILIATE_RULES.markers.filter(
        (marker) =>
            (marker.suffixes.length === 0 || matchesAnyHost(host, marker.suffixes)) &&
            (values.get(marker.param) || []).some((value) => marker.pattern.test(value)),
    );
}

/** パラメータを "affiliate" / "tracking" / "" (除去対象外) に分類する。 */
function paramKind(host, name, markedRules) {
    const lower = name.toLowerCase();
    if (matchesCategory(host, lower, AFFILIATE_RULES) || markedRules.some((rule) => matchesNames(lower, rule))) {
        return "affiliate";
    }
    if (matchesCategory(host, lower, TRACKING_RULES)) {
        return "tracking";
    }
    return "";
}

function matchesCategory(host, name, category) {
    return (
        matchesNames(name, category) ||
        category.hosts.some((entry) => matchesAnyHost(host, entry.suffixes) && matchesNames(name, entry))
    );
}

function matchesNames(name, rule) {
    return rule.names.has(name) || rule.prefixes.some((prefix) => name.startsWith(prefix));
}

function matchesAnyHost(host, suffixes) {
    return suffixes.some((suffix) => hostMatches(host, suffix));
}

function hostMatches(host, suffix) {
    return host === suffix || host.endsWith(`.${suffix}`);
}

/** リクエストのクエリから除去オプションを読み取る。 */
function stripOptions(searchParams) {
    return {
        tracking: searchParams.get(STRIP_TRACKING_PARAM) !== "0",
        affiliate: searchParams.get(STRIP_AFFILIATE_PARAM) !== "0",
    };
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

/** 解決時のエラーを API のエラーコードへ変換する。 */
function errorCode(err) {
    return err instanceof RedirectorError ? err.code : CODE_UPSTREAM_ERROR;
}

/**
 * 表示専用の経路で解決してよい URL かを検証する。
 * allowlist は求めない代わりに、内部ネットワーク宛でないことを確認する。
 */
function parseResolvableURL(raw) {
    let parsed;
    try {
        parsed = new URL(raw);
    } catch {
        throw new RedirectorError("invalid url", 400, CODE_INVALID_URL);
    }
    validateHopURL(parsed);
    return parsed;
}

/**
 * 302 を返す経路のために、allowlist 済みのトラッキング URL として解釈する。
 */
function parseTrackerURL(raw) {
    const parsed = parseResolvableURL(raw);
    if (!isTrackerURL(parsed)) {
        throw new RedirectorError("not a supported tracking url", 400, CODE_UNSUPPORTED_URL);
    }
    return parsed;
}

/** 入力文字列を検証してから上流を解決する。 */
async function lookup(raw, hostMap) {
    const target = parseResolvableURL(raw);
    console.log(`resolving: ${target.toString()}`);
    return resolveDestination(target, hostMap);
}

/**
 * UI (src/shared/ui) を配信する。
 * ヘッダはここで付与するため、_headers に依存しない。
 */
async function serveAsset(request, env) {
    if (!env || !env.ASSETS) {
        return textResponse("404 not found\n", 404);
    }

    const response = await env.ASSETS.fetch(request);
    if (response.status === 404) {
        return textResponse("404 not found\n", 404);
    }

    const headers = new Headers(response.headers);
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("Content-Security-Policy", UI_CSP);
    headers.set("X-Content-Type-Options", "nosniff");
    return new Response(response.body, { status: response.status, headers });
}

/** 対応サービスの一覧を JSON で返す。画面の一覧表示に使う。 */
function handleTrackers() {
    return new Response(JSON.stringify({ trackers: TRACKER_RULES.map((rule) => rule.host) }) + "\n", {
        status: 200,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    });
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
        return respond({ error: `missing "${RESOLVE_PARAM}" parameter`, code: CODE_INVALID_URL }, 400);
    }

    try {
        const result = await lookup(raw, hostMap);
        return respond(
            {
                original: raw,
                destination: stripParams(result.final, stripOptions(url.searchParams)).toString(),
                hops: hopLabels(result.hops),
            },
            200,
        );
    } catch (err) {
        console.log(`resolve failed for ${raw}: ${err.message}`);
        return respond({ original: raw, error: err.message, code: errorCode(err) }, resolveStatus(err));
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

    // ルート付け替え運用ではクエリが上流のものなので、オプションは読まない。
    const options = url.pathname === RESOLVE_ENDPOINT ? stripOptions(url.searchParams) : DEFAULT_STRIP_OPTIONS;
    const clean = stripParams(result.final, options);
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
        case API_ENDPOINT:
            return handleAPI(url, hostMap);
        case TRACKERS_ENDPOINT:
            return handleTrackers();
        case RESOLVE_ENDPOINT:
            return handleRedirect(url, hostMap);
        default:
            return serveAsset(request, env);
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
    errorCode,
    handleRequest,
    hopLabels,
    isNonPublicAddress,
    isTrackerHost,
    isTrackerURL,
    metaRefreshTarget,
    parseResolvableURL,
    parseTrackerURL,
    parseHostMap,
    resolveDestination,
    scriptRedirectTarget,
    stripParams,
    targetURL,
    validateHopURL,
};
