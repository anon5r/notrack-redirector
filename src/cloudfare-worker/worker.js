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
 * src/main.go と同じポリシーを実装している。allowlist とトラッキング
 * パラメータの定義は src/shared/rules.json で共有している。
 */

import rules from "../shared/rules.json" with { type: "json" };

const MAX_REDIRECT_HOPS = 8;
const UPSTREAM_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 64 * 1024;

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
 * 共有 UI に付与する Content-Security-Policy。
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
 * 共有ルール定義。Go 実装 (src/main.go) も同じファイルを読み込む。
 * ルールを変更する場合は src/shared/rules.json だけを編集すればよい。
 */
const TRACKER_RULES = rules.trackers.map((tracker) => ({
    host: tracker.host.toLowerCase(),
    paths: tracker.paths.map((pattern) => new RegExp(pattern)),
}));

/** 前方一致で除去するクエリパラメータ。 */
const TRACKING_PARAM_PREFIXES = rules.trackingParamPrefixes;

/** 完全一致で除去するクエリパラメータ。 */
const TRACKING_PARAM_NAMES = new Set(rules.trackingParamNames.map((name) => name.toLowerCase()));

/** ホスト (サフィックス一致) ごとに追加で除去するパラメータ。 */
const HOST_TRACKING_PARAMS = rules.hostTrackingParams.map((entry) => ({
    suffix: entry.suffix.toLowerCase(),
    names: entry.names.map((name) => name.toLowerCase()),
}));

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

/** 本文の先頭だけを読み取る。遷移先の指示はページ冒頭にあるため十分。 */
async function readBodyHead(response) {
    if (!response.body) {
        return "";
    }
    const buffer = await response.arrayBuffer();
    return new TextDecoder().decode(buffer.slice(0, MAX_BODY_BYTES));
}

const META_TAG_PATTERN = /<meta\s[^>]*>/gis;
const META_ATTR_PATTERN = /([a-z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gis;

/**
 * HTML の meta refresh による遷移先を返す。
 *
 * HTTP リダイレクトではなく <meta http-equiv="refresh"> で遷移させる
 * トラッキングサービスがあるため、それも追跡の対象にする。
 * JavaScript による遷移は誤検出を招くので対象にしない。
 */
function metaRefreshTarget(html) {
    for (const [tag] of String(html).matchAll(META_TAG_PATTERN)) {
        let isRefresh = false;
        let content = "";

        for (const [, name, rawValue] of tag.matchAll(META_ATTR_PATTERN)) {
            const value = rawValue.replace(/^["']|["']$/g, "");
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

        // HTTP リダイレクトでない場合だけ、HTML による遷移指示を探すために
        // 本文の先頭を読む。
        if (!redirected && isHTMLContentType(response.headers.get("Content-Type"))) {
            location = metaRefreshTarget(await readBodyHead(response));
        } else if (response.body) {
            await response.body.cancel();
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
        validateHopURL(next);
        hops.push(next);
        current = next;
    }

    throw new RedirectorError("too many redirect hops", 508, CODE_TOO_MANY_HOPS);
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
 * 共有 UI (src/shared/ui) を配信する。Go 実装も同じファイルを配信する。
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
                destination: stripTrackingParams(result.final).toString(),
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
    stripTrackingParams,
    targetURL,
    validateHopURL,
};
