/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run "npm run dev" in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run "npm run deploy" to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

// 特定のパスとパラメータの設定
const specPath = [
    { pattern: /^\/svt\/ejp/, param: "a8ejpredirect" },
    { pattern: /^\/ichiba\/[\w._]+/, param: "pc" },
    { pattern: /^\/hgc\/[\w._]+/, param: "pc" },
    { pattern: /^\/servlet\/referral/, param: "vc_url" },
];

// 共通のパラメータ
const commonParams = ["url", "redirect", "jump"];

// URL ホストごとのパラメータ
const urlParams = {
    "px.a8.net": ["a8ejpredirect"],
    "hb.afl.rakuten.co.jp": ["pc"],
    "ck.jp.ap.valuecommerce.com": ["vc_url"],
};

// リダイレクト処理
function actionRedirect(redirect, request) {
    if (redirect && (redirect.startsWith("http://") || redirect.startsWith("https://"))) {
        console.log(`Redirecting to: ${redirect}`);
        return new Response(null, {
            status: 302,
            headers: { Location: redirect },
        });
    }
    return null;
}

// リダイレクトロジック
async function handleRequest(request) {
    const url = new URL(request.url);

    if (url.pathname === "/favicon.ico") {
        return new Response(null, { status: 204 });
    }

    console.log(`Request: ${url.host}${url.pathname}?${url.searchParams.toString()}`);

    // 特定のホストのパラメータを処理
    if (urlParams[url.host]) {
        for (const paramName of urlParams[url.host]) {
            const redirect = url.searchParams.get(paramName);
            console.log(`Found param: ${paramName}, redirect: ${redirect}`);
            if (redirect) {
                return actionRedirect(redirect, request);
            }
        }
    }

    // 特定のパスのパラメータを処理
    for (const { pattern, param } of specPath) {
        if (pattern.test(url.pathname)) {
            const redirect = url.searchParams.get(param);
            console.log(`Matched path pattern: ${pattern}, param: ${param}, redirect: ${redirect}`);
            if (redirect) {
                return actionRedirect(redirect, request);
            }
        }
    }

    // 共通のパラメータを処理
    for (const key of commonParams) {
        const redirect = url.searchParams.get(key);
        console.log(`Matched common param: ${key}, redirect: ${redirect}`);
        if (redirect) {
            return actionRedirect(redirect, request);
        }
    }

    // リダイレクトが見つからない場合
    return new Response(`Hello, ${url.pathname}`, { status: 200, headers: { "Content-Type": "text/plain" } });
}

// Entrypoint of Cloudflare Worker
addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
});