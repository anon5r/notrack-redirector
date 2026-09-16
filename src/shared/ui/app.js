// notrack-redirector のフロントエンド。
//
// 画面はサーバー側でレンダリングせず、/api/resolve の結果を描画するだけに
// している。これにより Go 実装と Cloudflare Worker 実装が同じ静的ファイルを
// そのまま配信でき、ページの記述が一箇所で済む。
//
// 生成した要素には textContent と setAttribute だけを使い、innerHTML は
// 使用しない。

"use strict";

/**
 * API が返すエラーコードに対応する表示文言。
 * サーバー側は英語のエラー文字列とこのコードを返し、日本語の文言はここだけで
 * 管理する。
 */
const ERROR_MESSAGES = {
  unsupported_url: "このサービスは直接リダイレクトに対応していません。",
  invalid_url: "URL の形式が正しくありません。",
  blocked_destination: "そのアドレスは指定できません。",
  too_many_hops: "リダイレクトが多すぎるため中断しました。",
  upstream_error: "リダイレクト先を取得できませんでした。時間をおいて再度試してください。",
};

/**
 * 認証の有効期限が切れたときの文言。
 * サーバーから返るコードではなく、応答の形から画面側で判断する。
 */
const AUTH_MESSAGE = "認証の有効期限が切れています。再読み込みして認証してください。";

const DEFAULT_ERROR_MESSAGE = ERROR_MESSAGES.upstream_error;

/**
 * 「解決したら自動で開く」の保存先。
 *
 * この設定は端末にだけ保存し、URL パラメータからは絶対に有効化しない。
 * URL で指定できてしまうと「開くだけで任意の URL へ飛ぶリンク」を他人に
 * 送れることになり、このサービスがフィッシングの踏み台になる。
 */
const AUTO_OPEN_KEY = "notrack:auto-open";

const el = {
  input: document.getElementById("input"),
  paste: document.getElementById("paste"),
  autoOpen: document.getElementById("auto-open"),
  status: document.getElementById("status"),
  error: document.getElementById("error"),
  reauth: document.getElementById("reauth"),
  reload: document.getElementById("reload"),
  result: document.getElementById("result"),
  destination: document.getElementById("destination"),
  noRedirect: document.getElementById("no-redirect"),
  copy: document.getElementById("copy"),
  openBlank: document.getElementById("open-blank"),
  openSelf: document.getElementById("open-self"),
  hopsBlock: document.getElementById("hops-block"),
  hops: document.getElementById("hops"),
  trackers: document.getElementById("trackers"),
};

/** localStorage は利用できない環境があるため、失敗しても動作を止めない。 */
function readAutoOpen() {
  try {
    return localStorage.getItem(AUTO_OPEN_KEY) === "1";
  } catch {
    return false;
  }
}

function writeAutoOpen(enabled) {
  try {
    localStorage.setItem(AUTO_OPEN_KEY, enabled ? "1" : "0");
  } catch {
    // 保存できなくても今回の操作には影響しない。
  }
}

/**
 * 共有シートから渡される文字列には「タイトル 改行 URL」のように URL 以外が
 * 含まれるため、最初の http(s) URL を取り出す。
 */
function extractURL(raw) {
  const match = String(raw).match(/https?:\/\/\S+/);
  return match ? match[0] : String(raw).trim();
}

function showError(message, needsAuth = false) {
  el.error.textContent = message;
  el.error.hidden = false;
  el.reauth.hidden = !needsAuth;
  el.result.hidden = true;
}

/**
 * API を呼ぶ。
 *
 * Cloudflare Access のような認証プロキシの内側に置くと、セッションが切れた
 * 時点で API へのリクエストがログイン画面へリダイレクトされる。リダイレクトを
 * 追うと別オリジンへの要求になり CORS で失敗して原因が分からなくなるため、
 * redirect: "manual" で追わずに不透明な応答として受け取る。
 */
function requestJSON(path) {
  return fetch(path, {
    redirect: "manual",
    headers: { Accept: "application/json" },
  });
}

/** 応答が認証プロキシによるログイン画面への誘導かを判定する。 */
function isAuthRedirect(response) {
  if (response.type === "opaqueredirect" || response.status === 0) {
    return true;
  }
  const contentType = response.headers.get("Content-Type") || "";
  return !contentType.includes("application/json");
}

function showResult(body) {
  el.destination.textContent = body.destination;
  el.copy.dataset.url = body.destination;
  el.openBlank.setAttribute("href", body.destination);
  el.openSelf.setAttribute("href", body.destination);

  el.hops.replaceChildren();
  const hops = Array.isArray(body.hops) ? body.hops : [];
  for (const hop of hops) {
    const code = document.createElement("code");
    code.textContent = hop;
    const item = document.createElement("li");
    item.append(code);
    el.hops.append(item);
  }
  el.hopsBlock.hidden = hops.length === 0;
  el.noRedirect.hidden = hops.length !== 0;

  el.error.hidden = true;
  el.result.hidden = false;
}

async function resolve(raw) {
  el.status.hidden = false;
  el.error.hidden = true;
  el.result.hidden = true;

  try {
    const response = await requestJSON(`/api/resolve?u=${encodeURIComponent(raw)}`);

    if (isAuthRedirect(response)) {
      showError(AUTH_MESSAGE, true);
      return;
    }

    const body = await response.json();

    if (!response.ok || !body.destination) {
      showError(ERROR_MESSAGES[body.code] || DEFAULT_ERROR_MESSAGE);
      return;
    }

    el.reauth.hidden = true;
    showResult(body);

    if (el.autoOpen.checked) {
      // ページ自体が no-referrer なので、遷移先に参照元は渡らない。
      // 履歴を残さないよう replace で遷移する。
      location.replace(body.destination);
    }
  } catch {
    showError(DEFAULT_ERROR_MESSAGE);
  } finally {
    el.status.hidden = true;
  }
}

async function loadTrackers() {
  try {
    const response = await requestJSON("/api/trackers");
    if (isAuthRedirect(response)) {
      // 一覧は補助的な表示なので、ここでは黙って諦める。
      return;
    }
    const body = await response.json();
    const hosts = Array.isArray(body.trackers) ? body.trackers : [];

    el.trackers.replaceChildren();
    for (const host of hosts) {
      const code = document.createElement("code");
      code.textContent = host;
      const item = document.createElement("li");
      item.append(code);
      el.trackers.append(item);
    }
  } catch {
    el.trackers.replaceChildren();
  }
}

el.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(el.copy.dataset.url || "");
    el.copy.textContent = "コピーしました";
  } catch {
    el.copy.textContent = "コピーできませんでした";
  }
});

el.paste.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    const raw = extractURL(text);
    if (!raw) {
      return;
    }
    el.input.value = raw;
    resolve(raw);
  } catch {
    // 読み取りが許可されない環境では、利用者が入力欄に貼り付ければよい。
    el.input.focus();
  }
});

el.reload.addEventListener("click", () => location.reload());

el.autoOpen.checked = readAutoOpen();
el.autoOpen.addEventListener("change", () => writeAutoOpen(el.autoOpen.checked));

loadTrackers();

// フォームは通常の GET 送信で ?u= を付けて遷移する。共有シートから起動された
// 場合は url / text にも入りうるため、いずれかから URL を取り出す。
const params = new URLSearchParams(location.search);
const requested = params.get("u") || params.get("url") || params.get("text");
if (requested) {
  const raw = extractURL(requested);
  el.input.value = raw;
  resolve(raw);
}
