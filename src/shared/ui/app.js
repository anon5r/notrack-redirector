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
  unsupported_url: "対応していないサービスの URL です。下の対応サービス一覧を確認してください。",
  invalid_url: "URL の形式が正しくありません。",
  blocked_destination: "安全でないリダイレクト先が含まれていたため中断しました。",
  too_many_hops: "リダイレクトが多すぎるため中断しました。",
  no_destination: "この URL はリダイレクトを返しませんでした。",
  upstream_error: "リダイレクト先を取得できませんでした。時間をおいて再度試してください。",
};

const DEFAULT_ERROR_MESSAGE = ERROR_MESSAGES.upstream_error;

const el = {
  input: document.getElementById("input"),
  status: document.getElementById("status"),
  error: document.getElementById("error"),
  result: document.getElementById("result"),
  destination: document.getElementById("destination"),
  copy: document.getElementById("copy"),
  openBlank: document.getElementById("open-blank"),
  openSelf: document.getElementById("open-self"),
  hopsBlock: document.getElementById("hops-block"),
  hops: document.getElementById("hops"),
  trackers: document.getElementById("trackers"),
};

function showError(message) {
  el.error.textContent = message;
  el.error.hidden = false;
  el.result.hidden = true;
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

  el.error.hidden = true;
  el.result.hidden = false;
}

async function resolve(raw) {
  el.status.hidden = false;
  el.error.hidden = true;
  el.result.hidden = true;

  try {
    const response = await fetch(`/api/resolve?u=${encodeURIComponent(raw)}`, {
      headers: { Accept: "application/json" },
    });
    const body = await response.json();

    if (!response.ok || !body.destination) {
      showError(ERROR_MESSAGES[body.code] || DEFAULT_ERROR_MESSAGE);
      return;
    }
    showResult(body);
  } catch {
    showError(DEFAULT_ERROR_MESSAGE);
  } finally {
    el.status.hidden = true;
  }
}

async function loadTrackers() {
  try {
    const response = await fetch("/api/trackers", { headers: { Accept: "application/json" } });
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

loadTrackers();

// フォームは通常の GET 送信で ?u= を付けて遷移する。結果はその値から描画する
// ため、解決結果の URL をそのまま共有できる。
const requested = new URLSearchParams(location.search).get("u");
if (requested) {
  el.input.value = requested;
  resolve(requested);
}
