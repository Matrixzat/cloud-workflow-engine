var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var BOT_TOKEN = "8638824829:AAFDe5gBOiFisggH3Bp7sD_9vrVH7DafCnU";
var GROUP_ID_DEFAULT = -1001794534648;
var CHANNEL_ID = -1003921926614;
var HARDCODED_APPS = {
  reversalx: {
    app_id: "reversalx",
    display_name: "Adiza Moviez Box",
    tg_command: "reversalx",
    expiry_default: "2080",
    group_link: "https://t.me/reversemoda",
    app_secret: "",
    dialog_variant: "reversal",
    package_name: "com.adiza.moviezbox",
    created_at: 0
  }
};
function getAppByCommand(cmd) {
  return HARDCODED_APPS[cmd?.toLowerCase()] || null;
}
__name(getAppByCommand, "getAppByCommand");
function getAppById(id) {
  return Object.values(HARDCODED_APPS).find((a) => a.app_id === id) || null;
}
__name(getAppById, "getAppById");
function getAppByPackage(pkg) {
  return Object.values(HARDCODED_APPS).find((a) => a.package_name === pkg) || null;
}
__name(getAppByPackage, "getAppByPackage");
function getAllApps() {
  return Object.values(HARDCODED_APPS);
}
__name(getAllApps, "getAllApps");
var MUNO_EMAIL = "adizaapp2026@gmail.com";
var MUNO_PASS = "AdizaApp@2026";
var MUNO_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IkFuZHJvaWQgVFYiLCJhcHBuYW1lIjoiTXVub3dhdGNoIFRWIiwiaG9zdCI6Im11bm93YXRjaC5jbyIsImFwcHNlY3JldCI6IjAyMjc3OGU0MThhZDY4ZmZkYTlhYTRmYWIxODkyZmZmIiwiYWN0aXZhdGVkIjoiMSIsImV4cCI6MTcwNzM2ODQwMH0.unlPnEzptg6VFHs7WWm213bRHHNxYuAN2eZQvjtPKL0";
var APP_HMAC_SECRET = "RXMads93Kz7wPqLmVb2eN5fYcA1jTu8h";
var RESP_SIGN_SECRET = "pG6vHsE4nWxK9mBdJ3rQyUoZ2cIlFaT7";
var ADMIN_SECRET = "fCYay9SMF9LKHvtQYb!uRu3G";
var MUNO_COM = "https://munowatch.com";
var MUNO_ORG = "https://munowatch.org";
var MUNO_UA = "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
var _munoSession = null;
async function munoGetSession() {
  if (_munoSession && Date.now() < _munoSession.expires) return _munoSession.cookie;
  const resp = await fetch(`${MUNO_COM}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": MUNO_UA,
      "Referer": `${MUNO_COM}/login`,
      "Accept": "text/html,application/xhtml+xml"
    },
    body: `email=${encodeURIComponent(MUNO_EMAIL)}&password=${encodeURIComponent(MUNO_PASS)}`,
    redirect: "manual"
  });
  const setCookie = resp.headers.get("set-cookie") || "";
  const m = setCookie.match(/PHPSESSID=([^;]+)/);
  if (!m) throw new Error("Bambilla login failed \u2014 no session cookie");
  const cookie = `PHPSESSID=${m[1]}`;
  _munoSession = { cookie, expires: Date.now() + 25 * 60 * 1e3 };
  return cookie;
}
__name(munoGetSession, "munoGetSession");
function munoParseMovies(html2) {
  const movies = [];
  const parts = html2.split(/href="\/twolekede\?/);
  for (let i = 1; i < parts.length; i++) {
    const chunk = parts[i];
    const vM = chunk.match(/^v=([^&"]+)/);
    if (!vM) continue;
    const v = vM[1];
    const titleM = chunk.match(/(?:&amp;|&)title=([^"]+)"/);
    const title = titleM ? decodeURIComponent(titleM[1].replace(/\+/g, " ")).replace(/&amp;/g, "&") : "";
    const idM = chunk.match(/id="(\d{4,})"/);
    const vid = idM ? idM[1] : "";
    if (!vid) continue;
    const imgM = chunk.match(/src="(https:\/\/munoapp\.org[^"]+)"/);
    const thumbnail = imgM ? imgM[1] : "";
    const vjM = chunk.match(/<p[^>]*bg-green-500[^>]*>([^<]+)<\/p>/);
    const vj = vjM ? vjM[1].trim() : "";
    const locked = chunk.includes('fill-rule="evenodd"') && chunk.includes("4.5 4.5");
    movies.push({ id: vid, v, title, thumbnail, vj, locked });
  }
  return movies;
}
__name(munoParseMovies, "munoParseMovies");
async function munoAuthedGetSlot(path) {
  let cookie = await munoGetSession();
  let resp = await fetch(`${MUNO_COM}${path}`, {
    headers: {
      "User-Agent": MUNO_UA,
      "Accept": "*/*",
      "X-Requested-With": "XMLHttpRequest",
      "Referer": MUNO_COM,
      "Cookie": cookie
    },
    redirect: "manual"
  });
  if (resp.status === 302) {
    _munoSession = null;
    cookie = await munoGetSession();
    resp = await fetch(`${MUNO_COM}${path}`, {
      headers: {
        "User-Agent": MUNO_UA,
        "Accept": "*/*",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": MUNO_COM,
        "Cookie": cookie
      },
      redirect: "manual"
    });
  }
  if (resp.status === 302) throw new Error("Session still invalid after re-login");
  return resp;
}
__name(munoAuthedGetSlot, "munoAuthedGetSlot");
function munoGridSlotUrl(pipeType, pipeId, lastFetchId) {
  let url = `/grid-slot?pipe_type=${encodeURIComponent(pipeType)}&pipe_id=${encodeURIComponent(pipeId)}`;
  if (lastFetchId) url += `&last_fetch_id=${encodeURIComponent(lastFetchId)}`;
  return url;
}
__name(munoGridSlotUrl, "munoGridSlotUrl");
function munoParseGridResult(html2) {
  const movies = munoParseMovies(html2);
  const lastFetchId = movies.length > 0 ? movies[movies.length - 1].id : null;
  return { movies, lastFetchId };
}
__name(munoParseGridResult, "munoParseGridResult");
async function getGroupId(env) {
  if (GROUP_ID_DEFAULT) return GROUP_ID_DEFAULT;
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key='group_id'").first();
    if (row && row.value) return parseInt(row.value);
  } catch {
  }
  return 0;
}
__name(getGroupId, "getGroupId");
function getChannelId() {
  return CHANNEL_ID || 0;
}
__name(getChannelId, "getChannelId");
async function initDB(db) {
  await db.exec("CREATE TABLE IF NOT EXISTS activations (device_id TEXT PRIMARY KEY, username TEXT DEFAULT '', expiry TEXT DEFAULT '2099-12-31', is_active INTEGER DEFAULT 1, created_at INTEGER DEFAULT 0, notes TEXT DEFAULT '')");
  await db.exec("CREATE TABLE IF NOT EXISTS vip_tokens (token TEXT PRIMARY KEY, device_id TEXT, created_at INTEGER, used INTEGER DEFAULT 0, expires_at INTEGER)");
  await db.exec("CREATE TABLE IF NOT EXISTS apps (app_id TEXT PRIMARY KEY, display_name TEXT NOT NULL DEFAULT '', tg_command TEXT NOT NULL DEFAULT '', expiry_default TEXT NOT NULL DEFAULT '2080', group_link TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0)");
  await db.exec("CREATE TABLE IF NOT EXISTS app_activations (app_id TEXT NOT NULL, device_id TEXT NOT NULL, telegram_username TEXT NOT NULL DEFAULT '', expiry TEXT NOT NULL DEFAULT '2080', is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (app_id, device_id))");
  try {
    await db.exec("ALTER TABLE vip_tokens ADD COLUMN app_id TEXT NOT NULL DEFAULT 'default'");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE apps ADD COLUMN app_secret TEXT NOT NULL DEFAULT ''");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE apps ADD COLUMN dialog_variant TEXT NOT NULL DEFAULT 'reversal'");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE apps ADD COLUMN pkg_suffix TEXT NOT NULL DEFAULT ''");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE apps ADD COLUMN package_name TEXT NOT NULL DEFAULT ''");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE app_activations ADD COLUMN expired_notified INTEGER NOT NULL DEFAULT 0");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE app_activations ADD COLUMN telegram_user_id INTEGER NOT NULL DEFAULT 0");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE app_activations ADD COLUMN warn_sent INTEGER NOT NULL DEFAULT 0");
  } catch (e) {
  }
  try {
    await db.exec("ALTER TABLE app_activations ADD COLUMN source TEXT NOT NULL DEFAULT 'telegram'");
  } catch (e) {
  }
  await db.exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')");
  await db.exec("CREATE TABLE IF NOT EXISTS pending_activations (telegram_user_id INTEGER NOT NULL, app_id TEXT NOT NULL, device_id TEXT NOT NULL, telegram_username TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (telegram_user_id, app_id))");
}
__name(initDB, "initDB");
function randomToken(len = 32) {
  const arr = new Uint8Array(len / 2);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(randomToken, "randomToken");
async function freshToken(db, appId, deviceId, retries = 5) {
  await db.prepare("DELETE FROM vip_tokens WHERE device_id=? AND app_id=?").bind(deviceId, appId).run();
  for (let i = 0; i < retries; i++) {
    const token = randomToken(32);
    try {
      await db.prepare(
        "INSERT INTO vip_tokens (token, app_id, device_id, created_at, used) VALUES (?,?,?,?,0)"
      ).bind(token, appId, deviceId, Date.now()).run();
      return token;
    } catch (e) {
      if (i === retries - 1) throw e;
    }
  }
}
__name(freshToken, "freshToken");
function isExpired(expiry) {
  if (!expiry || expiry === "2080" || expiry === "2099-12-31") return false;
  try {
    return new Date(expiry) < /* @__PURE__ */ new Date();
  } catch {
    return false;
  }
}
__name(isExpired, "isExpired");
function isNearExpiry(expiry, ms = 48 * 3600 * 1e3) {
  if (!expiry || expiry === "2080" || expiry === "2099-12-31") return false;
  try {
    const exp = new Date(expiry).getTime();
    const now = Date.now();
    return exp > now && exp - now <= ms;
  } catch {
    return false;
  }
}
__name(isNearExpiry, "isNearExpiry");
function parseExpiry(str) {
  if (!str || str === "2080") return "2080";
  const mo = /^(\d+)\s*mo(?:nths?)?$/i.exec(str);
  const wk = /^(\d+)\s*w(?:eeks?)?$/i.exec(str);
  const dy = /^(\d+)\s*d(?:ays?)?$/i.exec(str);
  const hr = /^(\d+)h$/i.exec(str);
  const mn = /^(\d+)m$/i.exec(str);
  if (mo) {
    const d = /* @__PURE__ */ new Date();
    d.setMonth(d.getMonth() + +mo[1]);
    return d.toISOString();
  }
  if (wk) return new Date(Date.now() + +wk[1] * 7 * 864e5).toISOString();
  if (dy) return new Date(Date.now() + +dy[1] * 864e5).toISOString();
  if (hr) return new Date(Date.now() + +hr[1] * 36e5).toISOString();
  if (mn) return new Date(Date.now() + +mn[1] * 6e4).toISOString();
  return str;
}
__name(parseExpiry, "parseExpiry");
function fmtExpiry(exp) {
  if (!exp || exp === "2080" || exp === "2099-12-31") return "\u267E\uFE0F Lifetime";
  try {
    return new Date(exp).toUTCString().replace(" GMT", " UTC");
  } catch {
    return exp;
  }
}
__name(fmtExpiry, "fmtExpiry");
function statusBadge(isActive, expiry) {
  if (!isActive) return "\u26D4 Revoked";
  if (isExpired(expiry)) return "\u23F0 Expired";
  return "\u2705 Active";
}
__name(statusBadge, "statusBadge");
async function checkAdminKey(url, env) {
  if (!ADMIN_SECRET || ADMIN_SECRET.trim() === "") return false;
  const provided = url.searchParams.get("secret") || url.searchParams.get("key") || "";
  if (!provided) return false;
  if (provided.length !== ADMIN_SECRET.length) return false;
  let diff = 0;
  for (let i = 0; i < provided.length; i++) {
    diff |= provided.charCodeAt(i) ^ ADMIN_SECRET.charCodeAt(i);
  }
  return diff === 0;
}
__name(checkAdminKey, "checkAdminKey");
function _hexToBytes(hex) {
  const b = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}
__name(_hexToBytes, "_hexToBytes");
function _bytesToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(_bytesToHex, "_bytesToHex");
async function _importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
__name(_importHmacKey, "_importHmacKey");
async function verifyRequestHmac({ device_id, nonce, ts, sig, pkg }) {
  if (!APP_HMAC_SECRET) return true;
  if (!nonce || !ts || !sig) return false;
  // No timestamp window — works for all countries regardless of device clock skew
  const msg = `${nonce}|${ts}|${device_id}|${pkg || "com.adiza.moviezbox"}`;
  const key = await _importHmacKey(APP_HMAC_SECRET);
  try {
    return await crypto.subtle.verify("HMAC", key, _hexToBytes(sig), new TextEncoder().encode(msg));
  } catch {
    return false;
  }
}
__name(verifyRequestHmac, "verifyRequestHmac");
async function signResponse({ active, ts, nonce }) {
  if (!RESP_SIGN_SECRET) return "";
  const msg = `${active ? 1 : 0}|${ts}|${nonce}`;
  const key = await _importHmacKey(RESP_SIGN_SECRET);
  const buf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return _bytesToHex(buf);
}
__name(signResponse, "signResponse");
function validateAppSecret(app, provided) {
  if (!app) return false;
  return true;
}
__name(validateAppSecret, "validateAppSecret");
var CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,Authorization" };
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...CORS } });
}
__name(json, "json");
function html(content, status = 200) {
  return new Response(content, { status, headers: { "Content-Type": "text/html; charset=utf-8", ...CORS } });
}
__name(html, "html");
function ok() {
  return new Response("ok", { status: 200 });
}
__name(ok, "ok");
function toBold(text) {
  return [...text].map((c) => {
    const code = c.codePointAt(0);
    if (code >= 65 && code <= 90) return String.fromCodePoint(code + 120211);
    if (code >= 97 && code <= 122) return String.fromCodePoint(code + 120205);
    return c;
  }).join("");
}
__name(toBold, "toBold");
function escHtml(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
__name(escHtml, "escHtml");
async function sendPhoto(token, chatId, photoFileId, caption, replyMarkup, parseMode) {
  const body = { chat_id: chatId, photo: photoFileId, caption };
  if (replyMarkup) body.reply_markup = replyMarkup;
  if (parseMode) body.parse_mode = parseMode;
  return fetch(`https://api.telegram.org/bot${token}/sendPhoto`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}
__name(sendPhoto, "sendPhoto");
async function sendMessage(token, chatId, text, parseMode) {
  const body = { chat_id: chatId, text };
  if (parseMode) body.parse_mode = parseMode;
  return fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}
__name(sendMessage, "sendMessage");
async function sendMessageKeyboard(token, chatId, text, parseMode, replyMarkup) {
  const body = { chat_id: chatId, text, reply_markup: replyMarkup };
  if (parseMode) body.parse_mode = parseMode;
  return fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}
__name(sendMessageKeyboard, "sendMessageKeyboard");
async function editMessageText(token, chatId, msgId, text, parseMode, replyMarkup) {
  const body = { chat_id: chatId, message_id: msgId, text };
  if (parseMode) body.parse_mode = parseMode;
  if (replyMarkup) body.reply_markup = replyMarkup;
  return fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}
__name(editMessageText, "editMessageText");
async function answerCallback(token, id, text = "") {
  return fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ callback_query_id: id, text })
  });
}
__name(answerCallback, "answerCallback");
function deviceKb(deviceId, appId, isActive) {
  const safe = `${appId}|${deviceId}`;
  const toggleBtn = isActive ? { text: "\u26D4 Revoke", callback_data: `rv:${safe}` } : { text: "\u2705 Restore", callback_data: `rs:${safe}` };
  return { inline_keyboard: [
    [toggleBtn, { text: "\u{1F504} Refresh", callback_data: `ck:${safe}` }],
    [{ text: "\u{1F5D1}\uFE0F Delete", callback_data: `dl:${safe}` }]
  ] };
}
__name(deviceKb, "deviceKb");
var ANNOUNCE_PHOTOS = [
  "AgACAgQAAxkDAAN-agE0Hd3_ewpE64VAuF-FrptXjIsAAssNaxtWiwlQgi0aWMZoLecBAAMCAAN3AAM7BA",
  // 1 cyberpunk
  "AgACAgQAAxkDAAOCagE0OlMKm7sbBrkFij5xtOOAubMAAs8NaxtWiwlQ_9iBKWlD39sBAAMCAAN3AAM7BA",
  // 2 ice
  "AgACAgQAAxkDAAODagE0PN-71pRknetQL9fI9JHlzkoAAtANaxtWiwlQo9SsYYJwlZYBAAMCAAN3AAM7BA",
  // 3 neon
  "AgACAgQAAxkDAAOEagE0cmBWnK5SuWfIa2IPQRIri7wAAtENaxtWiwlQ2A8XOueE_VQBAAMCAAN3AAM7BA",
  // 4 lava
  "AgACAgQAAxkDAAOAagE0IPbxh-MJnxdY3wE522TGu2YAAs0NaxtWiwlQ4tQAAdyaiH9ZAQADAgADdwADOwQ",
  // 5 matrix
  "AgACAgQAAxkDAAOBagE0IuSSUm7EcMUpYdjyvhQ9VjMAAs4NaxtWiwlQoa2sH2Govj0BAAMCAAN3AAM7BA"
  // 6 purple
];
async function getNextBannerPhoto(db) {
  try {
    await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
    const row = await db.prepare("SELECT value FROM settings WHERE key='banner_seq'").first();
    const idx = row ? (parseInt(row.value, 10) + 1) % ANNOUNCE_PHOTOS.length : 0;
    await db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('banner_seq',?)").bind(String(idx)).run();
    return ANNOUNCE_PHOTOS[idx];
  } catch {
    return ANNOUNCE_PHOTOS[0];
  }
}
__name(getNextBannerPhoto, "getNextBannerPhoto");
var ANNOUNCE_KB = { inline_keyboard: [
  [{ text: "\u{1FA80} Join our Channel \u{1FA80}", url: "https://t.me/matrixxxxx2a" }],
  [{ text: "\u{1F98B} Reversal_X_Chatroom \u{1F98B}", url: "https://t.me/+WxUQKQZFdTA2NGY8" }]
] };
function buildAnnouncementMessage(app) {
  const nameB = toBold(app.display_name);
  return [
    "\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}",
    "\u27BD: " + nameB + " :\u27BD",
    "\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}",
    "",
    "\u{1F98B} " + toBold("GET ACTIVATED") + " \u{1F98B}",
    "",
    toBold("STEP 1") + " \u2014 Open " + app.display_name,
    "> Copy " + toBold("Device ID") + " on the dialog",
    "",
    toBold("STEP 2") + " \u2014 Send this command here:",
    "`/" + app.tg_command + " YOUR_DEVICE_ID`",
    "",
    toBold("STEP 3") + " \u2014 U will get a",
    " confirmation by our bot automatically when u are granted vip access.",
    "",
    "\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796",
    "\u{1F579} " + toBold("ACTIVATED BY") + " \u{1F579}",
    "",
    "         \u9006\u8F6C X \u6A21\u7EC4",
    "\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796"
  ].join("\n");
}
__name(buildAnnouncementMessage, "buildAnnouncementMessage");
function buildExpiredMessage(username, expiry, appName) {
  let expiryDisplay;
  try {
    expiryDisplay = new Date(expiry).toUTCString().replace(" GMT", "");
  } catch {
    expiryDisplay = expiry || "\u2014";
  }
  return `@${username}

\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}
\u27BD: ${toBold(appName)} VIP :\u27BD
\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}

\u23F0 ${toBold("SUBSCRIPTION EXPIRED")} \u23F0

Your VIP access for ${appName} has expired.
Contact the group admin to renew your subscription.

\u251C ${toBold("Status")}     : \u274C  ${toBold("Expired")}  \u274C
\u2514 ${toBold("Expired On")} : \u{1F9ED}  ${expiryDisplay} \u{1F9ED}

\u{1F4E5} Send a message to the admin in the group to get renewed.

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796
\u{1F579} ${toBold("Activated By")} :

      \u9006\u8F6C X \u6A21\u7EC4

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796`;
}
__name(buildExpiredMessage, "buildExpiredMessage");
function buildActivationMessage(username, deviceId, expiry, appName, isResend) {
  const nameB = toBold(appName + " VIP");
  let expiryDisplay;
  if (!expiry || expiry === "2080" || expiry === "2099-12-31") {
    expiryDisplay = toBold("Lifetime") + " \u267E\uFE0F";
  } else if (expiry.includes("T") || expiry.endsWith("Z")) {
    try {
      expiryDisplay = new Date(expiry).toUTCString().replace(" GMT", "");
    } catch {
      expiryDisplay = expiry;
    }
  } else {
    expiryDisplay = expiry;
  }
  return `@${username}

\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}
\u27BD: ${nameB} :\u27BD
\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}

\u{1F98B} ${isResend ? toBold("ALREADY ACTIVE") + " \u{1F98B}" : toBold("DEVICE ACTIVATED") + " \u{1F98B}"}

Your device has been verified and activated successfully. Kindly close your app and open again \u{1F60A}

\u251C ${toBold("Status")} : \u2705  ${toBold("Active")}  \u2705

\u2514 ${toBold("Expiry")} : \u{1F9ED}  ${expiryDisplay} \u{1F9ED}

\u{1F4E5} Enjoy full VIP access with no restrictions.

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796
\u{1F579} ${toBold("Activated By")} :

      \u9006\u8F6C X \u6A21\u7EC4

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796`;
}
__name(buildActivationMessage, "buildActivationMessage");
function buildAdminHelp(apps) {
  const exApp = apps[0];
  const exCmd = exApp ? exApp.tg_command : "yourapp";
  const exAppId = exApp ? exApp.app_id : "yourapp";
  const cmds = apps.length ? apps.map(
    (a) => `\u2022 <code>/${a.tg_command} &lt;device_id&gt;</code>  \u2190 user self-registers
  <code>/${a.tg_command} &lt;user_id&gt; &lt;device_id&gt; [expiry]</code>  \u2190 admin force-activates
  \u21B3 Binds device to that user's Telegram ID \u2014 prevents sharing/cheating`
  ).join("\n\n") : "\u2022 <i>(no apps registered yet)</i>";
  const text = `\u{1F510} <b>\u{1D5E7}\u{1D5F2}\u{1D5F9}\u{1D5F2}\u{1D5E3}\u{1D5EE}\u{1D601} \u{1D5E3}\u{1D5EE}\u{1D5FB}\u{1D5F2}\u{1D5F9} \u2014 Admin Commands</b> \u{1F510}
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501

\u{1F195} <b>\u{1D5D4}\u{1D5E3}\u{1D5E3} \u{1D5D6}\u{1D5E2}\u{1D5E0}\u{1D5E0}\u{1D5D4}\u{1D5E1}\u{1D5D7}\u{1D5E6}</b>
${cmds}
  \u21B3 e.g. <code>/${exCmd} 79837377 RX-ABC123 30d</code>

\u{1F3C6} <b>\u{1D5D4}\u{1D5D6}\u{1D5E7}\u{1D5DC}\u{1D5E9}\u{1D5D4}\u{1D5E7}\u{1D5DC}\u{1D5E2}\u{1D5E1} / \u{1D5E5}\u{1D5D8}\u{1D5E1}\u{1D5D8}\u{1D5EA}\u{1D5D4}\u{1D5DF}</b>
\u2022 /activate &lt;app_id&gt; &lt;device_id&gt; &lt;username&gt; [expiry]
  \u21B3 <code>/activate ${exAppId} RX-ABC john 30d</code>
  \u21B3 <code>/activate ${exAppId} RX-ABC john 1mo</code>
  \u21B3 <code>/activate ${exAppId} RX-ABC john 2080</code> \u267E\uFE0F
\u2022 /renewall &lt;app_id&gt; [expiry] \u2014 bulk renew all users

\u{1F512} <b>\u{1D5D4}\u{1D5D6}\u{1D5D6}\u{1D5D8}\u{1D5E6}\u{1D5E6} \u{1D5D6}\u{1D5E2}\u{1D5E1}\u{1D5E7}\u{1D5E5}\u{1D5E2}\u{1D5DF}</b>
\u2022 /revoke &lt;app_id&gt; &lt;device_id&gt; \u2014 disable access
\u2022 /restore &lt;app_id&gt; &lt;device_id&gt; \u2014 re-enable access
\u2022 /delete &lt;app_id&gt; &lt;device_id&gt; \u2014 remove permanently

\u{1F50D} <b>\u{1D5DF}\u{1D5E2}\u{1D5E2}\u{1D5DE}\u{1D5E8}\u{1D5E3} &amp; \u{1D5DF}\u{1D5DC}\u{1D5E6}\u{1D5E7}\u{1D5E6}</b>
\u2022 /check &lt;device_id | @username&gt; [app_id]
\u2022 /list [app_id] \u2014 paginated device list
\u2022 /listall [app_id] \u2014 full list with details
\u2022 /pending [app_id] \u2014 pending requests
\u2022 /stats \u2014 system totals

\u{1F5C4}\uFE0F <b>\u{1D5D7}\u{1D5D4}\u{1D5E7}\u{1D5D4}\u{1D5D5}\u{1D5D4}\u{1D5E6}\u{1D5D8}</b>
\u2022 /clearapp [app_id] \u2014 wipe one app's users
\u2022 /clear_database \u2014 wipe ALL records (double confirm)

\u23F1 <i>Expiry: <code>30m</code> <code>2h</code> <code>7d</code> <code>2w</code> <code>1mo</code> <code>YYYY-MM-DD</code> <code>2080</code>=lifetime</i>`;
  const kb = { inline_keyboard: [
    [
      { text: "\u{1F4CA} Stats", callback_data: "cmd:stats" },
      { text: "\u23F3 Pending", callback_data: "cmd:pending" }
    ],
    [
      { text: "\u{1F4CB} List", callback_data: "cmd:list" },
      { text: "\u{1F4C2} List All", callback_data: "cmd:listall" }
    ]
  ] };
  return { text, kb };
}
__name(buildAdminHelp, "buildAdminHelp");
var FONT_LINK = `<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">`;
var BASE_STYLE = `*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{background:#07080D}body{font-family:'Inter',system-ui,sans-serif;background:#07080D;color:#CBD5E1;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;-webkit-font-smoothing:antialiased}.wrap{position:relative;width:100%;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.grid{position:fixed;inset:0;background-image:linear-gradient(rgba(201,0,0,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(201,0,0,0.04) 1px,transparent 1px);background-size:48px 48px;pointer-events:none;z-index:0}.glow{position:fixed;width:520px;height:520px;border-radius:50%;background:radial-gradient(circle,rgba(201,0,0,0.10) 0%,transparent 70%);top:-100px;left:50%;transform:translateX(-50%);pointer-events:none;z-index:0;animation:orbPulse 6s ease-in-out infinite}.card{background:rgba(11,14,24,0.96);border:2px solid rgba(201,0,0,0.16);border-radius:24px;padding:22px 22px 18px;width:100%;max-width:360px;text-align:center;position:relative;z-index:1;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);box-shadow:0 32px 80px rgba(0,0,0,0.6),0 0 0 1px rgba(255,255,255,0.02) inset;animation:fadeUp .5s ease,rainbow 5s linear .5s infinite}.card::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:55%;height:1px;background:linear-gradient(90deg,transparent,rgba(201,0,0,0.55),transparent)}.icon-wrap{position:relative;width:76px;height:76px;margin:0 auto 16px}.ring{position:absolute;inset:-9px;border-radius:50%;border:1px solid rgba(201,0,0,0.2);animation:spinSlow 12s linear infinite}.ring2{position:absolute;inset:-19px;border-radius:50%;border:1px dashed rgba(201,0,0,0.07);animation:spinSlow 24s linear infinite reverse}.icon-box{width:76px;height:76px;border-radius:22px;display:flex;align-items:center;justify-content:center}.label{font-size:10px;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;margin-bottom:6px;opacity:.7}h1{font-size:20px;font-weight:800;color:#F1F5F9;letter-spacing:-.4px;margin-bottom:8px;line-height:1.2}.sub{font-size:12.5px;color:#475569;line-height:1.6;margin-bottom:16px}.divider{display:flex;align-items:center;gap:10px;margin-bottom:14px}.div-line{flex:1;height:1px;background:#1E293B}.div-txt{font-size:9px;font-weight:700;letter-spacing:2px;color:#334155;text-transform:uppercase;white-space:nowrap}.devid-box{background:#0F172A;border:1.5px solid #1E293B;border-radius:12px;padding:10px 14px;margin-bottom:14px;text-align:left;overflow:hidden;cursor:pointer;transition:border-color .2s}.devid-box:active{border-color:rgba(201,0,0,0.35)}.devid-label{font-size:10px;color:#475569;font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:4px}.devid-val{font-size:11px;color:#94A3B8;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.3px;transition:color .3s}.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:13px;border:none;border-radius:13px;font-size:14px;font-weight:800;cursor:pointer;font-family:inherit;letter-spacing:.2px;text-decoration:none;transition:.2s;margin-bottom:8px;position:relative;overflow:hidden}.btn:active{transform:scale(.97)}.btn-red{background:linear-gradient(135deg,#c90000,#8b0000);color:#fff;box-shadow:0 4px 20px rgba(201,0,0,0.3)}.btn-red::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,0.08),transparent);opacity:0;transition:.2s}.btn-red:hover::after,.btn-red:active::after{opacity:1}.btn-red:disabled{opacity:.55;pointer-events:none}.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.3px;margin-bottom:14px}.badge-red{background:rgba(201,0,0,0.09);border:1px solid rgba(201,0,0,0.22);color:#c90000}.dot{width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}.footer{margin-top:14px;padding-top:12px;border-top:1px solid #0F172A;display:flex;align-items:center;justify-content:center;gap:6px}.f-dot{width:6px;height:6px;border-radius:50%;background:#c90000;animation:blink 1.4s ease-in-out infinite;flex-shrink:0}.f-txt{font-size:10px;color:#334155;font-weight:600;letter-spacing:.8px;text-transform:uppercase}.msg-box{margin-top:10px;padding:9px 14px;border-radius:10px;font-size:12px;font-weight:600;text-align:center;display:none;animation:fadeUp .3s ease}.msg-ok{background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.2);color:#4ade80}.msg-err{background:rgba(201,0,0,0.08);border:1px solid rgba(201,0,0,0.22);color:#ef4444}@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}@keyframes blink{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.2;transform:scale(.65)}}@keyframes spinSlow{to{transform:rotate(360deg)}}@keyframes orbPulse{0%,100%{opacity:.6;transform:translateX(-50%) scale(1)}50%{opacity:1;transform:translateX(-50%) scale(1.12)}}@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(201,0,0,0)}50%{box-shadow:0 0 0 14px rgba(201,0,0,0.08)}}@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-4px)}40%,80%{transform:translateX(4px)}}@keyframes scanMove{0%{transform:translateY(-13px);opacity:0}15%{opacity:.85}85%{opacity:.85}100%{transform:translateY(13px);opacity:0}}@keyframes rainbow{0%{border-color:rgba(255,0,80,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(255,0,80,.25),0 0 0 1px rgba(255,255,255,.02) inset}14%{border-color:rgba(255,145,0,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(255,145,0,.25),0 0 0 1px rgba(255,255,255,.02) inset}28%{border-color:rgba(255,230,0,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(255,230,0,.25),0 0 0 1px rgba(255,255,255,.02) inset}42%{border-color:rgba(0,220,90,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(0,220,90,.25),0 0 0 1px rgba(255,255,255,.02) inset}57%{border-color:rgba(0,185,255,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(0,185,255,.25),0 0 0 1px rgba(255,255,255,.02) inset}71%{border-color:rgba(110,0,255,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(110,0,255,.25),0 0 0 1px rgba(255,255,255,.02) inset}85%{border-color:rgba(225,0,255,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(225,0,255,.25),0 0 0 1px rgba(255,255,255,.02) inset}100%{border-color:rgba(255,0,80,.75);box-shadow:0 32px 80px rgba(0,0,0,.6),0 0 18px rgba(255,0,80,.25),0 0 0 1px rgba(255,255,255,.02) inset}}`;
var CONTACT = "https://t.me/+WxUQKQZFdTA2NGY8";
var TAMPER_HTML = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Security Alert</title>
${FONT_LINK}
<style>${BASE_STYLE}
.icon-box{background:linear-gradient(135deg,rgba(255,0,80,0.14),rgba(139,0,0,0.07));border:1.5px solid rgba(255,0,80,0.4);animation:shake 3.5s ease-in-out 1s infinite,pulse 3s ease-in-out infinite}
</style></head>
<body>
<div class="grid"></div><div class="glow" style="background:radial-gradient(circle,rgba(255,0,80,0.13) 0%,transparent 70%)"></div>
<div class="wrap"><div class="card" style="animation:fadeUp .4s ease,rainbow 5s linear .4s infinite">
  <div class="icon-wrap">
    <div class="ring"></div><div class="ring2"></div>
    <div class="icon-box">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#ff2255" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12.5"/>
        <circle cx="12" cy="16" r=".8" fill="#ff2255"/>
      </svg>
    </div>
  </div>
  <div class="label" style="color:#ff2255">Security Alert</div>
  <h1>Tampered Date &amp; Time</h1>
  <p class="sub">Your device clock has been rolled back. This is not allowed. Set your date and time to <b style="color:#f1f5f9">Automatic</b> to continue.</p>
  <div class="badge badge-red" style="margin:0 auto 14px"><div class="dot"></div>Clock Manipulation Detected</div>
  <button class="btn btn-red" onclick="fixDateTime()" style="background:linear-gradient(135deg,#c90000,#8b0000)">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
    Fix Date &amp; Time
  </button>
  <div class="footer" style="margin-top:12px">
    <div class="f-dot"></div>
    <span class="f-txt">Security Check Active</span>
    <div class="f-dot" style="animation-delay:.7s"></div>
  </div>
</div></div>
<script>
const IS_ANDROID = typeof window.REVERSAL_X !== "undefined";
function fixDateTime(){if(IS_ANDROID){try{window.REVERSAL_X.openDateSettings();}catch(e){}}}
<\/script>
</body></html>`;
function buildDialogHTML(deviceId, activationCode, workerUrl, appId, appName, command, groupLink, appSecret) {
  const _appId = appId || "";
  const _secret = appSecret || "";
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>VIP Activation</title>
${FONT_LINK}
<style>${BASE_STYLE}
.icon-box{background:linear-gradient(135deg,rgba(201,0,0,0.14),rgba(139,0,0,0.07));border:1.5px solid rgba(201,0,0,0.32);animation:pulse 3s ease-in-out infinite}
</style></head>
<body>
<div class="grid"></div><div class="glow"></div>
<div class="wrap"><div class="card">

  <div class="icon-wrap">
    <div class="ring"></div><div class="ring2"></div>
    <div class="icon-box">
      <svg width="38" height="38" viewBox="0 0 24 24" fill="none" overflow="visible">
        <path d="M12 2L4 5.8v5.2c0 5.3 3.5 10.2 8 11.5 4.5-1.3 8-6.2 8-11.5V5.8L12 2z"
          fill="rgba(201,0,0,0.13)" stroke="#c90000" stroke-width="1.6"
          stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="5.5" y1="11" x2="18.5" y2="11"
          class="scan-line" stroke="#c90000" stroke-width="1.8" stroke-linecap="round"/>
        <circle cx="12" cy="11.5" r="2.2" fill="none" stroke="#c90000" stroke-width="1.4"/>
      </svg>
    </div>
  </div>

  <div class="label" style="color:#c90000">Reversal X Mods${appName ? " \u2014 " + appName : ""}</div>
  <h1 id="dlgTitle">Activate ${appName || "VIP"} Access</h1>
  <p class="sub" id="dlgSub">Tap the code below to copy it, then paste it in our Telegram group. Your app unlocks <b style="color:#f1f5f9">automatically</b>.</p>

  <div id="stepsSection">
  <div class="divider">
    <div class="div-line"></div>
    <div class="div-txt">Step 1 \u2014 Copy your code</div>
    <div class="div-line"></div>
  </div>

  <div class="devid-box" id="devIdBox" onclick="copyId()">
    <div class="devid-label">Activation Code \u2014 tap to copy</div>
    <div class="devid-val" id="devIdVal">Generating code...</div>
  </div>

  ${command ? `
  <div class="divider" style="margin-top:10px">
    <div class="div-line"></div>
    <div class="div-txt">Step 2 \u2014 Send this in the group</div>
    <div class="div-line"></div>
  </div>
  <div class="devid-box" id="cmdBox" onclick="copyCmd()" style="margin-bottom:10px">
    <div class="devid-label">Full command \u2014 tap to copy &amp; paste</div>
    <div class="devid-val" id="cmdVal" style="font-size:11px;word-break:break-all">/${command} ${deviceId}</div>
  </div>` : ""}
  </div>

  <div class="badge badge-red" id="statusBadge" style="margin:0 auto 14px">
    <div class="dot" id="statusDot"></div>
    <span id="statusTxt">Waiting for activation...</span>
  </div>

  <a class="btn btn-red" id="dlgBtn" href="#" onclick="openLink('${groupLink || CONTACT}');return false;"
    style="justify-content:space-between;padding-left:14px;padding-right:14px;margin-bottom:8px">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
      stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 18v-6a9 9 0 0 1 18 0v6"/>
      <path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3z"/>
      <path d="M3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/>
    </svg>
    <span id="dlgBtnTxt">Go to Group</span>
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
      stroke="#fff" stroke-width="2.5" stroke-linecap="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  </a>

  <div class="msg-box" id="msgBox"></div>

  <div class="footer">
    <div class="f-dot"></div>
    <span class="f-txt">${appName || "Reversal X"} VIP Access</span>
    <div class="f-dot" style="animation-delay:.7s"></div>
  </div>
</div></div>

<script>
const IS_ANDROID = typeof window.REVERSAL_X !== "undefined";
const _APP_ID  = '${_appId}';
const _SECRET  = '${_secret}';
const _APP_CMD = '${command || ""}';
let _rawId = "${deviceId}";
let _polling = true;
const _EXPIRED_GATE = new URLSearchParams(window.location.search).get('expired')==='1';

(function init(){
  if(IS_ANDROID){try{const id=window.REVERSAL_X.getDeviceId();if(id){_rawId=id;}}catch(e){}}
  fetchToken(_rawId);
  if(_EXPIRED_GATE){_polling=false;setExpiredState();return;}
  pollActivation();
})();

async function fetchToken(rawId){
  try{
    let url="/api/vip/token?device_id="+rawId;
    if(_APP_ID) url+="&app_id="+_APP_ID;
    if(_SECRET) url+="&secret="+_SECRET;
    const r=await fetch(url,{cache:"no-store"});
    const d=await r.json();
    if(d.token){
      const full=rawId+"."+d.token;
      document.getElementById("devIdVal").textContent=full;
      const c=document.getElementById("cmdVal");
      if(c&&_APP_CMD) c.textContent="/"+_APP_CMD+" "+full;
      return;
    }
  }catch(e){}
  document.getElementById("devIdVal").textContent=rawId;
  const c=document.getElementById("cmdVal");
  if(c&&_APP_CMD) c.textContent="/"+_APP_CMD+" "+rawId;
}
function openLink(url){
  if(IS_ANDROID){try{window.REVERSAL_X.openUrl(url);return;}catch(e){}}
  window.open(url,'_blank');
}

async function pollActivation(){
  if(!_polling) return;
  try{
    const r=await fetch("/api/vip/check",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({device_id:_rawId,app_id:_APP_ID,secret:_SECRET}),cache:"no-store"
    });
    const d=await r.json();
    if(d.active){
      _polling=false;
      setStatus("Activated! Closing app dialog...","#4ade80","#4ade80");
      if(IS_ANDROID){try{window.REVERSAL_X.onActivated(d.expiry||"2080");}catch(e){}}
      return;
    }
    if(d.expired){
      _polling=false;
      setExpiredState();
      return;
    }
    setStatus("Waiting for activation...","","");
  }catch(e){setStatus("Checking...","","");}
  setTimeout(pollActivation,3000);
}

function setStatus(txt,color,dotColor){
  document.getElementById("statusTxt").textContent=txt;
  if(color) document.getElementById("statusBadge").style.color=color;
  if(dotColor) document.getElementById("statusDot").style.background=dotColor;
}

function setExpiredState(){
  const title=document.getElementById("dlgTitle");
  const sub=document.getElementById("dlgSub");
  const btnTxt=document.getElementById("dlgBtnTxt");
  const devLbl=document.querySelector('#devIdBox .devid-label');
  if(title) title.textContent="Subscription Expired";
  if(sub){ sub.innerHTML='Your VIP subscription has expired.<br>Copy your Device ID below and <b style="color:#f1f5f9">send it to admin</b> to renew your access.'; }
  document.querySelectorAll('.divider').forEach(el=>el.style.display='none');
  const cmdBox=document.getElementById('cmdBox');
  if(cmdBox) cmdBox.style.display='none';
  if(devLbl) devLbl.textContent='Your Device ID \u2014 tap to copy & send to admin';
  if(btnTxt) btnTxt.textContent='Chat Admin to Renew';
  setStatus('\u26A0 Subscription expired','#ff4444','#ff4444');
}

function copyId(){
  const val=document.getElementById("devIdVal");
  const id=val.textContent.trim();
  if(!id||id==="Generating code..."||id==="Loading..."){showMsg("Code still loading, please wait","err");return;}
  (navigator.clipboard?navigator.clipboard.writeText(id):Promise.reject())
    .then(ok).catch(()=>{
      const t=document.createElement("textarea");
      t.value=id;t.style.cssText="position:fixed;opacity:0";
      document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();ok();
    });
  function ok(){val.style.color="#4ade80";setTimeout(()=>val.style.color="",900);showMsg("Activation code copied!","ok");}
}

function copyCmd(){
  const val=document.getElementById("cmdVal");
  if(!val) return;
  const id=val.textContent.trim();
  if(!id||id.startsWith("/"+"Generating")){showMsg("Still loading, please wait","err");return;}
  (navigator.clipboard?navigator.clipboard.writeText(id):Promise.reject())
    .then(ok).catch(()=>{
      const t=document.createElement("textarea");
      t.value=id;t.style.cssText="position:fixed;opacity:0";
      document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();ok();
    });
  function ok(){val.style.color="#4ade80";setTimeout(()=>val.style.color="",900);showMsg("Command copied \u2014 paste it in the group!","ok");}
}

function showMsg(text,type){
  const b=document.getElementById("msgBox");
  b.textContent=text;b.className="msg-box msg-"+(type==="ok"?"ok":"err");b.style.display="block";
  clearTimeout(b._t);b._t=setTimeout(()=>b.style.display="none",3500);
}
<\/script>
</body></html>`;
}
__name(buildDialogHTML, "buildDialogHTML");
function buildDirectDialogHTML(deviceId, appId, appName, pkg, adminLink) {
  const _appId = appId || "";
  const _pkg = pkg || "";
  const _name = appName || "Matrix VIP";
  const _link = adminLink || "https://t.me/matrixxxxxxxxx";
  const DIRECT_STYLE = BASE_STYLE.replace(/rgba\(201,0,0,/g, "rgba(14,165,233,").replace(/#c90000/g, "#0ea5e9").replace(/#8b0000/g, "#0284c7");
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>${_name}</title>
${FONT_LINK}
<style>${DIRECT_STYLE}
.icon-box{background:linear-gradient(135deg,rgba(14,165,233,0.14),rgba(2,132,199,0.07));border:1.5px solid rgba(14,165,233,0.32);animation:pulse 3s ease-in-out infinite}
</style></head>
<body>
<div class="grid"></div><div class="glow" style="background:radial-gradient(circle,rgba(14,165,233,0.10) 0%,transparent 70%)"></div>
<div class="wrap"><div class="card" style="border-color:rgba(14,165,233,0.18)">

  <div class="icon-wrap">
    <div class="ring" style="border-color:rgba(14,165,233,0.22)"></div><div class="ring2" style="border-color:rgba(14,165,233,0.08)"></div>
    <div class="icon-box">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" overflow="visible">
        <rect x="3"  y="3"  width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="14" y="3"  width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="3"  y="14" width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="14" y="14" width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
      </svg>
    </div>
  </div>

  <div class="label" style="color:#0ea5e9">${_name}</div>
  <h1>${_name} VIP Access</h1>
  <p class="sub">Copy your Device ID below and send it to admin. Your app activates <b style="color:#f1f5f9">automatically</b> once registered \u2014 no commands needed.</p>

  <div class="divider">
    <div class="div-line"></div>
    <div class="div-txt">Your Device ID</div>
    <div class="div-line"></div>
  </div>

  <div class="devid-box" id="devIdBox" onclick="copyId()">
    <div class="devid-label">Device ID \u2014 tap to copy</div>
    <div class="devid-val" id="devIdVal">Loading...</div>
  </div>

  <div class="badge" id="statusBadge" style="margin:0 auto 14px;background:rgba(14,165,233,0.09);border:1px solid rgba(14,165,233,0.22);color:#0ea5e9">
    <div class="dot" id="statusDot" style="background:#0ea5e9"></div>
    <span id="statusTxt">Waiting for activation...</span>
  </div>

  <a class="btn btn-red" href="#" onclick="openLink('${_link}');return false;"
    style="justify-content:space-between;padding-left:14px;padding-right:14px;margin-bottom:8px;background:linear-gradient(135deg,#0ea5e9,#0284c7);box-shadow:0 4px 20px rgba(14,165,233,0.35)">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.64 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.55 1h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.54a16 16 0 0 0 6 6l.91-.91a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/>
    </svg>
    <span>Contact Admin</span>
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round"><polyline points="9 18 15 12 9 6"/></svg>
  </a>

  <div class="msg-box" id="msgBox"></div>

  <div class="footer">
    <div class="f-dot" style="background:#0ea5e9"></div>
    <span class="f-txt">${_name} VIP Access</span>
    <div class="f-dot" style="background:#0ea5e9;animation-delay:.7s"></div>
  </div>
</div></div>

<script>
const IS_ANDROID = typeof window.REVERSAL_X !== "undefined";
const _PKG = '${_pkg}';
let _rawId = "${deviceId}";
let _polling = true;

(function init(){
  if(IS_ANDROID){try{const id=window.REVERSAL_X.getDeviceId();if(id){_rawId=id;}}catch(e){}}
  document.getElementById("devIdVal").textContent = _rawId || "Loading...";
  pollActivation();
})();

function openLink(url){
  if(IS_ANDROID){try{window.REVERSAL_X.openUrl(url);return;}catch(e){}}
  window.open(url,'_blank');
}

async function pollActivation(){
  if(!_polling) return;
  try{
    const r=await fetch("/api/vip/check-direct",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({device_id:_rawId}),cache:"no-store"
    });
    const d=await r.json();
    if(d.active){
      _polling=false;
      setStatus("Activated! Closing...","#4ade80","#4ade80");
      if(IS_ANDROID){try{window.REVERSAL_X.onActivated(d.expiry||"2080");}catch(e){}}
      return;
    }
    if(d.expired){
      _polling=false;
      setExpiredState();
      return;
    }
    setStatus("Waiting for activation...","","");
  }catch(e){setStatus("Checking...","","");}
  setTimeout(pollActivation,3500);
}

function setStatus(txt,color,dotColor){
  document.getElementById("statusTxt").textContent=txt;
  if(color) document.getElementById("statusBadge").style.color=color;
  if(dotColor) document.getElementById("statusDot").style.background=dotColor;
}

function setExpiredState(){
  const title=document.getElementById("dlgTitle");
  if(title) title.textContent="Subscription Expired";
  setStatus("Subscription expired","#ff4444","#ff4444");
}

function copyId(){
  const val=document.getElementById("devIdVal");
  const id=val.textContent.trim();
  if(!id||id==="Loading..."){showMsg("ID still loading","err");return;}
  (navigator.clipboard?navigator.clipboard.writeText(id):Promise.reject())
    .then(ok).catch(()=>{
      const t=document.createElement("textarea");
      t.value=id;t.style.cssText="position:fixed;opacity:0";
      document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();ok();
    });
  function ok(){val.style.color="#4ade80";setTimeout(()=>val.style.color="",900);showMsg("Device ID copied!","ok");}
}

function showMsg(text,type){
  const b=document.getElementById("msgBox");
  b.textContent=text;b.className="msg-box msg-"+(type==="ok"?"ok":"err");b.style.display="block";
  clearTimeout(b._t);b._t=setTimeout(()=>b.style.display="none",3500);
}
<\/script>
</body></html>`;
}
__name(buildDirectDialogHTML, "buildDirectDialogHTML");
function buildMatrixDialogHTML(deviceId, workerUrl, appId, appName, groupLink, appSecret) {
  const _appId = appId || "";
  const _secret = appSecret || "";
  const _link = groupLink || "https://t.me/+WxUQKQZFdTA2NGY8";
  const MATRIX_STYLE = BASE_STYLE.replace(/rgba\(201,0,0,/g, "rgba(14,165,233,").replace(/#c90000/g, "#0ea5e9").replace(/#8b0000/g, "#0284c7");
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Matrix VIP</title>
${FONT_LINK}
<style>${MATRIX_STYLE}
.icon-box{background:linear-gradient(135deg,rgba(14,165,233,0.14),rgba(2,132,199,0.07));border:1.5px solid rgba(14,165,233,0.32);animation:pulse 3s ease-in-out infinite}
</style></head>
<body>
<div class="grid"></div><div class="glow" style="background:radial-gradient(circle,rgba(14,165,233,0.10) 0%,transparent 70%)"></div>
<div class="wrap"><div class="card" style="border-color:rgba(14,165,233,0.18)">

  <div class="icon-wrap">
    <div class="ring" style="border-color:rgba(14,165,233,0.22)"></div><div class="ring2" style="border-color:rgba(14,165,233,0.08)"></div>
    <div class="icon-box">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" overflow="visible">
        <rect x="3"  y="3"  width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="14" y="3"  width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="3"  y="14" width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
        <rect x="14" y="14" width="7" height="7" rx="1.5" fill="rgba(14,165,233,0.15)" stroke="#0ea5e9" stroke-width="1.6"/>
      </svg>
    </div>
  </div>

  <div class="label" style="color:#0ea5e9">Matrix</div>
  <h1>Matrix VIP Access</h1>
  <p class="sub">Copy your Device ID below and send it to admin directly. Your app activates <b style="color:#f1f5f9">automatically</b> once registered \u2014 no commands needed.</p>

  <div class="divider">
    <div class="div-line"></div>
    <div class="div-txt">Your Device ID</div>
    <div class="div-line"></div>
  </div>

  <div class="devid-box" id="devIdBox" onclick="copyId()">
    <div class="devid-label">Device ID \u2014 tap to copy</div>
    <div class="devid-val" id="devIdVal">Loading...</div>
  </div>

  <div class="badge" id="statusBadge" style="margin:0 auto 14px;background:rgba(14,165,233,0.09);border:1px solid rgba(14,165,233,0.22);color:#0ea5e9">
    <div class="dot" id="statusDot" style="background:#0ea5e9"></div>
    <span id="statusTxt">Waiting for activation...</span>
  </div>

  <a class="btn btn-red" href="#" onclick="openLink('${_link}');return false;"
    style="justify-content:space-between;padding-left:14px;padding-right:14px;margin-bottom:8px;background:linear-gradient(135deg,#0ea5e9,#0284c7);box-shadow:0 4px 20px rgba(14,165,233,0.35)">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
      stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.64 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.55 1h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.54a16 16 0 0 0 6 6l.91-.91a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/>
    </svg>
    <span>Contact Admin</span>
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
      stroke="#fff" stroke-width="2.5" stroke-linecap="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  </a>

  <div class="msg-box" id="msgBox"></div>

  <div class="footer">
    <div class="f-dot" style="background:#0ea5e9"></div>
    <span class="f-txt">Matrix VIP Access</span>
    <div class="f-dot" style="background:#0ea5e9;animation-delay:.7s"></div>
  </div>
</div></div>

<script>
const IS_ANDROID = typeof window.REVERSAL_X !== "undefined";
const _APP_ID = '${_appId}';
const _SECRET = '${_secret}';
let _rawId = "${deviceId}";
let _polling = true;

(function init(){
  if(IS_ANDROID){try{const id=window.REVERSAL_X.getDeviceId();if(id){_rawId=id;}}catch(e){}}
  document.getElementById("devIdVal").textContent = _rawId;
  pollActivation();
})();

function openLink(url){
  if(IS_ANDROID){try{window.REVERSAL_X.openUrl(url);return;}catch(e){}}
  window.open(url,'_blank');
}

async function pollActivation(){
  if(!_polling) return;
  try{
    const r=await fetch("/api/vip/check",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({device_id:_rawId,app_id:_APP_ID,secret:_SECRET}),cache:"no-store"
    });
    const d=await r.json();
    if(d.active){
      _polling=false;
      setStatus("Activated! Closing app dialog...","#4ade80","#4ade80");
      if(IS_ANDROID){try{window.REVERSAL_X.onActivated(d.expiry||"2080");}catch(e){}}
      return;
    }
    if(d.expired){
      _polling=false;
      setExpiredState();
      return;
    }
    setStatus("Waiting for activation...","","");
  }catch(e){setStatus("Checking...","","");}
  setTimeout(pollActivation,3000);
}

function setStatus(txt,color,dotColor){
  document.getElementById("statusTxt").textContent=txt;
  if(color) document.getElementById("statusBadge").style.color=color;
  if(dotColor) document.getElementById("statusDot").style.background=dotColor;
}

function setExpiredState(){
  const title=document.getElementById("dlgTitle");
  const sub=document.getElementById("dlgSub");
  const btnTxt=document.getElementById("dlgBtnTxt");
  const devLbl=document.querySelector('#devIdBox .devid-label');
  if(title) title.textContent="Subscription Expired";
  if(sub){ sub.innerHTML='Your VIP subscription has expired.<br>Copy your Device ID below and <b style="color:#f1f5f9">send it to admin</b> to renew your access.'; }
  document.querySelectorAll('.divider').forEach(el=>el.style.display='none');
  const cmdBox=document.getElementById('cmdBox');
  if(cmdBox) cmdBox.style.display='none';
  if(devLbl) devLbl.textContent='Your Device ID \u2014 tap to copy & send to admin';
  if(btnTxt) btnTxt.textContent='Chat Admin to Renew';
  setStatus('\u26A0 Subscription expired','#ff4444','#ff4444');
}

function copyId(){
  const val=document.getElementById("devIdVal");
  const id=val.textContent.trim();
  if(!id||id==="Loading..."){showMsg("ID still loading, please wait","err");return;}
  (navigator.clipboard?navigator.clipboard.writeText(id):Promise.reject())
    .then(ok).catch(()=>{
      const t=document.createElement("textarea");
      t.value=id;t.style.cssText="position:fixed;opacity:0";
      document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();ok();
    });
  function ok(){val.style.color="#4ade80";setTimeout(()=>val.style.color="",900);showMsg("Device ID copied!","ok");}
}

function showMsg(text,type){
  const b=document.getElementById("msgBox");
  b.textContent=text;b.className="msg-box msg-"+(type==="ok"?"ok":"err");b.style.display="block";
  clearTimeout(b._t);b._t=setTimeout(()=>b.style.display="none",3500);
}
<\/script>
</body></html>`;
}
__name(buildMatrixDialogHTML, "buildMatrixDialogHTML");
async function handleGroupLeave(user, env, token, groupId) {
  if (!user?.id) return;
  const userId = user.id;
  const uname = user.username ? `@${user.username}` : user.first_name || "User";
  const rows = (await env.DB.prepare(
    "SELECT app_id FROM app_activations WHERE telegram_user_id = ? AND is_active = 1"
  ).bind(userId).all()).results || [];
  if (!rows.length) return;
  await env.DB.prepare(
    "UPDATE app_activations SET is_active = 0 WHERE telegram_user_id = ? AND is_active = 1"
  ).bind(userId).run();
  const appNames = [...new Set(rows.map((r) => getAppById(r.app_id)?.display_name || r.app_id))].join(", ");
  const msg = `\u{1F6A8} <b>VIP ACCESS SUSPENDED</b>

\u{1F464} ${uname} just left the group \u{1F3C3}\u{1F4A8}

\u{1F4F1} App: <b>${escHtml(appNames)}</b>
\u26D4 Status: <b>REVOKED</b>

<i>Rejoining the group will restore access automatically.</i>`;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: groupId, text: msg, parse_mode: "HTML" })
    });
  } catch (_) {
  }
}
__name(handleGroupLeave, "handleGroupLeave");
async function handleGroupRejoin(user, env, token, groupId) {
  if (!user?.id) return;
  const userId = user.id;
  const uname = user.username ? `@${user.username}` : user.first_name || "User";
  const rows = (await env.DB.prepare(
    "SELECT app_id, device_id, expiry, is_active FROM app_activations WHERE telegram_user_id = ?"
  ).bind(userId).all()).results || [];
  if (!rows.length) return;
  await env.DB.prepare(
    "UPDATE app_activations SET is_active = 1 WHERE telegram_user_id = ?"
  ).bind(userId).run();
  const appNames = [...new Set(rows.map((r) => getAppById(r.app_id)?.display_name || r.app_id))].join(", ");
  const msg = `\u{1F513} <b>VIP ACCESS RESTORED!</b>

\u{1F31F} Welcome back, ${uname}!

\u{1F3AC} App: <b>${escHtml(appNames)}</b>

\u{1F7E2} Status: <b>ACTIVE</b>

Close the app completely and reopen it \u2014 everything is back to normal! \u{1F680}

\u{1F514} Friendly warning: Don't even think about leaving again \u{1F605}\u{1F510}
The moment you exit, your access goes with you. Stay in the group, stay blessed! \u{1F48E}`;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: groupId, text: msg, parse_mode: "HTML" })
    });
  } catch (_) {
  }
}
__name(handleGroupRejoin, "handleGroupRejoin");
async function handleTelegram(request, env) {
  const token = BOT_TOKEN;
  const groupId = await getGroupId(env);
  const adminIds = [853645999, 6794070314, 5646628093];
  if (!token) return ok();
  let update;
  try {
    update = await request.json();
  } catch {
    return ok();
  }
  if (update.callback_query) {
    await handleCallbackQuery(update.callback_query, env, token, groupId, adminIds);
    return ok();
  }
  if (update.chat_member) {
    const cm = update.chat_member;
    const newStatus = cm.new_chat_member?.status || "";
    const oldStatus = cm.old_chat_member?.status || "";
    const chatUser = cm.new_chat_member?.user;
    const joinChatId = cm.chat?.id;
    const rejoined = ["member", "administrator"].includes(newStatus) && ["left", "kicked", "banned"].includes(oldStatus);
    const left = ["left", "kicked", "banned"].includes(newStatus) && ["member", "administrator", "restricted"].includes(oldStatus);
    if (joinChatId === groupId && chatUser && !chatUser.is_bot) {
      if (rejoined) await handleGroupRejoin(chatUser, env, token, groupId);
      else if (left) await handleGroupLeave(chatUser, env, token, groupId);
    }
    return ok();
  }
  const msg = update.message;
  if (!msg) return ok();
  const chatId = msg.chat.id;
  const chatType = msg.chat.type;
  const from = msg.from;
  const fromId = from?.id;
  const username = from?.username || from?.first_name || "User";
  const text = (msg.text || "").trim();
  const isAdmin = adminIds.includes(fromId);
  if (msg.new_chat_members) return ok();
  if (!text) return ok();
  if (chatType === "private") {
    if (isAdmin) {
      if (text.startsWith("/")) {
        const parts = text.trim().split(/\s+/);
        const cmdRaw = parts[0].slice(1).toLowerCase().split("@")[0];
        const args = parts.slice(1);
        if (args.length >= 2 && /^\d+$/.test(args[0])) {
          const app = getAppByCommand(cmdRaw);
          if (app) {
            await handleAdminAppActivation(chatId, app, args[0], args[1], args[2] || null, env, token);
            return ok();
          }
        }
      }
      await handleAdminCommand(chatId, text, env, token, groupId, adminIds, fromId);
    } else {
      return ok();
    }
    return ok();
  }
  if (chatId !== groupId) return ok();
  if (isAdmin && /^\/(activate|revoke|restore|delete|list|listall|check|stats|help|pending|clearapp|renewall|clear_database)/i.test(text)) {
    await handleAdminCommand(chatId, text, env, token, groupId, adminIds, fromId);
    return ok();
  }
  const rxMatch = /^\/reversalx\s+(\S+)/i.exec(text);
  if (rxMatch) {
    const deviceArg = rxMatch[1].trim();
    const app = getAppByCommand("reversalx");
    if (!app) return ok();
    if (deviceArg.includes(".")) {
      await handleActivationRequest(chatId, deviceArg, username, fromId, app, env, token);
    } else {
      await handleUserRegistration(chatId, deviceArg, username, fromId, app, env, token, groupId);
    }
    return ok();
  }
  return ok();
}
__name(handleTelegram, "handleTelegram");
async function handleActivationRequest(chatId, rawInput, username, fromId, app, env, token) {
  if (!rawInput.includes(".")) {
    await sendMessage(
      token,
      chatId,
      `@${username}

\u26A0\uFE0F Invalid format.

Copy the full activation code directly from the app screen \u2014 do not modify it.

The code looks like: <code>abc123.def456</code>`,
      "HTML"
    );
    return;
  }
  const dotIdx = rawInput.lastIndexOf(".");
  const rawDeviceId = rawInput.substring(0, dotIdx);
  const tkn = rawInput.substring(dotIdx + 1);
  if (rawDeviceId.length < 8 || tkn.length < 8) {
    await sendMessage(token, chatId, `@${username}

\u26A0\uFE0F Invalid activation code. Copy it directly from the VIP screen inside the app.`);
    return;
  }
  if (fromId) {
    const expiredAct = await env.DB.prepare(
      "SELECT device_id, expiry FROM app_activations WHERE app_id=? AND telegram_user_id=?"
    ).bind(app.app_id, fromId).first();
    if (expiredAct && isExpired(expiredAct.expiry)) {
      if (expiredAct.device_id === rawDeviceId) {
        await sendMessage(token, chatId, buildExpiredMessage(username, expiredAct.expiry, app.display_name));
      } else {
        await sendMessage(
          token,
          chatId,
          `@${username}

\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}
\u27BD: ${toBold(app.display_name)} VIP :\u27BD
\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}

\u274C ${toBold("SUBSCRIPTION EXPIRED")} \u274C

Your account is already bound to ${app.display_name} but your subscription has expired. You cannot register a new device.

\u251C ${toBold("Linked Device")} : ${expiredAct.device_id.slice(0, 12)}\u2026
\u2514 ${toBold("Expired On")}   : \u{1F9ED}  ${fmtExpiry(expiredAct.expiry)} \u{1F9ED}

\u{1F4E5} Contact the admin to renew your existing subscription.

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796
\u{1F579} ${toBold("Activated By")} :

      \u9006\u8F6C X \u6A21\u7EC4

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796`
        );
      }
      return;
    }
  }
  const tokenRow = await env.DB.prepare(
    "SELECT device_id, created_at, used, app_id FROM vip_tokens WHERE token=?"
  ).bind(tkn).first();
  if (!tokenRow) {
    await sendMessage(
      token,
      chatId,
      `@${username}

\u26A0\uFE0F Invalid or expired activation code.

Open the VIP screen in the app again to get a fresh code (valid for 10 minutes).`
    );
    return;
  }
  if (tokenRow.used) {
    await sendMessage(
      token,
      chatId,
      `@${username}

\u26A0\uFE0F This code has already been used.

Open the VIP screen again to generate a new one.`
    );
    return;
  }
  if (Date.now() - tokenRow.created_at > 10 * 60 * 1e3) {
    await env.DB.prepare("DELETE FROM vip_tokens WHERE token=?").bind(tkn).run();
    await sendMessage(
      token,
      chatId,
      `@${username}

\u23F1\uFE0F Activation code expired.

Codes are valid for 10 minutes. Open the VIP screen again to get a fresh one.`
    );
    return;
  }
  if (tokenRow.device_id !== rawDeviceId) {
    await sendMessage(
      token,
      chatId,
      `@${username}

\u26A0\uFE0F Device ID mismatch.

This code belongs to a different device. Copy it directly from your own VIP screen.`
    );
    return;
  }
  await env.DB.prepare("UPDATE vip_tokens SET used=1 WHERE token=?").bind(tkn).run();
  const existingByUser = await env.DB.prepare(
    "SELECT device_id, expiry FROM app_activations WHERE app_id=? AND telegram_username=?"
  ).bind(app.app_id, username).first();
  if (existingByUser) {
    const exExpired = isExpired(existingByUser.expiry);
    if (existingByUser.device_id === rawDeviceId) {
      if (exExpired) {
        await sendMessage(token, chatId, buildExpiredMessage(username, existingByUser.expiry, app.display_name));
      } else {
        await sendMessage(token, chatId, buildActivationMessage(username, rawDeviceId, existingByUser.expiry, app.display_name, true));
      }
    } else {
      if (exExpired) {
        await sendMessage(
          token,
          chatId,
          `@${username}

\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}
\u27BD: ${toBold(app.display_name)} VIP :\u27BD
\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}

\u274C ${toBold("SUBSCRIPTION EXPIRED")} \u274C

Your account is already bound to ${app.display_name} but your subscription has expired. You cannot register a new device.

\u251C ${toBold("Linked Device")} : ${existingByUser.device_id.slice(0, 12)}\u2026
\u2514 ${toBold("Expired On")}   : \u{1F9ED}  ${fmtExpiry(existingByUser.expiry)} \u{1F9ED}

\u{1F4E5} Contact the admin to renew your existing subscription.

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796
\u{1F579} ${toBold("Activated By")} :

      \u9006\u8F6C X \u6A21\u7EC4

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796`
        );
      } else {
        await sendMessage(
          token,
          chatId,
          `@${username}

\u{1F4F1} Account Already Linked

Your Telegram account (@${username}) is already linked to a different device for ${app.display_name}.

Each account can only activate one device per app. Contact the admin if you need to switch devices.`
        );
      }
    }
    return;
  }
  const existingByDevice = await env.DB.prepare(
    "SELECT telegram_username FROM app_activations WHERE app_id=? AND device_id=?"
  ).bind(app.app_id, rawDeviceId).first();
  if (existingByDevice) {
    await sendMessage(
      token,
      chatId,
      `@${username}

Device Already Registered

This device is already linked to another account for ${app.display_name}.

Contact the admin if you need help.`
    );
    return;
  }
  const expiry = app.expiry_default || "2080";
  await env.DB.prepare(
    "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)"
  ).bind(app.app_id, rawDeviceId, username, fromId || 0, expiry, Date.now()).run();
  await sendMessage(token, chatId, buildActivationMessage(username, rawDeviceId, expiry, app.display_name, false));
}
__name(handleActivationRequest, "handleActivationRequest");
async function handleUserRegistration(chatId, deviceId, username, fromId, app, env, token, adminGroupId) {
  const clean = deviceId.trim();
  if (clean.length < 4) {
    await sendMessage(token, chatId, `@${username}

\u26A0\uFE0F Invalid device ID. Copy it directly from the VIP screen inside the app.`);
    return;
  }
  const existing = await env.DB.prepare(
    "SELECT is_active, expiry FROM app_activations WHERE app_id=? AND device_id=?"
  ).bind(app.app_id, clean).first();
  if (existing && existing.is_active && !isExpired(existing.expiry)) {
    await sendMessage(token, chatId, buildActivationMessage(username, clean, existing.expiry, app.display_name, true));
    return;
  }
  if (existing && isExpired(existing.expiry)) {
    await sendMessage(token, chatId, buildExpiredMessage(username, existing.expiry, app.display_name));
    return;
  }
  const existingByUser = await env.DB.prepare(
    "SELECT device_id, expiry FROM app_activations WHERE app_id=? AND telegram_username=? AND is_active=1"
  ).bind(app.app_id, username).first();
  if (existingByUser && !isExpired(existingByUser.expiry)) {
    if (existingByUser.device_id === clean) {
      await sendMessage(token, chatId, buildActivationMessage(username, clean, existingByUser.expiry, app.display_name, true));
    } else {
      await sendMessage(
        token,
        chatId,
        `@${username}

\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}
\u27BD: ${toBold(app.display_name)} VIP :\u27BD
\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}\u{1F3DC}

\u274C ${toBold("ALREADY ACTIVATED")} \u274C

Your Telegram account is already linked to ${app.display_name}.
${toBold("One account = one device per app.")} You cannot register a second device.

\u251C ${toBold("Linked Device")} : ${existingByUser.device_id.slice(0, 10)}\u2026
\u2514 ${toBold("Expiry")}        : ${fmtExpiry(existingByUser.expiry)}

Contact the admin if you need to switch devices.

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796
\u{1F579} ${toBold("Activated By")} :

      \u9006\u8F6C X \u6A21\u7EC4

\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796\u2796`
      );
    }
    return;
  }
  const expiry = parseExpiry(app.expiry_default || "2080");
  await env.DB.prepare(
    "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)"
  ).bind(app.app_id, clean, username, fromId || 0, expiry, Date.now()).run();
  await sendMessage(token, chatId, buildActivationMessage(username, clean, expiry, app.display_name, false));
}
__name(handleUserRegistration, "handleUserRegistration");
async function handleAdminAppActivation(chatId, app, userIdStr, deviceId, rawExpiry, env, token) {
  const userId = parseInt(userIdStr);
  const clean = deviceId.trim();
  if (!userId || isNaN(userId)) {
    await sendMessage(
      token,
      chatId,
      `\u26A0\uFE0F Invalid user ID. Provide their numeric Telegram ID:
<code>/${escHtml(app.tg_command)} 123456789 DEVICE_ID</code>`,
      "HTML"
    );
    return;
  }
  if (clean.length < 4) {
    await sendMessage(token, chatId, `\u26A0\uFE0F Device ID too short: <code>${escHtml(clean)}</code>`, "HTML");
    return;
  }
  const deviceBound = await env.DB.prepare(
    "SELECT telegram_username, telegram_user_id FROM app_activations WHERE app_id=? AND device_id=? AND is_active=1 AND telegram_user_id!=0 AND telegram_user_id!=?"
  ).bind(app.app_id, clean, userId).first();
  if (deviceBound) {
    await sendMessage(
      token,
      chatId,
      `\u26D4 <b>Device Already Bound to Another Account</b>

\u{1F4F1} Device: <code>${escHtml(clean)}</code>
\u{1F464} Already registered to: @${escHtml(deviceBound.telegram_username)} (<code>${deviceBound.telegram_user_id}</code>)

One device cannot be shared between two accounts.
Revoke the other user first, then re-activate.`,
      "HTML"
    );
    return;
  }
  const userOldDevice = await env.DB.prepare(
    "SELECT device_id FROM app_activations WHERE app_id=? AND telegram_user_id=? AND is_active=1 AND device_id!=?"
  ).bind(app.app_id, userId, clean).first();
  if (userOldDevice) {
    await env.DB.prepare(
      "UPDATE app_activations SET is_active=0 WHERE app_id=? AND device_id=?"
    ).bind(app.app_id, userOldDevice.device_id).run();
  }
  const [pending, prevRecord] = await Promise.all([
    env.DB.prepare("SELECT telegram_username FROM pending_activations WHERE telegram_user_id=? AND app_id=?").bind(userId, app.app_id).first(),
    env.DB.prepare("SELECT telegram_username FROM app_activations WHERE telegram_user_id=? AND app_id=? LIMIT 1").bind(userId, app.app_id).first()
  ]);
  const tgUser = pending?.telegram_username || prevRecord?.telegram_username || `user${userId}`;
  const expiry = rawExpiry ? parseExpiry(rawExpiry) : parseExpiry(app.expiry_default || "2080");
  await env.DB.prepare(
    "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)"
  ).bind(app.app_id, clean, tgUser, userId, expiry, Date.now()).run();
  await env.DB.prepare(
    "DELETE FROM pending_activations WHERE telegram_user_id=? AND app_id=?"
  ).bind(userId, app.app_id).run();
  await sendMessage(token, chatId, buildActivationMessage(tgUser, clean, expiry, app.display_name, false));
  if (userOldDevice) {
    await sendMessage(
      token,
      chatId,
      `\u{1F504} <i>Note: old device <code>${escHtml(userOldDevice.device_id.slice(0, 14))}\u2026</code> has been deactivated for this account.</i>`,
      "HTML"
    );
  }
}
__name(handleAdminAppActivation, "handleAdminAppActivation");
async function handleCallbackQuery(cb, env, token, groupId, adminIds) {
  const data = cb.data || "";
  const chatId = cb.message?.chat?.id;
  const msgId = cb.message?.message_id;
  const fromId = cb.from?.id;
  if (!adminIds.includes(fromId)) {
    await answerCallback(token, cb.id, "\u26D4 Admin only.");
    return;
  }
  if (data === "noop") {
    await answerCallback(token, cb.id);
    return;
  }
  const lsM = /^ls:([^:]+):(\d+)$/.exec(data);
  if (lsM) {
    await answerCallback(token, cb.id, `Loading page ${lsM[2]}...`);
    await sendDeviceList(token, chatId, lsM[1], parseInt(lsM[2]), env, msgId, false);
    return;
  }
  const lsaM = /^lsa:([^:]+):(\d+)$/.exec(data);
  if (lsaM) {
    await answerCallback(token, cb.id, `Loading page ${lsaM[2]}...`);
    await sendDeviceList(token, chatId, lsaM[1], parseInt(lsaM[2]), env, msgId, true);
    return;
  }
  const ckM = /^ck:([^|]+)\|(.+)$/.exec(data);
  if (ckM) {
    await sendCheckInfo(token, chatId, ckM[1], ckM[2], env, msgId);
    await answerCallback(token, cb.id, "\u{1F50D} Refreshed");
    return;
  }
  const rvM = /^rv:([^|]+)\|(.+)$/.exec(data);
  if (rvM) {
    try {
      await env.DB.prepare("UPDATE app_activations SET is_active=0 WHERE app_id=? AND device_id=?").bind(rvM[1], rvM[2]).run();
      await answerCallback(token, cb.id, "\u26D4 Revoked");
      await sendCheckInfo(token, chatId, rvM[1], rvM[2], env, msgId);
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  const rsM = /^rs:([^|]+)\|(.+)$/.exec(data);
  if (rsM) {
    try {
      await env.DB.prepare("UPDATE app_activations SET is_active=1 WHERE app_id=? AND device_id=?").bind(rsM[1], rsM[2]).run();
      await answerCallback(token, cb.id, "\u2705 Restored");
      await sendCheckInfo(token, chatId, rsM[1], rsM[2], env, msgId);
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  const dlM = /^dl:([^|]+)\|(.+)$/.exec(data);
  if (dlM) {
    try {
      const row = await env.DB.prepare("SELECT telegram_username FROM app_activations WHERE app_id=? AND device_id=?").bind(dlM[1], dlM[2]).first();
      if (!row) {
        await answerCallback(token, cb.id, "Not found");
        return;
      }
      const kb = { inline_keyboard: [[
        { text: "\u2705 Yes, Delete", callback_data: `dlc:${dlM[1]}|${dlM[2]}` },
        { text: "\u274C Cancel", callback_data: `ck:${dlM[1]}|${dlM[2]}` }
      ]] };
      await editMessageText(token, chatId, msgId, `\u{1F5D1}\uFE0F <b>CONFIRM DELETE</b>

\u{1F464} @${row.telegram_username}
\u{1F4F1} <code>${dlM[2]}</code>
\u{1F4E6} App: ${dlM[1]}

\u26A0\uFE0F <b>This cannot be undone.</b>`, "HTML", kb);
      await answerCallback(token, cb.id, "\u26A0\uFE0F Confirm deletion");
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  const dlcM = /^dlc:([^|]+)\|(.+)$/.exec(data);
  if (dlcM) {
    try {
      await env.DB.prepare("DELETE FROM app_activations WHERE app_id=? AND device_id=?").bind(dlcM[1], dlcM[2]).run();
      await editMessageText(token, chatId, msgId, `\u{1F5D1}\uFE0F <b>DEVICE DELETED</b>

\u{1F4E6} App: ${dlcM[1]}
\u{1F4F1} <code>${dlcM[2]}</code>

\u{1F480} <i>Permanently removed.</i>`, "HTML");
      await answerCallback(token, cb.id, "\u{1F5D1}\uFE0F Deleted");
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  const caM = /^clearapp:select:(.+)$/.exec(data);
  if (caM) {
    try {
      const appId = caM[1];
      const app = getAppById(appId);
      const name = app ? app.display_name : appId;
      const count = (await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE app_id=?").bind(appId).first())?.c || 0;
      const kb = { inline_keyboard: [[
        { text: `\u2705 Yes, Clear "${name}"`, callback_data: `clearapp:confirm:${appId}` },
        { text: "\u274C Cancel", callback_data: "clearapp:cancel" }
      ]] };
      await editMessageText(
        token,
        chatId,
        msgId,
        `\u{1F5D1}\uFE0F <b>CONFIRM CLEAR APP DATA</b>

\u{1F4E6} App: <b>${escHtml(name)}</b>
\u{1F4F1} <code>${escHtml(appId)}</code>
\u{1F465} Users: <b>${count}</b>

\u26A0\uFE0F <b>This deletes ALL users and tokens for this app only. Other apps are untouched. This cannot be undone.</b>`,
        "HTML",
        kb
      );
      await answerCallback(token, cb.id, "\u26A0\uFE0F Confirm to proceed");
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  const cacM = /^clearapp:confirm:(.+)$/.exec(data);
  if (cacM) {
    try {
      const appId = cacM[1];
      const app = getAppById(appId);
      const name = app ? app.display_name : appId;
      const r1 = await env.DB.prepare("DELETE FROM app_activations WHERE app_id=?").bind(appId).run();
      const r2 = await env.DB.prepare("DELETE FROM vip_tokens WHERE app_id=?").bind(appId).run();
      await editMessageText(
        token,
        chatId,
        msgId,
        `\u2705 <b>APP DATA CLEARED</b>

\u{1F4E6} App: <b>${escHtml(name)}</b>
\u{1F465} Users removed: <b>${r1.changes || 0}</b>
\u{1F511} Tokens removed: <b>${r2.changes || 0}</b>

\u2714\uFE0F All other apps are untouched.`,
        "HTML"
      );
      await answerCallback(token, cb.id, "\u2705 Cleared!");
    } catch (e) {
      await answerCallback(token, cb.id, `Error: ${e.message}`);
    }
    return;
  }
  if (data === "clearapp:cancel") {
    await editMessageText(token, chatId, msgId, "\u274C <b>Cancelled.</b> No data was changed.", "HTML");
    await answerCallback(token, cb.id, "Cancelled");
    return;
  }
  if (data === "cmd:stats") {
    await answerCallback(token, cb.id, "Loading stats\u2026");
    await handleAdminCommand(chatId, "/stats", env, token, groupId, adminIds, fromId);
    return;
  }
  if (data === "cmd:pending") {
    await answerCallback(token, cb.id, "Loading pending\u2026");
    await handleAdminCommand(chatId, "/pending", env, token, groupId, adminIds, fromId);
    return;
  }
  if (data === "cmd:list") {
    await answerCallback(token, cb.id, "Loading users\u2026");
    await handleAdminCommand(chatId, "/list", env, token, groupId, adminIds, fromId);
    return;
  }
  if (data === "cmd:listall") {
    await answerCallback(token, cb.id, "Loading full list\u2026");
    await handleAdminCommand(chatId, "/listall", env, token, groupId, adminIds, fromId);
    return;
  }
  if (data === "cmd:help") {
    await answerCallback(token, cb.id, "Loading commands\u2026");
    await handleAdminCommand(chatId, "/help", env, token, groupId, adminIds, fromId);
    return;
  }
  if (data === "clrdb:confirm") {
    const kb = { inline_keyboard: [[
      { text: "\u{1F480} WIPE DATABASE", callback_data: "clrdb:yes" },
      { text: "\u274C Cancel", callback_data: "clrdb:no" }
    ]] };
    await editMessageText(
      token,
      chatId,
      msgId,
      `\u2620\uFE0F <b>FINAL WARNING</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F480} You are about to <b>wipe the entire database</b>.

This action is <b>irreversible</b>. All users across every app will lose access instantly.

Press <b>WIPE DATABASE</b> to confirm.`,
      "HTML",
      kb
    );
    await answerCallback(token, cb.id, "\u26A0\uFE0F Final confirmation required");
    return;
  }
  if (data === "clrdb:yes") {
    try {
      const [c1, c2, c3, c4] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) as n FROM app_activations").first(),
        env.DB.prepare("SELECT COUNT(*) as n FROM vip_tokens").first(),
        env.DB.prepare("SELECT COUNT(*) as n FROM activations").first(),
        env.DB.prepare("SELECT COUNT(*) as n FROM pending_activations").first()
      ]);
      const users = (c1?.n ?? 0) + (c3?.n ?? 0);
      const tokens = c2?.n ?? 0;
      const pending = c4?.n ?? 0;
      const total = users + tokens + pending;
      await Promise.all([
        env.DB.prepare("DELETE FROM app_activations").run(),
        env.DB.prepare("DELETE FROM activations").run(),
        env.DB.prepare("DELETE FROM vip_tokens").run(),
        env.DB.prepare("DELETE FROM pending_activations").run()
      ]);
      await editMessageText(
        token,
        chatId,
        msgId,
        `\u{1F5D1}\uFE0F <b>DATABASE WIPED</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F480} <b>${total}</b> total record(s) permanently deleted.

\u{1F465} Users removed: <b>${users}</b>
\u{1F511} Tokens removed: <b>${tokens}</b>
\u23F3 Pending removed: <b>${pending}</b>

The database is now empty. All users must re-activate.`,
        "HTML"
      );
      await answerCallback(token, cb.id, "\u2705 Database cleared");
    } catch (e) {
      await answerCallback(token, cb.id, `\u274C Error: ${e.message}`);
    }
    return;
  }
  if (data === "clrdb:no") {
    await editMessageText(
      token,
      chatId,
      msgId,
      `\u274C <b>Cancelled</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
No changes were made. The database is intact.`,
      "HTML"
    );
    await answerCallback(token, cb.id, "\u274C Cancelled");
    return;
  }
  await answerCallback(token, cb.id);
}
__name(handleCallbackQuery, "handleCallbackQuery");
async function sendCheckInfo(token, chatId, appId, deviceId, env, msgIdToEdit) {
  try {
    let row;
    if (deviceId.startsWith("@")) {
      const uname = deviceId.replace("@", "");
      row = appId === "all" ? await env.DB.prepare("SELECT * FROM app_activations WHERE telegram_username=? ORDER BY created_at DESC").bind(uname).first() : await env.DB.prepare("SELECT * FROM app_activations WHERE app_id=? AND telegram_username=?").bind(appId, uname).first();
    } else {
      row = appId === "all" ? await env.DB.prepare("SELECT * FROM app_activations WHERE device_id=? ORDER BY created_at DESC").bind(deviceId).first() : await env.DB.prepare("SELECT * FROM app_activations WHERE app_id=? AND device_id=?").bind(appId, deviceId).first();
    }
    if (!row) {
      const t = `\u274C <b>Not found:</b> <code>${escHtml(deviceId)}</code>${appId !== "all" ? ` in app <b>${escHtml(appId)}</b>` : ""}`;
      if (msgIdToEdit) await editMessageText(token, chatId, msgIdToEdit, t, "HTML");
      else await sendMessage(token, chatId, t, "HTML");
      return;
    }
    const status = statusBadge(row.is_active, row.expiry);
    const kb = deviceKb(row.device_id, row.app_id, row.is_active);
    const txt = `\u{1F50D} <b>DEVICE INFO</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} App: <b>${escHtml(row.app_id)}</b>
\u{1F464} User: @${escHtml(row.telegram_username || "N/A")}
\u{1F4F1} Device: <code>${escHtml(row.device_id)}</code>
\u{1F4C5} Expiry: <b>${fmtExpiry(row.expiry)}</b>
\u{1F3F7}\uFE0F Status: <b>${status}</b>
\u{1F5D3}\uFE0F Since: ${row.created_at ? new Date(row.created_at).toLocaleDateString("en-GB") : "N/A"}`;
    if (msgIdToEdit) await editMessageText(token, chatId, msgIdToEdit, txt, "HTML", kb);
    else await sendMessageKeyboard(token, chatId, txt, "HTML", kb);
  } catch (e) {
    await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
  }
}
__name(sendCheckInfo, "sendCheckInfo");
async function sendDeviceList(token, chatId, appId, page, env, msgIdToEdit, detailed = false) {
  const limit = 10;
  const offset = (page - 1) * limit;
  const prefix = detailed ? "lsa" : "ls";
  try {
    const query = appId === "all" ? await env.DB.prepare("SELECT * FROM app_activations ORDER BY created_at DESC LIMIT ? OFFSET ?").bind(limit, offset).all() : await env.DB.prepare("SELECT * FROM app_activations WHERE app_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?").bind(appId, limit, offset).all();
    const countQ = appId === "all" ? await env.DB.prepare("SELECT COUNT(*) as total FROM app_activations").first() : await env.DB.prepare("SELECT COUNT(*) as total FROM app_activations WHERE app_id=?").bind(appId).first();
    const total = countQ?.total || 0;
    const pages = Math.ceil(total / limit) || 1;
    const results = query.results || [];
    if (!results.length) {
      const t = "\u{1F4CB} No activations found.";
      if (msgIdToEdit) await editMessageText(token, chatId, msgIdToEdit, t);
      else await sendMessage(token, chatId, t);
      return;
    }
    const title = detailed ? `\u{1F4C2} <b>ALL ACTIVATIONS${appId !== "all" ? ` \u2014 ${escHtml(appId)}` : ""}</b>` : `\u{1F4CB} <b>DEVICES${appId !== "all" ? ` \u2014 ${escHtml(appId)}` : ""}</b>`;
    let msg = `${title}  (Page ${page}/${pages} \xB7 Total: ${total})
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501

`;
    results.forEach((r, i) => {
      const st = statusBadge(r.is_active, r.expiry);
      const date = r.created_at ? new Date(r.created_at).toLocaleDateString("en-GB") : "N/A";
      if (detailed) {
        msg += `<b>${offset + i + 1}.</b> @${escHtml(r.telegram_username || "N/A")} [${escHtml(r.app_id)}] \u2014 ${st}
<code>${escHtml(r.device_id)}</code>
\u{1F4C5} ${fmtExpiry(r.expiry)} \xB7 \u{1F5D3}\uFE0F ${date}

`;
      } else {
        msg += `<b>${offset + i + 1}.</b> @${escHtml(r.telegram_username || "N/A")} [${escHtml(r.app_id)}] \u2014 ${st}
<code>${escHtml(r.device_id)}</code> \xB7 ${fmtExpiry(r.expiry)}

`;
      }
    });
    const navRow = [];
    if (page > 1) navRow.push({ text: "\u25C0 Prev", callback_data: `${prefix}:${appId}:${page - 1}` });
    navRow.push({ text: `${page} / ${pages}`, callback_data: "noop" });
    if (page < pages) navRow.push({ text: "Next \u25B6", callback_data: `${prefix}:${appId}:${page + 1}` });
    const toggleRow = detailed ? [{ text: "\u{1F4CB} Basic List", callback_data: `ls:${appId}:1` }] : [{ text: "\u{1F4C2} Detailed List", callback_data: `lsa:${appId}:1` }];
    const kb = { inline_keyboard: [navRow, toggleRow] };
    if (msgIdToEdit) await editMessageText(token, chatId, msgIdToEdit, msg, "HTML", kb);
    else await sendMessageKeyboard(token, chatId, msg, "HTML", kb);
  } catch (e) {
    await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
  }
}
__name(sendDeviceList, "sendDeviceList");
async function handleAdminCommand(chatId, text, env, token, groupId, adminIds, fromId) {
  if (/^\/start/i.test(text)) {
    const kb = { inline_keyboard: [
      [
        { text: "\u{1F4CA} Stats", callback_data: "cmd:stats" },
        { text: "\u23F3 Pending", callback_data: "cmd:pending" }
      ],
      [
        { text: "\u{1F4CB} List Users", callback_data: "cmd:list" },
        { text: "\u{1F4C2} List All", callback_data: "cmd:listall" }
      ],
      [
        { text: "\u{1F4D6} Commands", callback_data: "cmd:help" }
      ]
    ] };
    await sendMessageKeyboard(
      token,
      chatId,
      `\u{1F510} <b>\u{1D5E7}\u{1D5F2}\u{1D5F9}\u{1D5F2}\u{1D5E3}\u{1D5EE}\u{1D601} \u{1D5E3}\u{1D5EE}\u{1D5FB}\u{1D5F2}\u{1D5F9}</b> \u{1F510}
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501

\u{1F44B} Welcome back, admin!

Use the quick buttons below or type any command directly.`,
      "HTML",
      kb
    );
    return;
  }
  if (/^\/help/i.test(text)) {
    const apps2 = getAllApps();
    const { text: helpText2, kb: helpKb2 } = buildAdminHelp(apps2);
    await sendMessageKeyboard(token, chatId, helpText2, "HTML", helpKb2);
    return;
  }
  const actM = /^\/activate\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/i.exec(text);
  if (actM) {
    const [, appId, deviceId, tgUser, rawExp = "2080"] = actM;
    const expiry = parseExpiry(rawExp);
    try {
      const existing = await env.DB.prepare("SELECT device_id FROM app_activations WHERE app_id=? AND telegram_username=?").bind(appId, tgUser).first();
      if (existing) {
        await env.DB.prepare("UPDATE app_activations SET device_id=?, expiry=?, is_active=1, created_at=? WHERE app_id=? AND telegram_username=?").bind(deviceId, expiry, Date.now(), appId, tgUser).run();
      } else {
        await env.DB.prepare("INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)").bind(appId, deviceId, tgUser, 0, expiry, Date.now()).run();
      }
      const kb = deviceKb(deviceId, appId, true);
      await sendMessageKeyboard(
        token,
        chatId,
        `\u{1F3C6} <b>ACTIVATED</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} App: <b>${appId}</b>
\u{1F464} User: @${tgUser}
\u{1F4F1} Device: <code>${deviceId}</code>
\u{1F4C5} Expiry: <b>${fmtExpiry(expiry)}</b>
\u2705 Status: <b>Active</b>`,
        "HTML",
        kb
      );
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  const rvM = /^\/revoke\s+(\S+)\s+(\S+)/i.exec(text);
  if (rvM) {
    try {
      await env.DB.prepare("UPDATE app_activations SET is_active=0 WHERE app_id=? AND device_id=?").bind(rvM[1], rvM[2]).run();
      await sendMessageKeyboard(
        token,
        chatId,
        `\u26D4 <b>REVOKED</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} App: <b>${rvM[1]}</b>
\u{1F4F1} Device: <code>${rvM[2]}</code>`,
        "HTML",
        deviceKb(rvM[2], rvM[1], false)
      );
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  const rsM = /^\/restore\s+(\S+)\s+(\S+)/i.exec(text);
  if (rsM) {
    try {
      await env.DB.prepare("UPDATE app_activations SET is_active=1 WHERE app_id=? AND device_id=?").bind(rsM[1], rsM[2]).run();
      await sendMessageKeyboard(
        token,
        chatId,
        `\u2705 <b>RESTORED</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} App: <b>${rsM[1]}</b>
\u{1F4F1} Device: <code>${rsM[2]}</code>`,
        "HTML",
        deviceKb(rsM[2], rsM[1], true)
      );
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  const dlM = /^\/delete\s+(\S+)\s+(\S+)/i.exec(text);
  if (dlM) {
    try {
      await env.DB.prepare("DELETE FROM app_activations WHERE app_id=? AND device_id=?").bind(dlM[1], dlM[2]).run();
      await sendMessage(token, chatId, `\u{1F5D1}\uFE0F <b>DELETED</b>
\u{1F4E6} App: <b>${dlM[1]}</b>
\u{1F4F1} <code>${dlM[2]}</code>`, "HTML");
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  const raM = /^\/renewall\s+(\S+)(?:\s+(\S+))?/i.exec(text);
  if (raM) {
    const [, appId, rawExp] = raM;
    const app = getAppById(appId);
    if (!app) {
      await sendMessage(token, chatId, `\u274C App <code>${escHtml(appId)}</code> not found.`, "HTML");
      return;
    }
    const expiry = parseExpiry(rawExp || app.expiry_default || "2080");
    try {
      const result = await env.DB.prepare(
        "UPDATE app_activations SET expiry=?, is_active=1 WHERE app_id=? AND is_active=1"
      ).bind(expiry, appId).run();
      const count = result.changes || 0;
      await sendMessage(
        token,
        chatId,
        `\u{1F504} <b>BULK RENEW COMPLETE</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} App: <b>${escHtml(app.display_name)}</b>
\u{1F465} Users renewed: <b>${count}</b>
\u{1F4C5} New expiry: <b>${fmtExpiry(expiry)}</b>
\u2705 All active users have been extended.`,
        "HTML"
      );
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  const ckM = /^\/check\s+(\S+)(?:\s+(\S+))?/i.exec(text);
  if (ckM) {
    const [, deviceId, appId = "all"] = ckM;
    await sendCheckInfo(token, chatId, appId, deviceId, env, null);
    return;
  }
  if (/^\/list(?!all)/i.test(text)) {
    const parts = text.split(/\s+/);
    const appId = parts[1] || "all";
    await sendDeviceList(token, chatId, appId, 1, env, null, false);
    return;
  }
  if (/^\/listall/i.test(text)) {
    const parts = text.split(/\s+/);
    const appId = parts[1] || "all";
    await sendDeviceList(token, chatId, appId, 1, env, null, true);
    return;
  }
  if (/^\/pending/i.test(text)) {
    const parts = text.split(/\s+/);
    const filterApp = parts[1] || null;
    try {
      const rows = filterApp ? (await env.DB.prepare("SELECT * FROM pending_activations WHERE app_id=? ORDER BY created_at DESC LIMIT 30").bind(filterApp).all()).results || [] : (await env.DB.prepare("SELECT * FROM pending_activations ORDER BY created_at DESC LIMIT 30").all()).results || [];
      if (!rows.length) {
        await sendMessage(token, chatId, `\u{1F4ED} <b>No pending requests${filterApp ? ` for ${escHtml(filterApp)}` : ""}</b>`, "HTML");
        return;
      }
      const cmdMap = {};
      for (const a of getAllApps()) cmdMap[a.app_id] = a.tg_command || a.app_id;
      let msg = `\u23F3 <b>PENDING REQUESTS</b> (${rows.length})
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501

`;
      for (const r of rows) {
        const age = Math.floor((Date.now() - r.created_at) / 6e4);
        const cmd = cmdMap[r.app_id] || r.app_id;
        msg += `\u{1F464} @${escHtml(r.telegram_username)} (<code>${r.telegram_user_id}</code>)
`;
        msg += `\u{1F4E6} App: <b>${escHtml(r.app_id)}</b>
`;
        msg += `\u{1F4F1} Device: <code>${escHtml(r.device_id)}</code>
`;
        msg += `\u{1F550} ${age}m ago
`;
        msg += `\u25B6 Tap to activate:
<code>/${escHtml(cmd)} ${r.telegram_user_id} ${escHtml(r.device_id)}</code>

`;
      }
      await sendMessage(token, chatId, msg, "HTML");
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  if (/^\/clearapp/i.test(text)) {
    try {
      const parts = text.split(/\s+/);
      const directAppId = parts[1] || null;
      const apps2 = getAllApps();
      if (!apps2.length) {
        await sendMessage(token, chatId, "\u{1F4ED} <b>No apps registered yet.</b>", "HTML");
        return;
      }
      if (directAppId) {
        const app = apps2.find((a) => a.app_id === directAppId);
        const name = app ? app.display_name : directAppId;
        const count = (await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE app_id=?").bind(directAppId).first())?.c || 0;
        const kb = { inline_keyboard: [[
          { text: `\u2705 Yes, Clear "${name}"`, callback_data: `clearapp:confirm:${directAppId}` },
          { text: "\u274C Cancel", callback_data: "clearapp:cancel" }
        ]] };
        await sendMessage(
          token,
          chatId,
          `\u{1F5D1}\uFE0F <b>CONFIRM CLEAR APP DATA</b>

\u{1F4E6} App: <b>${escHtml(name)}</b>
\u{1F4F1} <code>${escHtml(directAppId)}</code>
\u{1F465} Users: <b>${count}</b>

\u26A0\uFE0F <b>This deletes ALL users and tokens for this app only. Other apps are untouched.</b>`,
          "HTML",
          kb
        );
        return;
      }
      const rows = apps2.map((a) => [{ text: `\u{1F4E6} ${a.display_name}`, callback_data: `clearapp:select:${a.app_id}` }]);
      rows.push([{ text: "\u274C Cancel", callback_data: "clearapp:cancel" }]);
      await sendMessage(
        token,
        chatId,
        `\u{1F5D1}\uFE0F <b>CLEAR APP DATA</b>

Select which app to clear.
Only that app's users and tokens will be deleted \u2014 all other apps remain untouched.`,
        "HTML",
        { inline_keyboard: rows }
      );
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  if (/^\/stats/i.test(text)) {
    try {
      const all = (await env.DB.prepare("SELECT is_active, expiry, app_id FROM app_activations").all()).results || [];
      let active = 0, expired = 0, revoked = 0;
      const byApp = {};
      for (const r of all) {
        if (!byApp[r.app_id]) byApp[r.app_id] = { active: 0, expired: 0, revoked: 0 };
        if (!r.is_active) {
          revoked++;
          byApp[r.app_id].revoked++;
        } else if (isExpired(r.expiry)) {
          expired++;
          byApp[r.app_id].expired++;
        } else {
          active++;
          byApp[r.app_id].active++;
        }
      }
      let msg = `\u{1F4CA} <b>VIP SYSTEM STATS</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u{1F4E6} Total:   <b>${all.length}</b>
\u2705 Active:  <b>${active}</b>
\u23F0 Expired: <b>${expired}</b>
\u26D4 Revoked: <b>${revoked}</b>`;
      if (Object.keys(byApp).length) {
        msg += "\n\n<b>Per App:</b>\n";
        for (const [aid, s] of Object.entries(byApp)) {
          msg += `\u2022 <b>${escHtml(aid)}</b>: ${s.active} active, ${s.expired} expired, ${s.revoked} revoked
`;
        }
      }
      const kb = { inline_keyboard: [[
        { text: "\u{1F4CB} Devices", callback_data: "ls:all:1" },
        { text: "\u{1F4C2} Full List", callback_data: "lsa:all:1" }
      ]] };
      await sendMessageKeyboard(token, chatId, msg, "HTML", kb);
    } catch (e) {
      await sendMessage(token, chatId, `\u274C Error: ${e.message}`);
    }
    return;
  }
  if (/^\/clear_database/i.test(text)) {
    const kb = { inline_keyboard: [[
      { text: "\u26A0\uFE0F Yes, proceed", callback_data: "clrdb:confirm" },
      { text: "\u274C Cancel", callback_data: "clrdb:no" }
    ]] };
    await sendMessageKeyboard(
      token,
      chatId,
      `\u{1F5C4}\uFE0F <b>CLEAR ENTIRE DATABASE</b>
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u26A0\uFE0F This will permanently delete <b>ALL</b> activated devices across every app.

Every user will lose VIP access immediately.

Are you sure you want to continue?`,
      "HTML",
      kb
    );
    return;
  }
  const apps = getAllApps();
  const { text: helpText, kb: helpKb } = buildAdminHelp(apps);
  await sendMessageKeyboard(token, chatId, helpText, "HTML", helpKb);
}
__name(handleAdminCommand, "handleAdminCommand");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (method === "OPTIONS") return new Response(null, { headers: CORS });
    try {
      await initDB(env.DB);
    } catch (e) {
      return json({ error: "DB init failed", detail: e.message }, 500);
    }
    BOT_TOKEN = "8638824829:AAFDe5gBOiFisggH3Bp7sD_9vrVH7DafCnU";
    GROUP_ID_DEFAULT = -1001794534648;
    CHANNEL_ID = -1002662571827;
    const workerUrl = `${url.protocol}//${url.host}`;
    if (path === "/api/time") return json({ ts: Date.now() });
    if (path === "/api/vip/token" && method === "GET") {
      const deviceId = url.searchParams.get("device_id") || "";
      const appId = url.searchParams.get("app_id") || "";
      const pkg   = url.searchParams.get("pkg") || "";
      if (!deviceId) return json({ error: "missing device_id" }, 400);
      const tkSec = url.searchParams.get("secret") || "";
      const tkApp = (appId ? getAppById(appId) : null) || (pkg ? getAppByPackage(pkg) : null);
      const resolvedAppId = tkApp ? tkApp.app_id : (appId || "reversalx");
      const token = await freshToken(env.DB, resolvedAppId, deviceId);
      return json({ token });
    }
    if (path === "/api/vip/check" && method === "POST") {
      try {
        const { device_id, app_id = "default", secret = "" } = await request.json();
        if (!device_id) return json({ active: false });
        const _chkApp = getAppById(app_id) || getAppByPackage(app_id);
        if (!validateAppSecret(_chkApp, secret)) return json({ active: false });
        const resolvedId = _chkApp ? _chkApp.app_id : app_id;
        const row = await env.DB.prepare("SELECT expiry, is_active FROM app_activations WHERE app_id=? AND device_id=?").bind(resolvedId, device_id).first();
        if (!row) return json({ active: false, registered: false });
        const expired = isExpired(row.expiry);
        return json({ active: row.is_active === 1 && !expired, expired, registered: true, expiry: row.expiry });
      } catch {
        return json({ active: false });
      }
    }
    if (path === "/api/check" && method === "GET") {
      const deviceId = url.searchParams.get("device_id") || "";
      const appId = url.searchParams.get("app_id") || "";
      if (!deviceId) return json({ error: "missing device_id" }, 400);
      if (appId) {
        const legApp = getAppById(appId) || getAppByPackage(appId);
        const legSecret = url.searchParams.get("secret") || "";
        if (!validateAppSecret(legApp, legSecret)) return json({ active: false });
        const resolvedLegId = legApp ? legApp.app_id : appId;
        const row2 = await env.DB.prepare("SELECT expiry, is_active, warn_sent FROM app_activations WHERE app_id=? AND device_id=?").bind(resolvedLegId, deviceId).first();
        if (!row2) return json({ active: false, registered: false, ts: Date.now() });
        const expired2 = isExpired(row2.expiry);
        const near_expiry = !expired2 && isNearExpiry(row2.expiry);
        return json({ active: row2.is_active === 1 && !expired2, expired: expired2, registered: true, expiry: row2.expiry, ts: Date.now(), near_expiry, warn_needed: near_expiry && !row2.warn_sent });
      }
      const row = await env.DB.prepare("SELECT * FROM activations WHERE device_id=?").bind(deviceId).first();
      if (!row) return json({ active: false, expired: false, registered: false, ts: Date.now() });
      const expired = isExpired(row.expiry);
      let tkn = null;
      if (!row.is_active || expired) {
        tkn = await freshToken(env.DB, "default", deviceId);
      }
      return json({ active: row.is_active === 1 && !expired, expired, registered: true, expiry: row.expiry, username: row.username, token: tkn, ts: Date.now() });
    }
    if (path === "/vip/direct" && method === "GET") {
      const pkg = url.searchParams.get("pkg") || "";
      const deviceId = url.searchParams.get("device_id") || "";
      const app = pkg ? getAppByPackage(pkg) : null;
      const appName = app?.display_name || "Matrix VIP";
      const appId = app?.app_id || "";
      const adminLink = "https://t.me/matrixxxxxxxxx";
      return new Response(buildDirectDialogHTML(deviceId, appId, appName, pkg, adminLink), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...CORS }
      });
    }
    if (path === "/api/vip/check-direct") {
      let device_id, pkg = "com.adiza.moviezbox", nonce = "", ts = 0, sig = "";
      if (method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ active: false });
        }
        device_id = body.device_id;
        pkg = body.pkg || pkg;
        nonce = body.nonce || "";
        ts = Number(body.ts) || 0;
        sig = body.sig || "";
      } else {
        device_id = url.searchParams.get("device_id") || "";
        pkg = url.searchParams.get("pkg") || pkg;
        nonce = url.searchParams.get("nonce") || "";
        ts = Number(url.searchParams.get("ts")) || 0;
        sig = url.searchParams.get("sig") || "";
      }
      if (!device_id) return json({ active: false });
      const row = await env.DB.prepare(
        "SELECT is_active, expiry, telegram_user_id, telegram_username FROM app_activations WHERE device_id=? LIMIT 1"
      ).bind(device_id).first();
      if (!row || !row.is_active) {
        return json({ active: false });
      }
      if (isExpired(row.expiry)) {
        return json({ active: false, expired: true, expiry: row.expiry });
      }
      return json({
        active: true,
        expiry: row.expiry,
        expiry_ms: row.expiry ? new Date(row.expiry).getTime() : 0
      });
    }
    if (path === "/api/warn/ack" && method === "GET") {
      const wDeviceId = url.searchParams.get("device_id") || "";
      const wAppId = url.searchParams.get("app_id") || "";
      if (wDeviceId && wAppId) {
        const wApp = getAppById(wAppId) || getAppByPackage(wAppId);
        const resolvedWAppId = wApp ? wApp.app_id : wAppId;
        await env.DB.prepare("UPDATE app_activations SET warn_sent=1 WHERE app_id=? AND device_id=?").bind(resolvedWAppId, wDeviceId).run();
      }
      return json({ ok: true });
    }
    if (path === "/api/status" && method === "GET") {
      const deviceId = url.searchParams.get("device_id") || "";
      const appId = url.searchParams.get("app_id") || "";
      if (!deviceId) return json({ active: false });
      if (appId) {
        const row2 = await env.DB.prepare("SELECT is_active, expiry FROM app_activations WHERE app_id=? AND device_id=?").bind(appId, deviceId).first();
        if (!row2) return json({ active: false });
        return json({ active: row2.is_active === 1 && !isExpired(row2.expiry) });
      }
      const row = await env.DB.prepare("SELECT is_active, expiry FROM activations WHERE device_id=?").bind(deviceId).first();
      if (!row) return json({ active: false });
      return json({ active: row.is_active === 1 && !isExpired(row.expiry) });
    }
    if (path === "/api/spinner" && method === "GET") {
      const spDid = url.searchParams.get("device_id") || "unknown";
      const spAid = url.searchParams.get("app_id") || "";
      const spSec = url.searchParams.get("secret") || "";
      const spDialogUrl = `${workerUrl}/api/dialog?device_id=${encodeURIComponent(spDid)}&app_id=${encodeURIComponent(spAid)}&secret=${encodeURIComponent(spSec)}`;
      const spCheckUrl = `${workerUrl}/api/check?device_id=${encodeURIComponent(spDid)}&app_id=${encodeURIComponent(spAid)}&secret=${encodeURIComponent(spSec)}`;
      const spWarnAckUrl = `${workerUrl}/api/warn/ack?device_id=${encodeURIComponent(spDid)}&app_id=${encodeURIComponent(spAid)}`;
      const spinnerHtml = `<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07080D;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;font-family:system-ui,sans-serif;overflow:hidden}
@keyframes sp{to{transform:rotate(360deg)}}
@keyframes glw{0%,100%{opacity:.15;transform:scale(.9)}50%{opacity:.4;transform:scale(1.05)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.ring{position:absolute;border-radius:50%;border:2.5px solid transparent}
.wrap{position:relative;width:110px;height:110px;margin-bottom:32px}
.gcore{position:absolute;inset:38px;border-radius:50%;background:radial-gradient(circle,rgba(201,0,0,.28),transparent 70%);animation:glw 2s ease-in-out infinite}
.label{font-size:10px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#334155;animation:fadeUp .6s ease .1s both}
.dots{display:flex;gap:5px;margin-top:14px;animation:fadeUp .6s ease .2s both}
.dots span{width:5px;height:5px;border-radius:50%;background:#1e293b;animation:glw 1.2s ease-in-out infinite}
.dots span:nth-child(2){animation-delay:.2s}
.dots span:nth-child(3){animation-delay:.4s}
#warnBox{display:none;position:fixed;inset:0;background:#07080D;flex-direction:column;align-items:center;justify-content:center;z-index:99;padding:28px;text-align:center}
.wb-icon{font-size:48px;margin-bottom:14px}
.wb-title{color:#f1f5f9;font-size:16px;font-weight:700;margin-bottom:6px}
.wb-sub{color:#64748b;font-size:12px;margin-bottom:4px}
.wb-exp{color:#fb923c;font-size:13px;font-weight:700;margin-bottom:16px}
.wb-note{color:#475569;font-size:11px;margin-bottom:28px;line-height:1.5}
.wb-btn{background:#c90000;color:#fff;border:none;border-radius:10px;padding:14px 0;font-size:15px;font-weight:700;cursor:pointer;width:100%;max-width:260px;letter-spacing:.5px}
.wb-btn:active{opacity:.8}
</style></head>
<body>
<div class="wrap">
  <div class="ring" style="inset:0;border-top-color:#c90000;border-width:3px;animation:sp .8s linear infinite"></div>
  <div class="ring" style="inset:14px;border-top-color:rgba(201,0,0,.45);border-width:3px;animation:sp 1.25s linear infinite reverse"></div>
  <div class="ring" style="inset:28px;border-top-color:rgba(201,0,0,.2);border-width:2.5px;animation:sp 1.8s linear infinite"></div>
  <div class="gcore"></div>
</div>
<div class="label">Verifying access</div>
<div class="dots"><span></span><span></span><span></span></div>
<div id="warnBox">
  <div class="wb-icon">\u23F0</div>
  <div class="wb-title">Subscription Expiring Soon</div>
  <div class="wb-sub">Your VIP access expires on</div>
  <div class="wb-exp" id="wbExpiry"></div>
  <div class="wb-note">Contact the admin in the group<br>to renew before it runs out.</div>
  <button class="wb-btn" onclick="ackWarn()">Got It \u2014 Continue</button>
</div>
<script>
const IS_ANDROID=typeof window.REVERSAL_X!=="undefined";
let _pendingExpiry='';
async function ackWarn(){
  try{await fetch("${spWarnAckUrl}",{cache:"no-store"});}catch(e){}
  if(IS_ANDROID)try{window.REVERSAL_X.onActivated(_pendingExpiry||"2080");}catch(e){}
}
(async function(){
  try{
    const r=await fetch("${spCheckUrl}",{cache:"no-store"});
    const d=await r.json();
    if(d.active){
      if(d.near_expiry&&d.warn_needed){
        _pendingExpiry=d.expiry||"2080";
        let exStr=_pendingExpiry;
        try{exStr=new Date(d.expiry).toUTCString().replace(' GMT','');}catch(e){}
        document.getElementById('wbExpiry').textContent=exStr;
        document.querySelector('.wrap').style.display='none';
        document.querySelector('.label').style.display='none';
        document.querySelector('.dots').style.display='none';
        document.getElementById('warnBox').style.display='flex';
        return;
      }
      if(IS_ANDROID)try{window.REVERSAL_X.onActivated(d.expiry||"2080");}catch(e){}
      return;
    }
    if(d.expired){window.location.replace("${spDialogUrl}&expired=1");return;}
  }catch(e){}
  window.location.replace("${spDialogUrl}");
})();
<\/script>
</body></html>`;
      return new Response(spinnerHtml, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (path === "/api/dialog" && method === "GET") {
      const deviceId = url.searchParams.get("device_id") || "unknown";
      const appId = url.searchParams.get("app_id") || "";
      let appName = "", command = "", groupLink = "", activationCode = "", dlgAppSecret = "";
      let app = null;
      let resolvedAppId = appId;
      if (appId) {
        app = getAppById(appId) || getAppByPackage(appId);
        if (app) {
          resolvedAppId = app.app_id;
          appName = app.display_name;
          command = app.tg_command;
          groupLink = app.group_link;
          dlgAppSecret = app.app_secret || "";
          const dlgSecret = url.searchParams.get("secret") || "";
          if (!validateAppSecret(app, dlgSecret)) {
            return html(`<!DOCTYPE html><html><body style="background:#07080D;color:#ff2255;display:flex;align-items:center;justify-content:center;height:100vh;font-family:Inter,sans-serif;text-align:center;padding:20px"><div style="max-width:280px"><div style="font-size:52px">\u26D4</div><br><b style="font-size:16px">Invalid Configuration</b><br><br><span style="font-size:12px;color:#475569">This app copy is not authorized.<br>Contact your provider for a valid build.</span></div></body></html>`);
          }
        }
        const tkn = await freshToken(env.DB, resolvedAppId, deviceId);
        activationCode = `${deviceId}.${tkn}`;
      }
      if (app && app.dialog_variant === "matrix") {
        return html(buildMatrixDialogHTML(deviceId, workerUrl, resolvedAppId, appName, app.group_link || "https://t.me/+WxUQKQZFdTA2NGY8", dlgAppSecret));
      }
      return html(buildDialogHTML(deviceId, activationCode, workerUrl, resolvedAppId, appName, command, groupLink, dlgAppSecret));
    }
    if (path === "/api/tamper") return html(TAMPER_HTML);
    if (path === "/telegram" && method === "POST") return handleTelegram(request, env);
    if (!await checkAdminKey(url, env)) {
      if (path.startsWith("/api/admin")) return json({ error: "unauthorized" }, 401);
    }
    if (path === "/api/admin/storage") {
      const rows = (await env.DB.prepare(
        "SELECT app_id, COUNT(*) as rows FROM app_activations GROUP BY app_id"
      ).all()).results || [];
      const appMap = {};
      for (const a of getAllApps()) appMap[a.app_id] = a.display_name;
      const BYTES_PER_ROW = 512;
      const byApp = rows.map((r) => ({
        app_id: r.app_id,
        display_name: appMap[r.app_id] || r.app_id,
        rows: r.rows,
        estimated_bytes: r.rows * BYTES_PER_ROW
      }));
      const totalRows = byApp.reduce((s, a) => s + a.rows, 0);
      return json({ by_app: byApp, total_rows: totalRows, total_estimated_bytes: totalRows * BYTES_PER_ROW });
    }
    if (path === "/api/admin/stats") {
      const appIdFilter = url.searchParams.get("app_id") || "";
      const q = appIdFilter ? "SELECT COUNT(*) as c FROM app_activations WHERE app_id=?" : "SELECT COUNT(*) as c FROM app_activations";
      const bind = appIdFilter ? [appIdFilter] : [];
      const total = appIdFilter ? await env.DB.prepare(q).bind(...bind).first() : await env.DB.prepare(q).first();
      const active = appIdFilter ? await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND app_id=? AND (expiry='2080' OR datetime(expiry)>datetime('now'))").bind(appIdFilter).first() : await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND (expiry='2080' OR datetime(expiry)>datetime('now'))").first();
      const expired = appIdFilter ? await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND app_id=? AND expiry != '2080' AND datetime(expiry) <= datetime('now')").bind(appIdFilter).first() : await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND expiry != '2080' AND datetime(expiry) <= datetime('now')").first();
      const revoked = appIdFilter ? await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=0 AND app_id=?").bind(appIdFilter).first() : await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=0").first();
      let by_app = [];
      if (!appIdFilter) {
        const appRows = getAllApps();
        by_app = await Promise.all(appRows.map(async (a) => {
          const tot = await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE app_id=?").bind(a.app_id).first();
          const act = await env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE app_id=? AND is_active=1 AND (expiry='2080' OR datetime(expiry)>datetime('now'))").bind(a.app_id).first();
          return { app_id: a.app_id, display_name: a.display_name || a.app_id, total: tot ? tot.c : 0, active: act ? act.c : 0 };
        }));
        by_app = by_app.filter((a) => a.total > 0);
      }
      return json({ total: total.c, active: active.c, expired: expired.c, revoked: revoked.c, by_app });
    }
    if (path === "/api/admin/users") {
      const page = parseInt(url.searchParams.get("page") || "1");
      const limit = 50;
      const offset = (page - 1) * limit;
      const appIdFilter = url.searchParams.get("app_id") || "";
      const sourceFilter = url.searchParams.get("source") || "";
      const search = url.searchParams.get("q") || "";
      let rows;
      const srcClause = sourceFilter ? ` AND source=?` : "";
      const srcBind = sourceFilter ? [sourceFilter] : [];
      if (search && appIdFilter) {
        rows = await env.DB.prepare(`SELECT * FROM app_activations WHERE app_id=?${srcClause} AND (device_id LIKE ? OR telegram_username LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(appIdFilter, ...srcBind, `%${search}%`, `%${search}%`, limit, offset).all();
      } else if (search) {
        rows = await env.DB.prepare(`SELECT * FROM app_activations WHERE (device_id LIKE ? OR telegram_username LIKE ?)${srcClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(`%${search}%`, `%${search}%`, ...srcBind, limit, offset).all();
      } else if (appIdFilter) {
        rows = await env.DB.prepare(`SELECT * FROM app_activations WHERE app_id=?${srcClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(appIdFilter, ...srcBind, limit, offset).all();
      } else {
        rows = await env.DB.prepare(`SELECT * FROM app_activations WHERE 1=1${srcClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(...srcBind, limit, offset).all();
      }
      const users = (rows.results || []).map((r) => ({
        ...r,
        status: r.is_active === 0 ? "revoked" : isExpired(r.expiry) ? "expired" : "active"
      }));
      return json({ users, page });
    }
    if (path === "/api/admin/settings" && method === "GET") {
      const rows = (await env.DB.prepare("SELECT key, value FROM settings").all()).results || [];
      const out = {};
      for (const r of rows) out[r.key] = r.value;
      return json(out);
    }
    if (path === "/api/admin/settings" && method === "POST") {
      const body = await request.json();
      for (const [k, v] of Object.entries(body)) {
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)").bind(k, String(v)).run();
      }
      return json({ ok: true });
    }
    if (path === "/api/admin/apps" && method === "GET") {
      const srcFilter = url.searchParams.get("source") || "";
      let apps = await Promise.all(getAllApps().map(async (a) => {
        const srcCond = srcFilter === "direct" ? "AND source='direct'" : srcFilter === "telegram" ? "AND (source IS NULL OR source='telegram')" : "";
        const activeRow = await env.DB.prepare(`SELECT COUNT(*) as c FROM app_activations WHERE app_id=? AND is_active=1 AND (expiry='2080' OR datetime(expiry)>datetime('now')) ${srcCond}`).bind(a.app_id).first();
        const totalRow = await env.DB.prepare(`SELECT COUNT(*) as c FROM app_activations WHERE app_id=? ${srcCond}`).bind(a.app_id).first();
        return { ...a, active_count: activeRow?.c || 0, total_count: totalRow?.c || 0 };
      }));
      if (srcFilter === "direct") apps = apps.filter((a) => a.dialog_variant === "matrix" || a.package_name);
      if (srcFilter === "telegram") apps = apps.filter((a) => a.dialog_variant !== "matrix");
      return json({ apps });
    }
    if (path === "/api/admin/apps/register" && method === "POST") {
      return json({ error: "App registration via API is disabled. Add apps to HARDCODED_APPS in the worker source." }, 400);
    }
    if (path === "/api/admin/apps" && method === "DELETE") {
      const appId = url.searchParams.get("app_id") || "";
      if (!appId) return json({ error: "app_id required" }, 400);
      const countRow = await env.DB.prepare("SELECT COUNT(*) as total FROM app_activations WHERE app_id=?").bind(appId).first();
      const totalUsers = countRow?.total || 0;
      await env.DB.prepare("DELETE FROM app_activations WHERE app_id=?").bind(appId).run();
      await env.DB.prepare("DELETE FROM vip_tokens WHERE app_id=?").bind(appId).run();
      await env.DB.prepare("DELETE FROM pending_activations WHERE app_id=?").bind(appId).run();
      return json({ ok: true, app_id: appId, deleted: true, users_deleted: totalUsers });
    }
    if (path === "/api/admin/broadcast" && method === "POST") {
      const body = await request.json();
      const { app_id } = body;
      if (!app_id) return json({ error: "app_id required" }, 400);
      const app = getAppById(app_id);
      if (!app) return json({ error: "app not found" }, 404);
      const token = BOT_TOKEN;
      const groupId = await getGroupId(env);
      if (!token || !groupId) return json({ error: "GROUP_ID not set" }, 400);
      const channelId = getChannelId();
      const photo = await getNextBannerPhoto(env.DB);
      const caption = buildAnnouncementMessage(app).replace(/\r/g, "");
      const tgResp = await (await sendPhoto(token, channelId, photo, caption, ANNOUNCE_KB, "Markdown")).json();
      return json({ ok: tgResp.ok === true, app_id, tg: { ok: tgResp.ok, message_id: tgResp.result?.message_id, description: tgResp.description } });
    }
    if (path === "/api/admin/renewall" && method === "POST") {
      const body = await request.json();
      const { app_id, expiry: rawExpiry } = body;
      if (!app_id) return json({ error: "app_id required" }, 400);
      const app = getAppById(app_id);
      if (!app) return json({ error: "app not found" }, 404);
      const newExpiry = parseExpiry(rawExpiry || app.expiry_default);
      const result = await env.DB.prepare(
        "UPDATE app_activations SET expiry=?, is_active=1 WHERE app_id=? AND is_active=1"
      ).bind(newExpiry, app_id).run();
      return json({ ok: true, renewed: result.meta?.changes ?? 0, expiry: newExpiry });
    }
    if (path === "/api/admin/test-bot" && method === "POST") {
      const token = BOT_TOKEN;
      const groupId = await getGroupId(env);
      if (!token) return json({ error: "BOT_TOKEN not set in worker" }, 400);
      if (!groupId) return json({ error: "GROUP_ID not set \u2014 open worker.js and set GROUP_ID_DEFAULT to your group chat ID" }, 400);
      const tgResp = await (await sendMessage(token, groupId, "\u{1F916} <b>REVERSAL X</b> \u2014 bot connection test \u2705\nIf you see this, announcements are working!", "HTML")).json();
      return json({ ok: tgResp.ok === true, group_id: groupId, tg: { ok: tgResp.ok, message_id: tgResp.result?.message_id, description: tgResp.description } });
    }
    if (path === "/api/admin/setup-webhook") {
      const token = BOT_TOKEN;
      if (!token) return json({ error: "BOT_TOKEN not configured" }, 400);
      const workerBase = url.searchParams.get("worker_url") || workerUrl;
      const webhookUrl = `${workerBase}/telegram`;
      const resp = await fetch(`https://api.telegram.org/bot${token}/setWebhook?url=${encodeURIComponent(webhookUrl)}`);
      const data = await resp.json();
      return json({ ok: data.ok, result: data.result, webhook_url: webhookUrl });
    }
    if (path === "/api/admin/activate" && method === "POST") {
      const body = await request.json();
      const { device_id, username = "", expiry: rawExp, notes = "", app_id, app_display_name } = body;
      if (!device_id || !rawExp) return json({ error: "device_id and expiry required" }, 400);
      const expiry = parseExpiry(rawExp);
      if (app_id) {
        await env.DB.prepare("INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)").bind(app_id, device_id, username, 0, expiry, Date.now()).run();
      } else {
        await env.DB.prepare("INSERT OR REPLACE INTO activations (device_id, username, expiry, is_active, created_at, notes) VALUES (?,?,?,1,?,?)").bind(device_id, username, expiry, Date.now(), notes).run();
      }
      return json({ ok: true, device_id, username, expiry });
    }
    if (path === "/api/admin/direct/users" && method === "GET") {
      const rows = (await env.DB.prepare(
        "SELECT device_id, telegram_username, COUNT(*) as total_apps, SUM(CASE WHEN is_active=1 AND (expiry='2080' OR datetime(expiry)>datetime('now')) THEN 1 ELSE 0 END) as active_apps, MAX(created_at) as last_activated FROM app_activations WHERE source='direct' GROUP BY device_id ORDER BY last_activated DESC"
      ).all()).results || [];
      return json({ users: rows });
    }
    if (path === "/api/admin/direct/user-apps" && method === "GET") {
      const did = url.searchParams.get("device_id") || "";
      if (!did) return json({ apps: [] });
      const rows = (await env.DB.prepare(
        "SELECT aa.app_id, aa.device_id, aa.telegram_username, aa.expiry, aa.is_active, aa.created_at, a.display_name, a.package_name FROM app_activations aa LEFT JOIN apps a ON aa.app_id=a.app_id WHERE aa.device_id=? AND aa.source='direct' ORDER BY aa.created_at DESC"
      ).bind(did).all()).results || [];
      return json({ apps: rows });
    }
    if (path === "/api/admin/direct/clear-users" && method === "POST") {
      let _dcuBody;
      try {
        _dcuBody = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }
      const { app_id } = _dcuBody;
      if (!app_id) return json({ error: "app_id required" }, 400);
      const r = await env.DB.prepare("DELETE FROM app_activations WHERE app_id=? AND source='direct'").bind(app_id).run();
      return json({ ok: true, deleted: r.meta?.changes ?? 0 });
    }
    if (path === "/api/admin/activate-direct" && method === "POST") {
      let _dab;
      try {
        _dab = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }
      const { device_id, package_name, app_name, username = "direct", expiry: rawExp = "30d" } = _dab;
      if (!device_id || !package_name) return json({ error: "device_id and package_name required" }, 400);
      const app = getAppByPackage(package_name.trim());
      if (!app) return json({ error: `No app registered for package: ${package_name}` }, 404);
      const expiry = parseExpiry(rawExp);
      await env.DB.prepare(
        "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at, source) VALUES (?,?,?,0,?,1,?,'direct')"
      ).bind(app.app_id, device_id, username || app_name || "direct", expiry, Date.now()).run();
      return json({ ok: true, device_id, app_id: app.app_id, package_name, expiry });
    }
    if (path === "/api/admin/revoke" && method === "POST") {
      const { device_id, app_id } = await request.json();
      if (!device_id) return json({ error: "device_id required" }, 400);
      if (app_id) await env.DB.prepare("UPDATE app_activations SET is_active=0 WHERE app_id=? AND device_id=?").bind(app_id, device_id).run();
      else await env.DB.prepare("UPDATE activations SET is_active=0 WHERE device_id=?").bind(device_id).run();
      return json({ ok: true, device_id, status: "revoked" });
    }
    if (path === "/api/admin/enable" && method === "POST") {
      const { device_id, app_id } = await request.json();
      if (!device_id) return json({ error: "device_id required" }, 400);
      if (app_id) await env.DB.prepare("UPDATE app_activations SET is_active=1, expired_notified=0 WHERE app_id=? AND device_id=?").bind(app_id, device_id).run();
      else await env.DB.prepare("UPDATE activations SET is_active=1 WHERE device_id=?").bind(device_id).run();
      return json({ ok: true, device_id, status: "enabled" });
    }
    if (path === "/api/admin/restore" && method === "POST") {
      const { device_id, app_id } = await request.json();
      if (!device_id) return json({ error: "device_id required" }, 400);
      if (app_id) await env.DB.prepare("UPDATE app_activations SET is_active=1, expired_notified=0 WHERE app_id=? AND device_id=?").bind(app_id, device_id).run();
      else await env.DB.prepare("UPDATE activations SET is_active=1 WHERE device_id=?").bind(device_id).run();
      return json({ ok: true, device_id, status: "enabled" });
    }
    if (path === "/api/admin/extend" && method === "POST") {
      const { device_id, expiry: rawExp, app_id } = await request.json();
      if (!device_id || !rawExp) return json({ error: "device_id and expiry required" }, 400);
      const expiry = parseExpiry(rawExp);
      if (app_id) await env.DB.prepare("UPDATE app_activations SET expiry=?, is_active=1 WHERE app_id=? AND device_id=?").bind(expiry, app_id, device_id).run();
      else await env.DB.prepare("UPDATE activations SET expiry=?, is_active=1 WHERE device_id=?").bind(expiry, device_id).run();
      return json({ ok: true, device_id, expiry });
    }
    if (path === "/api/admin/user" && method === "DELETE") {
      const device_id = url.searchParams.get("device_id") || "";
      const app_id = url.searchParams.get("app_id") || "";
      if (!device_id) return json({ error: "device_id required" }, 400);
      if (app_id) await env.DB.prepare("DELETE FROM app_activations WHERE app_id=? AND device_id=?").bind(app_id, device_id).run();
      else await env.DB.prepare("DELETE FROM activations WHERE device_id=?").bind(device_id).run();
      return json({ ok: true, device_id, deleted: true });
    }
    if (path === "/api/admin/db") {
      const activations = await env.DB.prepare("SELECT * FROM app_activations ORDER BY created_at DESC LIMIT 200").all();
      const legacy = await env.DB.prepare("SELECT * FROM activations ORDER BY created_at DESC LIMIT 50").all();
      return json({ app_activations: activations.results, apps: getAllApps(), legacy_activations: legacy.results });
    }
    if (path === "/api/admin/clear-expired" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { app_id } = body;
      let result;
      if (app_id) {
        result = await env.DB.prepare(
          "DELETE FROM app_activations WHERE app_id=? AND is_active=1 AND expiry != '2080' AND datetime(expiry) <= datetime('now')"
        ).bind(app_id).run();
      } else {
        result = await env.DB.prepare(
          "DELETE FROM app_activations WHERE is_active=1 AND expiry != '2080' AND datetime(expiry) <= datetime('now')"
        ).run();
      }
      return json({ ok: true, deleted: result.changes || 0 });
    }
    if (path === "/api/admin/clear-revoked" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { app_id } = body;
      let result;
      if (app_id) {
        result = await env.DB.prepare(
          "DELETE FROM app_activations WHERE app_id=? AND is_active=0"
        ).bind(app_id).run();
      } else {
        result = await env.DB.prepare(
          "DELETE FROM app_activations WHERE is_active=0"
        ).run();
      }
      return json({ ok: true, deleted: result.changes || 0 });
    }
    if (path === "/api/admin/clear-app" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { app_id, confirm } = body;
      if (!app_id) return json({ error: "app_id required" }, 400);
      if (confirm !== "CONFIRM_CLEAR") return json({ error: 'Send confirm: "CONFIRM_CLEAR" to proceed' }, 400);
      const r1 = await env.DB.prepare("DELETE FROM app_activations WHERE app_id=?").bind(app_id).run();
      const r2 = await env.DB.prepare("DELETE FROM vip_tokens WHERE app_id=?").bind(app_id).run();
      return json({ ok: true, app_id, users_deleted: r1.changes || 0, tokens_deleted: r2.changes || 0 });
    }
    if (path === "/api/admin/clear-db" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { app_id, confirm } = body;
      if (confirm !== "CONFIRM_CLEAR") {
        return json({ error: 'Send confirm: "CONFIRM_CLEAR" to proceed' }, 400);
      }
      let result;
      if (app_id) {
        result = await env.DB.prepare("DELETE FROM app_activations WHERE app_id=?").bind(app_id).run();
      } else {
        result = await env.DB.prepare("DELETE FROM app_activations").run();
      }
      return json({ ok: true, deleted: result.changes || 0, cleared: app_id || "ALL" });
    }
    if (path === "/api/admin/set-username" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { device_id, app_id, username } = body;
      if (!device_id || !username) return json({ error: "device_id and username required" }, 400);
      if (app_id) {
        await env.DB.prepare("UPDATE app_activations SET telegram_username=? WHERE app_id=? AND device_id=?").bind(username, app_id, device_id).run();
      } else {
        await env.DB.prepare("UPDATE app_activations SET telegram_username=? WHERE device_id=?").bind(username, device_id).run();
      }
      return json({ ok: true, device_id, username });
    }
    if (path === "/api/admin/bulk-activate" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { device_ids, app_id, username = "bulk", expiry = "2080" } = body;
      if (!Array.isArray(device_ids) || device_ids.length === 0 || !app_id) {
        return json({ error: "device_ids (array) and app_id required" }, 400);
      }
      let count = 0;
      for (const did of device_ids) {
        await env.DB.prepare(
          "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)"
        ).bind(app_id, did.trim(), username, 0, expiry, Date.now()).run();
        count++;
      }
      return json({ ok: true, activated: count, app_id, expiry });
    }
    if (path === "/api/admin/user-detail" && method === "GET") {
      const device_id = url.searchParams.get("device_id") || "";
      const app_id = url.searchParams.get("app_id") || "";
      if (!device_id) return json({ error: "device_id required" }, 400);
      let row;
      if (app_id) {
        row = await env.DB.prepare("SELECT * FROM app_activations WHERE app_id=? AND device_id=?").bind(app_id, device_id).first();
      } else {
        row = await env.DB.prepare("SELECT * FROM app_activations WHERE device_id=? LIMIT 1").bind(device_id).first();
      }
      if (!row) return json({ error: "not found" }, 404);
      const status = row.is_active === 0 ? "revoked" : isExpired(row.expiry) ? "expired" : "active";
      return json({ ...row, status });
    }
    if (path === "/api/admin/pending" && method === "GET") {
      const appId = url.searchParams.get("app_id") || "";
      const rows = appId ? (await env.DB.prepare("SELECT * FROM pending_activations WHERE app_id=? ORDER BY created_at DESC").bind(appId).all()).results || [] : (await env.DB.prepare("SELECT * FROM pending_activations ORDER BY created_at DESC").all()).results || [];
      return json({ ok: true, pending: rows, count: rows.length });
    }
    if (path === "/api/admin/pending/approve" && method === "POST") {
      const body = await request.json();
      const { telegram_user_id, app_id, device_id, telegram_username, expiry: rawExp } = body;
      if (!telegram_user_id || !app_id || !device_id) return json({ error: "missing fields" }, 400);
      const expiry = parseExpiry(rawExp || "30d");
      const now = Date.now();
      await env.DB.prepare(
        "INSERT OR REPLACE INTO app_activations (app_id, device_id, telegram_username, telegram_user_id, expiry, is_active, created_at) VALUES (?,?,?,?,?,1,?)"
      ).bind(app_id, device_id, telegram_username || "", telegram_user_id, expiry, now).run();
      await env.DB.prepare("DELETE FROM pending_activations WHERE telegram_user_id=? AND app_id=?").bind(telegram_user_id, app_id).run();
      return json({ ok: true, device_id, expiry });
    }
    if (path === "/api/admin/pending" && method === "DELETE") {
      const telegram_user_id = url.searchParams.get("telegram_user_id") || "";
      const app_id = url.searchParams.get("app_id") || "";
      if (!telegram_user_id) return json({ error: "telegram_user_id required" }, 400);
      if (app_id) {
        await env.DB.prepare("DELETE FROM pending_activations WHERE telegram_user_id=? AND app_id=?").bind(telegram_user_id, app_id).run();
      } else {
        await env.DB.prepare("DELETE FROM pending_activations WHERE telegram_user_id=?").bind(telegram_user_id).run();
      }
      return json({ ok: true });
    }
    if (path === "/api/admin/webhook-status" && method === "GET") {
      const token = BOT_TOKEN;
      if (!token) return json({ error: "BOT_TOKEN not set" }, 400);
      const resp = await fetch(`https://api.telegram.org/bot${token}/getWebhookInfo`);
      const data = await resp.json();
      return json({ ok: data.ok, info: data.result });
    }
    if (path === "/api/admin/chart-data" && method === "GET") {
      const nowMs = Date.now();
      const daily = [];
      for (let i = 6; i >= 0; i--) {
        const dayStart = nowMs - (i + 1) * 864e5;
        const dayEnd = nowMs - i * 864e5;
        const r = await env.DB.prepare(
          "SELECT COUNT(*) as c FROM app_activations WHERE created_at >= ? AND created_at < ?"
        ).bind(dayStart, dayEnd).first();
        const label = new Date(dayStart + 432e5).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
        daily.push({ label, count: r?.c || 0 });
      }
      const [active, expired, revoked, pending] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND (expiry='2080' OR datetime(expiry)>datetime('now'))").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=1 AND expiry != '2080' AND datetime(expiry) <= datetime('now')").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM app_activations WHERE is_active=0").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM pending_activations").first()
      ]);
      return json({ ok: true, daily, status: { active: active?.c || 0, expired: expired?.c || 0, revoked: revoked?.c || 0, pending: pending?.c || 0 } });
    }
    if (path === "/api/admin/bulk-revoke" && method === "POST") {
      const body = await request.json();
      const { app_id, device_ids } = body;
      if (!app_id || !device_ids?.length) return json({ error: "app_id and device_ids required" }, 400);
      let revoked = 0;
      for (const did of device_ids) {
        const r = await env.DB.prepare("UPDATE app_activations SET is_active=0 WHERE app_id=? AND device_id=?").bind(app_id, did).run();
        revoked += r.changes || 0;
      }
      return json({ ok: true, revoked });
    }
    if (path === "/api/admin/bulk-delete" && method === "POST") {
      const body = await request.json();
      const { app_id, device_ids } = body;
      if (!app_id || !device_ids?.length) return json({ error: "app_id and device_ids required" }, 400);
      let deleted = 0;
      for (const did of device_ids) {
        const r = await env.DB.prepare("DELETE FROM app_activations WHERE app_id=? AND device_id=?").bind(app_id, did).run();
        deleted += r.changes || 0;
      }
      return json({ ok: true, deleted });
    }
    if (path === "/api/admin/apps" && method === "PATCH") {
      return json({ error: "App definitions are hardcoded in the worker. Edit HARDCODED_APPS in the worker source to update app settings." }, 400);
    }
    if (path === "/" || path === "") {
      return new Response("Not Found", { status: 404, headers: { "Content-Type": "text/plain" } });
    }
    if (path === "/browse") {
      try {
        const r = await fetch(`${MUNO_COM}/browse`, { headers: { "User-Agent": MUNO_UA, "Accept": "application/json" } });
        return new Response(await r.text(), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/batch-grid") {
      try {
        await munoGetSession();
        const sections = [
          // ── Top 8 priority rows ──────────────────────────────────────────
          { pipeType: "p", pipeId: 4, title: "Latest (2026)", badge: "NEW" },
          { pipeType: "p", pipeId: 6, title: "Favourites", badge: "" },
          { pipeType: "g", pipeId: 17, title: "Drama", badge: "" },
          { pipeType: "g", pipeId: 5, title: "Series", badge: "TV" },
          { pipeType: "g", pipeId: 15, title: "Romance", badge: "" },
          { pipeType: "g", pipeId: 2, title: "Horror", badge: "" },
          { pipeType: "g", pipeId: 14, title: "Sci-Fi", badge: "" },
          { pipeType: "g", pipeId: 1, title: "Action", badge: "" },
          // ── Rest of genres ───────────────────────────────────────────────
          { pipeType: "g", pipeId: 9, title: "Comedy", badge: "" },
          { pipeType: "g", pipeId: 7, title: "Adventure", badge: "" },
          { pipeType: "g", pipeId: 8, title: "Love Story", badge: "" },
          { pipeType: "g", pipeId: 19, title: "Thriller", badge: "" },
          { pipeType: "g", pipeId: 12, title: "Crime", badge: "" },
          { pipeType: "g", pipeId: 16, title: "Kung Fu", badge: "" },
          { pipeType: "g", pipeId: 18, title: "Sport", badge: "" },
          { pipeType: "g", pipeId: 20, title: "Animation", badge: "" },
          { pipeType: "g", pipeId: 13, title: "Family", badge: "" },
          { pipeType: "g", pipeId: 21, title: "Korean", badge: "" },
          { pipeType: "g", pipeId: 22, title: "Filipino", badge: "" },
          { pipeType: "g", pipeId: 23, title: "Indian", badge: "" },
          { pipeType: "g", pipeId: 24, title: "Chinese", badge: "" },
          // ── VJ sections ──────────────────────────────────────────────────
          { pipeType: "p", pipeId: 2, title: "By Vj Emmy", badge: "" },
          { pipeType: "p", pipeId: 8, title: "By Vj Jingo", badge: "" },
          { pipeType: "p", pipeId: 9, title: "By Vj Ice P", badge: "" },
          { pipeType: "p", pipeId: 5, title: "By Vj Shao Khan", badge: "" },
          { pipeType: "p", pipeId: 3, title: "By Vj Jovan", badge: "" },
          { pipeType: "p", pipeId: 1, title: "By Vj Junior", badge: "" },
          { pipeType: "p", pipeId: 7, title: "By Vj 7", badge: "" }
        ];
        const results = await Promise.all(sections.map(async (s) => {
          try {
            const slotUrl = munoGridSlotUrl(s.pipeType, s.pipeId, null);
            const r = await munoAuthedGetSlot(slotUrl);
            const { movies } = munoParseGridResult(await r.text());
            return { ...s, movies };
          } catch (_) {
            return { ...s, movies: [] };
          }
        }));
        return new Response(JSON.stringify({ sections: results }), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/grid") {
      try {
        const pipeType = url.searchParams.get("pipe_type") || "g";
        const pipeId = url.searchParams.get("pipe_id") || "1";
        const lastFetchId = url.searchParams.get("last_fetch_id") || null;
        const slotUrl = munoGridSlotUrl(pipeType, pipeId, lastFetchId);
        const r = await munoAuthedGetSlot(slotUrl);
        const { movies, lastFetchId: newLastFetchId } = munoParseGridResult(await r.text());
        return new Response(JSON.stringify({ movies, last_fetch_id: newLastFetchId, hasMore: movies.length >= 1 }), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/debug-search") {
      try {
        const key = url.searchParams.get("k") || "";
        if (key !== "adiza2026dbg") return new Response("nope", { status: 403 });
        const q = url.searchParams.get("q") || "action";
        const lid = url.searchParams.get("lid") || "0";
        const mode = url.searchParams.get("mode") || "uid";
        const cookie = await munoGetSession();
        if (mode === "uid") {
          const r2 = await fetch(`${MUNO_COM}/`, {
            headers: { "User-Agent": MUNO_UA, "Referer": MUNO_COM, "Cookie": cookie, "Accept": "text/html" },
            redirect: "manual"
          });
          const html3 = await r2.text();
          const uidM = html3.match(/data-user-id="(\d+)"|"user_id"\s*:\s*"?(\d+)"?|\/users\/(\d+)|uid=(\d+)|\/profile\/(\d+)|user_uid.*?(\d{4,})/);
          const uid = uidM ? uidM[1] || uidM[2] || uidM[3] || uidM[4] || uidM[5] || uidM[6] : null;
          const allNums = [...html3.matchAll(/\bid=["']?(\d{3,8})["']?/g)].map((m) => m[1]).slice(0, 10);
          const showLinks = [...html3.matchAll(/\/shows\/[^/"']+\/[^/"']+\/(\d+)/g)].map((m) => m[1]).slice(0, 5);
          return new Response(JSON.stringify({ status: r2.status, len: html3.length, uid, allNums, showLinks, first1000: html3.slice(0, 1e3) }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        if (mode === "shows-com") {
          const testUid = url.searchParams.get("uid") || "1";
          const testUrl = `/shows/g/1/${testUid}/0`;
          const r2 = await munoAuthedGetSlot(testUrl);
          const html22 = await r2.text();
          const twolekCount2 = (html22.match(/href="\/twolekede\?/g) || []).length;
          return new Response(JSON.stringify({ url: testUrl, status: r2.status, len: html22.length, twolekede_links: twolekCount2, first600: html22.slice(0, 600) }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        if (mode === "orgshows") {
          const testUrl = `${MUNO_ORG}/shows/g/1/0/${encodeURIComponent(lid)}`;
          const r2 = await fetch(testUrl, {
            headers: { "User-Agent": MUNO_UA, "Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "Referer": MUNO_ORG, "Cookie": cookie },
            redirect: "manual"
          });
          const html3 = await r2.text();
          const twolekCount2 = (html3.match(/href="\/twolekede\?/g) || []).length;
          return new Response(JSON.stringify({ url: testUrl, status: r2.status, len: html3.length, twolekede_links: twolekCount2, first600: html3.slice(0, 600), last200: html3.slice(-200) }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        if (mode === "orgsearch") {
          const testUrl = `${MUNO_ORG}/search?q=${encodeURIComponent(q)}&page=2`;
          const r2 = await fetch(testUrl, {
            headers: { "User-Agent": MUNO_UA, "Accept": "text/html,*/*", "X-Requested-With": "XMLHttpRequest", "Referer": MUNO_ORG, "Cookie": cookie },
            redirect: "manual"
          });
          const html3 = await r2.text();
          const twolekCount2 = (html3.match(/href="\/twolekede\?/g) || []).length;
          return new Response(JSON.stringify({ url: testUrl, status: r2.status, len: html3.length, twolekede_links: twolekCount2, first600: html3.slice(0, 600) }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        let rawUrl;
        if (mode === "qs") rawUrl = `/search?q=${encodeURIComponent(q)}&page=2`;
        else rawUrl = `/search/${encodeURIComponent(q)}/0/${encodeURIComponent(lid)}`;
        const r = await munoAuthedGetSlot(rawUrl);
        const html2 = await r.text();
        const twolekCount = (html2.match(/href="\/twolekede\?/g) || []).length;
        return new Response(JSON.stringify({ url: rawUrl, status: r.status, len: html2.length, twolekede_links: twolekCount, first500: html2.slice(0, 500), last300: html2.slice(-300) }), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/search") {
      try {
        const q = url.searchParams.get("q") || "";
        const lid = url.searchParams.get("last_fetch_id") || "0";
        if (!q) return new Response(JSON.stringify({ error: "Missing q parameter" }), { status: 400, headers: { "Content-Type": "application/json", ...CORS } });
        const r = await munoAuthedGetSlot(`/search?q=${encodeURIComponent(q)}`);
        const { movies, lastFetchId: newLid } = munoParseGridResult(await r.text());
        return new Response(JSON.stringify({ movies, last_fetch_id: newLid, hasMore: false }), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/movies") {
      try {
        const lastFetchId = url.searchParams.get("last_fetch_id") || null;
        const slotUrl = munoGridSlotUrl("p", "4", lastFetchId);
        const r = await munoAuthedGetSlot(slotUrl);
        const { movies, lastFetchId: newLid } = munoParseGridResult(await r.text());
        return new Response(JSON.stringify({ movies, last_fetch_id: newLid, hasMore: movies.length >= 1 }), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/stream") {
      try {
        const vid = url.searchParams.get("vid");
        if (!vid) return new Response(JSON.stringify({ error: "Missing vid parameter" }), { status: 400, headers: { "Content-Type": "application/json", ...CORS } });
        const uid = "1";
        const h = {
          "User-Agent": MUNO_UA,
          "Accept": "*/*",
          "Accept-Encoding": "identity",
          "Referer": "https://munowatch.org/",
          "Origin": "https://munowatch.org",
          "X-Requested-With": "XMLHttpRequest",
          "Authorization": `Bearer ${MUNO_API_KEY}`,
          "Content-Type": "application/x-www-form-urlencoded"
        };
        const dlResp = await fetch(`${MUNO_ORG}/api/download`, { method: "POST", headers: h, body: `uid=${uid}&vid=${vid}&state=on` });
        if (dlResp.ok) {
          const data = await dlResp.json().catch(() => null);
          if (data && data.playingurl) return new Response(JSON.stringify({
            url: data.playingurl,
            title: data.title || "",
            vj: data.vj || "",
            size: data.size || "",
            duration: data.duration || "",
            image: data.image || "",
            description: data.description || "",
            series_code: data.series_code || "",
            category_id: data.category_id || "",
            type: data.type || "",
            vid
          }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        const viewResp = await fetch(`${MUNO_ORG}/api/view`, { method: "POST", headers: h, body: `uid=${uid}&vid=${vid}` });
        if (viewResp.ok) {
          const data = await viewResp.json().catch(() => null);
          if (data && data.nextUrl) return new Response(JSON.stringify({ url: data.nextUrl, title: data.vtitle || "", series_code: data.series_code || "", category_id: data.category_id || "", type: data.type || "", vid }), { headers: { "Content-Type": "application/json", ...CORS } });
        }
        const previewResp = await fetch(`${MUNO_ORG}/api/preview/v2/${vid}/${uid}`, { headers: { ...h, "Content-Type": "application/json" } });
        if (previewResp.ok) {
          const data = await previewResp.json().catch(() => null);
          if (data) {
            const findUrl = /* @__PURE__ */ __name((obj) => {
              if (typeof obj === "string" && (obj.includes(".m3u8") || obj.includes(".mp4") || obj.includes("b-cdn.net") || obj.includes("munowatch"))) return obj;
              if (typeof obj === "object" && obj !== null) {
                for (const v of Object.values(obj)) {
                  const found = findUrl(v);
                  if (found) return found;
                }
              }
              return null;
            }, "findUrl");
            const videoUrl = findUrl(data);
            if (videoUrl) return new Response(JSON.stringify({ url: videoUrl, series_code: data.series_code || "", category_id: data.category_id || "", type: data.type || "", vid }), { headers: { "Content-Type": "application/json", ...CORS } });
          }
        }
        return new Response(JSON.stringify({ error: "Could not load video." }), { status: 404, headers: { "Content-Type": "application/json", ...CORS } });
      } catch (_) {
        return new Response(JSON.stringify({ error: "Could not load video." }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/episodes") {
      try {
        const vid = url.searchParams.get("vid") || "";
        const scode = url.searchParams.get("scode") || "";
        const no = url.searchParams.get("no") || "1";
        if (!vid || !scode) return new Response(JSON.stringify({ error: "Missing vid or scode" }), { status: 400, headers: { "Content-Type": "application/json", ...CORS } });
        const cfCache = caches.default;
        const cacheReq = new Request(`https://ep-cache.internal/ep/${encodeURIComponent(scode)}/${encodeURIComponent(no)}`);
        const cfHit = await cfCache.match(cacheReq);
        if (cfHit) {
          const body = await cfHit.text();
          return new Response(body, { headers: { "Content-Type": "application/json", ...CORS } });
        }
        const h = {
          "User-Agent": MUNO_UA,
          "Accept": "application/json, text/plain, */*",
          "Referer": "https://munowatch.org/",
          "Origin": "https://munowatch.org",
          "X-Requested-With": "XMLHttpRequest",
          "Authorization": `Bearer ${MUNO_API_KEY}`
        };
        const epResp = await fetch(`${MUNO_ORG}/api/episodes/range/${encodeURIComponent(vid)}/${encodeURIComponent(scode)}/${encodeURIComponent(no)}`, { headers: h });
        const epText = await epResp.text();
        let epData;
        try {
          epData = JSON.parse(epText);
        } catch {
          epData = null;
        }
        if (epData === null) return new Response(JSON.stringify({ error: "Invalid response from episodes API" }), { status: 502, headers: { "Content-Type": "application/json", ...CORS } });
        if (Array.isArray(epData) && epData.length > 0) {
          cfCache.put(cacheReq, new Response(epText, {
            headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=14400" }
          }));
        }
        return new Response(JSON.stringify(epData), { headers: { "Content-Type": "application/json", ...CORS } });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", ...CORS } });
      }
    }
    if (path === "/football/matches" || path === "/football/matches/") {
      return await _fbHandleMatches(url);
    }
    const _fbStreamMatch = path.match(/^\/football\/stream\/([^/]+)\/([^/]+)\/?$/);
    if (_fbStreamMatch) {
      const [, src, id] = _fbStreamMatch;
      return await _fbHandleStreams(src, id);
    }
    if (path.startsWith("/football/image/")) {
      const encoded = path.slice("/football/image/".length);
      return await _fbHandleImage(encoded);
    }
    if (path === "/relay") {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Forward-Cookie, X-Forward-Referer, Accept",
            "Access-Control-Max-Age": "86400"
          }
        });
      }
      const targetUrl = url.searchParams.get("url");
      if (!targetUrl) {
        return new Response(JSON.stringify({ error: "Missing url parameter" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      let targetParsed;
      try {
        targetParsed = new URL(targetUrl);
        const allowedHosts = ["aoneroom.com", "movbox.cc", "hakunaymatata.com"];
        if (!allowedHosts.some((h) => targetParsed.hostname.endsWith(h))) {
          return new Response(JSON.stringify({ error: "Host not allowed" }), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }
      } catch {
        return new Response(JSON.stringify({ error: "Invalid URL" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      const relayHeaders = new Headers();
      relayHeaders.set("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");
      relayHeaders.set("Accept", "application/json");
      relayHeaders.set("Accept-Language", "en-ZA,en;q=0.9,en-US;q=0.8");
      relayHeaders.set("X-Client-Info", '{"timezone":"Africa/Johannesburg"}');
      relayHeaders.set("Host", targetParsed.hostname);
      relayHeaders.set("Referer", `https://${targetParsed.hostname}`);
      relayHeaders.set("Origin", `https://${targetParsed.hostname}`);
      relayHeaders.set("Connection", "keep-alive");
      const fwdCookie = request.headers.get("X-Forward-Cookie");
      if (fwdCookie) relayHeaders.set("Cookie", fwdCookie);
      const fwdReferer = request.headers.get("X-Forward-Referer");
      if (fwdReferer) {
        relayHeaders.set("Referer", fwdReferer);
        try {
          relayHeaders.set("Origin", new URL(fwdReferer).origin);
        } catch (_) {
        }
      }
      const ct = request.headers.get("Content-Type");
      if (ct) relayHeaders.set("Content-Type", ct);
      const _SA_IPS = ["41.0.0.1", "41.76.108.1", "102.65.0.1", "154.0.0.1", "196.21.0.1", "197.80.0.1", "41.0.0.2", "41.76.108.2"];
      const _saIP = _SA_IPS[Math.floor(Math.random() * _SA_IPS.length)];
      relayHeaders.set("X-Forwarded-For", _saIP);
      relayHeaders.set("CF-Connecting-IP", _saIP);
      relayHeaders.set("X-Real-IP", _saIP);
      relayHeaders.set("True-Client-IP", _saIP);
      let relayBody = null;
      if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
        relayBody = await request.text();
      }
      const upstream = await fetch(targetUrl, { method: request.method, headers: relayHeaders, body: relayBody });
      const respHeaders = new Headers(upstream.headers);
      respHeaders.set("Access-Control-Allow-Origin", "*");
      respHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      respHeaders.set("Access-Control-Allow-Headers", "Content-Type, X-Forward-Cookie");
      const setCookie = upstream.headers.get("set-cookie");
      if (setCookie) respHeaders.set("X-Set-Cookie", setCookie);
      return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
    }
    return json({ error: "not found", path }, 404);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runExpiryNotifications(env));
  }
};
var _FB_ORIGIN = "https://streamed.pk";
var _FB_UA_POOL = [
  "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.72 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
];
var _FB_LANG_POOL = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,fr;q=0.8", "en-ZA,en;q=0.9"];
var _fbCache = /* @__PURE__ */ new Map();
function _fbGetCache(key) {
  const e = _fbCache.get(key);
  if (!e) return null;
  if (Date.now() > e.exp) {
    _fbCache.delete(key);
    return null;
  }
  return e.val;
}
__name(_fbGetCache, "_fbGetCache");
function _fbSetCache(key, val, ttlSecs) {
  _fbCache.set(key, { val, exp: Date.now() + ttlSecs * 1e3 });
}
__name(_fbSetCache, "_fbSetCache");
async function _fbJitter() {
  await new Promise((r) => setTimeout(r, Math.random() * 120 + 30));
}
__name(_fbJitter, "_fbJitter");
function _fbBuildHeaders(mode) {
  const ua = _FB_UA_POOL[Math.floor(Math.random() * _FB_UA_POOL.length)];
  const lang = _FB_LANG_POOL[Math.floor(Math.random() * _FB_LANG_POOL.length)];
  const h = {
    "User-Agent": ua,
    "Accept-Language": lang,
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Referer": `${_FB_ORIGIN}/`,
    "Origin": _FB_ORIGIN,
    "DNT": "1"
  };
  if (mode === "json") {
    h["Accept"] = "application/json, text/plain, */*";
    h["sec-fetch-dest"] = "empty";
    h["sec-fetch-mode"] = "cors";
    h["sec-fetch-site"] = "same-origin";
  }
  if (mode === "image") {
    h["Accept"] = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8";
    h["sec-fetch-dest"] = "image";
    h["sec-fetch-mode"] = "no-cors";
    h["sec-fetch-site"] = "same-origin";
  }
  return h;
}
__name(_fbBuildHeaders, "_fbBuildHeaders");
async function _fbUpstream(url, mode) {
  return fetch(url, { headers: _fbBuildHeaders(mode), cf: { cacheTtl: 0 } });
}
__name(_fbUpstream, "_fbUpstream");
function _fbRewrite(obj, base) {
  if (typeof obj === "string") {
    return obj.replace(/https?:\/\/streamed\.pk\/api\/images\/proxy\//g, `${base}/football/image/`).replace(/^\/api\/images\/proxy\//g, `${base}/football/image/`);
  }
  if (Array.isArray(obj)) return obj.map((i) => _fbRewrite(i, base));
  if (obj && typeof obj === "object") {
    const r = {};
    for (const [k, v] of Object.entries(obj)) r[k] = _fbRewrite(v, base);
    return r;
  }
  return obj;
}
__name(_fbRewrite, "_fbRewrite");
function _fbJsonResp(body) {
  return new Response(body, { headers: { "Content-Type": "application/json", ...CORS } });
}
__name(_fbJsonResp, "_fbJsonResp");
async function _fbHandleMatches(url) {
  const workerBase = `${url.protocol}//${url.host}`;
  const key = "fb:matches";
  const cached = _fbGetCache(key);
  if (cached) return _fbJsonResp(cached);
  await _fbJitter();
  const r = await _fbUpstream(`${_FB_ORIGIN}/api/matches/football`, "json");
  if (!r.ok) return new Response(JSON.stringify({ error: "Upstream unavailable" }), { status: r.status, headers: { "Content-Type": "application/json", ...CORS } });
  const raw = await r.json();
  const body = JSON.stringify(_fbRewrite(raw, workerBase));
  _fbSetCache(key, body, 30);
  return _fbJsonResp(body);
}
__name(_fbHandleMatches, "_fbHandleMatches");
async function _fbHandleStreams(source, id) {
  const key = `fb:stream:${source}:${id}`;
  const cached = _fbGetCache(key);
  if (cached) return _fbJsonResp(cached);
  await _fbJitter();
  const r = await _fbUpstream(`${_FB_ORIGIN}/api/stream/${source}/${id}`, "json");
  if (!r.ok) return new Response(JSON.stringify({ error: "Upstream unavailable" }), { status: r.status, headers: { "Content-Type": "application/json", ...CORS } });
  const raw = await r.json().catch(() => null);
  const body = raw ? JSON.stringify(raw) : "[]";
  _fbSetCache(key, body, 12);
  return _fbJsonResp(body);
}
__name(_fbHandleStreams, "_fbHandleStreams");
async function _fbHandleImage(encoded) {
  if (!encoded) return new Response("Not found", { status: 404, headers: CORS });
  const key = `fb:img:${encoded}`;
  const cached = _fbGetCache(key);
  if (cached) return new Response(cached.buf, { headers: { ...CORS, "Content-Type": cached.type, "Cache-Control": "public, max-age=604800" } });
  await _fbJitter();
  const r = await _fbUpstream(`${_FB_ORIGIN}/api/images/proxy/${encoded}`, "image");
  if (!r.ok) return new Response("Not found", { status: 404, headers: CORS });
  const type = r.headers.get("Content-Type") || "image/webp";
  const buf = await r.arrayBuffer();
  if (buf.byteLength < 200 * 1024) _fbSetCache(key, { buf, type }, 7 * 24 * 3600);
  return new Response(buf, { headers: { ...CORS, "Content-Type": type, "Cache-Control": "public, max-age=604800" } });
}
__name(_fbHandleImage, "_fbHandleImage");
async function runExpiryNotifications(env) {
  try {
    await initDB(env.DB);
    const rows = (await env.DB.prepare(
      `SELECT a.app_id, a.device_id, a.telegram_username, a.expiry, ap.display_name
       FROM app_activations a
       LEFT JOIN apps ap ON a.app_id = ap.app_id
       WHERE a.is_active = 1
         AND a.expiry != '2080'
         AND datetime(a.expiry) <= datetime('now')
         AND a.expired_notified = 0`
    ).all()).results || [];
    for (const row of rows) {
      try {
        if (row.telegram_username) {
          const msg = buildExpiredMessage(row.telegram_username, row.expiry, row.display_name || row.app_id);
          await sendMessage(BOT_TOKEN, GROUP_ID_DEFAULT, msg);
        }
      } catch (e) {
      }
      await env.DB.prepare(
        "UPDATE app_activations SET expired_notified = 1 WHERE app_id = ? AND device_id = ?"
      ).bind(row.app_id, row.device_id).run();
    }
  } catch (e) {
    console.error("Expiry cron error:", e);
  }
}
__name(runExpiryNotifications, "runExpiryNotifications");
export {
  worker_default as default
};