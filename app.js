// Singo web: Spotify login (PKCE, no server), card dealing, printable cards, host mode.
// Everything runs in the browser; saved games live in this browser's localStorage.

// ---------------------------------------------------------------- config
const CLIENT_ID = "279a8d973bf24f8e9cefe3fdb898ec95";
const SCOPES = "playlist-read-private playlist-read-collaborative user-read-currently-playing";
const REDIRECT_URI = (location.origin + location.pathname).replace(/index\.html$/, "");
const MIN_SONGS = 40;
const RECOMMENDED_SONGS = 75;
const MAX_CARDS = 300;
const COPY_TIP = "To use one anyway, open it in Spotify, select all the songs, and choose Add to playlist → New playlist. Then pick your copy here.";
const FORBIDDEN_MSG = "Spotify won't share this playlist's songs with the app. Use a playlist you created (or copy this one into a new playlist of yours) and try again.";
const forbidden = () => Object.assign(new Error(FORBIDDEN_MSG), { forbidden: true });

// ---------------------------------------------------------------- utils
const app = document.getElementById("app");
const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtDate = (iso) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });

const store = {
  get(key, fallback = null) {
    try { const v = localStorage.getItem("singo." + key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
  },
  set(key, value) {
    try {
      if (value == null) localStorage.removeItem("singo." + key);
      else localStorage.setItem("singo." + key, JSON.stringify(value));
      return true;
    } catch { return false; }
  },
};

function toast(msg, ms = 6000) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), ms);
}
const showError = (e) => toast(e?.message || String(e), 9000);

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffle(arr, rnd) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ---------------------------------------------------------------- spotify auth (PKCE)
const randomString = (n) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from(crypto.getRandomValues(new Uint8Array(n)), (x) => chars[x % chars.length]).join("");
};
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const loggedIn = () => !!store.get("auth");

async function login() {
  const verifier = randomString(64);
  const st = randomString(16);
  store.set("pkce", { verifier, state: st, returnTo: location.hash });
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const params = new URLSearchParams({
    client_id: CLIENT_ID, response_type: "code", redirect_uri: REDIRECT_URI,
    code_challenge_method: "S256", code_challenge: challenge, state: st, scope: SCOPES,
  });
  location.href = "https://accounts.spotify.com/authorize?" + params;
}

function logout() {
  store.set("auth", null);
  state.me = null;
  state.meId = null;
  state.playlists = null;
  meRequest = null;
}

/** Finishes login when Spotify sends the browser back with ?code=… */
async function handleRedirect() {
  const q = new URLSearchParams(location.search);
  if (!q.has("code") && !q.has("error")) return;
  const pkce = store.get("pkce");
  store.set("pkce", null);
  history.replaceState(null, "", REDIRECT_URI + (pkce?.returnTo || ""));
  if (q.get("error")) {
    throw new Error(q.get("error") === "access_denied" ? "Spotify login was cancelled." : "Spotify login failed: " + q.get("error"));
  }
  if (!pkce || pkce.state !== q.get("state")) throw new Error("That login link expired. Click Connect Spotify again.");
  await tokenRequest({
    grant_type: "authorization_code", code: q.get("code"), redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID, code_verifier: pkce.verifier,
  });
  toast("Connected to Spotify 🐟", 3000);
}

async function tokenRequest(params) {
  const res = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("Spotify sign-in failed: " + (data.error_description || data.error || `HTTP ${res.status}`));
    err.auth = true;
    throw err;
  }
  const prev = store.get("auth") || {};
  store.set("auth", {
    access: data.access_token,
    refresh: data.refresh_token || prev.refresh,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
}

let refreshing = null;
async function accessToken() {
  const auth = store.get("auth");
  if (!auth) throw new Error("Connect Spotify first.");
  if (auth.access && Date.now() < auth.expiresAt - 60_000) return auth.access;
  refreshing ??= tokenRequest({ grant_type: "refresh_token", refresh_token: auth.refresh, client_id: CLIENT_ID })
    .catch((e) => { if (e.auth) { logout(); route(); } throw e; })
    .finally(() => { refreshing = null; });
  await refreshing;
  return store.get("auth").access;
}

async function api(path, retried = false) {
  const url = path.startsWith("https://") ? path : "https://api.spotify.com/v1" + path;
  const res = await fetch(url, { headers: { Authorization: "Bearer " + (await accessToken()) } });
  if (res.status === 204) return null;
  if (res.status === 401 && !retried) {
    const auth = store.get("auth");
    if (auth) store.set("auth", { ...auth, expiresAt: 0 });
    return api(path, true);
  }
  if (res.status === 429) throw new Error("Spotify is asking us to slow down. Wait a few seconds and try again.");
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.error?.message ? `Spotify said: ${data.error.message}` : `Spotify error ${res.status}`);
    err.status = res.status;
    throw err;
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// ---------------------------------------------------------------- spotify data
async function myPlaylists() {
  const all = [];
  let next = "/me/playlists?limit=50";
  while (next) {
    const page = await api(next);
    all.push(...page.items.filter(Boolean));
    next = page.next;
  }
  return all;
}

async function getPlaylist(id) {
  try {
    return await api(`/playlists/${id}`);
  } catch (e) {
    if (e.status === 403 || e.status === 404) throw forbidden();
    throw e;
  }
}

const trackCount = (p) => p.items?.total ?? p.tracks?.total ?? null;
const playlistImage = (p) => p.images?.[0]?.url || "";

function cleanTitle(title) {
  const t = title
    .replace(/\s+-\s+.*(remaster|version|edit|mono|stereo|live|mix|from|deluxe|anniversary).*$/i, "")
    .replace(/\s*[(\[](feat\.?|ft\.?|with)\s[^)\]]*[)\]]/gi, "")
    .replace(/\s*[(\[][^)\]]*remaster[^)\]]*[)\]]/gi, "")
    .trim();
  return t || title;
}
const matchKey = (s) => `${s.title.toLowerCase()}|${s.artist.toLowerCase()}`;

function toSong(track) {
  if (!track || !track.id || track.is_local || (track.type ?? "track") !== "track" || !track.name) return null;
  const artist = (track.artists || []).map((a) => a?.name).filter(Boolean).slice(0, 2).join(", ");
  return { id: track.id, title: cleanTitle(track.name), artist };
}

async function playlistSongs(id) {
  const tracks = [];
  let next = `/playlists/${id}/items?limit=100`;
  let triedLegacy = false;
  while (next) {
    try {
      const page = await api(next);
      tracks.push(...page.items.map((e) => e?.item ?? e?.track).filter(Boolean));
      next = page.next;
    } catch (e) {
      if (e.status === 404 && !triedLegacy && !tracks.length) {
        triedLegacy = true;
        next = `/playlists/${id}/tracks?limit=100`;
        continue;
      }
      if (e.status === 403) throw forbidden();
      throw e;
    }
  }
  const ids = new Set(), keys = new Set();
  return tracks.map(toSong).filter((s) => s && !ids.has(s.id) && !keys.has(matchKey(s)) && ids.add(s.id) && keys.add(matchKey(s)));
}

let meRequest = null;
/** The signed-in user's Spotify profile, fetched once. */
function getMe() {
  meRequest ??= api("/me")
    .then((me) => { state.me = me?.display_name || null; state.meId = me?.id || null; return me; })
    .catch((e) => { meRequest = null; throw e; });
  return meRequest;
}
const ownsPlaylist = (p) => !!state.meId && p?.owner?.id === state.meId;

async function nowPlaying() {
  const data = await api("/me/player/currently-playing");
  return data?.item ? toSong(data.item) : null;
}

function playlistIdFrom(text) {
  const s = text.trim();
  const m = s.match(/playlist[/:]([A-Za-z0-9]{22})/);
  if (m) return m[1];
  return /^[A-Za-z0-9]{22}$/.test(s) ? s : null;
}

// ---------------------------------------------------------------- games
const Games = {
  all: () => store.get("games", []),
  get: (id) => Games.all().find((g) => g.id === id),
  save(list) { if (!store.set("games", list)) toast("Couldn't save. This browser's storage is full."); },
  add(game) { Games.save([game, ...Games.all()]); },
  update(id, fn) {
    const list = Games.all();
    const g = list.find((x) => x.id === id);
    if (g) { fn(g); Games.save(list); }
    return g;
  },
  remove(id) { Games.save(Games.all().filter((g) => g.id !== id)); },
};
const gameName = (g) => g.customName || g.playlistName;

/** Deals unique cards, spreading songs evenly so no song is on far more cards than another. */
function makeCards(songCount, count, freeSpace, seed) {
  const perCard = freeSpace ? 24 : 25;
  const rnd = mulberry32(seed);
  const usage = new Array(songCount).fill(0);
  const seen = new Set();
  const cards = [];
  let attempts = 0;
  while (cards.length < count && attempts < count * 100) {
    attempts++;
    const ranked = shuffle([...Array(songCount).keys()], rnd)
      .map((s, i) => ({ s, i, k: usage[s] + (rnd() < 0.5 ? 0 : 1) }))
      .sort((a, b) => a.k - b.k || a.i - b.i);
    const picks = ranked.slice(0, perCard).map((x) => x.s);
    const key = [...picks].sort((a, b) => a - b).join(",");
    if (seen.has(key) && songCount > perCard) continue;
    seen.add(key);
    picks.forEach((s) => usage[s]++);
    const cells = shuffle(picks, rnd);
    if (freeSpace) cells.splice(12, 0, null);
    cards.push({ number: cards.length + 1, cells });
  }
  return cards;
}

function makeGame(playlistID, playlistName, songs, cardCount, freeSpace) {
  const seed = crypto.getRandomValues(new Uint32Array(1))[0];
  const rnd = mulberry32(seed ^ 0x5bd1e995);
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    playlistID, playlistName, customName: null, songs,
    cards: makeCards(songs.length, cardCount, freeSpace, seed),
    freeSpace,
    code: Array.from({ length: 4 }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join(""),
    played: [],
    pattern: "line",
  };
}

const rows = [0, 1, 2, 3, 4].map((r) => [0, 1, 2, 3, 4].map((c) => r * 5 + c));
const cols = [0, 1, 2, 3, 4].map((c) => [0, 1, 2, 3, 4].map((r) => r * 5 + c));
const PATTERNS = {
  line: { title: "Any line", groups: [...rows, ...cols, [0, 6, 12, 18, 24], [4, 8, 12, 16, 20]] },
  fourCorners: { title: "Four corners", groups: [[0, 4, 20, 24]] },
  x: { title: "Big X", groups: [[0, 6, 12, 18, 24, 4, 8, 16, 20]] },
  blackout: { title: "Blackout", groups: [[...Array(25).keys()]] },
};
const marks = (g, card, played) => card.cells.map((i) => i == null || played.has(g.songs[i].id));
function winningCells(g, card, played) {
  const m = marks(g, card, played);
  const win = new Set();
  for (const group of PATTERNS[g.pattern].groups) if (group.every((i) => m[i])) group.forEach((i) => win.add(i));
  return win;
}
function songsAway(g, card, played) {
  const m = marks(g, card, played);
  return Math.min(...PATTERNS[g.pattern].groups.map((grp) => grp.filter((i) => !m[i]).length));
}
function winningCards(g) {
  const p = new Set(g.played);
  return g.cards.filter((c) => winningCells(g, c, p).size).map((c) => c.number);
}
const songMatching = (g, s) => g.songs.find((x) => x.id === s.id) || g.songs.find((x) => matchKey(x) === matchKey(s));

function demoSongs(count = 80) {
  const first = ["Tidepool", "Neon", "Paper", "Golden", "Midnight", "Coral", "Velvet", "Glass", "Silver", "Lonely", "Electric", "Salty"];
  const second = ["Heart", "Kingdom", "Summer", "Highway", "Lagoon", "Bubbles", "Dance", "Telephone", "Lullaby", "Parade", "Echo"];
  const artists = ["The Guppies", "Bettafish", "Angelfish & The Tetras", "Koi Division", "Neon Tetra", "Plecostomus Jones", "The Snails", "Sea Monkeys"];
  const titles = ["Everybody Wants to Live in a Fishbowl Tonight", "(Don't Let Me) Swim Away", "Hey"];
  for (const a of first) for (const b of second) if (titles.length < count) titles.push(`${a} ${b}`);
  return titles.map((t, i) => ({ id: `demo-${i}`, title: t, artist: artists[i % artists.length] }));
}

// ---------------------------------------------------------------- drawing helpers
/** Minimalist fish facing right inside (x, y, w, h). Fill with fill-rule evenodd so the eye is a hole. */
function fishPath(x, y, w, h) {
  const midY = y + h / 2, bl = x + w * 0.30, bu = x + w * 0.64;
  const d = h * 0.13, r = d / 2, ex = x + w * 0.80 - r, ey = midY - h * 0.12;
  const f = (n) => +n.toFixed(2);
  return `M${f(x + w)} ${f(midY)} Q${f(bu)} ${f(y - h * 0.15)} ${f(bl)} ${f(midY)} Q${f(bu)} ${f(y + h * 1.15)} ${f(x + w)} ${f(midY)} Z ` +
    `M${f(bl)} ${f(midY)} L${f(x)} ${f(y + h * 0.12)} L${f(x + w * 0.08)} ${f(midY)} L${f(x)} ${f(y + h * 0.88)} Z ` +
    `M${f(ex)} ${f(ey)} a${f(r)} ${f(r)} 0 1 0 ${f(d)} 0 a${f(r)} ${f(r)} 0 1 0 ${f(-d)} 0 Z`;
}
const fishSVG = (w = 80, color = "#F28B5B") =>
  `<svg viewBox="0 0 68 40" width="${w}" aria-hidden="true"><path d="${fishPath(0, 0, 68, 40)}" fill="${color}" fill-rule="evenodd"/></svg>`;

// ---------------------------------------------------------------- printable cards
const fitCache = new Map();
let measureEl = null;
const songHTML = (s, size) =>
  `<div class="t" style="font-size:${size}pt">${esc(s.title)}</div>` +
  (s.artist ? `<div class="a" style="font-size:${Math.max(6, size * 0.72).toFixed(1)}pt">${esc(s.artist)}</div>` : "");

/** Largest font size (pt) at which a song's title + artist fit inside a card cell. */
function fitSong(song) {
  const key = song.title + "|" + song.artist;
  if (fitCache.has(key)) return fitCache.get(key);
  if (!measureEl) {
    const wrap = document.createElement("div");
    wrap.id = "measure";
    wrap.innerHTML = `<div class="cell-text"></div>`;
    document.body.appendChild(wrap);
    measureEl = wrap.firstChild;
  }
  const maxPx = 79.2 * 96 / 72;
  let result = { size: 6, squeeze: true };
  for (let size = 13.5; size >= 6; size -= 0.5) {
    measureEl.innerHTML = songHTML(song, size);
    if (measureEl.offsetHeight <= maxPx && measureEl.scrollWidth <= measureEl.clientWidth + 0.5) {
      result = { size, squeeze: false };
      break;
    }
  }
  fitCache.set(key, result);
  return result;
}

function tankSVG(seed) {
  const top = 112;
  let wave = `M40 ${top}`;
  for (let x = 40; x <= 572; x += 2) wave += ` L${x} ${(top + 3 * Math.sin(((x - 40) / 38) * 2 * Math.PI)).toFixed(2)}`;
  const tank = "M40 92 H572 V732 Q572 752 552 752 H60 Q40 752 40 732 Z";
  const rnd = mulberry32(seed * 7919 + 17);
  let pebbles = "";
  for (let x = 54; x < 558;) {
    const w = 7 + rnd() * 6, h = 4 + rnd() * 3, y = 752 - 6 - h - rnd() * 7;
    pebbles += `<ellipse cx="${(x + w / 2).toFixed(1)}" cy="${(y + h / 2).toFixed(1)}" rx="${(w / 2).toFixed(1)}" ry="${(h / 2).toFixed(1)}" fill="#CFDCDA"/>`;
    x += w * (0.7 + rnd() * 0.4);
  }
  const weed = [[62, 46, 1], [546, 38, -1]].map(([b, h, l]) =>
    `<path d="M${b} 742 C${b + 9 * l} ${742 - h * 0.35} ${b - 7 * l} ${742 - h * 0.65} ${b + 4 * l} ${742 - h}" fill="none" stroke="#3A9AA6" stroke-width="1.4" stroke-linecap="round"/>`).join("");
  return `<svg class="tank" viewBox="0 0 612 792" aria-hidden="true">
    <path d="${wave} L572 732 Q572 752 552 752 L60 752 Q40 752 40 732 Z" fill="#F0F8F7"/>
    ${pebbles}${weed}
    <path d="${wave}" fill="none" stroke="#3A9AA6" stroke-width="1.2"/>
    <path d="${tank}" fill="none" stroke="#163C46" stroke-width="1.6"/>
    <rect x="32" y="82" width="548" height="8" rx="3" fill="#163C46"/>
  </svg>`;
}

function freeSVG() {
  const W = 94.8, m = W / 2;
  const bubbles = [[0.36, -0.30, 3.2], [0.42, -0.40, 2.2], [0.34, -0.46, 1.5]]
    .map(([dx, dy, r]) => `<circle cx="${(m + W * dx).toFixed(1)}" cy="${(m + W * dy).toFixed(1)}" r="${r}" fill="none" stroke="#3A9AA6" stroke-width=".9"/>`).join("");
  return `<svg viewBox="0 0 ${W} ${W}" aria-hidden="true">
    <path d="${fishPath(m - W * 0.30, m - W * 0.24, W * 0.56, W * 0.33)}" fill="#F28B5B" fill-rule="evenodd"/>${bubbles}
    <text x="${m + 1.5}" y="${(m + W * 0.16 + 11).toFixed(1)}" text-anchor="middle" font-family="Nunito, sans-serif" font-weight="900" font-size="11" letter-spacing="3" fill="#163C46">FREE</text>
  </svg>`;
}

function sheetHTML(g, card) {
  const digits = Math.max(3, String(g.cards.length).length);
  const cells = card.cells.map((i) => {
    if (i == null) return `<div class="cell free">${freeSVG()}</div>`;
    const s = g.songs[i];
    const fit = fitSong(s);
    return `<div class="cell"><div class="cell-text${fit.squeeze ? " squeeze" : ""}">${songHTML(s, fit.size)}</div></div>`;
  }).join("");
  return `<div class="sheet">
    ${tankSVG(card.number)}
    <div class="brand">FISHBOWL&nbsp;&nbsp;·&nbsp;&nbsp;SONG BINGO</div>
    <div class="cardno">CARD ${String(card.number).padStart(digits, "0")}</div>
    <div class="letters">${[..."SINGO"].map((l) => `<span>${l}</span>`).join("")}</div>
    <div class="grid">${cells}</div>
    <div class="foot">${esc(gameName(g))}&nbsp;&nbsp;·&nbsp;&nbsp;game ${esc(g.code)}</div>
  </div>`;
}

async function fontsReady() {
  try {
    await Promise.all(["800 13pt Nunito", "600 9pt Nunito", "900 34pt Nunito", "700 9pt Nunito"].map((f) => document.fonts.load(f)));
  } catch { /* fall back to whatever font is there */ }
}

// ---------------------------------------------------------------- state + router
const state = {
  me: null,
  meId: null,
  playlists: null,
  setup: null,       // { playlist, songs }
  hostTab: "songs",
  search: "",
  cardNumber: "",
  follow: false,
  nowPlaying: null,
};
let followTimer = null;
let wakeLock = null;

function setFollow(on) {
  state.follow = on;
  clearInterval(followTimer);
  followTimer = null;
  wakeLock?.release?.().catch(() => {});
  wakeLock = null;
  if (on) {
    pollNowPlaying();
    followTimer = setInterval(pollNowPlaying, 4000);
    navigator.wakeLock?.request("screen").then((l) => { wakeLock = l; }).catch(() => {});
  } else {
    state.nowPlaying = null;
  }
}

async function pollNowPlaying() {
  const id = currentGameId();
  try {
    const song = await nowPlaying();
    state.nowPlaying = song;
    const g = id && Games.get(id);
    const match = g && song && songMatching(g, song);
    if (match && !g.played.includes(match.id)) Games.update(id, (x) => x.played.push(match.id));
  } catch (e) {
    state.nowPlaying = null;
    if (e.auth || e.status === 403) { setFollow(false); showError(e); }
  }
  if (location.hash.startsWith("#/host/")) refreshHost();
}

const currentGameId = () => location.hash.split("/")[2] || null;

function route() {
  const [view = "", id] = location.hash.replace(/^#\/?/, "").split("/");
  if (view !== "host" && state.follow) setFollow(false);
  window.scrollTo(0, 0);
  switch (view) {
    case "pick": return viewPick();
    case "setup": return viewSetup(id);
    case "game": return viewGame(id);
    case "host": return viewHost(id);
    default: return viewHome();
  }
}
window.addEventListener("hashchange", route);

// ---------------------------------------------------------------- views
const back = (href, label = "Back") => `<a class="back" href="${href}">‹ ${esc(label)}</a>`;

function viewHome() {
  const games = Games.all();
  app.innerHTML = `
    <header class="hero">
      ${fishSVG(80)}
      <h1>SINGO</h1>
      <p>song bingo at the Fishbowl</p>
    </header>

    <section class="panel">
      <h2>New game</h2>
      ${loggedIn() ? `
        <p>Pick a playlist with at least ${MIN_SONGS} songs and we'll deal out cards that are all different.</p>
        <a class="btn" href="#/pick">Choose a playlist</a>
        <p class="small">Signed in${state.me ? ` as ${esc(state.me)}` : ""} · <button class="link" data-action="logout">Disconnect Spotify</button></p>
      ` : `
        <p>Connect Spotify to pull in your playlists.</p>
        <button class="btn" data-action="login">Connect Spotify</button>
      `}
      <button class="btn ghost" data-action="demo">Try a demo game (fake songs)</button>
    </section>

    ${games.length ? `
    <section class="panel">
      <h2>Your games</h2>
      <ul class="rows">
        ${games.map((g) => `<li><a class="row" href="#/game/${g.id}">
          <span class="code">${esc(g.code)}</span>
          <span class="grow"><b>${esc(gameName(g))}</b><small>${g.cards.length} cards · ${fmtDate(g.createdAt)}</small></span>
          <span class="chev">›</span></a></li>`).join("")}
      </ul>
    </section>` : ""}

    <section class="panel">
      <h2>How to play</h2>
      <ol class="tips">
        <li>Pick a playlist and deal the cards. Print them.</li>
        <li>Hand out cards. Shuffle the playlist in Spotify and hit play.</li>
        <li>Players mark songs they hear. First to complete the pattern yells SINGO!</li>
        <li>Open Host mode to track played songs and check card numbers.</li>
      </ol>
    </section>`;
}

async function viewPick() {
  if (!loggedIn()) { location.hash = "#/"; return; }
  app.innerHTML = `
    ${back("#/")}
    <h1 class="title">Pick a playlist</h1>
    <section class="panel">
      <h2>Paste a link</h2>
      <form class="inline" data-form="link">
        <input name="link" placeholder="open.spotify.com/playlist/…" autocomplete="off" aria-label="Spotify playlist link">
        <button class="btn small">Use</button>
      </form>
    </section>
    <section class="panel">
      <h2>Your playlists</h2>
      <input type="search" class="search" placeholder="Search playlists" data-input="plsearch" aria-label="Search playlists">
      <ul class="rows" id="pl-list"><li class="muted">Loading…</li></ul>
    </section>`;
  try {
    const [playlists] = await Promise.all([state.playlists ?? myPlaylists(), getMe()]);
    state.playlists = playlists;
    renderPlaylistList("");
  } catch (e) {
    showError(e);
    const list = $("#pl-list");
    if (list) list.innerHTML = `<li class="muted">Couldn't load playlists.</li>`;
  }
}

function renderPlaylistList(filter) {
  const list = $("#pl-list");
  if (!list || !state.playlists) return;
  // Only show playlists this user owns. Spotify blocks the app from reading anyone else's.
  const mine = state.playlists.filter(ownsPlaylist);
  const hidden = state.playlists.length - mine.length;
  const items = mine.filter((p) => p.name.toLowerCase().includes(filter.toLowerCase()));
  const hint = hidden
    ? `<li class="hint">${hidden} playlist${hidden === 1 ? "" : "s"} made by other people ${hidden === 1 ? "is" : "are"} hidden. Spotify only lets Singo read playlists you created. ${COPY_TIP}</li>`
    : "";
  list.innerHTML = (items.length ? items.map((p) => {
    const n = trackCount(p);
    const short = n != null && n < MIN_SONGS;
    return `<li><a class="row${short ? " dim" : ""}" href="#/setup/${p.id}">
      ${playlistImage(p) ? `<img class="art" src="${esc(playlistImage(p))}" alt="" loading="lazy">` : `<span class="art"></span>`}
      <span class="grow"><b>${esc(p.name)}</b><small class="${short ? "warn" : ""}">${n == null ? esc(p.owner?.display_name || "") : `${n} songs${short ? " · too short" : ""}`}</small></span>
      <span class="chev">›</span></a></li>`;
  }).join("") : `<li class="muted">No playlists of yours found.</li>`) + hint;
}

async function viewSetup(id) {
  if (!loggedIn()) { location.hash = "#/"; return; }
  const cached = state.playlists?.find((p) => p.id === id);
  state.setup = { playlist: cached || null, songs: null, notMine: false };
  renderSetup();
  try {
    const [playlist] = await Promise.all([cached || getPlaylist(id), getMe()]);
    if (currentSetupId() !== id) return;
    state.setup.playlist = playlist;
    // Spotify only lets this app read playlists the signed-in user owns, so stop here
    // with an explanation instead of an error.
    if (!ownsPlaylist(playlist)) {
      state.setup.notMine = true;
      return renderSetup();
    }
    renderSetup();
    const songs = await playlistSongs(id);
    if (currentSetupId() !== id) return;
    state.setup.songs = songs;
    renderSetup();
  } catch (e) {
    if (e.forbidden && currentSetupId() === id) {
      state.setup.notMine = true;
      return renderSetup();
    }
    showError(e);
  }
}
const currentSetupId = () => location.hash.startsWith("#/setup/") ? location.hash.split("/")[2] : null;

function renderSetup() {
  const { playlist, songs, notMine } = state.setup;
  if (notMine) {
    app.innerHTML = `
      ${back("#/pick")}
      <section class="panel">
        <h2>Singo can't use this playlist</h2>
        <p>${playlist ? `“${esc(playlist.name)}” was made by ${esc(playlist.owner?.display_name || "someone else")}. ` : ""}Spotify only lets Singo read playlists you created yourself.</p>
        <p>${COPY_TIP}</p>
        <a class="btn ghost" href="#/pick">Pick another playlist</a>
      </section>`;
    return;
  }
  const count = store.get("cardCount", 40);
  const freeSpace = store.get("freeSpace", true);
  const perCard = freeSpace ? 24 : 25;
  app.innerHTML = `
    ${back("#/pick")}
    <section class="panel head">
      ${playlist && playlistImage(playlist) ? `<img class="art big" src="${esc(playlistImage(playlist))}" alt="">` : `<span class="art big"></span>`}
      <div>
        <h1>${esc(playlist?.name || "Loading…")}</h1>
        <p>${songs ? `${songs.length} playable songs` : "Reading the playlist…"}</p>
      </div>
    </section>
    ${!songs ? "" : songs.length < MIN_SONGS ? `
      <section class="panel">
        <h2>Needs more songs</h2>
        <p>Singo needs at least ${MIN_SONGS} songs (this one has ${songs.length} once duplicates, podcasts and local files are skipped). Add ${MIN_SONGS - songs.length} more in Spotify and come back.</p>
      </section>` : `
      <section class="panel">
        <h2>Cards</h2>
        <div class="count-row">
          <input type="number" min="1" max="${MAX_CARDS}" value="${count}" data-input="count" id="count" aria-label="Number of cards">
          <label for="count">cards</label>
        </div>
        <div class="chips">${[20, 40, 60, 100].map((n) => `<button class="chip${n === count ? " on" : ""}" data-action="count" data-n="${n}">${n}</button>`).join("")}</div>
        <label class="check"><input type="checkbox" data-input="free" ${freeSpace ? "checked" : ""}> Free space in the middle</label>
        <p class="small">Each card uses ${perCard} of ${songs.length} songs (${Math.round((perCard / songs.length) * 100)}%).${songs.length < RECOMMENDED_SONGS ? ` With ${RECOMMENDED_SONGS}+ songs, games last longer and fewer people win at once.` : ""}</p>
        <button class="btn" data-action="deal">Deal ${count} cards</button>
      </section>`}
    ${songs ? `
      <section class="panel songs-preview">
        <h2>In the tank</h2>
        ${songs.slice(0, 8).map((s) => `<div><b>${esc(s.title)}</b><span>${esc(s.artist)}</span></div>`).join("")}
        ${songs.length > 8 ? `<p class="small">…and ${songs.length - 8} more</p>` : ""}
      </section>` : ""}`;
}

async function viewGame(id) {
  const g = Games.get(id);
  if (!g) { app.innerHTML = `${back("#/", "Home")}<section class="panel"><p>This game swam away.</p></section>`; return; }
  app.innerHTML = `
    ${back("#/", "Home")}
    <section class="panel">
      <div class="name-row">
        <h1>${esc(gameName(g))}</h1>
        <button class="link" data-action="rename">Rename</button>
      </div>
      ${g.customName ? `<p class="small">Playlist: ${esc(g.playlistName)}</p>` : ""}
      <div class="stats">
        <div class="stat"><b>${g.cards.length}</b><span>cards</span></div>
        <div class="stat"><b>${g.songs.length}</b><span>songs</span></div>
        <div class="stat"><b>${esc(g.code)}</b><span>game code</span></div>
      </div>
    </section>

    <section class="panel">
      <h2>Print the cards</h2>
      <p>One card per page on US Letter paper. This opens your browser's print dialog.</p>
      <ul class="tips">
        <li>Choose your printer, or <b>Save as PDF</b> to keep a file.</li>
        <li>Under <i>More settings</i>: Margins <b>None</b>, turn on <b>Background graphics</b>, turn off <b>Headers and footers</b>.</li>
      </ul>
      <button class="btn" data-action="print" id="print-btn" disabled>Preparing cards…</button>
      <div class="preview" id="preview"></div>
    </section>

    <section class="panel">
      <h2>Play</h2>
      <p>Turn on shuffle in Spotify, hit play, and keep Host mode open to track songs and check winners.</p>
      ${g.playlistID.startsWith("demo") ? "" : `<a class="btn ghost" href="https://open.spotify.com/playlist/${esc(g.playlistID)}" target="_blank" rel="noopener">Open playlist in Spotify ↗</a>`}
      <a class="btn" href="#/host/${g.id}">Host the game</a>
    </section>

    <p style="text-align:center"><button class="link danger" data-action="delete">Delete this game</button></p>`;

  await fontsReady();
  if (currentGameId() !== id) return;
  $("#print-root").innerHTML = g.cards.map((c) => sheetHTML(g, c)).join("");
  $("#preview").innerHTML = g.cards.slice(0, 2).map((c) => sheetHTML(g, c)).join("") +
    `<p class="small">Preview of ${Math.min(2, g.cards.length)} of ${g.cards.length} cards</p>`;
  const btn = $("#print-btn");
  btn.disabled = false;
  btn.textContent = `Print ${g.cards.length} cards`;
}

function viewHost(id) {
  const g = Games.get(id);
  if (!g) { location.hash = "#/"; return; }
  state.search = "";
  state.cardNumber = "";
  app.innerHTML = `
    ${back(`#/game/${id}`, gameName(g))}
    <h1 class="title">Host mode</h1>
    <section class="panel" id="host-status"></section>
    <div class="tabs" role="tablist">
      <button role="tab" data-action="tab" data-tab="songs">Songs</button>
      <button role="tab" data-action="tab" data-tab="check">Check a card</button>
    </div>
    <section class="panel" id="host-songs">
      <input type="search" class="search" placeholder="Find a song" data-input="songsearch" aria-label="Find a song">
      <p class="small">Click a song to mark it played (or unmark it).</p>
      <div id="host-list"></div>
    </section>
    <section class="panel" id="host-check">
      <div class="card-input"><label for="cardno">Card #</label>
        <input id="cardno" type="number" min="1" inputmode="numeric" placeholder="e.g. 12" data-input="cardno"></div>
      <div id="host-card"></div>
    </section>
    <p style="text-align:center"><button class="link" data-action="reset">Reset played songs</button></p>`;
  refreshHost();
}

function refreshHost() {
  const id = currentGameId();
  const g = Games.get(id);
  if (!g || !$("#host-status")) return;
  const played = new Set(g.played);
  const winners = winningCards(g);
  const isDemo = g.playlistID.startsWith("demo");

  $("#host-status").innerHTML = `
    <div class="status-top">
      <span class="big-num">${g.played.length}</span><span class="muted">of ${g.songs.length} songs played</span>
      <select data-input="pattern" aria-label="Winning pattern">
        ${Object.entries(PATTERNS).map(([k, p]) => `<option value="${k}" ${k === g.pattern ? "selected" : ""}>${p.title}</option>`).join("")}
      </select>
    </div>
    <div class="winners">
      ${winners.length ? `<b>SINGO possible on ${winners.length === 1 ? "card" : "cards"}:</b>
        <div class="chips">${winners.map((n) => `<button class="chip fish" data-action="check" data-n="${n}">#${n}</button>`).join("")}</div>`
        : `<span class="muted">No winning cards yet.</span>`}
    </div>
    ${isDemo ? "" : `
    <label class="follow">
      <span><b>Follow Spotify</b><small>${esc(followCaption())}</small></span>
      <input type="checkbox" class="switch" data-input="follow" ${state.follow ? "checked" : ""} ${loggedIn() ? "" : "disabled"}>
    </label>`}`;

  document.querySelectorAll(".tabs button").forEach((b) => {
    const on = b.dataset.tab === state.hostTab;
    b.classList.toggle("on", on);
    b.setAttribute("aria-selected", on);
  });
  $("#host-songs").hidden = state.hostTab !== "songs";
  $("#host-check").hidden = state.hostTab !== "check";

  // Song list
  const q = state.search.toLowerCase();
  const order = new Map(g.played.map((sid, i) => [sid, i + 1]));
  const matches = g.songs.filter((s) => !q || s.title.toLowerCase().includes(q) || s.artist.toLowerCase().includes(q));
  const done = matches.filter((s) => played.has(s.id)).sort((a, b) => order.get(b.id) - order.get(a.id));
  const waiting = matches.filter((s) => !played.has(s.id)).sort((a, b) => a.title.localeCompare(b.title));
  const songBtn = (s) => `<button class="song" data-action="toggle" data-id="${esc(s.id)}">
      <span class="dot${order.has(s.id) ? " on" : ""}">${order.get(s.id) ?? ""}</span>
      <span><b>${esc(s.title)}</b><span>${esc(s.artist)}</span></span></button>`;
  $("#host-list").innerHTML =
    (done.length ? `<div class="label">PLAYED</div>${done.map(songBtn).join("")}` : "") +
    (waiting.length ? `<div class="label">STILL IN THE TANK</div>${waiting.map(songBtn).join("")}` : "") +
    (!matches.length ? `<p class="muted">No songs match.</p>` : "");

  // Card checker
  const n = parseInt(state.cardNumber, 10);
  const card = g.cards.find((c) => c.number === n);
  const box = $("#host-card");
  if (!card) {
    box.innerHTML = state.cardNumber ? `<p class="muted">This game has cards 1–${g.cards.length}.</p>` : "";
    return;
  }
  const win = winningCells(g, card, played);
  const m = marks(g, card, played);
  const away = songsAway(g, card, played);
  box.innerHTML = `
    <div class="verdict${win.size ? " win" : ""}">${fishSVG(34, win.size ? "#F28B5B" : "rgba(191,232,228,.5)")}
      ${win.size ? "SINGO! It's a winner." : `Not yet: ${away} song${away === 1 ? "" : "s"} away`}</div>
    <div class="mini">
      ${[..."SINGO"].map((l) => `<div class="h">${l}</div>`).join("")}
      ${card.cells.map((i, k) => `<div class="c${win.has(k) ? " w" : m[k] ? " m" : ""}">${i == null ? fishSVG(40, win.has(k) ? "#0A2A33" : "#F28B5B") : esc(g.songs[i].title)}</div>`).join("")}
    </div>`;
}

function followCaption() {
  if (!loggedIn()) return "Connect Spotify to auto-mark songs";
  if (!state.follow) return "Auto-mark songs as they play on your Spotify account";
  return state.nowPlaying ? `Now: ${state.nowPlaying.title} — ${state.nowPlaying.artist}` : "Listening… start playback in Spotify";
}

// ---------------------------------------------------------------- events
const actions = {
  login: () => login().catch(showError),
  logout: () => { logout(); route(); },
  demo: () => {
    const g = makeGame("demo", "Fishbowl Demo Mix", demoSongs(), 12, true);
    Games.add(g);
    location.hash = `#/game/${g.id}`;
  },
  count: (el) => { store.set("cardCount", +el.dataset.n); renderSetup(); },
  deal: () => {
    const { playlist, songs } = state.setup;
    const n = Math.max(1, Math.min(MAX_CARDS, store.get("cardCount", 40)));
    const g = makeGame(playlist.id, playlist.name, songs, n, store.get("freeSpace", true));
    Games.add(g);
    location.replace(`#/game/${g.id}`);
  },
  print: () => window.print(),
  rename: () => {
    const id = currentGameId();
    const g = Games.get(id);
    const name = prompt("Rename game (shows on the printed cards). Leave empty to use the playlist name.", g.customName || "");
    if (name == null) return;
    const trimmed = name.trim();
    Games.update(id, (x) => { x.customName = trimmed && trimmed !== x.playlistName ? trimmed : null; });
    viewGame(id);
  },
  delete: () => {
    const g = Games.get(currentGameId());
    if (g && confirm(`Delete "${gameName(g)}"? Printed cards from this game can't be checked here after this.`)) {
      Games.remove(g.id);
      location.hash = "#/";
    }
  },
  tab: (el) => { state.hostTab = el.dataset.tab; refreshHost(); },
  toggle: (el) => {
    const sid = el.dataset.id;
    Games.update(currentGameId(), (g) => {
      const i = g.played.indexOf(sid);
      i >= 0 ? g.played.splice(i, 1) : g.played.push(sid);
    });
    refreshHost();
  },
  check: (el) => {
    state.hostTab = "check";
    state.cardNumber = el.dataset.n;
    $("#cardno").value = el.dataset.n;
    refreshHost();
  },
  reset: () => {
    if (confirm("Clear all played songs? Use this to replay the same cards for a new round.")) {
      Games.update(currentGameId(), (g) => { g.played = []; });
      refreshHost();
    }
  },
};

document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el) return;
  e.preventDefault();
  actions[el.dataset.action]?.(el);
});

document.addEventListener("input", (e) => {
  const el = e.target;
  switch (el.dataset.input) {
    case "plsearch": return renderPlaylistList(el.value);
    case "songsearch": state.search = el.value; return refreshHost();
    case "cardno": state.cardNumber = el.value; return refreshHost();
    case "count": {
      const n = parseInt(el.value, 10);
      if (n >= 1 && n <= MAX_CARDS) {
        store.set("cardCount", n);
        document.querySelectorAll(".chip[data-n]").forEach((c) => c.classList.toggle("on", +c.dataset.n === n));
        const deal = $("[data-action=deal]");
        if (deal) deal.textContent = `Deal ${n} cards`;
      }
    }
  }
});

document.addEventListener("change", (e) => {
  const el = e.target;
  switch (el.dataset.input) {
    case "free": store.set("freeSpace", el.checked); return renderSetup();
    case "pattern": Games.update(currentGameId(), (g) => { g.pattern = el.value; }); return refreshHost();
    case "follow": setFollow(el.checked); return refreshHost();
  }
});

document.addEventListener("submit", async (e) => {
  if (e.target.dataset.form !== "link") return;
  e.preventDefault();
  const id = playlistIdFrom(new FormData(e.target).get("link") || "");
  if (!id) return toast("That doesn't look like a Spotify playlist link.");
  location.hash = `#/setup/${id}`;
});

// ---------------------------------------------------------------- tank background
function startBackground() {
  const canvas = $("#bg");
  const ctx = canvas.getContext("2d");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const r = (i, k) => { const v = Math.sin(i * 12.9898 + k * 78.233) * 43758.5453; return v - Math.floor(v); };
  const fish = new Path2D(fishPath(-23, -13.5, 46, 27));
  let w, h, dpr;
  const resize = () => {
    dpr = Math.min(devicePixelRatio || 1, 2);
    w = innerWidth; h = innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + "px"; canvas.style.height = h + "px";
    if (reduce) draw(0);
  };

  function draw(ms) {
    const t = ms / 1000;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "#2C8794"); grad.addColorStop(0.5, "#134B58"); grad.addColorStop(1, "#0A2A33");
    ctx.fillStyle = grad; ctx.fillRect(0, 0, w, h);

    for (let i = 0; i < 3; i++) {   // light shafts
      const x = w * (0.15 + 0.32 * i) + Math.sin(t * 0.15 + i * 2) * 18;
      const g = ctx.createLinearGradient(x, 0, x + 60, h * 0.8);
      g.addColorStop(0, "rgba(255,255,255,.07)"); g.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.moveTo(x - 18, 0); ctx.lineTo(x + 26, 0); ctx.lineTo(x + 120, h * 0.8); ctx.lineTo(x + 30, h * 0.8); ctx.fill();
    }

    ctx.strokeStyle = "rgba(191,232,228,.22)"; ctx.lineWidth = 3; ctx.lineCap = "round"; ctx.lineJoin = "round";
    [[0.07, 170], [0.13, 120], [0.9, 150]].forEach(([fx, height], i) => {   // seaweed
      const bx = w * fx;
      ctx.beginPath(); ctx.moveTo(bx, h);
      for (let s = 1; s <= 12; s++) { const k = s / 12; ctx.lineTo(bx + Math.sin(t * 0.8 + i + k * 3) * 10 * k, h - height * k); }
      ctx.stroke();
    });

    for (let x = 0, i = 0; x < w; i++) {   // gravel
      const pw = 8 + r(i, 1) * 8, ph = 5 + r(i, 2) * 4, y = h - 4 - ph - r(i, 3) * 10;
      ctx.fillStyle = `rgba(255,255,255,${0.05 + r(i, 4) * 0.08})`;
      ctx.beginPath(); ctx.ellipse(x + pw / 2, y + ph / 2, pw / 2, ph / 2, 0, 0, Math.PI * 2); ctx.fill();
      x += pw * 0.8;
    }

    const swim = (x, y, scale, right, alpha) => {
      ctx.save(); ctx.translate(x, y); ctx.scale(right ? scale : -scale, scale);
      ctx.fillStyle = `rgba(242,139,91,${alpha})`; ctx.fill(fish, "evenodd"); ctx.restore();
    };
    swim(((t * 20) % (w + 160)) - 80, h * 0.64 + Math.sin(t * 0.9) * 10, 1, true, 0.9);
    swim(w + 80 - ((t * 13 + 260) % (w + 160)), h * 0.36 + Math.sin(t * 0.7 + 1) * 8, 0.65, false, 0.6);

    ctx.strokeStyle = "rgba(255,255,255,.32)"; ctx.lineWidth = 1;
    for (let b = 0; b < 18; b++) {   // bubbles
      const speed = 16 + r(b, 2) * 28, rad = 2 + r(b, 3) * 4.5, cycle = h + 40;
      const y = h + 20 - ((t * speed + r(b, 4) * cycle) % cycle);
      const x = r(b, 1) * w + Math.sin(t * 1.3 + b) * 4;
      ctx.beginPath(); ctx.arc(x, y, rad, 0, Math.PI * 2); ctx.stroke();
    }
    if (!reduce) requestAnimationFrame(draw);
  }

  resize();
  addEventListener("resize", resize);
  if (!reduce) requestAnimationFrame(draw);
}

// ---------------------------------------------------------------- start
startBackground();
try {
  await handleRedirect();
} catch (e) {
  showError(e);
}
route();
if (loggedIn()) {
  getMe().then(() => { if (!location.hash || location.hash === "#/") viewHome(); }).catch(() => {});
}
