import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import mineflayer from "mineflayer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { startDiscordBot } from "./discord-bot.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app        = express();
const httpServer = createServer(app);
const io         = new Server(httpServer, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const PORT      = process.env.PORT || 3000;
const MAX_SLOTS = 100;
const DATA_FILE = path.join(__dirname, "bot-slots.json");
const AUTH_FILE = path.join(__dirname, "auth-data.json");

const ENC_KEY = crypto.createHash("sha256")
  .update(process.env.SESSION_SECRET || "mc-afk-enc-key-change-me")
  .digest();

function encryptPass(text) {
  if (!text) return null;
  try {
    const iv = crypto.randomBytes(16);
    const c  = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
    const enc = Buffer.concat([c.update(text, "utf8"), c.final()]);
    return iv.toString("hex") + ":" + enc.toString("hex");
  } catch { return null; }
}

function decryptPass(enc) {
  if (!enc) return null;
  if (!enc.includes(":")) return enc;
  try {
    const [ivHex, encHex] = enc.split(":");
    const d = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, Buffer.from(ivHex, "hex"));
    return Buffer.concat([d.update(Buffer.from(encHex, "hex")), d.final()]).toString("utf8");
  } catch { return null; }
}

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "kaiser";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin@kaiser";

function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw + "mc-afk-salt-2024").digest("hex");
}
function generateToken() { return crypto.randomBytes(32).toString("hex"); }

function loadAuthData() {
  try { if (fs.existsSync(AUTH_FILE)) return JSON.parse(fs.readFileSync(AUTH_FILE, "utf-8")); } catch {}
  return { tempAccounts: [], sessions: [] };
}
function saveAuthData(d) { try { fs.writeFileSync(AUTH_FILE, JSON.stringify(d, null, 2)); } catch {} }

function purgeAuthData(d) {
  const now = Date.now();
  d.sessions     = d.sessions.filter(s => s.expiresAt > now);
  d.tempAccounts = d.tempAccounts.filter(a => !a.revoked || a.expiresAt > now);
  return d;
}

function extractToken(req) {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  const cookie = (req.headers.cookie || "").split(";").find(c => c.trim().startsWith("mc_token="));
  if (cookie) return cookie.trim().slice("mc_token=".length);
  return null;
}

function getSession(req) {
  const token = extractToken(req);
  if (!token) return null;
  const d = purgeAuthData(loadAuthData());
  return d.sessions.find(s => s.token === token && s.expiresAt > Date.now()) ?? null;
}

function requireAdmin(req, res, next) {
  const session = getSession(req);
  if (!session || session.type !== "admin") { res.status(403).json({ error: "Admin access required" }); return; }
  req.session = session; next();
}

function requireSlotAccess(req, res, next) {
  const session = getSession(req);
  if (!session) { res.status(401).json({ error: "Not logged in" }); return; }
  if (session.type === "admin") { req.session = session; next(); return; }
  const d = loadAuthData();
  const account = d.tempAccounts.find(a => a.id === session.tempAccountId && !a.revoked && a.expiresAt > Date.now());
  if (!account) { res.status(403).json({ error: "Account expired or revoked" }); return; }
  if (!account.allowedSlot) { res.status(403).json({ error: "No slot assigned to your account" }); return; }
  if (req.params.id && req.params.id !== String(account.allowedSlot)) {
    res.status(403).json({ error: `Access denied — you can only use Slot ${account.allowedSlot}` }); return;
  }
  req.session = session;
  req.allowedSlot = String(account.allowedSlot);
  next();
}

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) { res.status(400).json({ error: "Username and password required" }); return; }
  const d    = purgeAuthData(loadAuthData());
  const hash = hashPassword(password);
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token   = generateToken();
    const session = { token, username, type: "admin", expiresAt: Date.now() + 365*24*3600*1000 };
    d.sessions.push(session); saveAuthData(d);
    res.json({ success: true, token, type: "admin", expiresAt: session.expiresAt, username });
    return;
  }
  const account = d.tempAccounts.find(
    a => a.username === username && a.passwordHash === hash && !a.revoked && a.expiresAt > Date.now()
  );
  if (!account) { res.status(401).json({ error: "Invalid credentials or account expired" }); return; }
  const token   = generateToken();
  const session = { token, username, type: "temp", expiresAt: account.expiresAt, tempAccountId: account.id };
  d.sessions.push(session); saveAuthData(d);
  res.json({ success: true, token, type: "temp", expiresAt: account.expiresAt, username, allowedSlot: account.allowedSlot });
});

app.get("/api/auth/verify", (req, res) => {
  const session = getSession(req);
  if (!session) { res.status(401).json({ valid: false }); return; }
  const d = loadAuthData();
  const acc = session.type === "temp" ? d.tempAccounts.find(a => a.id === session.tempAccountId) : null;
  res.json({ valid: true, username: session.username, type: session.type, expiresAt: session.expiresAt, allowedSlot: acc?.allowedSlot || null });
});

app.post("/api/auth/logout", (req, res) => {
  const token = extractToken(req);
  if (token) { const d=loadAuthData(); d.sessions=d.sessions.filter(s=>s.token!==token); saveAuthData(d); }
  res.json({ success: true });
});

app.post("/api/admin/temp-accounts", requireAdmin, (req, res) => {
  const { username, password, hours=0, minutes=0, seconds=0, label="", allowedSlot=null } = req.body;
  if (!username || !password) { res.status(400).json({ error: "Username and password required" }); return; }
  if (!allowedSlot) { res.status(400).json({ error: "Allowed slot number required" }); return; }
  const slotNum = Number(allowedSlot);
  if (!slotNum || slotNum < 1 || slotNum > MAX_SLOTS) { res.status(400).json({ error: `Slot must be between 1 and ${MAX_SLOTS}` }); return; }
  const totalMs = (Number(hours)*3600 + Number(minutes)*60 + Number(seconds)) * 1000;
  if (totalMs <= 0) { res.status(400).json({ error: "Duration must be > 0" }); return; }
  const d   = loadAuthData();
  const now = Date.now();
  const existing = d.tempAccounts.find(a => a.username===username && !a.revoked && a.expiresAt>now);
  if (existing) { res.status(409).json({ error: "Username already in use" }); return; }
  const account = {
    id: crypto.randomUUID(), username,
    passwordHash: hashPassword(password),
    plainPassword: password,
    createdAt: now, expiresAt: now+totalMs,
    label: label||username, revoked: false,
    allowedSlot: String(slotNum),
  };
  d.tempAccounts.push(account); saveAuthData(d);
  res.json({ success: true, account: sanitizeAccount(account) });
});

app.get("/api/admin/temp-accounts", requireAdmin, (_req, res) => {
  const d = purgeAuthData(loadAuthData());
  res.json({ accounts: d.tempAccounts.map(sanitizeAccount) });
});

app.get("/api/admin/temp-accounts/passwords", requireAdmin, (_req, res) => {
  const d = purgeAuthData(loadAuthData());
  const result = d.tempAccounts.map(a => ({
    id: a.id, username: a.username, label: a.label,
    plainPassword: a.plainPassword || "N/A (purana account)",
    allowedSlot: a.allowedSlot, expiresAt: a.expiresAt, revoked: a.revoked,
  }));
  res.json({ accounts: result });
});

app.delete("/api/admin/temp-accounts/:id", requireAdmin, (req, res) => {
  const d = loadAuthData();
  const a = d.tempAccounts.find(a => a.id===req.params.id);
  if (!a) { res.status(404).json({ error: "Account not found" }); return; }
  a.revoked = true;
  d.sessions = d.sessions.filter(s => s.tempAccountId !== a.id);
  saveAuthData(d); res.json({ success: true });
});

app.get("/api/admin/stats", requireAdmin, (_req, res) => {
  const d   = purgeAuthData(loadAuthData());
  const now = Date.now();
  res.json({
    totalAccounts:  d.tempAccounts.length,
    active:         d.tempAccounts.filter(a => !a.revoked && a.expiresAt>now).length,
    expired:        d.tempAccounts.filter(a => a.expiresAt<=now || a.revoked).length,
    activeSessions: d.sessions.filter(s => s.expiresAt>now).length,
  });
});

function sanitizeAccount(a) {
  return { id:a.id, username:a.username, label:a.label, createdAt:a.createdAt, expiresAt:a.expiresAt, revoked:a.revoked, allowedSlot:a.allowedSlot||null };
}

// ================================================================
//  BOT SYSTEM
// ================================================================

// Kick ke baad 10-15 second mein rejoin
const RECONNECT_BASE_MS = 12_000;
const RECONNECT_MAX_MS  = 5 * 60_000;
const GHOST_DELAY_MS    = 45_000;
const JITTER_MS         = 3_000;

function loadSlots() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8")); } catch {}
  return {};
}
function saveSlots(slots) { try { fs.writeFileSync(DATA_FILE, JSON.stringify(slots,null,2),"utf-8"); } catch {} }

let slotsData = loadSlots();
function getSlotData(id)       { return slotsData[String(id)] ?? null; }
function setSlotData(id, data) { slotsData[String(id)] = data; saveSlots(slotsData); }
function deleteSlotData(id)    { delete slotsData[String(id)]; saveSlots(slotsData); }

const botStates = new Map();

function freshState(slotId) {
  return {
    slotId, bot: null, reconnectTimer: null, afkTimer: null, afkBusy: false,
    shouldReconnect: false, isReconnecting: false,
    destroyed: true, reconnectAttempts: 0
  };
}
function getState(slotId) {
  const id = String(slotId);
  if (!botStates.has(id)) botStates.set(id, freshState(id));
  return botStates.get(id);
}

function emitStatus(slotId) {
  const state  = getState(slotId);
  const data   = getSlotData(slotId);
  const status = {
    slotId: String(slotId), online: false,
    reconnecting: state.isReconnecting,
    playerCount: null, players: [],
    serverHost: data?.host ?? null
  };
  if (state.bot?.entity) {
    const players       = Object.values(state.bot.players ?? {}).map(p => p.username);
    status.online       = true;
    status.reconnecting = false;
    status.playerCount  = players.length;
    status.players      = players;
  }
  io.emit("botStatus", status);
  return status;
}
function emitLog(slotId, sender, message) {
  io.emit("botLog", { slotId: String(slotId), sender, message, timestamp: new Date().toISOString() });
}

// ================================================================
//  BUG FIX: Kick reason parser
//  Pehle reason kabhi object hota tha toh .toLowerCase() crash
//  karta tha aur scheduleReconnect kabhi call nahi hota tha.
//  Ab safely string mein convert hoga — koi bhi format ho.
// ================================================================
function parseKickReason(reason) {
  try {
    if (typeof reason === "string") {
      try {
        const parsed = JSON.parse(reason);
        return String(parsed?.text ?? parsed?.extra?.[0]?.text ?? reason);
      } catch {
        return reason;
      }
    }
    if (reason && typeof reason === "object") {
      return String(reason.text ?? reason.message ?? JSON.stringify(reason));
    }
    return String(reason ?? "unknown");
  } catch {
    return "unknown";
  }
}

// ================================================================
//  ANTI-AFK CONFIG  —  Yahan se poori activity loop configure karo
//  Master switch, intervals aur har action ki settings yahan hain.
//  Band karna ho toh `enabled: false` kar do — tab bot bilkul
//  still rahega (purana AFK tarika). Per-slot override (optional):
//  slot ki JSON me `antiAfkEnabled: false` daalne par sirf wahi
//  slot band ho jayega, baaki unaffected.
// ================================================================
const ANTI_AFK = {
  enabled:        true,        // Master switch: false = anti-afk band, bot still
  minIntervalMs:  12_000,      // do actions ke beech minimum gap (ms)
  maxIntervalMs:  35_000,      // do actions ke beech maximum gap (ms) — randomized
  walkDurationMs: 1_000,       // ek direction me walk kitni der (ms)
  walkReturn:     true,        // true = aage jaane ke baad wapas peeche se return
  sneakDurationMs:1_200,       // sneak kitni der rakho (ms)
  jumpDurationMs: 400,         // jump control on kitni der (ms)
  lookSteps:      3,           // slow head rotation me kitne steps
  lookStepDelayMs:350,         // rotation ke steps ke beech delay (ms)
  lookYawStep:    0.6,         // har step me yaw kitna rotate (radians)
  hotbarSlots:    [0,1,2,3,4,5,6,7,8], // switch karne ke liye hotbar slots
};

// Global defaults ko cfg (slot data) ke saath merge karta hai.
// Sirf `antiAfkEnabled` field per-slot override hone deta hai.
function getAfkConfig(cfg) {
  const c = { ...ANTI_AFK };
  if (cfg && typeof cfg.antiAfkEnabled === "boolean") c.enabled = cfg.antiAfkEnabled;
  if (c.minIntervalMs > c.maxIntervalMs) c.minIntervalMs = c.maxIntervalMs; // safety
  return c;
}

// Random integer [min, max] inclusive — action gaps ke liye
function randInt(min, max) { return Math.floor(min + Math.random() * (max - min + 1)); }

// Weighted random pick — kuch actions zyada common, kuch rare
function pickWeighted(actions) {
  const total = actions.reduce((s, a) => s + a.weight, 0);
  let r = Math.random() * total;
  for (const a of actions) { if ((r -= a.weight) < 0) return a; }
  return actions[actions.length - 1];
}

// ── Harmless action functions ────────────────────────────────────
// Har function (bot, cfg) leta hai aur MAANGTA hai "kitni der chalega"
// (ms) return karta hai, taaki scheduler agle action tab tak na
// schedule kare jab tak yeh khatam ho jaye. Sab safe hain — koi
// block break/place nahi, koi chat spam nahi.

// 1) Idhar-udhar dekhna — random yaw + thoda pitch
function actLookAround(bot, c) {
  try {
    const yaw   = Math.random() * Math.PI * 2;
    const pitch = (Math.random() - 0.5) * 0.6; // halka upar/neeche
    bot.look(yaw, pitch, false);
  } catch {}
  return 250;
}

// 2) Sir dheere-dheere ghumana — incremental yaw steps
function actRotateHead(bot, c) {
  try {
    const startYaw = bot.entity.yaw || 0;
    let step = 0;
    const rotate = () => {
      try {
        if (step >= c.lookSteps || !bot?.entity) return;
        bot.look(startYaw + c.lookYawStep * (step + 1), bot.entity.pitch || 0, false);
        step++;
        setTimeout(rotate, c.lookStepDelayMs);
      } catch {}
    };
    rotate();
  } catch {}
  return c.lookSteps * c.lookStepDelayMs + 300;
}

// 3) Thoda aage chal ke wapas aana (safe area, return enabled)
function actWalk(bot, c) {
  try {
    bot.setControlState("forward", true);
    setTimeout(() => {
      if (!bot?.entity) return;
      bot.setControlState("forward", false);
      if (c.walkReturn) {
        bot.setControlState("back", true);
        setTimeout(() => {
          if (!bot) return;
          bot.setControlState("back", false);
        }, c.walkDurationMs);
      }
    }, c.walkDurationMs);
  } catch {}
  return c.walkReturn ? c.walkDurationMs * 2 + 200 : c.walkDurationMs + 200;
}

// 4) Kabhi-kabhi jump
function actJump(bot, c) {
  try {
    bot.setControlState("jump", true);
    setTimeout(() => { if (bot) bot.setControlState("jump", false); }, c.jumpDurationMs);
  } catch {}
  return c.jumpDurationMs + 200;
}

// 5) Halki der sneak karna
function actSneak(bot, c) {
  try {
    bot.setControlState("sneak", true);
    setTimeout(() => { if (bot) bot.setControlState("sneak", false); }, c.sneakDurationMs);
  } catch {}
  return c.sneakDurationMs + 200;
}

// 6) Hotbar slot switch karna
function actHotbar(bot, c) {
  try {
    const slots = c.hotbarSlots?.length ? c.hotbarSlots : [0,1,2,3,4,5,6,7,8];
    const slot  = slots[Math.floor(Math.random() * slots.length)];
    bot.setQuickBarSlot(slot);
  } catch {}
  return 300;
}

// 7) Inventory khol ke band karna (1.5s baad)
function actInventory(bot) {
  try {
    bot.openInventory();
    setTimeout(() => { try { bot.closeInventory(); } catch {} }, 1_500);
  } catch {}
  return 1_800;
}

// 8) Paas ke kisi block ki taraf dekhna (lookAt)
function actLookAtBlock(bot) {
  try {
    const pos = bot.entity.position;
    const dx  = Math.round((Math.random() - 0.5) * 6);
    const dy  = Math.round((Math.random() - 0.5) * 3);
    const dz  = Math.round((Math.random() - 0.5) * 6);
    bot.lookAt(pos.offset(dx, dy, dz));
  } catch {}
  return 300;
}

// Weighted action list — weight zyada = zyada baar chalega
const AFK_ACTIONS = [
  { weight: 3, fn: actLookAround },
  { weight: 2, fn: actRotateHead },
  { weight: 3, fn: actWalk },
  { weight: 2, fn: actJump },
  { weight: 2, fn: actSneak },
  { weight: 2, fn: actHotbar },
  { weight: 1, fn: actInventory },
  { weight: 2, fn: actLookAtBlock },
];

// Ek random action chalata hai aur `afkBusy` flag manage karta hai
// taaki do action overlap na hon (agar interval bahut chhota ho).
function runAfkAction(state, c) {
  const bot = state.bot;
  if (!bot?.entity) { state.afkBusy = false; return; }
  const action = pickWeighted(AFK_ACTIONS);
  state.afkBusy = true;
  let dur = 300;
  try { dur = action.fn(bot, c) || 300; } catch {}
  // Action khatam hone ke thodi der baad busy flag hata do
  setTimeout(() => { state.afkBusy = false; }, dur + 250);
}

// Self-rescheduling loop — har baar naya random gap (setTimeout),
// fixed interval nahi, isliye detection se bachta hai.
function scheduleNextAfk(state, cfg) {
  const c = getAfkConfig(cfg);
  if (!c.enabled) return; // band hai toh kuch schedule nahi
  const gap = randInt(c.minIntervalMs, c.maxIntervalMs);
  state.afkTimer = setTimeout(() => {
    state.afkTimer = null;
    if (!state.bot?.entity || !state.shouldReconnect) return;
    if (!state.afkBusy) runAfkAction(state, c);
    scheduleNextAfk(state, cfg); // agla action naye random gap ke baad
  }, gap);
}

// ================================================================
//  ANTI-AFK start/stop  —  purane fixed 20s interval loop ki
//  jagah modular + randomized activity loop. Reconnect, auto-
//  login, dashboard, Socket.IO, API sab pehle jaisa hi chalta hai.
// ================================================================
function stopAfk(state) {
  if (state.afkTimer) { clearTimeout(state.afkTimer); state.afkTimer = null; }
  state.afkBusy = false;
  // Safety: agar koi control state on reh gaya ho toh off kar do
  try {
    const b = state.bot;
    if (b?.entity) {
      b.setControlState("forward", false);
      b.setControlState("back", false);
      b.setControlState("jump", false);
      b.setControlState("sneak", false);
    }
  } catch {}
}

function startAfk(state, cfg) {
  stopAfk(state);
  const c = getAfkConfig(cfg);
  if (!c.enabled) {
    emitLog(state.slotId, "[Anti-AFK]", "Disabled — bot will stay still.");
    return;
  }
  emitLog(state.slotId, "[Anti-AFK]", `Active — random action every ${c.minIntervalMs / 1000}-${c.maxIntervalMs / 1000}s.`);
  scheduleNextAfk(state, cfg);
}

function cancelReconnect(state) {
  if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
}
function calcBackoff(attempts) {
  const base = Math.min(RECONNECT_BASE_MS * (2 ** attempts), RECONNECT_MAX_MS);
  return Math.max(RECONNECT_BASE_MS, base + (Math.random() - 0.5) * 2 * JITTER_MS);
}
function destroyBot(state) {
  if (state.destroyed) return;
  state.destroyed = true; stopAfk(state);
  const b = state.bot; state.bot = null; emitStatus(state.slotId);
  try { b?.quit?.(); } catch {} try { b?.end?.(); } catch {}
}
function scheduleReconnect(state, delayOverrideMs) {
  cancelReconnect(state);
  if (!state.shouldReconnect) return;
  state.isReconnecting = true; emitStatus(state.slotId);
  const delay = delayOverrideMs ?? calcBackoff(state.reconnectAttempts);
  state.reconnectAttempts++;
  emitLog(state.slotId, "[System]", `🔄 Reconnect #${state.reconnectAttempts} in ${Math.round(delay / 1000)}s...`);
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    if (state.shouldReconnect) {
      const data = getSlotData(state.slotId);
      if (data) createMineflayerBot(state.slotId, data);
    }
  }, delay);
}

function createMineflayerBot(slotId, cfg) {
  const state = getState(slotId);
  state.destroyed = false;

  const physicsTick = cfg.fps ? Math.round(1000 / Number(cfg.fps)) : 50;

  const b = mineflayer.createBot({
    host: cfg.host,
    port: Number(cfg.port) || 25565,
    username: cfg.username,
    version: cfg.version && cfg.version !== "auto" ? cfg.version : false,
    auth: "offline",
    hideErrors: true,
    physicsEnabled: true,
    checkTimeoutInterval: 30_000,
    ...(physicsTick !== 50 ? { physicsInterval: physicsTick } : {}),
  });
  state.bot = b;

  b.once("spawn", () => {
    if (b !== state.bot) return;
    state.reconnectAttempts = 0; state.isReconnecting = false; emitStatus(slotId);
    const pingMs = cfg.pingInterval ? `${cfg.pingInterval}s ping` : "default ping";
    const fpsVal = cfg.fps ? `${cfg.fps} FPS` : "default FPS";
    emitLog(slotId, "[System]", `✅ Joined ${cfg.host}:${cfg.port || 25565} as ${cfg.username} [${pingMs}, ${fpsVal}]`);
    startAfk(state, cfg);
    const rp = decryptPass(cfg.password);
    if (rp) setTimeout(() => { if (b !== state.bot) return; try { b.chat(`/login ${rp}`); } catch {} }, 1_500);
  });

  b.on("chat", (username, message) => {
    if (b !== state.bot || username === b.username) return;
    emitLog(slotId, username, message);
  });

  b.on("message", (jsonMsg) => {
    if (b !== state.bot) return;
    const raw = jsonMsg.toString(), lower = raw.toLowerCase();
    const rp = decryptPass(cfg.password);
    if (rp) {
      if (lower.includes("/register") || lower.includes("please register") || lower.includes("register with")) {
        setTimeout(() => { if (b !== state.bot) return; try { b.chat(`/register ${rp} ${rp}`); } catch {} }, 800);
        return;
      }
      if (lower.includes("/login") || lower.includes("please login") || lower.includes("log in")) {
        setTimeout(() => { if (b !== state.bot) return; try { b.chat(`/login ${rp}`); } catch {} }, 800);
        return;
      }
    }
    if (raw.trim()) emitLog(slotId, "[Server]", raw);
  });

  b.on("playerJoined", () => { if (b === state.bot) emitStatus(slotId); });
  b.on("playerLeft",   () => { if (b === state.bot) emitStatus(slotId); });
  b.on("error", (err)  => { if (b !== state.bot) return; emitLog(slotId, "[Error]", String(err?.message ?? err)); });

  // BUG FIX: parseKickReason() use karo — reason object bhi ho sakta hai
  b.on("kicked", (reason) => {
    if (b !== state.bot) return;
    const msg = parseKickReason(reason);
    emitLog(slotId, "[System]", `❌ Kicked: ${msg}`);
    destroyBot(state);
    const isGhost = msg.toLowerCase().includes("already online")
      || msg.toLowerCase().includes("already connected")
      || msg.toLowerCase().includes("logged in from another location");
    scheduleReconnect(state, isGhost ? GHOST_DELAY_MS : undefined);
  });

  b.on("end", (reason) => {
    if (b !== state.bot) return;
    emitLog(slotId, "[System]", `🔌 Disconnected: ${String(reason ?? "unknown")}`);
    destroyBot(state);
    scheduleReconnect(state);
  });
}

function startSlot(slotId) {
  const data = getSlotData(slotId);
  if (!data?.registered) return { ok: false, error: "Slot not registered" };
  if (!data.host) return { ok: false, error: "No host configured" };
  const state = getState(slotId);
  state.shouldReconnect = false; cancelReconnect(state); destroyBot(state);
  state.reconnectAttempts = 0; state.shouldReconnect = true;
  state.isReconnecting = false; state.destroyed = false;
  createMineflayerBot(slotId, data);
  return { ok: true };
}
function stopSlot(slotId) {
  const state = getState(slotId);
  state.shouldReconnect = false; state.isReconnecting = false; state.reconnectAttempts = 0;
  cancelReconnect(state); destroyBot(state); emitStatus(slotId);
  return { ok: true };
}
function restartSlot(slotId) {
  stopSlot(slotId);
  setTimeout(() => startSlot(slotId), 2_000);
  return { ok: true };
}

// ================================================================
//  EXPRESS ROUTES
// ================================================================

app.get("/api/slots", (_req, res) => {
  const result = {};
  for (let i = 1; i <= MAX_SLOTS; i++) {
    const id = String(i), data = slotsData[id] ?? null, state = getState(id);
    result[id] = {
      registered: data?.registered ?? false,
      username: data?.username ?? null,
      host: data?.host ?? null,
      online: !!(state.bot?.entity),
      reconnecting: state.isReconnecting,
      pingInterval: data?.pingInterval ?? null,
      fps: data?.fps ?? null,
    };
  }
  res.json(result);
});

app.get("/api/slot/:id/status", (req, res) => {
  const id = req.params.id, state = getState(id), data = getSlotData(id);
  const online = !!(state.bot?.entity);
  const players = online ? Object.values(state.bot.players ?? {}).map(p => p.username) : [];
  res.json({
    slotId: id, registered: data?.registered ?? false,
    online, reconnecting: state.isReconnecting,
    playerCount: players.length, players,
    host: data?.host ?? null, username: data?.username ?? null,
    pingInterval: data?.pingInterval ?? null, fps: data?.fps ?? null,
  });
});

app.post("/api/slot/:id/register", (req, res) => {
  const id = req.params.id, num = Number(id);
  if (!num || num < 1 || num > MAX_SLOTS) { res.status(400).json({ error: "Invalid slot ID (1-100)" }); return; }
  const { host, port, version, username, password, pingInterval, fps } = req.body;
  if (!host || !username) { res.status(400).json({ error: "host and username required" }); return; }
  const existing = getSlotData(id) ?? {};
  setSlotData(id, {
    ...existing,
    host, port: Number(port) || 25565, version: version || "auto", username,
    password: encryptPass(password),
    registered: true,
    pingInterval: pingInterval ? Number(pingInterval) : null,
    fps: fps ? Number(fps) : null,
  });
  emitLog(id, "[System]", `📝 Slot ${id} registered: ${username} @ ${host} [ping:${pingInterval || 'default'}s, fps:${fps || 'default'}]`);
  res.json({ ok: true });
});

app.post("/api/slot/:id/start", (req, res) => {
  const result = startSlot(req.params.id);
  if (!result.ok) { res.status(400).json(result); return; }
  emitLog(req.params.id, "[System]", "🚀 Bot starting...");
  res.json(result);
});
app.post("/api/slot/:id/stop", (req, res) => {
  res.json(stopSlot(req.params.id));
  emitLog(req.params.id, "[System]", "⏹ Bot stopped.");
});
app.post("/api/slot/:id/restart", (req, res) => {
  res.json(restartSlot(req.params.id));
  emitLog(req.params.id, "[System]", "🔄 Restarting bot...");
});
app.post("/api/slot/:id/chat", (req, res) => {
  const state = getState(req.params.id), { message } = req.body;
  if (!message) { res.status(400).json({ error: "message required" }); return; }
  if (!state.bot?.entity) { res.status(400).json({ error: "Bot not online" }); return; }
  try { state.bot.chat(message); res.json({ ok: true }); } catch { res.status(500).json({ error: "Failed to send" }); }
});
app.delete("/api/slot/:id", (req, res) => {
  const id = req.params.id; stopSlot(id); deleteSlotData(id);
  emitLog(id, "[System]", `🗑 Slot ${id} deleted.`);
  io.emit("slotDeleted", { slotId: id });
  res.json({ ok: true });
});
app.get("/api/slot/:id/settings", (req, res) => {
  const d = getSlotData(req.params.id) ?? {};
  const { password: _, ...safe } = d;
  res.json(safe);
});
app.get("/api/admin/slot/:id/password", requireAdmin, (req, res) => {
  const d = getSlotData(req.params.id);
  if (!d?.registered) { res.status(404).json({ error: "Slot not registered" }); return; }
  const plain = decryptPass(d.password);
  res.json({ slotId: req.params.id, username: d.username, password: plain || "(no password set)" });
});
app.get("/api/healthz", (_req, res) => res.json({ status: "ok", activeBots: [...botStates.values()].filter(s => s.bot?.entity).length }));
app.get("/health",     (_req, res) => res.json({ status: "ok", uptime: process.uptime(), activeBots: [...botStates.values()].filter(s => s.bot?.entity).length }));

// ── Socket.IO ─────────────────────────────────────────────────────
io.on("connection", (socket) => {
  console.log("[WS] Client connected:", socket.id);
  for (let i = 1; i <= MAX_SLOTS; i++) emitStatus(String(i));
  socket.on("disconnect", () => console.log("[WS] Client disconnected:", socket.id));
});

// ── Auto-start saved slots ────────────────────────────────────────
for (const [id, data] of Object.entries(slotsData)) {
  if (data?.registered && data?.host) {
    console.log(`[Boot] Auto-starting slot ${id}...`);
    setTimeout(() => startSlot(id), 3_000 + Number(id) * 300);
  }
}

// ── Self-ping keep-alive ──────────────────────────────────────────
const pingTarget =
  process.env.APP_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  process.env.REPLIT_DOMAINS;

if (pingTarget) {
  const base    = pingTarget.startsWith("http") ? pingTarget : `https://${pingTarget.split(",")[0]}`;
  const selfUrl = `${base}/health`;
  const interval = parseInt(process.env.PING_INTERVAL_MS) || 4 * 60_000;
  setInterval(async () => {
    try {
      await fetch(selfUrl);
      console.log(`[KeepAlive] ✅ Ping OK — ${new Date().toLocaleTimeString()}`);
    } catch (e) {
      console.warn(`[KeepAlive] ⚠️ Ping failed: ${e.message}`);
    }
  }, interval);
  console.log(`[KeepAlive] 🚀 Self-ping started → ${selfUrl} every ${interval / 1000}s`);
}

httpServer.listen(PORT, () => console.log(`[Server] Running on port ${PORT}`));

startDiscordBot().catch(e => console.error("[Discord] Fatal:", e.message));
