import express from "express";
import { createServer } from "http";
import https from "https";
import http from "http";
import { Server } from "socket.io";
import mineflayer from "mineflayer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const customRequire = typeof require !== "undefined" ? require : createRequire(import.meta.url);

let pathfinderPkg: any = null;
let pathfinder: any = null;
let Movements: any = null;
let goals: any = null;
let GoalBlock: any = null;

try {
  pathfinderPkg = customRequire("mineflayer-pathfinder");
  pathfinder = pathfinderPkg?.pathfinder;
  Movements = pathfinderPkg?.Movements;
  goals = pathfinderPkg?.goals;
  GoalBlock = goals?.GoalBlock;
} catch (e) {
  console.log("[Notice] mineflayer-pathfinder package not installed. Anti-AFK will run without pathfinder.");
}

let minecraftData: any = null;
try {
  minecraftData = customRequire("minecraft-data");
} catch (e) {
  console.log("[Notice] minecraft-data package not installed.");
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from public or dist directory if present
const publicDir = path.join(__dirname, "public");
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}
const distDir = path.join(__dirname, "dist");
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir));
}

const PORT = process.env.PORT || 3000;
const MAX_SLOTS = 100;
const DATA_FILE = path.join(__dirname, "bot-slots.json");
const AUTH_FILE = path.join(__dirname, "auth-data.json");
const LOGS_LIMIT = 500;

// Logging store for web dashboard / logs
const inMemoryLogs: string[] = [];

function addGlobalLog(msg: string) {
  const timestamp = new Date().toISOString();
  const formatted = `[${timestamp}] ${msg}`;
  inMemoryLogs.push(formatted);
  if (inMemoryLogs.length > LOGS_LIMIT) {
    inMemoryLogs.shift();
  }
  console.log(msg);
}

function getGlobalLogs(): string[] {
  return [...inMemoryLogs];
}

// Encryption helpers for passwords
const ENC_KEY = crypto.createHash("sha256")
  .update(process.env.SESSION_SECRET || "mc-afk-enc-key-change-me")
  .digest();

function encryptPass(text: string | null | undefined): string | null {
  if (!text) return null;
  try {
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
    const enc = Buffer.concat([c.update(text, "utf8"), c.final()]);
    return iv.toString("hex") + ":" + enc.toString("hex");
  } catch {
    return null;
  }
}

function decryptPass(enc: string | null | undefined): string | null {
  if (!enc) return null;
  if (!enc.includes(":")) return enc;
  try {
    const [ivHex, encHex] = enc.split(":");
    const d = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, Buffer.from(ivHex, "hex"));
    return Buffer.concat([d.update(Buffer.from(encHex, "hex")), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}

// Authentication Data & Admin Management
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "kaiser";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin@kaiser";

function hashPassword(pw: string): string {
  return crypto.createHash("sha256").update(pw + "mc-afk-salt-2024").digest("hex");
}

function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

interface AuthData {
  tempAccounts: any[];
  sessions: any[];
}

function loadAuthData(): AuthData {
  try {
    if (fs.existsSync(AUTH_FILE)) return JSON.parse(fs.readFileSync(AUTH_FILE, "utf-8"));
  } catch {}
  return { tempAccounts: [], sessions: [] };
}

function saveAuthData(d: AuthData) {
  try {
    fs.writeFileSync(AUTH_FILE, JSON.stringify(d, null, 2));
  } catch {}
}

function purgeAuthData(d: AuthData): AuthData {
  const now = Date.now();
  d.sessions = d.sessions.filter(s => s.expiresAt > now);
  d.tempAccounts = d.tempAccounts.filter(a => !a.revoked || a.expiresAt > now);
  return d;
}

function extractToken(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  const cookie = (req.headers.cookie || "").split(";").find(c => c.trim().startsWith("mc_token="));
  if (cookie) return cookie.trim().slice("mc_token=".length);
  return null;
}

function getSession(req: express.Request) {
  const token = extractToken(req);
  if (!token) return null;
  const d = purgeAuthData(loadAuthData());
  return d.sessions.find(s => s.token === token && s.expiresAt > Date.now()) ?? null;
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const session = getSession(req);
  if (!session || session.type !== "admin") {
    res.status(403).json({ error: "Admin access required" });
    return;
  }
  (req as any).session = session;
  next();
}

function requireSlotAccess(req: express.Request, res: express.Response, next: express.NextFunction) {
  const session = getSession(req);
  if (!session) {
    res.status(401).json({ error: "Not logged in" });
    return;
  }
  if (session.type === "admin") {
    (req as any).session = session;
    next();
    return;
  }
  const d = loadAuthData();
  const account = d.tempAccounts.find(a => a.id === session.tempAccountId && !a.revoked && a.expiresAt > Date.now());
  if (!account) {
    res.status(403).json({ error: "Account expired or revoked" });
    return;
  }
  if (!account.allowedSlot) {
    res.status(403).json({ error: "No slot assigned to your account" });
    return;
  }
  if (req.params.id && req.params.id !== String(account.allowedSlot)) {
    res.status(403).json({ error: `Access denied — you can only use Slot ${account.allowedSlot}` });
    return;
  }
  (req as any).session = session;
  (req as any).allowedSlot = String(account.allowedSlot);
  next();
}

function sanitizeAccount(a: any) {
  return {
    id: a.id,
    username: a.username,
    label: a.label,
    createdAt: a.createdAt,
    expiresAt: a.expiresAt,
    revoked: a.revoked,
    allowedSlot: a.allowedSlot || null,
  };
}

// AUTH ROUTES
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: "Username and password required" });
    return;
  }
  const d = purgeAuthData(loadAuthData());
  const hash = hashPassword(password);
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = generateToken();
    const session = { token, username, type: "admin", expiresAt: Date.now() + 365 * 24 * 3600 * 1000 };
    d.sessions.push(session);
    saveAuthData(d);
    res.json({ success: true, token, type: "admin", expiresAt: session.expiresAt, username });
    return;
  }
  const account = d.tempAccounts.find(
    a => a.username === username && a.passwordHash === hash && !a.revoked && a.expiresAt > Date.now()
  );
  if (!account) {
    res.status(401).json({ error: "Invalid credentials or account expired" });
    return;
  }
  const token = generateToken();
  const session = { token, username, type: "temp", expiresAt: account.expiresAt, tempAccountId: account.id };
  d.sessions.push(session);
  saveAuthData(d);
  res.json({ success: true, token, type: "temp", expiresAt: account.expiresAt, username, allowedSlot: account.allowedSlot });
});

app.get("/api/auth/verify", (req, res) => {
  const session = getSession(req);
  if (!session) {
    res.status(401).json({ valid: false });
    return;
  }
  const d = loadAuthData();
  const acc = session.type === "temp" ? d.tempAccounts.find(a => a.id === session.tempAccountId) : null;
  res.json({
    valid: true,
    username: session.username,
    type: session.type,
    expiresAt: session.expiresAt,
    allowedSlot: acc?.allowedSlot || null,
  });
});

app.post("/api/auth/logout", (req, res) => {
  const token = extractToken(req);
  if (token) {
    const d = loadAuthData();
    d.sessions = d.sessions.filter(s => s.token !== token);
    saveAuthData(d);
  }
  res.json({ success: true });
});

app.post("/api/admin/temp-accounts", requireAdmin, (req, res) => {
  const { username, password, hours = 0, minutes = 0, seconds = 0, label = "", allowedSlot = null } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: "Username and password required" });
    return;
  }
  if (!allowedSlot) {
    res.status(400).json({ error: "Allowed slot number required" });
    return;
  }
  const slotNum = Number(allowedSlot);
  if (!slotNum || slotNum < 1 || slotNum > MAX_SLOTS) {
    res.status(400).json({ error: `Slot must be between 1 and ${MAX_SLOTS}` });
    return;
  }
  const totalMs = (Number(hours) * 3600 + Number(minutes) * 60 + Number(seconds)) * 1000;
  if (totalMs <= 0) {
    res.status(400).json({ error: "Duration must be > 0" });
    return;
  }
  const d = loadAuthData();
  const now = Date.now();
  const existing = d.tempAccounts.find(a => a.username === username && !a.revoked && a.expiresAt > now);
  if (existing) {
    res.status(409).json({ error: "Username already in use" });
    return;
  }
  const account = {
    id: crypto.randomUUID(),
    username,
    passwordHash: hashPassword(password),
    plainPassword: password,
    createdAt: now,
    expiresAt: now + totalMs,
    label: label || username,
    revoked: false,
    allowedSlot: String(slotNum),
  };
  d.tempAccounts.push(account);
  saveAuthData(d);
  res.json({ success: true, account: sanitizeAccount(account) });
});

app.get("/api/admin/temp-accounts", requireAdmin, (_req, res) => {
  const d = purgeAuthData(loadAuthData());
  res.json({ accounts: d.tempAccounts.map(sanitizeAccount) });
});

app.get("/api/admin/temp-accounts/passwords", requireAdmin, (_req, res) => {
  const d = purgeAuthData(loadAuthData());
  const result = d.tempAccounts.map(a => ({
    id: a.id,
    username: a.username,
    label: a.label,
    plainPassword: a.plainPassword || "N/A",
    allowedSlot: a.allowedSlot,
    expiresAt: a.expiresAt,
    revoked: a.revoked,
  }));
  res.json({ accounts: result });
});

app.delete("/api/admin/temp-accounts/:id", requireAdmin, (req, res) => {
  const d = loadAuthData();
  const a = d.tempAccounts.find(acc => acc.id === req.params.id);
  if (!a) {
    res.status(404).json({ error: "Account not found" });
    return;
  }
  a.revoked = true;
  d.sessions = d.sessions.filter(s => s.tempAccountId !== a.id);
  saveAuthData(d);
  res.json({ success: true });
});

app.get("/api/admin/stats", requireAdmin, (_req, res) => {
  const d = purgeAuthData(loadAuthData());
  const now = Date.now();
  res.json({
    totalAccounts: d.tempAccounts.length,
    active: d.tempAccounts.filter(a => !a.revoked && a.expiresAt > now).length,
    expired: d.tempAccounts.filter(a => a.expiresAt <= now || a.revoked).length,
    activeSessions: d.sessions.filter(s => s.expiresAt > now).length,
  });
});

// ================================================================
// DISCORD WEBHOOK INTEGRATION
// ================================================================
let lastDiscordSend = 0;
const DISCORD_RATE_LIMIT_MS = 5000;

function sendDiscordWebhook(content: string, color = 0x0099ff) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl || webhookUrl.includes("YOUR_DISCORD")) return;

  const now = Date.now();
  if (now - lastDiscordSend < DISCORD_RATE_LIMIT_MS) return;
  lastDiscordSend = now;

  const protocol = webhookUrl.startsWith("https") ? https : http;
  try {
    const urlParts = new URL(webhookUrl);
    const payload = JSON.stringify({
      username: "AFK Bot System",
      embeds: [
        {
          description: content,
          color: color,
          timestamp: new Date().toISOString(),
          footer: { text: "Minecraft Multi-Slot Bot" },
        },
      ],
    });

    const options = {
      hostname: urlParts.hostname,
      port: urlParts.port || (webhookUrl.startsWith("https") ? 443 : 80),
      path: urlParts.pathname + urlParts.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload, "utf8"),
      },
    };

    const req = protocol.request(options, () => {});
    req.on("error", (e) => addGlobalLog(`[Discord] Error: ${e.message}`));
    req.write(payload);
    req.end();
  } catch (e: any) {
    addGlobalLog(`[Discord] Webhook error: ${e.message}`);
  }
}

// ================================================================
//  BOT SYSTEM (MULTI-SLOT & ANTI-AFK MODULES)
// ================================================================

const RECONNECT_BASE_MS = 12_000;
const RECONNECT_MAX_MS = 5 * 60_000;
const GHOST_DELAY_MS = 45_000;
const JITTER_MS = 3_000;

function loadSlots(): Record<string, any> {
  try {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  } catch {}
  return {};
}

function saveSlots(slots: Record<string, any>) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(slots, null, 2), "utf-8");
  } catch {}
}

let slotsData = loadSlots();

function getSlotData(id: string) {
  return slotsData[String(id)] ?? null;
}

function setSlotData(id: string, data: any) {
  slotsData[String(id)] = data;
  saveSlots(slotsData);
}

function deleteSlotData(id: string) {
  delete slotsData[String(id)];
  saveSlots(slotsData);
}

interface BotState {
  slotId: string;
  bot: any;
  reconnectTimer: any;
  afkTimers: any[];
  shouldReconnect: boolean;
  isReconnecting: boolean;
  destroyed: boolean;
  reconnectAttempts: number;
  lastActivity: number;
  startTime: number;
  lockedTarget?: any;
  lockedTargetExpiry?: number;
}

const botStates = new Map<string, BotState>();

function freshState(slotId: string): BotState {
  return {
    slotId,
    bot: null,
    reconnectTimer: null,
    afkTimers: [],
    shouldReconnect: false,
    isReconnecting: false,
    destroyed: true,
    reconnectAttempts: 0,
    lastActivity: Date.now(),
    startTime: Date.now(),
  };
}

function getState(slotId: string): BotState {
  const id = String(slotId);
  if (!botStates.has(id)) botStates.set(id, freshState(id));
  return botStates.get(id)!;
}

function emitStatus(slotId: string) {
  const state = getState(slotId);
  const data = getSlotData(slotId);
  const status = {
    slotId: String(slotId),
    online: false,
    reconnecting: state.isReconnecting,
    playerCount: null as number | null,
    players: [] as string[],
    serverHost: data?.host ?? null,
    coords: state.bot?.entity?.position ?? null,
  };
  if (state.bot?.entity) {
    const players = Object.values(state.bot.players ?? {}).map((p: any) => p.username);
    status.online = true;
    status.reconnecting = false;
    status.playerCount = players.length;
    status.players = players;
  }
  io.emit("botStatus", status);
  return status;
}

function emitLog(slotId: string, sender: string, message: string) {
  const formatted = `[Slot ${slotId}] [${sender}] ${message}`;
  addGlobalLog(formatted);
  io.emit("botLog", { slotId: String(slotId), sender, message, timestamp: new Date().toISOString() });
}

function parseKickReason(reason: any): string {
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

// Clear internal timers for anti-AFK modules
function stopAfk(state: BotState) {
  if (state.afkTimers && state.afkTimers.length > 0) {
    state.afkTimers.forEach(t => clearInterval(t));
    state.afkTimers = [];
  }
}

// ADVANCED ANTI-AFK ENGINE + COMBAT + AUTO-EAT + BED MODULES
function startAfkModules(state: BotState, cfg: any) {
  stopAfk(state);
  const b = state.bot;
  if (!b) return;

  // 1. Movement AFK Loop (Forward/Back/Jump)
  const afkInterval = setInterval(() => {
    if (!state.bot?.entity) return;
    try {
      state.bot.setControlState("forward", true);
      setTimeout(() => {
        if (!state.bot?.entity) return;
        state.bot.setControlState("forward", false);
        state.bot.setControlState("back", true);
        setTimeout(() => {
          if (!state.bot?.entity) return;
          state.bot.setControlState("back", false);
        }, 1000);
      }, 1000);

      setTimeout(() => {
        if (!state.bot?.entity) return;
        state.bot.setControlState("jump", true);
        setTimeout(() => {
          if (state.bot) state.bot.setControlState("jump", false);
        }, 400);
      }, 500);
      state.lastActivity = Date.now();
    } catch {}
  }, 20_000);
  state.afkTimers.push(afkInterval);

  // 2. Arm Swinging
  const swingInterval = setInterval(() => {
    if (!state.bot?.entity) return;
    try {
      state.bot.swingArm();
    } catch {}
  }, 10_000 + Math.floor(Math.random() * 20_000));
  state.afkTimers.push(swingInterval);

  // 3. Hotbar Cycling
  const hotbarInterval = setInterval(() => {
    if (!state.bot?.entity) return;
    try {
      const slot = Math.floor(Math.random() * 9);
      state.bot.setQuickBarSlot(slot);
    } catch {}
  }, 30_000 + Math.floor(Math.random() * 30_000));
  state.afkTimers.push(hotbarInterval);

  // 4. Random Look Around
  const lookInterval = setInterval(() => {
    if (!state.bot?.entity) return;
    try {
      const yaw = Math.random() * Math.PI * 2 - Math.PI;
      const pitch = (Math.random() * Math.PI) / 2 - Math.PI / 4;
      state.bot.look(yaw, pitch, false);
      state.lastActivity = Date.now();
    } catch {}
  }, 15_000 + Math.floor(Math.random() * 20_000));
  state.afkTimers.push(lookInterval);

  // 5. Teabagging / Sneak
  const teabagInterval = setInterval(() => {
    if (!state.bot?.entity) return;
    if (Math.random() > 0.7) {
      let count = 2 + Math.floor(Math.random() * 3);
      const doTeabag = () => {
        if (count <= 0 || !state.bot?.entity) return;
        try {
          state.bot.setControlState("sneak", true);
          setTimeout(() => {
            if (state.bot) state.bot.setControlState("sneak", false);
            count--;
            setTimeout(doTeabag, 150);
          }, 150);
        } catch {}
      };
      doTeabag();
    }
  }, 60_000 + Math.floor(Math.random() * 60_000));
  state.afkTimers.push(teabagInterval);

  // 6. Auto-Eat on Health Event
  b.on("health", () => {
    try {
      if (b.food < 14) {
        const food = b.inventory?.items()?.find((i: any) => i.foodPoints && i.foodPoints > 0);
        if (food) {
          b.equip(food, "hand")
            .then(() => b.consume())
            .catch(() => {});
        }
      }
    } catch {}
  });

  // 7. Auto Bed / Night Sleeping
  let isTryingToSleep = false;
  const bedInterval = setInterval(async () => {
    if (!state.bot?.entity) return;
    try {
      const isNight = b.time?.timeOfDay >= 12500 && b.time?.timeOfDay <= 23500;
      if (isNight && !isTryingToSleep) {
        const bedBlock = b.findBlock?.({
          matching: (block: any) => block.name.includes("bed"),
          maxDistance: 8,
        });
        if (bedBlock) {
          isTryingToSleep = true;
          try {
            await b.sleep(bedBlock);
            emitLog(state.slotId, "[System]", "😴 Sleeping in nearby bed...");
          } catch {} finally {
            isTryingToSleep = false;
          }
        }
      }
    } catch {
      isTryingToSleep = false;
    }
  }, 20_000);
  state.afkTimers.push(bedInterval);
}

function cancelReconnect(state: BotState) {
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
}

function calcBackoff(attempts: number) {
  const base = Math.min(RECONNECT_BASE_MS * (2 ** attempts), RECONNECT_MAX_MS);
  return Math.max(RECONNECT_BASE_MS, base + (Math.random() - 0.5) * 2 * JITTER_MS);
}

function destroyBot(state: BotState) {
  if (state.destroyed) return;
  state.destroyed = true;
  stopAfk(state);
  const b = state.bot;
  state.bot = null;
  emitStatus(state.slotId);
  try {
    b?.quit?.();
  } catch {}
  try {
    b?.end?.();
  } catch {}
}

function scheduleReconnect(state: BotState, delayOverrideMs?: number) {
  cancelReconnect(state);
  if (!state.shouldReconnect) return;
  state.isReconnecting = true;
  emitStatus(state.slotId);
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

function createMineflayerBot(slotId: string, cfg: any) {
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
    checkTimeoutInterval: 60_000,
    ...(physicsTick !== 50 ? { physicsInterval: physicsTick } : {}),
  });
  state.bot = b;

  if (pathfinder) {
    try {
      b.loadPlugin(pathfinder);
    } catch {}
  }

  b.once("spawn", () => {
    if (b !== state.bot) return;
    state.reconnectAttempts = 0;
    state.isReconnecting = false;
    state.startTime = Date.now();
    state.lastActivity = Date.now();
    emitStatus(slotId);

    const pingMs = cfg.pingInterval ? `${cfg.pingInterval}s ping` : "default ping";
    const fpsVal = cfg.fps ? `${cfg.fps} FPS` : "default FPS";
    emitLog(slotId, "[System]", `✅ Joined ${cfg.host}:${cfg.port || 25565} as ${cfg.username} [${pingMs}, ${fpsVal}] (Version: ${b.version})`);

    sendDiscordWebhook(`[+] **Slot ${slotId} Connected**: \`${cfg.username}\` joined \`${cfg.host}\``, 0x4ade80);

    startAfkModules(state, cfg);

    // Auto Pathfinder default Movements setup
    if (minecraftData && Movements) {
      try {
        const mcData = minecraftData(b.version);
        if (mcData) {
          const move = new Movements(b);
          move.canDig = false;
          (b as any).pathfinder?.setMovements(move);
        }
      } catch {}
    }

    // Auto login/register password execution
    const rp = decryptPass(cfg.password);
    if (rp) {
      setTimeout(() => {
        if (b !== state.bot) return;
        try {
          b.chat(`/login ${rp}`);
        } catch {}
      }, 1_500);
    }
  });

  b.on("chat", (username: string, message: string) => {
    if (b !== state.bot || username === b.username) return;
    emitLog(slotId, username, message);
  });

  b.on("message", (jsonMsg: any) => {
    if (b !== state.bot) return;
    const raw = jsonMsg.toString();
    const lower = raw.toLowerCase();
    const rp = decryptPass(cfg.password);

    if (rp) {
      if (lower.includes("/register") || lower.includes("please register") || lower.includes("register with")) {
        setTimeout(() => {
          if (b !== state.bot) return;
          try {
            b.chat(`/register ${rp} ${rp}`);
          } catch {}
        }, 800);
        return;
      }
      if (lower.includes("/login") || lower.includes("please login") || lower.includes("log in")) {
        setTimeout(() => {
          if (b !== state.bot) return;
          try {
            b.chat(`/login ${rp}`);
          } catch {}
        }, 800);
        return;
      }
    }
    if (raw.trim()) emitLog(slotId, "[Server]", raw);
  });

  b.on("playerJoined", () => {
    if (b === state.bot) emitStatus(slotId);
  });
  b.on("playerLeft", () => {
    if (b === state.bot) emitStatus(slotId);
  });
  b.on("error", (err: any) => {
    if (b !== state.bot) return;
    emitLog(slotId, "[Error]", String(err?.message ?? err));
  });

  b.on("kicked", (reason: any) => {
    if (b !== state.bot) return;
    const msg = parseKickReason(reason);
    emitLog(slotId, "[System]", `❌ Kicked: ${msg}`);
    sendDiscordWebhook(`[!] **Slot ${slotId} Kicked**: ${msg}`, 0xff0000);
    destroyBot(state);
    const isGhost =
      msg.toLowerCase().includes("already online") ||
      msg.toLowerCase().includes("already connected") ||
      msg.toLowerCase().includes("logged in from another location");
    scheduleReconnect(state, isGhost ? GHOST_DELAY_MS : undefined);
  });

  b.on("end", (reason: any) => {
    if (b !== state.bot) return;
    emitLog(slotId, "[System]", `🔌 Disconnected: ${String(reason ?? "unknown")}`);
    sendDiscordWebhook(`[-] **Slot ${slotId} Disconnected**: ${String(reason ?? "unknown")}`, 0xf87171);
    destroyBot(state);
    scheduleReconnect(state);
  });
}

function startSlot(slotId: string) {
  const data = getSlotData(slotId);
  if (!data?.registered) return { ok: false, error: "Slot not registered" };
  if (!data.host) return { ok: false, error: "No host configured" };
  const state = getState(slotId);
  state.shouldReconnect = false;
  cancelReconnect(state);
  destroyBot(state);
  state.reconnectAttempts = 0;
  state.shouldReconnect = true;
  state.isReconnecting = false;
  state.destroyed = false;
  createMineflayerBot(slotId, data);
  return { ok: true };
}

function stopSlot(slotId: string) {
  const state = getState(slotId);
  state.shouldReconnect = false;
  state.isReconnecting = false;
  state.reconnectAttempts = 0;
  cancelReconnect(state);
  destroyBot(state);
  emitStatus(slotId);
  return { ok: true };
}

function restartSlot(slotId: string) {
  stopSlot(slotId);
  setTimeout(() => startSlot(slotId), 2_000);
  return { ok: true };
}

// ================================================================
//  EXPRESS SLOT CONTROL API ROUTES
// ================================================================

app.get("/api/slots", (_req, res) => {
  const result: Record<string, any> = {};
  for (let i = 1; i <= MAX_SLOTS; i++) {
    const id = String(i);
    const data = slotsData[id] ?? null;
    const state = getState(id);
    result[id] = {
      registered: data?.registered ?? false,
      username: data?.username ?? null,
      host: data?.host ?? null,
      online: !!state.bot?.entity,
      reconnecting: state.isReconnecting,
      pingInterval: data?.pingInterval ?? null,
      fps: data?.fps ?? null,
    };
  }
  res.json(result);
});

app.get("/api/slot/:id/status", (req, res) => {
  const id = req.params.id;
  const state = getState(id);
  const data = getSlotData(id);
  const online = !!state.bot?.entity;
  const players = online ? Object.values(state.bot.players ?? {}).map((p: any) => p.username) : [];
  res.json({
    slotId: id,
    registered: data?.registered ?? false,
    online,
    reconnecting: state.isReconnecting,
    playerCount: players.length,
    players,
    host: data?.host ?? null,
    username: data?.username ?? null,
    pingInterval: data?.pingInterval ?? null,
    fps: data?.fps ?? null,
    coords: state.bot?.entity?.position ?? null,
  });
});

app.post("/api/slot/:id/register", (req, res) => {
  const id = req.params.id;
  const num = Number(id);
  if (!num || num < 1 || num > MAX_SLOTS) {
    res.status(400).json({ error: "Invalid slot ID (1-100)" });
    return;
  }
  const { host, port, version, username, password, pingInterval, fps } = req.body;
  if (!host || !username) {
    res.status(400).json({ error: "host and username required" });
    return;
  }
  const existing = getSlotData(id) ?? {};
  setSlotData(id, {
    ...existing,
    host,
    port: Number(port) || 25565,
    version: version || "auto",
    username,
    password: encryptPass(password),
    registered: true,
    pingInterval: pingInterval ? Number(pingInterval) : null,
    fps: fps ? Number(fps) : null,
  });
  emitLog(id, "[System]", `📝 Slot ${id} registered: ${username} @ ${host}`);
  res.json({ ok: true });
});

app.post("/api/slot/:id/start", (req, res) => {
  const result = startSlot(req.params.id);
  if (!result.ok) {
    res.status(400).json(result);
    return;
  }
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
  const state = getState(req.params.id);
  const { message } = req.body;
  if (!message) {
    res.status(400).json({ error: "message required" });
    return;
  }
  if (!state.bot?.entity) {
    res.status(400).json({ error: "Bot not online" });
    return;
  }
  try {
    state.bot.chat(message);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to send" });
  }
});

app.delete("/api/slot/:id", (req, res) => {
  const id = req.params.id;
  stopSlot(id);
  deleteSlotData(id);
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
  if (!d?.registered) {
    res.status(404).json({ error: "Slot not registered" });
    return;
  }
  const plain = decryptPass(d.password);
  res.json({ slotId: req.params.id, username: d.username, password: plain || "(no password set)" });
});

// ================================================================
// DASHBOARD & HTML INTERFACE ROUTES (FROM INDEX.JS)
// ================================================================

app.get("/ping", (_req, res) => res.send("pong"));

app.get("/health", (_req, res) => {
  const activeBots = [...botStates.values()].filter(s => s.bot?.entity).length;
  const slot1 = getState("1");
  res.json({
    status: activeBots > 0 ? "connected" : "disconnected",
    activeBots,
    uptime: Math.floor(process.uptime()),
    coords: slot1?.bot?.entity?.position ?? null,
    lastActivity: slot1?.lastActivity ?? Date.now(),
    memoryUsage: (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2) + " MB",
  });
});

app.get("/api/healthz", (_req, res) => {
  const activeBots = [...botStates.values()].filter(s => s.bot?.entity).length;
  res.json({ status: "ok", activeBots });
});

// Primary HTML Dashboard View
app.get("/", (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Minecraft AFK Bot Manager</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
        <style>
          *, *::before, *::after { box-sizing: border-box; }
          body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            margin: 0;
            padding: 24px;
            display: flex;
            justify-content: center;
          }
          main { width: 100%; max-width: 650px; }
          header { margin-bottom: 24px; }
          header h1 { font-size: 26px; font-weight: 700; color: #f0f6fc; margin: 0; }
          header p { font-size: 14px; color: #8b949e; margin: 6px 0 0; }
          .status-section {
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 16px;
          }
          .status-section.online  { background: #0d2218; border: 2px solid #238636; }
          .status-section.offline { background: #200d0d; border: 2px solid #da3633; }
          .status-icon {
            width: 44px; height: 44px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; flex-shrink: 0;
          }
          .status-icon.online  { background: #238636; }
          .status-icon.offline { background: #da3633; }
          .status-label { font-size: 18px; font-weight: 700; }
          .status-label.online  { color: #3fb950; }
          .status-label.offline { color: #f85149; }
          .status-detail { font-size: 13px; color: #8b949e; margin-top: 3px; }
          .stat-card {
            background: #161b22; border: 1px solid #21262d;
            border-radius: 10px; padding: 16px 20px; margin-bottom: 10px;
          }
          dt { font-size: 12px; color: #8b949e; font-weight: 600; margin-bottom: 4px; }
          dd { margin: 0; font-size: 17px; font-weight: 600; color: #e6edf3; }
          .btn-grid { display: grid; gap: 10px; margin-bottom: 10px; grid-template-columns: 1fr 1fr; }
          .btn {
            min-height: 48px; border-radius: 10px; font-size: 14px; font-weight: 700;
            cursor: pointer; display: flex; align-items: center; justify-content: center;
            text-decoration: none; font-family: inherit; border: none;
          }
          .btn-start { border: 2px solid #238636; background: #0d2218; color: #3fb950; }
          .btn-stop  { border: 2px solid #da3633; background: #200d0d; color: #f85149; }
          .btn-sec   { border: 1px solid #21262d; background: #161b22; color: #8b949e; }
          .btn-sec:hover { background: #21262d; color: #c9d1d9; }
        </style>
      </head>
      <body>
        <main>
          <header>
            <h1>AFK Bot Dashboard</h1>
            <p>Multi-Slot Minecraft Anti-AFK Server & Live Status</p>
          </header>

          <section id="status-section" class="status-section offline">
            <div id="status-icon" class="status-icon offline">✗</div>
            <div>
              <div id="status-label" class="status-label offline">Connecting…</div>
              <div id="status-detail" class="status-detail">Checking bot instances</div>
            </div>
          </section>

          <section>
            <dl>
              <div class="stat-card">
                <dt>Active Bot Slots</dt>
                <dd id="bots-count">0 Online</dd>
              </div>
              <div class="stat-card">
                <dt>Uptime</dt>
                <dd id="uptime-text">0s</dd>
              </div>
            </dl>
          </section>

          <section class="controls">
            <div class="btn-grid">
              <button class="btn btn-start" onclick="startSlot('1')">Start Slot 1</button>
              <button class="btn btn-stop" onclick="stopSlot('1')">Stop Slot 1</button>
            </div>
            <div class="btn-grid">
              <a href="/tutorial" class="btn btn-sec">Setup Guide</a>
              <a href="/logs" class="btn btn-sec">Live Console Logs</a>
            </div>
          </section>
        </main>

        <script>
          async function update() {
            try {
              const r = await fetch('/health');
              const data = await r.json();
              const online = data.activeBots > 0;
              const section = document.getElementById('status-section');
              const icon = document.getElementById('status-icon');
              const label = document.getElementById('status-label');
              const detail = document.getElementById('status-detail');

              section.className = 'status-section ' + (online ? 'online' : 'offline');
              icon.className = 'status-icon ' + (online ? 'online' : 'offline');
              icon.textContent = online ? '✓' : '✗';
              label.className = 'status-label ' + (online ? 'online' : 'offline');
              label.textContent = online ? 'Online (' + data.activeBots + ' Active)' : 'Offline';
              detail.textContent = online ? 'Bot running anti-AFK tasks' : 'No bots currently connected';

              document.getElementById('bots-count').textContent = data.activeBots + ' Bots Active';
              document.getElementById('uptime-text').textContent = data.uptime + ' seconds';
            } catch (e) {}
          }
          async function startSlot(id) {
            const r = await fetch('/api/slot/' + id + '/start', { method: 'POST' });
            update();
          }
          async function stopSlot(id) {
            const r = await fetch('/api/slot/' + id + '/stop', { method: 'POST' });
            update();
          }
          setInterval(update, 3000);
          update();
        </script>
      </body>
    </html>
  `);
});

app.get("/tutorial", (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Setup Guide</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
        <style>
          body { font-family: 'Inter', sans-serif; background: #0d1117; color: #e6edf3; padding: 40px 24px; margin: 0; }
          main { max-width: 560px; margin: 0 auto; }
          .card { background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 24px; margin-bottom: 16px; }
          h1 { color: #f0f6fc; font-size: 24px; margin-bottom: 12px; }
          p, li { color: #8b949e; font-size: 14px; line-height: 1.6; }
          a { color: #58a6ff; text-decoration: none; }
        </style>
      </head>
      <body>
        <main>
          <a href="/">← Back to Dashboard</a>
          <h1>AFK Bot Setup Guide</h1>
          <div class="card">
            <h3>1. Configure Minecraft Server / Aternos</h3>
            <ul>
              <li>Install <strong>Paper/Bukkit</strong> software.</li>
              <li>Enable <strong>Cracked</strong> mode if using offline authentication.</li>
              <li>Install <code>ViaVersion</code> for multiversion compatibility.</li>
            </ul>
          </div>
          <div class="card">
            <h3>2. Manage Slots via API or Web Dashboard</h3>
            <ul>
              <li>Use the Live Console Logs at <code>/logs</code> to issue commands.</li>
              <li>Register bot slots with your server IP and credentials.</li>
              <li>Anti-AFK movement, auto-eating, and reconnection are automatic.</li>
            </ul>
          </div>
        </main>
      </body>
    </html>
  `);
});

app.get("/logs", (_req, res) => {
  const logs = getGlobalLogs();
  const escapeHTML = (str: string) =>
    str.replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[m] || m);

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Live Bot Logs & Console</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
        <style>
          body { font-family: 'Inter', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; }
          main { max-width: 760px; margin: 0 auto; }
          .log-box {
            background: #0d1117; border: 1px solid #21262d; border-radius: 12px;
            padding: 16px; height: 480px; overflow-y: auto; font-family: monospace; font-size: 13px; line-height: 1.6;
          }
          .log-entry { display: block; word-break: break-all; }
          .console-row { display: flex; gap: 10px; margin-top: 12px; }
          .input { flex: 1; background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 10px; color: #fff; font-family: monospace; }
          .btn { background: #238636; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 700; cursor: pointer; }
          a { color: #58a6ff; text-decoration: none; }
        </style>
      </head>
      <body>
        <main>
          <a href="/">← Back to Dashboard</a>
          <h2>Bot Live Console Logs</h2>
          <div class="log-box" id="logs">
            ${logs.map(l => `<span class="log-entry">${escapeHTML(l)}</span>`).join("")}
          </div>
          <div class="console-row">
            <input id="cmd" class="input" placeholder="Type chat message or /command for Slot 1..." onkeydown="if(event.key==='Enter') sendCmd()">
            <button class="btn" onclick="sendCmd()">Send</button>
          </div>
        </main>
        <script>
          const box = document.getElementById('logs');
          box.scrollTop = box.scrollHeight;
          async function sendCmd() {
            const input = document.getElementById('cmd');
            const val = input.value.trim();
            if (!val) return;
            input.value = '';
            await fetch('/api/slot/1/chat', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ message: val })
            });
            setTimeout(() => location.reload(), 500);
          }
          setInterval(() => location.reload(), 6000);
        </script>
      </body>
    </html>
  `);
});

app.post("/start", (_req, res) => {
  const result = startSlot("1");
  res.json(result);
});

app.post("/stop", (_req, res) => {
  const result = stopSlot("1");
  res.json(result);
});

app.post("/command", (req, res) => {
  const cmd = (req.body.command || "").trim();
  if (!cmd) {
    res.json({ success: false, msg: "Empty command." });
    return;
  }
  const state = getState("1");
  if (state.bot?.entity) {
    try {
      state.bot.chat(cmd);
      res.json({ success: true, msg: `Sent to slot 1: ${cmd}` });
    } catch (e: any) {
      res.json({ success: false, msg: e.message });
    }
  } else {
    res.json({ success: false, msg: "Slot 1 bot is offline" });
  }
});

// ── Socket.IO Connection ──────────────────────────────────────────
io.on("connection", (socket) => {
  addGlobalLog(`[WS] Client connected: ${socket.id}`);
  for (let i = 1; i <= MAX_SLOTS; i++) {
    emitStatus(String(i));
  }
  socket.on("disconnect", () => {
    addGlobalLog(`[WS] Client disconnected: ${socket.id}`);
  });
});

// ── Auto-start registered slots on boot ─────────────────────────
for (const [id, data] of Object.entries(slotsData)) {
  if (data?.registered && data?.host) {
    addGlobalLog(`[Boot] Auto-starting slot ${id}...`);
    setTimeout(() => startSlot(id), 3_000 + Number(id) * 300);
  }
}

// ── Self-ping Keep-Alive ──────────────────────────────────────────
const pingTarget =
  process.env.APP_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  process.env.REPLIT_DOMAINS;

if (pingTarget) {
  const base = pingTarget.startsWith("http") ? pingTarget : `https://${pingTarget.split(",")[0]}`;
  const selfUrl = `${base}/ping`;
  const interval = parseInt(process.env.PING_INTERVAL_MS || "240000") || 4 * 60_000;
  setInterval(async () => {
    try {
      await fetch(selfUrl);
      addGlobalLog(`[KeepAlive] ✅ Self-ping OK — ${new Date().toLocaleTimeString()}`);
    } catch (e: any) {
      addGlobalLog(`[KeepAlive] ⚠️ Ping failed: ${e.message}`);
    }
  }, interval);
  addGlobalLog(`[KeepAlive] 🚀 Self-ping started → ${selfUrl}`);
}

// ── Immortal Crash Recovery Process Event Handlers ────────────────
process.on("uncaughtException", (err) => {
  addGlobalLog(`[FATAL] Uncaught Exception: ${err.message || err}`);
});

process.on("unhandledRejection", (reason) => {
  addGlobalLog(`[FATAL] Unhandled Rejection: ${reason}`);
});

// ── HTTP Listening Server ─────────────────────────────────────────
httpServer.listen(PORT, () => {
  addGlobalLog(`==================================================`);
  addGlobalLog(` Minecraft AFK Bot Manager Server Running on Port ${PORT}`);
  addGlobalLog(`==================================================`);
});
