# MC AFK Bot Manager v2.0 — Render.com Deploy Guide

## Is Project Mein Kya Hai
- ✅ 100-Slot Minecraft AFK Bot Manager
- ✅ Login System (Admin + Temp Accounts)
- ✅ Admin Panel — Temp accounts banao, time-limited access do
- ✅ Animated Neon UI + Background Video
- ✅ Discord Bot Integration (optional)
- ✅ Auto-reconnect with exponential backoff

---

## Ek Baar Ka Setup

### Step 1 — bgvideo.mp4 Add Karo
`public/` folder mein `bgvideo.mp4` dalo (yahi background video chalegi).
Agar nahi hai to bhi sab kaam karega, sirf background black rahega.

### Step 2 — GitHub Pe Upload Karo
1. https://github.com jao → New repository banao (name: `mc-afk-bot`, Private)
2. Sari files upload karo (drag & drop karo repository page pe):
   - `server.js`
   - `discord-bot.js`
   - `package.json`
   - `.env.example`  ← isko `.env` mat karo, waise hi rehne do
   - `public/` folder (index.html, login.html, admin.html, bgvideo.mp4)
3. "Commit changes" click karo

### Step 3 — Render.com Pe Deploy Karo
1. https://render.com → Sign up with GitHub
2. **"New +"** → **"Web Service"**
3. Apni `mc-afk-bot` repo connect karo

### Step 4 — Service Settings Fill Karo

| Field | Value |
|-------|-------|
| **Name** | mc-afk-bot |
| **Region** | Singapore |
| **Runtime** | Node |
| **Build Command** | `npm install` |
| **Start Command** | `node server.js` |
| **Plan** | Free |

### Step 5 — Environment Variables Add Karo

"Environment Variables" section mein yeh add karo:

| Key | Value |
|-----|-------|
| `PORT` | `10000` |
| `ADMIN_USERNAME` | `admin` (ya koi bhi naam) |
| `ADMIN_PASSWORD` | `TumharaStrongPassword123!` ← **CHANGE KARO** |

**Discord bot use karna ho to yeh bhi add karo (warna skip karo):**

| Key | Value |
|-----|-------|
| `DISCORD_BOT_TOKEN` | Bot token from Discord Developer Portal |
| `DISCORD_CLIENT_ID` | Bot's Client ID |
| `DISCORD_GUILD_ID` | Server ID (optional — faster command reg) |

### Step 6 — Deploy!
"Create Web Service" → 2-3 min mein build hoga → URL milega!

---

## Website Use Karna

### Admin Login
- `https://your-app.onrender.com/login.html` pe jao
- Username: jo `ADMIN_USERNAME` diya (default: `admin`)
- Password: jo `ADMIN_PASSWORD` diya

### Kisi Ko Temp Access Dena
1. `https://your-app.onrender.com/admin.html` pe jao (admin login se)
2. **"Create Temp Account"** form fill karo:
   - Username (jo dena chahte ho friend ko)
   - Password
   - Duration: jitne Hours : Minutes : Seconds ke liye access chahiye
3. **CREATE** press karo → Credentials dikhenge → Copy karke share karo
4. Woh `login.html` pe login karega — sirf utne time tak

### Access Turant Band Karna
Admin panel mein account ke saamne **✕ Revoke** button dabao — user turant logout!

---

## Login System Details

| Feature | Details |
|---------|---------|
| Admin account | Permanent, kabhi expire nahi hota |
| Temp account | Custom duration (seconds se weeks tak) |
| Auto-expire | Server side + Browser side dono check karta hai |
| Revoke | Admin kisi bhi waqt access kaat sakta hai |
| No login | Bina valid credentials ke `index.html` nahi khulega |
| Session timer | Temp users ko countdown dikhta hai |

---

## Data Files (Render Pe)
- `bot-slots.json` — Bot settings
- `auth-data.json` — Login accounts & sessions
- `discord-slots.json` — Discord bot data

**Important:** Render Free plan pe har restart pe yeh files **delete ho jati hain**.
Data save rakhne ke liye Render Disk add karo:
1. Service → Settings → Disks → "Add Disk"
2. Mount Path: `/opt/render/project/src`
3. Size: 1 GB

---

## 24/7 Ke Liye
Free plan 15 min inactivity pe sleep hoti hai. Auto-ping already code mein hai (har 4 min).
Better option: UptimeRobot (free) se ping karwao:
- URL: `https://your-app.onrender.com/api/healthz`
- Interval: 5 minutes

---

**Made by King Khizar | Enhanced by AI**
