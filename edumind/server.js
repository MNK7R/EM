/**
 * EduMind AI — BITTA FAYL: backend + frontend (HTML/CSS/JS) + baza.
 *
 * O'rnatish (bir marta):
 *   npm init -y
 *   npm install express bcryptjs jsonwebtoken
 *
 * Ishga tushirish:
 *   node server.js          ->  http://localhost:3000
 *
 * Sozlamalar (muhit o'zgaruvchilari):
 *   ANTHROPIC_API_KEY   — haqiqiy AI uchun (bo'lmasa demo rejim)
 *   AI_MODEL            — standart claude-sonnet-5-5
 *   JWT_SECRET          — productionda (NODE_ENV=production) MAJBURIY
 *   TZ_OFFSET_HOURS     — kunlik limit vaqt zonasi (standart 5, Toshkent)
 *   ALLOW_FREE_UPGRADE=1— faqat lokal sinov: to'lovsiz Premium tugmasi
 *   DB_FILE             — baza fayli yo'li (standart edumind-data.json)
 *
 * Frontend fayl oxirida (INDEX_HTML, STYLE_CSS, APP_JS) shablon satr sifatida joylangan.
 */

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";
const API_KEY = process.env.ANTHROPIC_API_KEY || "";
const MODEL = process.env.AI_MODEL || "claude-sonnet-5-5";
const TZ_OFFSET = Number(process.env.TZ_OFFSET_HOURS ?? 5); // Toshkent = UTC+5
const ALLOW_FREE_UPGRADE = process.env.ALLOW_FREE_UPGRADE === "1";

const FREE_DAILY_LIMIT = 3; // bepul: kuniga konspekt
const FREE_TEST_LIMIT = 10; // bepul: kuniga test
const PREMIUM_DAILY_CAP = 100; // premium: suiiste'molga qarshi yuqori chegara

const MAX_TOPIC = 200;
const MAX_SUBJECT = 100;
const MAX_SOURCE = 8000;

/* ---------- JWT maxfiy kalit ---------- */
let JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET) {
  if (IS_PROD) {
    console.error("XATO: productionda JWT_SECRET muhit o'zgaruvchisi majburiy.");
    process.exit(1);
  }
  JWT_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn("Ogohlantirish: JWT_SECRET berilmagan — vaqtinchalik kalit ishlatilmoqda (qayta ishga tushganda sessiyalar o'chadi).");
}


/* ------------------------------------------------------------------ */
/*  BAZA (JSON fayl): atomik yozish, buzilgan faylni himoya qilish     */
/* ------------------------------------------------------------------ */

const FILE = process.env.DB_FILE || path.join(__dirname, "edumind-data.json");
const TMP = FILE + ".tmp";

function empty() {
  return {
    seq: { users: 0, materials: 0, tests: 0, attempts: 0, groups: 0 },
    users: [],
    materials: [],
    tests: [],
    attempts: [],
    groups: [],
    group_members: [], // {group_id, user_id}
  };
}

function load() {
  if (!fs.existsSync(FILE)) return empty();
  const raw = fs.readFileSync(FILE, "utf8");
  if (raw.trim() === "") return empty();
  try {
    const parsed = JSON.parse(raw);
    const base = empty();
    return { ...base, ...parsed, seq: { ...base.seq, ...(parsed.seq || {}) } };
  } catch (e) {
    const backup = FILE + ".corrupt-" + Date.now();
    fs.copyFileSync(FILE, backup);
    throw new Error(
      `Baza fayli (${FILE}) buzilgan: ${e.message}\n` +
        `Nusxasi saqlandi: ${backup}\n` +
        `Iltimos, faylni qo'lda tuzating yoki tiklang — server bazani o'chirib yubormaslik uchun to'xtatildi.`
    );
  }
}

const data = load();

let saveTimer = null;
let dirty = false;

function writeNow() {
  if (!dirty) return;
  fs.writeFileSync(TMP, JSON.stringify(data, null, 2));
  fs.renameSync(TMP, FILE); // atomik almashtirish
  dirty = false;
}

function save() {
  dirty = true;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      writeNow();
    } catch (e) {
      console.error("Bazani saqlashda xato:", e.message);
    }
  }, 50);
}

/** Kutilayotgan o'zgarishlarni darhol yozadi (o'chirishdan oldin chaqiriladi). */
function flush() {
  clearTimeout(saveTimer);
  try {
    writeNow();
  } catch (e) {
    console.error("Bazani saqlashda xato:", e.message);
  }
}

process.on("exit", flush);

function nextId(table) {
  data.seq[table] = (data.seq[table] || 0) + 1;
  return data.seq[table];
}

function nowISO() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

/* ------------------------------------------------------------------ */
/*  YORDAMCHI                                                          */
/* ------------------------------------------------------------------ */

class AiError extends Error {}

const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", 10);

function sign(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, plan: u.plan };
}

function findUser(id) {
  return data.users.find((u) => u.id === id);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Avval tizimga kiring." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUser(payload.id);
    if (!user) return res.status(401).json({ error: "Foydalanuvchi topilmadi." });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Sessiya eskirgan, qayta kiring." });
  }
}

function teacherOnly(req, res, next) {
  if (req.user.role !== "teacher")
    return res.status(403).json({ error: "Bu bo'lim faqat o'qituvchi uchun." });
  next();
}

/** Async handlerlardagi xatolarni Express xato ishlovchisiga uzatadi. */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** Oddiy xotiradagi rate-limit (tashqi paket kerak emas). */
function rateLimit({ windowMs, max, message, byUser = false }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();
  return (req, res, next) => {
    const key = byUser && req.user ? "u" + req.user.id : "ip" + req.ip;
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset <= now) {
      h = { count: 0, reset: now + windowMs };
      hits.set(key, h);
    }
    h.count++;
    if (h.count > max) {
      res.set("Retry-After", String(Math.ceil((h.reset - now) / 1000)));
      return res.status(429).json({ error: message || "Juda ko'p so'rov. Birozdan keyin urinib ko'ring." });
    }
    next();
  };
}

/* ---- Sana (mahalliy vaqt zonasi bo'yicha) ---- */
function localDay(isoUtc) {
  const t = Date.parse(String(isoUtc).replace(" ", "T") + "Z");
  if (Number.isNaN(t)) return "";
  return new Date(t + TZ_OFFSET * 3600e3).toISOString().slice(0, 10);
}
function todayLocal() {
  return new Date(Date.now() + TZ_OFFSET * 3600e3).toISOString().slice(0, 10);
}

function usedToday(userId) {
  const today = todayLocal();
  return data.materials.filter((m) => m.user_id === userId && localDay(m.created_at) === today).length;
}
function testsToday(userId) {
  const today = todayLocal();
  return data.tests.filter((t) => t.owner_id === userId && localDay(t.created_at) === today).length;
}

/** Kunlik limitni tekshiradi; limit oshgan bo'lsa {status, error} qaytaradi. */
function quotaError(user, used, freeLimit, what) {
  if (user.plan === "premium") {
    return used >= PREMIUM_DAILY_CAP
      ? { status: 429, error: `Bugungi ${what} chegarasiga yetdingiz. Ertaga davom eting.` }
      : null;
  }
  return used >= freeLimit
    ? { status: 402, error: `Bepul tarifda kuniga ${freeLimit} ta ${what}. Premiumga o'ting.` }
    : null;
}

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // O/0, I/1 aralashmasligi uchun
function randomCode() {
  let s = "";
  for (let i = 0; i < 6; i++) s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  return s;
}

/** Email: ko'rinmas belgilar va bo'sh joylarni olib tashlaydi, kichik harfga o'tkazadi. */
function normalizeEmail(v) {
  return String(v == null ? "" : v)
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
    .trim()
    .toLowerCase();
}
const EMAIL_RE = /^[a-z0-9._%+'-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

/** Email xatosi matnini qaytaradi, to'g'ri bo'lsa null. */
function emailProblem(email) {
  if (!email) return "Emailni kiriting.";
  if (email.length > 254) return "Email juda uzun.";
  if (/[^\x00-\x7F]/.test(email))
    return "Email faqat lotin harflarida yozilishi kerak. Klaviatura tili (rus/o'zbek) ni tekshiring.";
  if (!EMAIL_RE.test(email)) return "Email noto'g'ri. Namuna: ism@gmail.com";
  return null;
}

function clampStr(v, max) {
  return String(v == null ? "" : v).trim().slice(0, max);
}

function parseIntStrict(v) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : NaN;
}

function isTeacherOfGroup(userId, groupId) {
  return data.groups.some((g) => g.id === groupId && g.teacher_id === userId);
}
function isMember(userId, groupId) {
  return data.group_members.some((m) => m.group_id === groupId && m.user_id === userId);
}
function canAccessTest(user, t) {
  if (t.owner_id === user.id) return true;
  if (!t.group_id) return false;
  return isTeacherOfGroup(user.id, t.group_id) || isMember(user.id, t.group_id);
}

function parseWeak(attempt) {
  try {
    const v = JSON.parse(attempt.weak_topics);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

/** Zaif mavzularni (katta-kichik harf farqisiz) sanaydi, eng ko'p uchraganidan boshlab. */
function tallyWeak(attempts) {
  const counts = new Map();
  for (const a of attempts) {
    for (const w of parseWeak(a)) {
      const label = String(w).trim();
      if (!label) continue;
      const key = label.toLowerCase();
      const cur = counts.get(key) || { topic: label, times: 0 };
      cur.times++;
      counts.set(key, cur);
    }
  }
  return [...counts.values()].sort((a, b) => b.times - a.times);
}

/** Test javoblaridan natija (review) tuzadi. */
function buildResult(test, questions, answers) {
  let score = 0;
  const weak = [];
  const review = questions.map((q, i) => {
    const chosen = Number.isInteger(answers[i]) ? answers[i] : null;
    const ok = chosen === q.answer;
    if (ok) score++;
    else weak.push(q.subtopic || test.topic);
    return {
      question: q.question,
      options: q.options,
      chosen,
      correct: q.answer,
      ok,
      explanation: q.explanation || "",
    };
  });
  return { score, total: questions.length, weak: [...new Set(weak)], review };
}

/* ------------------------------------------------------------------ */
/*  AI QATLAMI                                                         */
/* ------------------------------------------------------------------ */

async function askClaude(prompt, maxTokens) {
  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: maxTokens,
        messages: [{ role: "user", content: prompt }],
      }),
      signal: AbortSignal.timeout(90_000),
    });
  } catch (e) {
    throw new AiError("AI xizmatiga ulanib bo'lmadi: " + e.message);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new AiError(`AI xizmati xato qaytardi (${res.status}, model: ${MODEL}): ${body.slice(0, 300)}`);
  }
  const responseData = await res.json();
  if (responseData.stop_reason === "max_tokens")
    throw new AiError("AI javobi uzilib qoldi (max_tokens yetmadi).");
  return (responseData.content || [])
    .map((b) => (b.type === "text" ? b.text : ""))
    .join("")
    .trim();
}

function parseJson(text) {
  const clean = text.replace(/```json|```/g, "").trim();
  const start = clean.indexOf("{");
  const end = clean.lastIndexOf("}");
  try {
    return JSON.parse(start >= 0 && end > start ? clean.slice(start, end + 1) : clean);
  } catch {
    throw new AiError("AI javobini JSON sifatida o'qib bo'lmadi.");
  }
}

function cleanKonspekt(k, topic) {
  const arr = (v) => (Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : []);
  const summary = arr(k && k.summary).slice(0, 10);
  if (!summary.length) throw new AiError("AI javobi kutilgan formatda emas (summary yo'q).");
  return {
    topic: clampStr((k && k.topic) || topic, MAX_TOPIC),
    summary,
    explanation: clampStr(k && k.explanation, 4000),
    subtopics: arr(k && k.subtopics).slice(0, 6),
  };
}

function cleanQuestions(list, count) {
  const out = [];
  for (const q of Array.isArray(list) ? list : []) {
    if (!q || typeof q.question !== "string" || !q.question.trim()) continue;
    if (!Array.isArray(q.options) || q.options.length !== 4) continue;
    const answer = Number.parseInt(q.answer, 10);
    if (!(answer >= 0 && answer <= 3)) continue;
    out.push({
      question: q.question.trim(),
      options: q.options.map((o) => String(o).trim()),
      answer,
      subtopic: String(q.subtopic || "").trim(),
      explanation: String(q.explanation || "").trim(),
    });
  }
  return out.slice(0, count);
}

/** Kalit bo'lmasa ishlaydigan oddiy generator — faqat demo uchun. */
function demoKonspekt(topic, source) {
  const sentences = (source || "")
    .split(/[.!?\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 25)
    .slice(0, 5);
  const points =
    sentences.length > 0
      ? sentences
      : [
          `${topic} — asosiy tushuncha va ta'rifi.`,
          `${topic} qanday holatlarda yuzaga keladi.`,
          `${topic} bo'yicha asosiy qoida va formulalar.`,
          `${topic}ga oid tipik masala va yechim yo'li.`,
          `${topic}da eng ko'p uchraydigan xatolar.`,
        ];
  return {
    topic,
    summary: points,
    explanation: `${topic} mavzusi bo'yicha qisqa konspekt. Har bir band alohida o'rganilsa, mavzu to'liq yopiladi. (Demo rejim: ANTHROPIC_API_KEY qo'yilsa haqiqiy AI ishlaydi.)`,
    subtopics: points.slice(0, 3).map((p) => p.slice(0, 40)),
  };
}

function demoTest(topic, count) {
  const qs = [];
  for (let i = 1; i <= count; i++) {
    qs.push({
      question: `${topic} — namuna savol ${i}. To'g'ri javobni tanlang.`,
      options: [
        `${topic} bilan bog'liq to'g'ri javob`,
        "Noto'g'ri variant A",
        "Noto'g'ri variant B",
        "Noto'g'ri variant C",
      ],
      answer: 0,
      subtopic: `${topic} — qism ${i}`,
      explanation: "Demo rejimdagi tushuntirish.",
    });
  }
  return qs;
}

async function generateKonspekt(topic, source) {
  if (!API_KEY) return demoKonspekt(topic, source);
  const prompt = `Sen o'zbek tilidagi maktab va litsey o'quvchilariga dars beradigan tajribali o'qituvchisan.
Mavzu: "${topic}"
${source ? "Material:\n" + source.slice(0, 6000) : "Material berilmagan, mavzuning o'zidan foydalan."}

Faqat JSON qaytar, boshqa hech narsa yozma:
{"topic":"...","summary":["5-8 ta qisqa asosiy fikr"],"explanation":"2-4 abzas sodda tushuntirish","subtopics":["3-5 ta kichik mavzu nomi"]}`;
  return cleanKonspekt(parseJson(await askClaude(prompt, 3000)), topic);
}

async function generateTest(topic, source, count) {
  if (!API_KEY) return demoTest(topic, count);
  const prompt = `O'zbek tilida "${topic}" mavzusidan ${count} ta test savoli tuz.
${source ? "Material:\n" + source.slice(0, 6000) : ""}
Har savolda 4 ta variant bo'lsin, faqat bittasi to'g'ri. "answer" — to'g'ri variantning indeksi (0 dan 3 gacha, raqam).
"subtopic" — savol qaysi kichik mavzuni tekshirayotgani (qisqa, izchil nom).
"explanation" — 1-2 gap.

Faqat JSON qaytar:
{"questions":[{"question":"...","options":["...","...","...","..."],"answer":0,"subtopic":"...","explanation":"nega shunday"}]}`;
  const parsed = parseJson(await askClaude(prompt, 6000));
  const qs = cleanQuestions(parsed.questions, count);
  if (!qs.length) throw new AiError("AI yaroqli savollar qaytarmadi.");
  return qs;
}

/* ------------------------------------------------------------------ */
/*  APP                                                                */
/* ------------------------------------------------------------------ */

const app = express();
if (process.env.TRUST_PROXY) app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "200kb" }));

/* ---------- Frontend (server.js ichiga joylangan) ---------- */
app.get(["/", "/index.html"], (req, res) => res.type("html").send(INDEX_HTML));
app.get("/style.css", (req, res) => res.type("css").send(STYLE_CSS));
app.get("/app.js", (req, res) => res.type("js").send(APP_JS));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: "Juda ko'p urinish. 15 daqiqadan keyin qayta urinib ko'ring.",
});
const joinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  byUser: true,
  message: "Juda ko'p urinish. Birozdan keyin qayta urinib ko'ring.",
});
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  byUser: true,
  message: "Juda tez-tez so'rayapsiz. Bir daqiqadan keyin urinib ko'ring.",
});

/* ---------- Auth ---------- */

app.post("/api/auth/register", authLimiter, (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (typeof name !== "string" || name.trim().length < 2 || name.trim().length > 80)
    return res.status(400).json({ error: "Ismni kiriting (2–80 belgi)." });
  const emailLower = normalizeEmail(email);
  const emailErr = emailProblem(emailLower);
  if (emailErr) return res.status(400).json({ error: emailErr });
  if (typeof password !== "string" || password.length < 6)
    return res.status(400).json({ error: "Parol kamida 6 ta belgi bo'lsin." });
  if (password.length > 72)
    return res.status(400).json({ error: "Parol 72 ta belgidan oshmasin." });

  if (data.users.find((u) => u.email === emailLower))
    return res.status(409).json({ error: "Bu email allaqachon ro'yxatdan o'tgan." });

  const user = {
    id: nextId("users"),
    name: name.trim(),
    email: emailLower,
    password: bcrypt.hashSync(password, 10),
    role: role === "teacher" ? "teacher" : "student",
    plan: "free",
    created_at: nowISO(),
  };
  data.users.push(user);
  save();

  res.json({ token: sign(user), user: publicUser(user) });
});

app.post("/api/auth/login", authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const emailLower = normalizeEmail(email);
  const pass = typeof password === "string" ? password.slice(0, 72) : "";
  const user = data.users.find((u) => u.email === emailLower);
  // Foydalanuvchi topilmasa ham bcrypt ishlaydi — vaqt farqidan email aniqlanmasligi uchun.
  const ok = bcrypt.compareSync(pass, user ? user.password : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: "Email yoki parol xato." });
  res.json({ token: sign(user), user: publicUser(user) });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: publicUser(req.user),
    usedToday: usedToday(req.user.id),
    limit: FREE_DAILY_LIMIT,
    testsToday: testsToday(req.user.id),
    testLimit: FREE_TEST_LIMIT,
    upgradeEnabled: ALLOW_FREE_UPGRADE,
  });
});

/* ---------- Konspekt ---------- */

app.post(
  "/api/konspekt",
  auth,
  aiLimiter,
  wrap(async (req, res) => {
    const body = req.body || {};
    const topic = clampStr(body.topic, MAX_TOPIC);
    const subject = clampStr(body.subject, MAX_SUBJECT);
    const source = clampStr(body.source, MAX_SOURCE);
    if (topic.length < 2) return res.status(400).json({ error: "Mavzu nomini kiriting." });

    const q = quotaError(req.user, usedToday(req.user.id), FREE_DAILY_LIMIT, "konspekt");
    if (q) return res.status(q.status).json({ error: q.error });

    // Xato bo'lsa shu yerda AiError otiladi — hech narsa saqlanmaydi va limitga sanalmaydi.
    const konspekt = await generateKonspekt(topic, source);
    const row = {
      id: nextId("materials"),
      user_id: req.user.id,
      subject: subject || null,
      topic,
      source,
      konspekt: JSON.stringify(konspekt),
      created_at: nowISO(),
    };
    data.materials.push(row);
    save();

    res.json({ id: row.id, konspekt });
  })
);

app.get("/api/konspekt", auth, (req, res) => {
  const rows = data.materials
    .filter((m) => m.user_id === req.user.id)
    .sort((a, b) => b.id - a.id)
    .slice(0, 50)
    .map((m) => ({ id: m.id, topic: m.topic, subject: m.subject, created_at: m.created_at }));
  res.json(rows);
});

app.get("/api/konspekt/:id", auth, (req, res) => {
  const id = parseIntStrict(req.params.id);
  const row = data.materials.find((m) => m.id === id && m.user_id === req.user.id);
  if (!row) return res.status(404).json({ error: "Topilmadi." });
  res.json({ id: row.id, topic: row.topic, konspekt: JSON.parse(row.konspekt) });
});

/* ---------- Testlar ---------- */

app.post(
  "/api/tests",
  auth,
  aiLimiter,
  wrap(async (req, res) => {
    const body = req.body || {};
    const topic = clampStr(body.topic, MAX_TOPIC);
    const subject = clampStr(body.subject, MAX_SUBJECT);
    const source = clampStr(body.source, MAX_SOURCE);
    if (topic.length < 2) return res.status(400).json({ error: "Mavzu nomini kiriting." });
    const n = Math.min(Math.max(parseIntStrict(body.count) || 5, 1), 15);

    // Guruhga biriktirish: faqat o'qituvchi, faqat o'z guruhiga.
    let groupId = null;
    if (body.groupId !== undefined && body.groupId !== null && body.groupId !== "") {
      groupId = parseIntStrict(body.groupId);
      if (req.user.role !== "teacher" || !isTeacherOfGroup(req.user.id, groupId))
        return res.status(403).json({ error: "Bu guruhga test biriktira olmaysiz." });
    }

    const q = quotaError(req.user, testsToday(req.user.id), FREE_TEST_LIMIT, "test");
    if (q) return res.status(q.status).json({ error: q.error });

    const questions = await generateTest(topic, source, n);
    const row = {
      id: nextId("tests"),
      owner_id: req.user.id,
      group_id: groupId,
      topic,
      subject: subject || null,
      questions: JSON.stringify(questions),
      created_at: nowISO(),
    };
    data.tests.push(row);
    save();

    res.json({
      id: row.id,
      topic: row.topic,
      questions: questions.map((x) => ({ question: x.question, options: x.options })),
    });
  })
);

/** O'quvchi a'zo bo'lgan guruhlarga biriktirilgan testlar. */
app.get("/api/my-tests", auth, (req, res) => {
  const groupIds = new Set(
    data.group_members.filter((m) => m.user_id === req.user.id).map((m) => m.group_id)
  );
  const rows = data.tests
    .filter((t) => t.group_id && groupIds.has(t.group_id))
    .sort((a, b) => b.id - a.id)
    .slice(0, 50)
    .map((t) => {
      const g = data.groups.find((x) => x.id === t.group_id);
      return {
        id: t.id,
        topic: t.topic,
        group: g ? g.name : "",
        created_at: t.created_at,
        done: data.attempts.some((a) => a.test_id === t.id && a.user_id === req.user.id),
      };
    });
  res.json(rows);
});

app.get("/api/tests/:id", auth, (req, res) => {
  const t = data.tests.find((x) => x.id === parseIntStrict(req.params.id));
  if (!t || !canAccessTest(req.user, t)) return res.status(404).json({ error: "Test topilmadi." });
  const qs = JSON.parse(t.questions);
  res.json({
    id: t.id,
    topic: t.topic,
    questions: qs.map((q) => ({ question: q.question, options: q.options })),
  });
});

/** Oldin topshirilgan bo'lsa — saqlangan natija. */
app.get("/api/tests/:id/result", auth, (req, res) => {
  const t = data.tests.find((x) => x.id === parseIntStrict(req.params.id));
  if (!t || !canAccessTest(req.user, t)) return res.status(404).json({ error: "Test topilmadi." });
  const att = data.attempts.find((a) => a.test_id === t.id && a.user_id === req.user.id);
  if (!att) return res.status(404).json({ error: "Bu testni hali topshirmagansiz." });
  const result = buildResult(t, JSON.parse(t.questions), Array.isArray(att.answers) ? att.answers : []);
  res.json({ ...result, already: true });
});

app.post("/api/tests/:id/submit", auth, (req, res) => {
  const t = data.tests.find((x) => x.id === parseIntStrict(req.params.id));
  if (!t || !canAccessTest(req.user, t)) return res.status(404).json({ error: "Test topilmadi." });

  const questions = JSON.parse(t.questions);

  // Har test bir marta topshiriladi: qayta yuborilsa, saqlangan natija qaytadi (statistika buzilmaydi).
  const prev = data.attempts.find((a) => a.test_id === t.id && a.user_id === req.user.id);
  if (prev) {
    const result = buildResult(t, questions, Array.isArray(prev.answers) ? prev.answers : []);
    return res.json({ ...result, already: true });
  }

  const answers = req.body && req.body.answers;
  if (
    !Array.isArray(answers) ||
    answers.length !== questions.length ||
    !answers.every((a) => Number.isInteger(a) && a >= 0 && a <= 3)
  )
    return res.status(400).json({ error: "Barcha savollarga javob bering." });

  const result = buildResult(t, questions, answers);
  data.attempts.push({
    id: nextId("attempts"),
    test_id: t.id,
    user_id: req.user.id,
    score: result.score,
    total: result.total,
    answers,
    weak_topics: JSON.stringify(result.weak),
    created_at: nowISO(),
  });
  save();

  res.json(result);
});

/* ---------- Zaif mavzular va reja ---------- */

app.get("/api/plan", auth, (req, res) => {
  const rows = data.attempts
    .filter((a) => a.user_id === req.user.id)
    .sort((a, b) => b.id - a.id)
    .slice(0, 30);

  const weak = tallyWeak(rows).slice(0, 6);

  const days = ["Dushanba", "Seshanba", "Chorshanba", "Payshanba", "Juma"];
  const plan = weak.slice(0, 5).map((w, i) => ({
    day: days[i] || `Kun ${i + 1}`,
    task: `${w.topic} — konspektni qayta o'qing va 5 ta test yeching.`,
  }));

  const totalQ = rows.reduce((s, r) => s + r.total, 0);
  const totalS = rows.reduce((s, r) => s + r.score, 0);

  res.json({
    attempts: rows.length,
    accuracy: totalQ ? Math.round((totalS / totalQ) * 100) : null,
    weak,
    plan,
  });
});

app.get("/api/attempts", auth, (req, res) => {
  const rows = data.attempts
    .filter((a) => a.user_id === req.user.id)
    .sort((a, b) => b.id - a.id)
    .slice(0, 30)
    .map((a) => {
      const t = data.tests.find((x) => x.id === a.test_id);
      return { id: a.id, score: a.score, total: a.total, created_at: a.created_at, topic: t ? t.topic : "?" };
    });
  res.json(rows);
});

/* ---------- Guruhlar (o'qituvchi) ---------- */

app.post("/api/groups", auth, teacherOnly, (req, res) => {
  const name = clampStr(req.body && req.body.name, 80);
  if (name.length < 2) return res.status(400).json({ error: "Guruh nomini kiriting." });
  let code = randomCode();
  while (data.groups.find((g) => g.code === code)) code = randomCode();
  const row = {
    id: nextId("groups"),
    teacher_id: req.user.id,
    name,
    code,
    created_at: nowISO(),
  };
  data.groups.push(row);
  save();
  res.json({ id: row.id, name, code });
});

app.get("/api/groups", auth, teacherOnly, (req, res) => {
  const rows = data.groups
    .filter((g) => g.teacher_id === req.user.id)
    .sort((a, b) => b.id - a.id)
    .map((g) => ({
      ...g,
      members: data.group_members.filter((m) => m.group_id === g.id).length,
    }));
  res.json(rows);
});

app.post("/api/groups/join", auth, joinLimiter, (req, res) => {
  const code = clampStr(req.body && req.body.code, 20).toUpperCase();
  const g = data.groups.find((x) => x.code === code);
  if (!g) return res.status(404).json({ error: "Bunday kodli guruh yo'q." });
  if (!isMember(req.user.id, g.id)) {
    data.group_members.push({ group_id: g.id, user_id: req.user.id });
    save();
  }
  res.json({ ok: true, group: { id: g.id, name: g.name } });
});

app.get("/api/groups/:id/results", auth, teacherOnly, (req, res) => {
  const gid = parseIntStrict(req.params.id);
  const g = data.groups.find((x) => x.id === gid && x.teacher_id === req.user.id);
  if (!g) return res.status(404).json({ error: "Guruh topilmadi." });

  // Faqat shu guruhga biriktirilgan testlar bo'yicha natijalar ko'rsatiladi
  // (o'quvchining shaxsiy mashqlari o'qituvchiga ko'rinmaydi).
  const groupTestIds = new Set(data.tests.filter((t) => t.group_id === g.id).map((t) => t.id));
  const memberIds = data.group_members.filter((m) => m.group_id === g.id).map((m) => m.user_id);
  const members = memberIds.map((id) => findUser(id)).filter(Boolean);

  const rows = members.map((m) => {
    const att = data.attempts
      .filter((a) => a.user_id === m.id && groupTestIds.has(a.test_id))
      .sort((a, b) => b.id - a.id);
    const totalT = att.reduce((s, a) => s + a.total, 0);
    const totalS = att.reduce((s, a) => s + a.score, 0);
    const weak = tallyWeak(att.slice(0, 10))
      .slice(0, 3)
      .map((w) => w.topic);
    return {
      id: m.id,
      name: m.name,
      email: m.email,
      attempts: att.length,
      accuracy: totalT ? Math.round((totalS / totalT) * 100) : null,
      weak,
    };
  });

  res.json({ group: { id: g.id, name: g.name, code: g.code }, students: rows });
});

/* ---------- Tarif ---------- */

// To'lov tizimi ulanmaguncha bu yo'l O'CHIRILGAN. Faqat lokal sinov uchun
// ALLOW_FREE_UPGRADE=1 bilan yoqiladi (productionda yoqmang).
app.post("/api/plan/upgrade", auth, (req, res) => {
  if (!ALLOW_FREE_UPGRADE)
    return res.status(501).json({ error: "Premium to'lovi hali ulanmagan." });
  req.user.plan = "premium";
  save();
  res.json({ ok: true, plan: "premium" });
});

/* ---------- Fallback va xato ishlovchi ---------- */

app.use((req, res) => res.status(404).json({ error: "Bunday manzil yo'q." }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed")
    return res.status(400).json({ error: "So'rov formati noto'g'ri." });
  if (err.type === "entity.too.large")
    return res.status(413).json({ error: "So'rov juda katta." });
  if (err instanceof AiError) {
    console.error("AI xatosi:", err.message);
    return res
      .status(502)
      .json({ error: "AI xizmati hozir javob bermadi. Birozdan keyin qayta urinib ko'ring." });
  }
  console.error("Server xatosi:", err);
  res.status(500).json({ error: "Ichki server xatosi." });
});

const server = app.listen(PORT, () => {
  console.log(`EduMind AI ishga tushdi: http://localhost:${PORT}`);
  console.log(
    API_KEY
      ? `AI rejimi: haqiqiy (Anthropic API, model: ${MODEL})`
      : "AI rejimi: demo (ANTHROPIC_API_KEY qo'yilmagan)"
  );
});

function shutdown() {
  flush();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);


/* ------------------------------------------------------------------ */
/*  FRONTEND (shablon satrlar)                                         */
/*  Diqqat: ichkaridagi teskari tirnoq (`) va ${ } oldiga \ qo'yilgan  */
/*  — bu shablon satr ichida shunday yozish shart.                     */
/* ------------------------------------------------------------------ */

const INDEX_HTML = `<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>EduMind AI</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css">
</head>
<body>

<!-- ============ KIRISH EKRANI ============ -->
<div id="authScreen" class="auth-screen">
  <div class="auth-left">
    <div class="brand"><span class="glyph">EM</span>EduMind AI</div>
    <h1>Mavzuni yuklang.<br>Konspekt, test va o'quv reja o'zi tayyorlanadi.</h1>
    <p class="lead">Talaba mavzu yoki matnni beradi — platforma konspekt yozadi, test tuzadi va xato qilingan joylardan haftalik reja chiqaradi. O'qituvchi butun guruhni bitta ekrandan ko'radi.</p>
    <ul class="facts">
      <li>Konspekt va tushuntirish</li>
      <li>Avtomatik test va tekshiruv</li>
      <li>Zaif mavzular ro'yxati</li>
      <li>Guruh natijalari</li>
    </ul>
  </div>

  <div class="auth-right">
    <div class="panel">
      <div class="tabs">
        <button id="tabLogin" class="on">Kirish</button>
        <button id="tabReg">Ro'yxatdan o'tish</button>
      </div>

      <div id="regFields" hidden>
        <label for="rName">Ism familiya</label>
        <input id="rName" type="text" placeholder="Ism familiyangiz">
        <label for="rRole">Kim sifatida</label>
        <select id="rRole">
          <option value="student">Talaba</option>
          <option value="teacher">O'qituvchi</option>
        </select>
      </div>

      <label for="aEmail">Email</label>
      <input id="aEmail" type="email" placeholder="ism@example.com" autocomplete="email" autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="email">
      <label for="aPass">Parol</label>
      <input id="aPass" type="password" placeholder="Kamida 6 ta belgi">

      <button id="authBtn" class="cta">Kirish</button>
      <p id="authMsg" class="msg"></p>
      <p class="hint">Ma'lumotlaringiz serverda saqlanadi, parol shifrlangan holda.</p>
    </div>
  </div>
</div>

<!-- ============ ASOSIY ILOVA ============ -->
<div id="app" hidden>
  <header>
    <div class="bar">
      <div class="brand"><span class="glyph">EM</span>EduMind AI</div>
      <nav id="nav">
        <button data-view="konspekt" class="on">Konspekt</button>
        <button data-view="test">Test</button>
        <button data-view="plan">Reja</button>
        <button data-view="group">Guruh</button>
      </nav>
      <div class="who">
        <span id="whoName"></span>
        <span id="whoPlan" class="badge"></span>
        <span id="whoQuota" class="badge" hidden></span>
        <button id="upgradeBtn" class="ghost" hidden>Premium (sinov)</button>
        <button id="logout" class="ghost">Chiqish</button>
      </div>
    </div>
  </header>

  <main class="wrap">

    <!-- KONSPEKT -->
    <section id="v-konspekt" class="view">
      <h2>Konspekt tayyorlash</h2>
      <div class="grid2">
        <div class="card">
          <label for="kTopic">Mavzu</label>
          <input id="kTopic" placeholder="Masalan: Oksidlanish-qaytarilish reaksiyalari">
          <label for="kSubject">Fan (ixtiyoriy)</label>
          <input id="kSubject" placeholder="Kimyo">
          <label for="kSource">Matn (ixtiyoriy — darslikdan ko'chiring)</label>
          <textarea id="kSource" placeholder="Bu yerga mavzu matnini qo'ying..."></textarea>
          <button id="kBtn" class="cta">Konspekt yasash</button>
          <p id="kMsg" class="msg"></p>
        </div>
        <div>
          <div id="kOut" class="card out empty">Konspekt shu yerda chiqadi.</div>
          <h3 class="mini">Oxirgi konspektlar</h3>
          <div id="kList" class="list"></div>
        </div>
      </div>
    </section>

    <!-- TEST -->
    <section id="v-test" class="view" hidden>
      <h2>Test</h2>
      <div class="grid2">
        <div class="card">
          <label for="tTopic">Mavzu</label>
          <input id="tTopic" placeholder="Masalan: Nyuton qonunlari">
          <label for="tSource">Matn (ixtiyoriy)</label>
          <textarea id="tSource" placeholder="Test shu matndan tuzilsin..."></textarea>
          <div id="tGroupWrap" hidden>
            <label for="tGroup">Guruhga biriktirish (ixtiyoriy)</label>
            <select id="tGroup"><option value="">Biriktirmaslik</option></select>
          </div>
          <label for="tCount">Savollar soni</label>
          <input id="tCount" type="number" min="1" max="15" value="5">
          <button id="tBtn" class="cta">Test tuzish</button>
          <p id="tMsg" class="msg"></p>
        </div>
        <div id="tOut" class="card out empty">Savollar shu yerda chiqadi.</div>
      </div>
      <div id="gtBox" hidden>
        <h3 class="mini">Guruh testlari</h3>
        <div id="gtList" class="list"></div>
      </div>
    </section>

    <!-- REJA -->
    <section id="v-plan" class="view" hidden>
      <h2>Zaif mavzular va o'quv reja</h2>
      <div id="planOut" class="card out empty">Bir nechta test yechsangiz, reja shu yerda paydo bo'ladi.</div>
      <h3 class="mini">Test tarixi</h3>
      <div id="attList" class="list"></div>
    </section>

    <!-- GURUH -->
    <section id="v-group" class="view" hidden>
      <h2>Guruh</h2>
      <div id="groupBody"></div>
    </section>

  </main>
</div>

<script src="/app.js"></script>
</body>
</html>
`;

const STYLE_CSS = `:root{
  --paper:#FBFAF7; --card:#FFFFFF; --ink:#16243D; --graphite:#59627A;
  --blue:#1F4FD8; --blue-soft:#E8EDFF; --mark:#FFD24A; --rule:#E4E7EE;
  --ok:#1C8A5B; --err:#C23B33;
  box-sizing:border-box;
  padding-top:env(safe-area-inset-top,0px);
  padding-bottom:env(safe-area-inset-bottom,0px);
}
@media (prefers-color-scheme: dark){
  :root{
    --paper:#0F1420; --card:#161D2B; --ink:#EEF2FA; --graphite:#98A2B8;
    --blue:#7D9BFF; --blue-soft:#1B2540; --rule:#27304A;
    --ok:#4BC28C; --err:#FF8177;
  }
}
*,*::before,*::after{box-sizing:border-box}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:Inter,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.6;
  -webkit-font-smoothing:antialiased}
h1,h2,h3,.brand{font-family:"Bricolage Grotesque",Inter,sans-serif;font-weight:700;
  line-height:1.1;letter-spacing:-.02em;margin:0}
h1{font-size:clamp(1.8rem,3.6vw,2.7rem)}
h2{font-size:1.5rem;margin-bottom:24px}
h3{font-size:1rem;font-weight:600}
p{margin:0}
.wrap{max-width:1100px;margin:0 auto;padding:0 20px}
.brand{display:flex;align-items:center;gap:10px;font-size:1.12rem}
.glyph{width:30px;height:30px;border-radius:9px;background:var(--ink);color:var(--paper);
  display:grid;place-items:center;font-size:.82rem;font-weight:700}

/* ---- kirish ekrani ---- */
.auth-screen{display:grid;grid-template-columns:1.05fr .95fr;min-height:100vh}
@media(max-width:900px){.auth-screen{grid-template-columns:1fr}}
.auth-left{padding:56px 48px;border-right:1px solid var(--rule);
  background-image:repeating-linear-gradient(to bottom,transparent 0 31px,var(--rule) 31px 32px);
  background-position:0 160px}
@media(max-width:900px){.auth-left{border-right:0;border-bottom:1px solid var(--rule);padding:40px 20px}}
.auth-left h1{margin-top:44px}
.lead{margin-top:18px;max-width:46ch;color:var(--graphite)}
.facts{margin:30px 0 0;padding:0;list-style:none;display:grid;gap:0;max-width:340px}
.facts li{padding:12px 0;border-top:1px solid var(--rule);font-size:.94rem}
.facts li:last-child{border-bottom:1px solid var(--rule)}
.auth-right{padding:56px 48px;display:flex;align-items:center}
@media(max-width:900px){.auth-right{padding:40px 20px}}
.panel{width:100%;max-width:380px;margin:0 auto}
.tabs{display:flex;gap:4px;background:var(--blue-soft);padding:4px;border-radius:11px;margin-bottom:8px}
.tabs button{flex:1;border:0;background:transparent;font:inherit;font-size:.92rem;
  color:var(--graphite);padding:9px;border-radius:8px;cursor:pointer}
.tabs button.on{background:var(--card);color:var(--ink);font-weight:600}

/* ---- formalar ---- */
label{display:block;font-size:.85rem;margin:16px 0 6px;color:var(--graphite)}
input,select,textarea{width:100%;padding:11px 13px;border:1px solid var(--rule);
  background:var(--card);color:var(--ink);border-radius:10px;font:inherit;font-size:.95rem}
textarea{min-height:120px;resize:vertical}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.cta{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;
  background:var(--ink);color:var(--paper);font:inherit;font-weight:600;cursor:pointer}
.cta:hover{background:var(--blue)}
.cta:disabled{opacity:.6;cursor:default}
.ghost{border:1px solid var(--rule);background:transparent;color:var(--graphite);
  border-radius:999px;padding:6px 13px;font:inherit;font-size:.85rem;cursor:pointer}
.ghost:hover{color:var(--ink)}
.msg{margin-top:12px;font-size:.88rem;min-height:20px}
.msg.err{color:var(--err)}
.msg.ok{color:var(--ok)}
.hint{margin-top:18px;font-size:.8rem;color:var(--graphite);
  border-top:1px solid var(--rule);padding-top:12px}

/* ---- header ---- */
header{position:sticky;top:env(safe-area-inset-top,0px);z-index:30;
  background:var(--paper);border-bottom:1px solid var(--rule)}
.bar{max-width:1100px;margin:0 auto;padding:0 20px;display:flex;align-items:center;
  gap:22px;height:66px;flex-wrap:wrap}
nav{display:flex;gap:4px}
nav button{border:0;background:transparent;font:inherit;font-size:.93rem;
  color:var(--graphite);padding:7px 13px;border-radius:8px;cursor:pointer}
nav button.on{background:var(--blue-soft);color:var(--blue);font-weight:600}
.who{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:.9rem}
.badge{background:var(--mark);color:#16243D;padding:2px 9px;border-radius:999px;font-size:.76rem;font-weight:600}
@media(max-width:700px){.bar{height:auto;padding:12px 20px}.who{width:100%;margin-left:0}}

/* ---- kontent ---- */
main{padding:38px 0 70px}
.grid2{display:grid;grid-template-columns:minmax(0,340px) minmax(0,1fr);gap:26px;align-items:start}
@media(max-width:860px){.grid2{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--rule);border-radius:14px;padding:22px}
.card label:first-child{margin-top:0}
.out{min-height:160px}
.out.empty{color:var(--graphite);display:grid;place-items:center;text-align:center;font-size:.93rem}
.mini{margin:28px 0 12px;color:var(--graphite);font-weight:600;font-size:.88rem}
.list{display:grid;gap:0}
.list .row{display:flex;justify-content:space-between;gap:14px;padding:12px 0;
  border-top:1px solid var(--rule);font-size:.92rem;align-items:center}
.list .row:last-child{border-bottom:1px solid var(--rule)}
.list .row span{color:var(--graphite);font-size:.85rem}
.list .row button{border:0;background:transparent;color:var(--blue);font:inherit;
  font-size:.88rem;cursor:pointer;padding:0}

.k-points{margin:14px 0 0;padding-left:20px;display:grid;gap:8px}
.k-points li{font-size:.95rem}
.k-exp{margin-top:16px;padding-top:14px;border-top:1px solid var(--rule);
  color:var(--graphite);font-size:.93rem;white-space:pre-wrap}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:14px}
.chip{background:var(--blue-soft);color:var(--blue);padding:4px 10px;border-radius:999px;font-size:.82rem}

/* test */
.q{padding:18px 0;border-top:1px solid var(--rule)}
.q:first-child{border-top:0;padding-top:0}
.q p.qt{font-weight:600;font-size:.96rem}
.opts{display:grid;gap:7px;margin-top:10px}
.opt{display:flex;gap:9px;align-items:flex-start;padding:9px 12px;border:1px solid var(--rule);
  border-radius:9px;cursor:pointer;font-size:.92rem}
.opt:hover{border-color:var(--blue)}
.opt input{width:auto;margin-top:4px}
.opt.right{border-color:var(--ok);color:var(--ok)}
.opt.wrong{border-color:var(--err);color:var(--err)}
.exp{margin-top:8px;font-size:.86rem;color:var(--graphite)}
.score{font-family:"Bricolage Grotesque";font-size:1.6rem;margin-bottom:6px}

/* reja */
.plan-row{display:grid;grid-template-columns:110px 1fr;gap:14px;padding:12px 0;border-top:1px solid var(--rule)}
.plan-row b{color:var(--blue);font-weight:600;font-size:.9rem}
.stat{display:flex;gap:30px;flex-wrap:wrap;margin-bottom:6px}
.stat div b{display:block;font-family:"Bricolage Grotesque";font-size:1.7rem;font-weight:700}
.stat div span{color:var(--graphite);font-size:.85rem}
table{width:100%;border-collapse:collapse;font-size:.92rem;margin-top:8px}
th,td{text-align:left;padding:11px 8px;border-top:1px solid var(--rule)}
th{color:var(--graphite);font-weight:500;font-size:.84rem}
.code{font-family:ui-monospace,Menlo,monospace;background:var(--blue-soft);color:var(--blue);
  padding:2px 8px;border-radius:6px}
`;

const APP_JS = `/* EduMind AI — frontend mantiq */

const $ = (id) => document.getElementById(id);
let token = null;
let me = null;
let currentTest = null;

try { token = localStorage.getItem("em_token"); } catch (e) {}

/* ---------- API ---------- */
async function api(path, options = {}) {
  const res = await fetch("/api" + path, {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  // Sessiya tugagan bo'lsa (login/ro'yxat so'rovlaridan tashqari) — kirish ekraniga qaytamiz.
  if (res.status === 401 && token && !path.startsWith("/auth/")) {
    forceLogout("Sessiya tugadi, qayta kiring.");
    throw new Error(data.error || "Sessiya tugadi.");
  }
  if (!res.ok) throw new Error(data.error || "Xatolik yuz berdi.");
  return data;
}

function say(el, text, ok) {
  el.textContent = text;
  el.className = "msg " + (ok ? "ok" : "err");
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/* ---------- Ekranni tozalash (chiqishda oldingi foydalanuvchi ma'lumoti qolmasligi uchun) ---------- */
function resetKonspektOut() {
  const el = $("kOut");
  el.className = "card out empty";
  el.textContent = "Konspekt shu yerda chiqadi.";
}
function resetTestOut() {
  currentTest = null;
  const el = $("tOut");
  el.className = "card out empty";
  el.textContent = "Savollar shu yerda chiqadi.";
}
function clearUI() {
  currentTest = null;
  resetKonspektOut();
  resetTestOut();
  $("kList").innerHTML = "";
  $("gtList").innerHTML = "";
  $("gtBox").hidden = true;
  $("groupBody").innerHTML = "";
  $("attList").innerHTML = "";
  const plan = $("planOut");
  plan.className = "card out empty";
  plan.textContent = "Bir nechta test yechsangiz, reja shu yerda paydo bo'ladi.";
  ["kTopic", "kSubject", "kSource", "tTopic", "tSource", "aPass"].forEach((id) => ($(id).value = ""));
  $("tCount").value = 5;
  $("tGroup").innerHTML = '<option value="">Biriktirmaslik</option>';
  $("tGroupWrap").hidden = true;
  ["kMsg", "tMsg"].forEach((id) => { $(id).textContent = ""; });
}

function forceLogout(message) {
  token = null;
  me = null;
  try { localStorage.removeItem("em_token"); } catch (e) {}
  clearUI();
  $("app").hidden = true;
  $("authScreen").hidden = false;
  if (message) say($("authMsg"), message);
}

/* ---------- Kirish / ro'yxat ---------- */
let mode = "login";

$("tabLogin").onclick = () => setMode("login");
$("tabReg").onclick = () => setMode("register");

function setMode(m) {
  mode = m;
  $("tabLogin").className = m === "login" ? "on" : "";
  $("tabReg").className = m === "register" ? "on" : "";
  $("regFields").hidden = m !== "register";
  $("authBtn").textContent = m === "login" ? "Kirish" : "Hisob ochish";
  $("authMsg").textContent = "";
}

$("authBtn").onclick = async () => {
  const btn = $("authBtn");
  // Ko'rinmas belgilar (telefon klaviaturasi qo'shishi mumkin) va bo'sh joylarni olib tashlaymiz
  const email = $("aEmail").value
    .normalize("NFKC")
    .replace(/[\\u200B-\\u200D\\u2060\\uFEFF]/g, "")
    .trim();
  if (/[^\\x00-\\x7F]/.test(email)) {
    say($("authMsg"), "Email faqat lotin harflarida yozilishi kerak. Klaviatura tilini tekshiring.");
    return;
  }
  const body = { email, password: $("aPass").value };
  if (mode === "register") {
    body.name = $("rName").value.trim();
    body.role = $("rRole").value;
  }
  btn.disabled = true;
  try {
    const data = await api(mode === "login" ? "/auth/login" : "/auth/register", {
      method: "POST",
      body,
    });
    token = data.token;
    try { localStorage.setItem("em_token", token); } catch (e) {}
    await start();
  } catch (e) {
    say($("authMsg"), e.message);
  } finally {
    btn.disabled = false;
  }
};

$("logout").onclick = () => forceLogout();

/* ---------- Boshlash ---------- */
async function refreshMe() {
  const data = await api("/me");
  me = data.user;
  $("whoName").textContent = me.name + (me.role === "teacher" ? " · o'qituvchi" : "");
  $("whoPlan").textContent = me.plan === "premium" ? "Premium" : "Bepul";

  const quota = $("whoQuota");
  if (me.plan === "free") {
    quota.hidden = false;
    quota.textContent = \`Bugun: konspekt \${data.usedToday}/\${data.limit} · test \${data.testsToday}/\${data.testLimit}\`;
  } else {
    quota.hidden = true;
  }
  // Faqat server sinov rejimida ruxsat bersa ko'rinadi
  $("upgradeBtn").hidden = !(data.upgradeEnabled && me.plan === "free");
  return data;
}

$("upgradeBtn").onclick = async () => {
  try {
    await api("/plan/upgrade", { method: "POST" });
    await refreshMe();
  } catch (e) {
    alert(e.message);
  }
};

async function start() {
  await refreshMe();
  $("authScreen").hidden = true;
  $("app").hidden = false;
  $("aPass").value = "";
  loadKonspektList();
  show("konspekt");
}

/* ---------- Navigatsiya ---------- */
document.querySelectorAll("#nav button").forEach((b) => {
  b.onclick = () => show(b.dataset.view);
});

function show(view) {
  document.querySelectorAll("#nav button").forEach((b) =>
    b.classList.toggle("on", b.dataset.view === view)
  );
  ["konspekt", "test", "plan", "group"].forEach((v) => {
    $("v-" + v).hidden = v !== view;
  });
  if (view === "test") loadTestSidebar();
  if (view === "plan") loadPlan();
  if (view === "group") loadGroup();
}

/* ---------- Konspekt ---------- */
$("kBtn").onclick = async () => {
  const btn = $("kBtn");
  btn.disabled = true;
  btn.textContent = "Tayyorlanmoqda...";
  say($("kMsg"), "", true);
  try {
    const data = await api("/konspekt", {
      method: "POST",
      body: {
        topic: $("kTopic").value.trim(),
        subject: $("kSubject").value.trim(),
        source: $("kSource").value.trim(),
      },
    });
    renderKonspekt(data.konspekt);
    loadKonspektList();
    refreshMe().catch(() => {});
    say($("kMsg"), "Tayyor.", true);
  } catch (e) {
    say($("kMsg"), e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Konspekt yasash";
  }
};

function renderKonspekt(k) {
  const el = $("kOut");
  el.className = "card out";
  el.innerHTML =
    \`<h3>\${esc(k.topic)}</h3>\` +
    \`<ol class="k-points">\${(k.summary || []).map((s) => \`<li>\${esc(s)}</li>\`).join("")}</ol>\` +
    (k.explanation ? \`<div class="k-exp">\${esc(k.explanation)}</div>\` : "") +
    (k.subtopics && k.subtopics.length
      ? \`<div class="chips">\${k.subtopics.map((s) => \`<span class="chip">\${esc(s)}</span>\`).join("")}</div>\`
      : "");
}

async function loadKonspektList() {
  try {
    const rows = await api("/konspekt");
    $("kList").innerHTML = rows.length
      ? rows
          .map(
            (r) =>
              \`<div class="row"><button data-k="\${r.id}">\${esc(r.topic)}</button>
               <span>\${esc((r.created_at || "").slice(0, 10))}</span></div>\`
          )
          .join("")
      : \`<div class="row"><span>Hozircha bo'sh.</span></div>\`;
    $("kList").querySelectorAll("button[data-k]").forEach((b) => {
      b.onclick = async () => {
        try {
          const data = await api("/konspekt/" + b.dataset.k);
          renderKonspekt(data.konspekt);
          window.scrollTo({ top: 0, behavior: "smooth" });
        } catch (e) {
          say($("kMsg"), e.message);
        }
      };
    });
  } catch (e) {}
}

/* ---------- Test ---------- */
async function loadTestSidebar() {
  if (!me) return;
  try {
    if (me.role === "teacher") {
      // Guruhga biriktirish uchun o'qituvchining guruhlari
      const groups = await api("/groups");
      const sel = $("tGroup");
      const keep = sel.value;
      sel.innerHTML =
        '<option value="">Biriktirmaslik</option>' +
        groups.map((g) => \`<option value="\${g.id}">\${esc(g.name)}</option>\`).join("");
      if ([...sel.options].some((o) => o.value === keep)) sel.value = keep;
      $("tGroupWrap").hidden = groups.length === 0;
      $("gtBox").hidden = true;
    } else {
      $("tGroupWrap").hidden = true;
      await loadGroupTests();
    }
  } catch (e) {}
}

async function loadGroupTests() {
  const rows = await api("/my-tests");
  $("gtBox").hidden = rows.length === 0;
  $("gtList").innerHTML = rows
    .map(
      (r) =>
        \`<div class="row"><button data-t="\${r.id}" data-done="\${r.done ? 1 : 0}">\${esc(r.topic)}</button>
         <span>\${esc(r.group)} · \${r.done ? "topshirilgan" : "yechilmagan"}</span></div>\`
    )
    .join("");
  $("gtList").querySelectorAll("button[data-t]").forEach((b) => {
    b.onclick = async () => {
      try {
        if (b.dataset.done === "1") {
          renderResult(await api("/tests/" + b.dataset.t + "/result"));
        } else {
          const t = await api("/tests/" + b.dataset.t);
          currentTest = t;
          renderTest(t);
        }
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch (e) {
        say($("tMsg"), e.message);
      }
    };
  });
}

$("tBtn").onclick = async () => {
  const btn = $("tBtn");
  btn.disabled = true;
  btn.textContent = "Tuzilmoqda...";
  say($("tMsg"), "", true);
  try {
    const body = {
      topic: $("tTopic").value.trim(),
      source: $("tSource").value.trim(),
      count: parseInt($("tCount").value, 10) || 5,
    };
    if (me && me.role === "teacher" && $("tGroup").value) body.groupId = $("tGroup").value;
    const data = await api("/tests", { method: "POST", body });
    currentTest = data;
    renderTest(data);
    refreshMe().catch(() => {});
    say($("tMsg"), body.groupId ? "Test tayyor va guruhga biriktirildi." : "Test tayyor.", true);
  } catch (e) {
    say($("tMsg"), e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Test tuzish";
  }
};

function renderTest(t) {
  const el = $("tOut");
  el.className = "card out";
  el.innerHTML =
    \`<h3>\${esc(t.topic)}</h3>\` +
    t.questions
      .map(
        (q, i) => \`
      <div class="q" data-q="\${i}">
        <p class="qt">\${i + 1}. \${esc(q.question)}</p>
        <div class="opts">
          \${q.options
            .map(
              (o, j) =>
                \`<label class="opt"><input type="radio" name="q\${i}" value="\${j}">
                 <span>\${esc(o)}</span></label>\`
            )
            .join("")}
        </div>
      </div>\`
      )
      .join("") +
    \`<button class="cta" id="submitTest">Javoblarni topshirish</button>
     <p class="msg" id="testMsg"></p>\`;

  $("submitTest").onclick = submitTest;
}

async function submitTest() {
  if (!currentTest) return;
  const answers = currentTest.questions.map((_, i) => {
    const sel = document.querySelector(\`input[name="q\${i}"]:checked\`);
    return sel ? parseInt(sel.value, 10) : -1;
  });
  if (answers.includes(-1)) {
    say($("testMsg"), "Barcha savollarga javob bering.");
    return;
  }
  const btn = $("submitTest");
  btn.disabled = true;
  try {
    const r = await api("/tests/" + currentTest.id + "/submit", {
      method: "POST",
      body: { answers },
    });
    renderResult(r);
    if (me && me.role !== "teacher") loadGroupTests().catch(() => {});
  } catch (e) {
    say($("testMsg"), e.message);
    btn.disabled = false;
  }
}

function renderResult(r) {
  const el = $("tOut");
  el.className = "card out";
  el.innerHTML =
    (r.already
      ? \`<p style="color:var(--graphite);font-size:.85rem;margin-bottom:8px">Bu testni avval topshirgansiz — oldingi natija ko'rsatilmoqda.</p>\`
      : "") +
    \`<div class="score">\${r.score} / \${r.total}</div>
     <p style="color:var(--graphite);font-size:.92rem">\${
       r.weak.length ? "Bo'sh qolgan mavzular: " + esc(r.weak.join(", ")) : "Hamma savol to'g'ri."
     }</p>\` +
    r.review
      .map(
        (q, i) => \`
      <div class="q">
        <p class="qt">\${i + 1}. \${esc(q.question)}</p>
        <div class="opts">
          \${q.options
            .map(
              (o, j) =>
                \`<div class="opt \${j === q.correct ? "right" : j === q.chosen ? "wrong" : ""}">
                  <span>\${esc(o)}</span></div>\`
            )
            .join("")}
        </div>
        \${q.explanation ? \`<p class="exp">\${esc(q.explanation)}</p>\` : ""}
      </div>\`
      )
      .join("") +
    \`<button class="cta" id="newTestBtn">Yangi test</button>\`;

  $("newTestBtn").onclick = () => {
    resetTestOut();
    $("tTopic").focus();
  };
}

/* ---------- Reja ---------- */
async function loadPlan() {
  try {
    const p = await api("/plan");
    const el = $("planOut");
    if (!p.attempts) {
      el.className = "card out empty";
      el.textContent = "Bir nechta test yechsangiz, reja shu yerda paydo bo'ladi.";
    } else {
      el.className = "card out";
      el.innerHTML =
        \`<div class="stat">
           <div><b>\${p.attempts}</b><span>test yechildi</span></div>
           <div><b>\${p.accuracy == null ? "—" : p.accuracy + "%"}</b><span>to'g'ri javob</span></div>
           <div><b>\${p.weak.length}</b><span>zaif mavzu</span></div>
         </div>\` +
        (p.weak.length
          ? \`<div class="chips">\${p.weak
              .map((w) => \`<span class="chip">\${esc(w.topic)} · \${w.times}</span>\`)
              .join("")}</div>\`
          : "") +
        (p.plan.length
          ? \`<h3 style="margin-top:22px">Shu haftaga reja</h3>\` +
            p.plan
              .map((d) => \`<div class="plan-row"><b>\${esc(d.day)}</b><div>\${esc(d.task)}</div></div>\`)
              .join("")
          : "");
    }

    const rows = await api("/attempts");
    $("attList").innerHTML = rows.length
      ? rows
          .map(
            (a) =>
              \`<div class="row"><div>\${esc(a.topic)}</div>
               <span>\${a.score}/\${a.total} · \${esc((a.created_at || "").slice(0, 10))}</span></div>\`
          )
          .join("")
      : \`<div class="row"><span>Hozircha bo'sh.</span></div>\`;
  } catch (e) {}
}

/* ---------- Guruh ---------- */
async function loadGroup() {
  const el = $("groupBody");
  try {
    if (me.role === "teacher") {
      const groups = await api("/groups");
      el.innerHTML =
        \`<div class="card" style="max-width:420px">
           <label for="gName">Yangi guruh nomi</label>
           <input id="gName" placeholder="10-A sinf, Kimyo">
           <button class="cta" id="gBtn">Guruh ochish</button>
           <p class="msg" id="gMsg"></p>
         </div>
         <h3 class="mini">Guruhlarim</h3>
         <div class="list" id="gList">\${
           groups.length
             ? groups
                 .map(
                   (g) =>
                     \`<div class="row"><button data-g="\${g.id}">\${esc(g.name)}</button>
                      <span>kod: <b class="code">\${esc(g.code)}</b> · \${g.members} o'quvchi</span></div>\`
                 )
                 .join("")
             : \`<div class="row"><span>Hali guruh yo'q.</span></div>\`
         }</div>
         <div id="gResults"></div>\`;

      $("gBtn").onclick = async () => {
        try {
          await api("/groups", { method: "POST", body: { name: $("gName").value.trim() } });
          loadGroup();
        } catch (e) {
          say($("gMsg"), e.message);
        }
      };

      el.querySelectorAll("button[data-g]").forEach((b) => {
        b.onclick = async () => {
          try {
            const r = await api("/groups/" + b.dataset.g + "/results");
            $("gResults").innerHTML =
              \`<h3 class="mini">\${esc(r.group.name)} — natijalar (kod: \${esc(r.group.code)})</h3>
               <div class="card"><table>
                 <tr><th>O'quvchi</th><th>Testlar</th><th>To'g'ri</th><th>Zaif mavzular</th></tr>
                 \${
                   r.students.length
                     ? r.students
                         .map(
                           (s) =>
                             \`<tr><td>\${esc(s.name)}</td><td>\${s.attempts}</td>
                              <td>\${s.accuracy == null ? "—" : s.accuracy + "%"}</td>
                              <td>\${esc(s.weak.join(", ")) || "—"}</td></tr>\`
                         )
                         .join("")
                     : \`<tr><td colspan="4">Hali o'quvchi qo'shilmagan. Kodni ularga bering.</td></tr>\`
                 }
               </table></div>
               <p class="hint">Bu yerda faqat shu guruhga biriktirilgan testlar natijasi ko'rsatiladi.</p>\`;
          } catch (e) {
            say($("gMsg"), e.message);
          }
        };
      });
    } else {
      el.innerHTML = \`
        <div class="card" style="max-width:420px">
          <label for="jCode">Guruh kodi</label>
          <input id="jCode" placeholder="Masalan: 7KD2QX">
          <button class="cta" id="jBtn">Guruhga qo'shilish</button>
          <p class="msg" id="jMsg"></p>
        </div>\`;
      $("jBtn").onclick = async () => {
        try {
          const r = await api("/groups/join", { method: "POST", body: { code: $("jCode").value } });
          say($("jMsg"), \`"\${r.group.name}" guruhiga qo'shildingiz.\`, true);
        } catch (e) {
          say($("jMsg"), e.message);
        }
      };
    }
  } catch (e) {
    el.innerHTML = \`<p class="msg err">\${esc(e.message)}</p>\`;
  }
}

/* ---------- Avtomatik kirish ---------- */
if (token) {
  start().catch(() => {
    // Token yaroqsiz bo'lsa api() o'zi chiqarib yuboradi; tarmoq xatosida tokenni saqlab qolamiz.
    $("authScreen").hidden = false;
    $("app").hidden = true;
  });
}
`;
