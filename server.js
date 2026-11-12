const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const fs = require("fs");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");
const crypto = require("crypto");
const JWT_KEYS = {
  k1: process.env.JWT_SECRET || "dev-only-secret-change-me",
  k2: process.env.JWT_SECRET_NEW || "dev-rotated-secret-two"
};
let currentKid = process.env.JWT_ACTIVE_KID || "k1";

function signToken(payload) {
  return jwt.sign(payload, JWT_KEYS[currentKid], {
    algorithm: "HS256",
    expiresIn: "1h",
    keyid: currentKid
  });
}

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "dev-webhook-secret";
const DATA_KEY = crypto
  .createHash("sha256")
  .update(process.env.DATA_KEY || "dev-data-key-change-me")
  .digest();

function encryptText(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", DATA_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, enc].map(b => b.toString("base64")).join(".");
}

function decryptText(payload) {
  const parts = String(payload).split(".").map(p => Buffer.from(p, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", DATA_KEY, parts[0]);
  decipher.setAuthTag(parts[1]);
  return Buffer.concat([decipher.update(parts[2]), decipher.final()]).toString("utf8");
}

const orders = [
  { id: 1001, status: "pending" },
  { id: 1002, status: "pending" }
];

function markPaid(orderId) {
  const id = Number(orderId);
  for (let i = 0; i < orders.length; i++) {
    if (orders[i].id === id) {
      orders[i].status = "paid";
      return orders[i];
    }
  }
  return null;
}

const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync(":memory:");

db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL, hidden INTEGER)");

const insert = db.prepare("INSERT INTO items (name, price, hidden) VALUES (?, ?, ?)");
insert.run("Notebook", 15, 0);
insert.run("Pen", 5, 0);
insert.run("Backpack", 120, 0);
insert.run("Staff Discount Item", 1, 1);
insert.run("Unreleased Laptop", 999, 1);
db.exec("CREATE TABLE profiles_plain (username TEXT PRIMARY KEY, phone TEXT, address TEXT)");
db.exec("CREATE TABLE profiles_enc (username TEXT PRIMARY KEY, phone TEXT, address TEXT)");
const app = express();
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV === "production") {
  const required = ["JWT_SECRET", "JWT_SECRET_NEW", "WEBHOOK_SECRET", "DATA_KEY", "ADMIN_PASSWORD"];
  const missing = required.filter(name => !process.env[name]);
  if (missing.length > 0) {
    console.error("Refusing to start. Missing environment variables: " + missing.join(", "));
    process.exit(1);
  }
}

const LOG_FILE = path.join(__dirname, "security.log");
const recentEvents = [];

function logEvent(type, details, req) {
  const entry = Object.assign(
    { time: new Date().toISOString(), type: type, ip: req ? req.ip : "-" },
    details
  );
  const line = JSON.stringify(entry);
  console.log("[SECURITY] " + line);
  fs.appendFile(LOG_FILE, line + "\n", function () {});
  recentEvents.push(entry);
  if (recentEvents.length > 100) {
    recentEvents.shift();
  }
}

app.use(express.json({
  verify: function (req, res, buf) {
    req.rawBody = buf.toString();
  }
}));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      "script-src-attr": ["'unsafe-inline'"],
      "upgrade-insecure-requests": process.env.NODE_ENV === "production" ? [] : null
    }
  }
}));

app.set("trust proxy", 1);

const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Please slow down." }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  handler: function (req, res) {
    logEvent("rate_limited", { path: req.originalUrl }, req);
    res.status(429).json({ error: "Too many login attempts. Try again in 15 minutes." });
  }
});

app.use("/api/", globalLimiter);
app.use("/api/login", loginLimiter);
app.use("/api/register", loginLimiter);
app.use(["/api/vulnerable", "/api/debug", "/api/admin/raw-db"], function (req, res, next) {
  if (process.env.NODE_ENV === "production") {
    return res.status(404).json({ error: "Not found." });
  }
  next();
});

app.use(express.static(path.join(__dirname, "public")));

const products = [
  { id: 1, name: "Notebook", price: 15 },
  { id: 2, name: "Pen", price: 5 },
  { id: 3, name: "Backpack", price: 120 },
  { id: 4, name: "Calculator", price: 80 },
  { id: 5, name: "Water Bottle", price: 25 }
];

let nextProductId = 6;

app.get("/api/products", (req, res) => {
  res.json(products);
});

app.get("/api/health", (req, res) => {
  res.json({ status: "Server is running" });
});

const users = [];

users.push({
  id: 1,
  username: "admin",
  passwordHash: bcrypt.hashSync(process.env.ADMIN_PASSWORD || "Admin@12345", 10),
  role: "admin"
});

function checkPassword(password) {
  if (password.length < 8) {
    return "Password must be at least 8 characters.";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password needs an uppercase letter.";
  }
  if (!/[a-z]/.test(password)) {
    return "Password needs a lowercase letter.";
  }
  if (!/[0-9]/.test(password)) {
    return "Password needs a number.";
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return "Password needs a symbol, e.g. ! or @.";
  }
  return "";
}

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3-20 letters, numbers or underscores." });
  }

  const problem = checkPassword(password);
  if (problem !== "") {
    return res.status(400).json({ error: problem });
  }

  for (let i = 0; i < users.length; i++) {
    if (users[i].username === username) {
      return res.status(409).json({ error: "Username already taken." });
    }
  }

  const hash = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username: username, passwordHash: hash, role: "customer" });

  res.status(201).json({ message: "Account created." });
});

app.get("/api/debug/users", (req, res) => {
  res.json(users);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  let user = null;
  for (let i = 0; i < users.length; i++) {
    if (users[i].username === username) {
      user = users[i];
    }
  }

  const passwordOk = user && await bcrypt.compare(password, user.passwordHash);

  if (!passwordOk) {
    logEvent("login_failed", { username: String(username).slice(0, 30) }, req);
    return res.status(401).json({ error: "Invalid username or password." });
  }

  if (user.mfaEnabled) {
    const code = String(req.body.code || "");

    if (code === "") {
      return res.json({ mfaRequired: true });
    }
    if (!authenticator.check(code, user.mfaSecret)) {
      logEvent("mfa_failed", { username: user.username }, req);
      return res.status(401).json({ error: "Invalid code." });
    }
  }

  const token = signToken({ id: user.id, username: user.username, role: user.role });

  logEvent("login_success", { username: user.username, role: user.role }, req);
  res.json({ token: token });
});

function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.replace("Bearer ", "");

  try {
    const decoded = jwt.decode(token, { complete: true });
    const key = decoded && JWT_KEYS[decoded.header.kid];
    if (!key) {
      throw new Error("unknown key");
    }
    req.user = jwt.verify(token, key, { algorithms: ["HS256"] });
    next();
  } catch (error) {
    logEvent("unauthenticated_request", { path: req.originalUrl }, req);
    res.status(401).json({ error: "Please log in." });
  }
}

function requireRole(role) {
  return function (req, res, next) {
    if (req.user.role !== role) {
      logEvent("forbidden_action", { username: req.user.username, path: req.originalUrl }, req);
      return res.status(403).json({ error: "You do not have permission to do this." });
    }

    if (role === "admin") {
      const account = findUserById(req.user.id);
      if (!account || !account.mfaEnabled) {
        logEvent("admin_blocked_no_mfa", { username: req.user.username, path: req.originalUrl }, req);
        return res.status(403).json({ error: "Admins must enable MFA before using admin features.", mfaSetupRequired: true });
      }
    }
    next();
  };
}

app.get("/api/me", requireAuth, (req, res) => {
  const account = findUserById(req.user.id);
  res.json({
    username: req.user.username,
    role: req.user.role,
    mfaEnabled: !!(account && account.mfaEnabled)
  });
});

app.post("/api/products", requireAuth, requireRole("admin"), (req, res) => {
  const { name, price } = req.body;

  if (typeof name !== "string" || name.trim() === "" || name.length > 50) {
    return res.status(400).json({ error: "Product name is required (max 50 characters)." });
  }
  if (typeof price !== "number" || price <= 0 || price > 100000) {
    return res.status(400).json({ error: "Price must be a number above 0." });
  }

  const newProduct = { id: nextProductId++, name: name.trim(), price: price };
  products.push(newProduct);
  logEvent("product_added", { by: req.user.username, product: newProduct.name }, req);

  res.status(201).json(newProduct);
});

// INSECURE: for the attack demo only. Delete before deployment.
app.get("/api/vulnerable/search", (req, res) => {
  const q = req.query.q || "";
  const sql = "SELECT id, name, price FROM items WHERE name LIKE '%" + q + "%' AND hidden = 0";
  try {
    res.json(db.prepare(sql).all());
  } catch (error) {
    res.status(500).json({ error: error.message, sql: sql });
  }
});

// SECURE: parameterized query
app.get("/api/search", (req, res) => {
  const q = String(req.query.q || "").slice(0, 50);
  const rows = db
    .prepare("SELECT id, name, price FROM items WHERE name LIKE ? AND hidden = 0")
    .all("%" + q + "%");
  res.json(rows);
});

app.delete("/api/products/:id", requireAuth, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: "Invalid product id." });
  }

  const index = products.findIndex(p => p.id === id);
  if (index === -1) {
    return res.status(404).json({ error: "Product not found." });
  }

  const removed = products.splice(index, 1)[0];
  logEvent("product_deleted", { by: req.user.username, product: removed.name }, req);
  res.json({ message: "Removed " + removed.name });
});

app.get("/api/admin/logs", requireAuth, requireRole("admin"), (req, res) => {
  res.json(recentEvents.slice(-50).reverse());
});

function findUserById(id) {
  for (let i = 0; i < users.length; i++) {
    if (users[i].id === id) {
      return users[i];
    }
  }
  return null;
}

app.post("/api/mfa/setup", requireAuth, async (req, res) => {
  const user = findUserById(req.user.id);
  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  const secret = authenticator.generateSecret();
  user.pendingSecret = secret;

  const otpauth = authenticator.keyuri(user.username, "SecureShop", secret);
  const qr = await QRCode.toDataURL(otpauth);

  res.json({ qr: qr, secret: secret });
});

app.post("/api/mfa/enable", requireAuth, (req, res) => {
  const user = findUserById(req.user.id);
  const code = String((req.body || {}).code || "");

  if (!user || !user.pendingSecret) {
    return res.status(400).json({ error: "Start MFA setup first." });
  }
  if (!authenticator.check(code, user.pendingSecret)) {
    logEvent("mfa_enable_failed", { username: user.username }, req);
    return res.status(400).json({ error: "Invalid code. Try again." });
  }

  user.mfaSecret = user.pendingSecret;
  user.pendingSecret = null;
  user.mfaEnabled = true;

  logEvent("mfa_enabled", { username: user.username }, req);
  res.json({ message: "MFA enabled." });
});

// INSECURE: for the attack demo only. Delete before deployment.
app.post("/api/vulnerable/webhook", (req, res) => {
  const order = markPaid((req.body || {}).orderId);
  res.json(order ? { message: "Order marked paid", order: order } : { error: "Order not found." });
});

// SECURE: signature and timestamp verified
app.post("/api/webhooks/payment", (req, res) => {
  const timestamp = String(req.headers["x-timestamp"] || "");
  const signature = String(req.headers["x-signature"] || "");
  const age = Math.abs(Date.now() - Number(timestamp));

  if (timestamp === "" || signature === "") {
    logEvent("webhook_rejected", { reason: "missing signature" }, req);
    return res.status(401).json({ error: "Invalid webhook signature." });
  }
  if (!(age <= 5 * 60 * 1000)) {
    logEvent("webhook_rejected", { reason: "stale timestamp (possible replay)" }, req);
    return res.status(401).json({ error: "Invalid webhook signature." });
  }

  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(timestamp + "." + (req.rawBody || ""))
    .digest("hex");

  const a = Buffer.from(expected);
  const b = Buffer.from(signature);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    logEvent("webhook_rejected", { reason: "bad signature" }, req);
    return res.status(401).json({ error: "Invalid webhook signature." });
  }

  const order = markPaid((req.body || {}).orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found." });
  }

  logEvent("webhook_accepted", { orderId: order.id }, req);
  res.json({ message: "Order marked paid", order: order });
});

app.get("/api/admin/orders", requireAuth, requireRole("admin"), (req, res) => {
  res.json(orders);
});

app.post("/api/admin/rotate-key", requireAuth, requireRole("admin"), (req, res) => {
  const next = currentKid === "k1" ? "k2" : "k1";
  if (!JWT_KEYS[next]) {
    return res.status(400).json({ error: "No spare key available." });
  }

  currentKid = next;
  logEvent("jwt_key_rotated", { by: req.user.username, activeKey: currentKid }, req);

  const token = signToken({ id: req.user.id, username: req.user.username, role: req.user.role });
  res.json({ message: "Now signing with " + currentKid, token: token });
});

app.post("/api/admin/retire-key", requireAuth, requireRole("admin"), (req, res) => {
  for (const kid of Object.keys(JWT_KEYS)) {
    if (kid !== currentKid) {
      delete JWT_KEYS[kid];
    }
  }
  logEvent("jwt_key_retired", { by: req.user.username, remaining: Object.keys(JWT_KEYS) }, req);
  res.json({ message: "Old keys retired.", remaining: Object.keys(JWT_KEYS) });
});

app.post("/api/admin/rotate-key", requireAuth, requireRole("admin"), (req, res) => {
  const next = currentKid === "k1" ? "k2" : "k1";
  if (!JWT_KEYS[next]) {
    return res.status(400).json({ error: "No spare key available." });
  }

  currentKid = next;
  logEvent("jwt_key_rotated", { by: req.user.username, activeKey: currentKid }, req);

  const token = signToken({ id: req.user.id, username: req.user.username, role: req.user.role });
  res.json({ message: "Now signing with " + currentKid, token: token });
});

app.post("/api/admin/retire-key", requireAuth, requireRole("admin"), (req, res) => {
  for (const kid of Object.keys(JWT_KEYS)) {
    if (kid !== currentKid) {
      delete JWT_KEYS[kid];
    }
  }
  logEvent("jwt_key_retired", { by: req.user.username, remaining: Object.keys(JWT_KEYS) }, req);
  res.json({ message: "Old keys retired.", remaining: Object.keys(JWT_KEYS) });
});

app.post("/api/profile", requireAuth, (req, res) => {
  const phone = String((req.body || {}).phone || "").trim();
  const address = String((req.body || {}).address || "").trim();

  if (!/^[0-9+ ]{7,15}$/.test(phone)) {
    return res.status(400).json({ error: "Phone must be 7-15 digits." });
  }
  if (address === "" || address.length > 100 || /[<>]/.test(address)) {
    return res.status(400).json({ error: "Address is required (max 100 characters, no < or >)." });
  }

  // Plain copy exists only so you can screenshot the "before". Delete before deployment.
  db.prepare("INSERT OR REPLACE INTO profiles_plain (username, phone, address) VALUES (?, ?, ?)")
    .run(req.user.username, phone, address);
  db.prepare("INSERT OR REPLACE INTO profiles_enc (username, phone, address) VALUES (?, ?, ?)")
    .run(req.user.username, encryptText(phone), encryptText(address));

  logEvent("profile_saved", { username: req.user.username }, req);
  res.json({ message: "Profile saved." });
});

app.get("/api/profile", requireAuth, (req, res) => {
  const row = db.prepare("SELECT phone, address FROM profiles_enc WHERE username = ?")
    .get(req.user.username);
  if (!row) {
    return res.status(404).json({ error: "No profile saved." });
  }
  try {
    res.json({ phone: decryptText(row.phone), address: decryptText(row.address) });
  } catch (error) {
    logEvent("decrypt_failed", { username: req.user.username }, req);
    res.status(500).json({ error: "Stored data failed integrity check." });
  }
});

// DEMO ONLY: shows what a database thief would see. Delete before deployment.
app.get("/api/admin/raw-db", requireAuth, requireRole("admin"), (req, res) => {
  res.json({
    plaintext: db.prepare("SELECT * FROM profiles_plain").all(),
    encrypted: db.prepare("SELECT * FROM profiles_enc").all()
  });
});

app.listen(PORT, () => {
  console.log("Server running on http://localhost:" + PORT);
});