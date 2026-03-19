"use strict";

const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const multer = require("multer");
const { Pool } = require("pg");

// SAST findings: hardcoded credentials
const DB_PASSWORD = "petshop123";
const SECRET_KEY = "BITS_AND_BYTES_SUPER_SECRET_KEY_2024";
const INTERNAL_API_TOKEN = "sk_live_dd_internal_api_token_never_commit";

const TRACER_NAME = "dd-trace-js";
const TRACER_VERSION = "5.x";

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const dbUrl = process.env.DATABASE_URL || `postgresql://petshop:${DB_PASSWORD}@localhost:5432/petshop`;
const pool = new Pool({ connectionString: dbUrl });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);

app.use((req, res, next) => {
  res.locals.tracer = TRACER_NAME;
  res.locals.version = TRACER_VERSION;
  res.locals.session = req.session;
  res.locals.prefix = req.headers["x-forwarded-prefix"] || "";
  next();
});

const uploadDir = "/tmp/uploads";
try {
  fs.mkdirSync(uploadDir, { recursive: true });
} catch (e) {
  // ignore if exists
}

const multerUpload = multer({ dest: uploadDir });

async function queryDb(sql, params = [], fetchOne = false) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return fetchOne ? result.rows[0] || null : result.rows;
  } finally {
    client.release();
  }
}

// Routes

app.get("/", async (req, res) => {
  const products = await queryDb("SELECT * FROM products ORDER BY id");
  res.render("index", { products });
});

app.get("/search", async (req, res) => {
  const q = req.query.q || "";
  let results = [];
  let error = null;
  if (q) {
    try {
      const sql = `SELECT * FROM products WHERE name ILIKE '%${q}%' OR description ILIKE '%${q}%'`;
      results = await queryDb(sql);
    } catch (e) {
      error = e.message;
    }
  }
  res.render("search", { q, results, error });
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";
  let error = null;
  try {
    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    const user = await queryDb(sql, [], true);
    if (user) {
      req.session.user = user.username;
      req.session.role = user.role;
      return res.redirect(res.locals.prefix + "/");
    }
    error = "Invalid username or password";
  } catch (e) {
    error = e.message;
  }
  res.render("login", { error });
});

app.get("/logout", (req, res) => {
  const prefix = req.headers["x-forwarded-prefix"] || "";
  req.session.destroy(() => {
    res.redirect(prefix + "/");
  });
});

app.get("/product/:id", async (req, res) => {
  try {
    const sql = `SELECT * FROM products WHERE id = ${req.params.id}`;
    const product = await queryDb(sql, [], true);
    if (!product) {
      return res.status(404).render("error", { error: "Product not found" });
    }
    const reviews = await queryDb(
      "SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC",
      [product.id]
    );
    res.render("product", { product, reviews });
  } catch (e) {
    res.status(400).render("error", { error: e.message });
  }
});

app.post("/review", async (req, res) => {
  const productId = req.body.product_id;
  const username = req.body.username || "anonymous";
  const rating = req.body.rating || "5";
  const body = req.body.body || "";
  await queryDb(
    "INSERT INTO reviews (product_id, username, rating, body) VALUES ($1, $2, $3, $4)",
    [productId, username, rating, body]
  );
  const prefix = req.headers["x-forwarded-prefix"] || "";
  res.redirect(`${prefix}/product/${productId}`);
});

app.get("/profile/:username", async (req, res) => {
  const username = req.params.username;
  const user = await queryDb("SELECT * FROM users WHERE username = $1", [username], true);
  res.render("profile", { username, user });
});

app.post("/upload", multerUpload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file provided" });
  }
  const filename = req.body.filename || req.file.originalname || "upload";
  const savePath = path.join(uploadDir, filename);
  try {
    fs.renameSync(req.file.path, savePath);
  } catch (e) {
    fs.copyFileSync(req.file.path, savePath);
    fs.unlinkSync(req.file.path);
  }
  res.json({ message: `Saved to ${savePath}`, filename });
});

app.post("/webhook", async (req, res) => {
  const url = req.body?.url || "";
  if (!url) {
    return res.status(400).json({ error: "url required" });
  }
  try {
    const resp = await fetch(url);
    const data = await resp.text();
    res.json({ status: resp.status, body: data.slice(0, 2000) });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/export", (req, res) => {
  const filename = req.query.file || "";
  if (!filename) {
    return res.status(400).json({ error: "file parameter required" });
  }
  try {
    const result = execSync(`cat /tmp/uploads/${filename}`);
    res.type("text/plain").send(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/cart/restore", (req, res) => {
  const cartData = req.body?.cart_data || "";
  if (!cartData) {
    return res.status(400).json({ error: "cart_data required" });
  }
  try {
    const cart = eval("(" + Buffer.from(cartData, "base64").toString() + ")");
    res.json({ cart: String(cart) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "petshop-node", tracer: TRACER_NAME });
});

const PORT = 8002;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bits & Bytes Pet Shop (Node) listening on port ${PORT}`);
});
