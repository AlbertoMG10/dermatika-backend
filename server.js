import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import multer from "multer";
import nodemailer from "nodemailer";
import Stripe from "stripe";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const app = express();

app.get("/api/config", (req, res) => {
  res.json({
    publicKey: process.env.STRIPE_PUBLIC_KEY || null
  });
});

const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const frontendOrigin = process.env.FRONTEND_ORIGIN || "http://localhost:3000";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

const plans = {
  esencial: { name: "Nova Esencial", price: 1390 },
  avanzado: { name: "Nova Avanzado", price: 1559 },
  elite: { name: "Nova Elite", price: 2290 }
};

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: (_req, file, cb) => {
    cb(null, /^image\/(png|jpe?g|webp|heic|heif)$/i.test(file.mimetype));
  }
});

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) {
    const error = new Error("stripe_not_configured");
    error.statusCode = 503;
    throw error;
  }
  return new Stripe(process.env.STRIPE_SECRET_KEY);
}

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function appendCsv(file, headers, row) {
  const target = path.join(dataDir, file);
  const exists = fs.existsSync(target);
  if (!exists) fs.writeFileSync(target, headers.join(",") + "\n", "utf8");
  fs.appendFileSync(target, headers.map(header => csvEscape(row[header])).join(",") + "\n", "utf8");
}

function sanitize(value, max = 2000) {
  return String(value || "")
    .replace(/<[^>]*>/g, "")
    .replace(/[^\S\r\n]+/g, " ")
    .trim()
    .slice(0, max);
}

function getPlan(planKey, amount) {
  const plan = plans[planKey];
  if (!plan) return null;
  if (amount !== undefined && Number(amount) !== plan.price) return null;
  return plan;
}

function encryptionKey() {
  const raw = process.env.DATA_ENCRYPTION_KEY || "";
  if (!raw && isProduction) throw new Error("DATA_ENCRYPTION_KEY is required in production");
  return crypto.createHash("sha256").update(raw || "dermatika-local-development-key").digest();
}

function encryptPayload(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
}

function normalizeFields(body) {
  return Object.fromEntries(Object.entries(body || {}).map(([key, value]) => [key, sanitize(value)]));
}

function filePayload(files = {}) {
  return Object.fromEntries(
    Object.entries(files).map(([key, value]) => [key, value?.[0]?.filename || ""])
  );
}

function publicSiteUrl(req) {
  const configured = process.env.PUBLIC_SITE_URL || frontendOrigin;
  if (configured && configured !== "*") return configured.replace(/\/$/, "");
  return `${req.protocol}://${req.get("host")}`;
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

app.set("trust proxy", 1);

app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const stripe = getStripe();
  const signature = req.headers["stripe-signature"];
  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).json({ error: "stripe_webhook_secret_not_configured" });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    return res.status(400).json({ error: "invalid_stripe_signature", detail: error.message });
  }

  appendCsv("payment-events.csv", ["created_at", "provider", "event_id", "event_type", "payload"], {
    created_at: new Date().toISOString(),
    provider: "stripe",
    event_id: event.id,
    event_type: event.type,
    payload: JSON.stringify(event.data?.object || {})
  });

  if (event.type === "payment_intent.succeeded") {
    const intent = event.data.object;
    appendCsv("payments.csv", ["created_at", "provider", "payment_id", "status", "patient_reference", "amount", "currency"], {
      created_at: new Date().toISOString(),
      provider: "stripe",
      payment_id: intent.id,
      status: intent.status,
      patient_reference: intent.metadata?.patient_reference || "",
      amount: intent.amount_received || intent.amount,
      currency: intent.currency
    });
  }

  res.json({ received: true });
});

app.use(cors({
  origin: frontendOrigin === "*" ? true : frontendOrigin,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Stripe-Signature"]
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(projectRoot));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "dermatika-backend" });
});

app.post("/api/track-event", (req, res) => {
  const payload = req.body?.payload || {};
  appendCsv("events.csv", ["created_at", "event_name", "session_id", "payload"], {
    created_at: new Date().toISOString(),
    event_name: sanitize(req.body?.eventName || payload.event_name || "event", 120),
    session_id: sanitize(payload.session_id || "", 120),
    payload: JSON.stringify(payload)
  });
  res.json({ ok: true });
});

app.post("/api/intake", upload.fields([
  { name: "photoFront", maxCount: 1 },
  { name: "photoLeft", maxCount: 1 },
  { name: "photoRight", maxCount: 1 }
]), asyncHandler(async (req, res) => {
  const fields = normalizeFields(req.body);
  const plan = getPlan(fields.plan_key);
  if (!plan) return res.status(400).json({ error: "invalid_plan" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email || "")) return res.status(400).json({ error: "invalid_email" });
  if (!/^\d{10}$/.test(fields.phone || "")) return res.status(400).json({ error: "invalid_phone" });

  const reference = fields.patient_reference || `DMK-${Date.now()}`;
  const files = filePayload(req.files);
  appendCsv("pacientes.csv", [
    "created_at", "patient_reference", "name", "email", "phone", "plan_key",
    "plan_name", "payment_status", "payment_reference", "encrypted_payload"
  ], {
    created_at: new Date().toISOString(),
    patient_reference: reference,
    name: fields.name,
    email: fields.email,
    phone: fields.phone,
    plan_key: fields.plan_key,
    plan_name: plan.name,
    payment_status: fields.payment_status || "pending",
    payment_reference: fields.payment_reference || "",
    encrypted_payload: encryptPayload({ ...fields, files })
  });

  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD && process.env.ADMIN_EMAIL) {
    try {
      await transporter.sendMail({
        from: `"DERMATIKA" <${process.env.GMAIL_USER}>`,
        to: process.env.ADMIN_EMAIL,
        subject: `Nuevo paciente - ${req.body.patient_reference || reference}`,
        text: `
Nuevo cuestionario recibido

Referencia: ${req.body.patient_reference || reference}
Payment ID: ${req.body.payment_reference || "Sin referencia"}
Nombre: ${req.body.name}
WhatsApp: ${req.body.phone}
Correo: ${req.body.email}
Plan: ${req.body.plan_name || plan.name}
Pago: ${req.body.payment_status}
Payment Reference: ${req.body.payment_reference || "Sin referencia"}

Revisa las fotos en el backend.
      `
      });
    } catch (error) {
      console.error("[DERMATIKA mail error]", error);
    }
  } else {
    console.warn("[DERMATIKA mail skipped] Missing GMAIL_USER, GMAIL_APP_PASSWORD or ADMIN_EMAIL");
  }

  res.json({ ok: true, patientReference: reference, files });
}));

app.post("/api/create-stripe-payment-intent", asyncHandler(async (req, res) => {
  const plan = getPlan(req.body?.planKey, req.body?.amount);
  if (!plan) return res.status(400).json({ error: "invalid_plan_or_amount" });
  if (!process.env.STRIPE_PUBLIC_KEY) return res.status(503).json({ error: "stripe_public_key_not_configured" });

  const email = sanitize(req.body?.email || "", 160);
  const stripe = getStripe();
  const paymentIntent = await stripe.paymentIntents.create({
    amount: plan.price * 100,
    currency: "mxn",
    automatic_payment_methods: { enabled: true },
    description: `DERMATIKA ${plan.name}`,
    receipt_email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : undefined,
    metadata: {
      patient_reference: sanitize(req.body?.patientReference || "", 120),
      plan_key: sanitize(req.body?.planKey || "", 60),
      plan_name: plan.name
    }
  });

  res.json({
    clientSecret: paymentIntent.client_secret,
    paymentIntentId: paymentIntent.id,
    publishableKey: process.env.STRIPE_PUBLIC_KEY,
    provider: "stripe"
  });
}));

app.get("/", (req, res) => {
  res.json({ ok: true, service: "dermatika-backend" });
});

app.use((error, _req, res, _next) => {
  console.error("[DERMATIKA backend error]", error);
  res.status(error.statusCode || 500).json({ error: error.message || "server_error" });
});

app.listen(port, () => {
  console.log(`DERMATIKA backend listo en http://localhost:${port}`);
  console.log(`Frontend permitido: ${frontendOrigin}`);
});
