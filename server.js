import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import multer from "multer";
import { Resend } from "resend";
import Stripe from "stripe";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
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
const adminEmail = process.env.RESEND_TO_EMAIL || process.env.ADMIN_EMAIL;
const resendFrom = process.env.RESEND_FROM || "onboarding@resend.dev";

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

function normalizeFields(body) {
  return Object.fromEntries(Object.entries(body || {}).map(([key, value]) => [key, sanitize(value)]));
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
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

app.set("trust proxy", 1);
app.use(cors({
  origin(origin, cb) {
    if (!origin || origin === frontendOrigin) return cb(null, true);
    if (!isProduction) return cb(null, true);
    return cb(new Error("Origen no permitido por CORS"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Stripe-Signature"]
}));

app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  let event;

  try {
    const stripe = getStripe();
    const signature = req.headers["stripe-signature"];
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
    } else {
      event = JSON.parse(req.body.toString("utf8"));
    }
  } catch (error) {
    console.error("[DERMATIKA stripe webhook error]", error.message);
    return res.status(400).json({ ok: false, error: "stripe_webhook_invalid" });
  }

  appendCsv("stripe_webhooks.csv", ["created_at", "event_id", "event_type", "payload"], {
    created_at: new Date().toISOString(),
    event_id: event.id,
    event_type: event.type,
    payload: JSON.stringify(event.data?.object || {})
  });

  if (event.type === "payment_intent.succeeded") {
    const intent = event.data.object;
    const resend = new Resend(process.env.RESEND_API_KEY);

    appendCsv("payments.csv", ["created_at", "provider", "payment_id", "status", "patient_reference", "amount", "currency"], {
      created_at: new Date().toISOString(),
      provider: "stripe",
      payment_id: intent.id,
      status: intent.status,
      patient_reference: intent.metadata?.patient_reference || "",
      amount: intent.amount_received || intent.amount,
      currency: intent.currency
    });

    if (process.env.RESEND_API_KEY && adminEmail) {
      try {
        console.log("INTENT DETECTADO:", intent.id);

        await resend.emails.send({
          from: resendFrom,
          to: adminEmail,
          subject: "Nuevo pago recibido 💰",
          html: `<p>Pago exitoso de $${(intent.amount_received || intent.amount) / 100} ${intent.currency}</p>`
        });

        console.log("EMAIL ENVIADO");
      } catch (error) {
        console.log("ERROR EMAIL:", error);
      }
    } else {
      console.warn("[DERMATIKA payment mail skipped] Missing RESEND_API_KEY or RESEND_TO_EMAIL/ADMIN_EMAIL");
    }
  }

  return res.json({ received: true });
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "dermatika-backend" });
});

app.post("/api/create-stripe-payment-intent", asyncHandler(async (req, res) => {
  const { planKey, amount, currency = "MXN", email, patientReference, sessionId, externalReference } = req.body || {};
  const plan = getPlan(planKey, amount);

  if (!process.env.STRIPE_PUBLIC_KEY) {
    return res.status(503).json({ ok: false, error: "stripe_public_key_missing" });
  }
  if (!plan) {
    return res.status(400).json({ ok: false, error: "invalid_plan" });
  }

  const stripe = getStripe();
  const intent = await stripe.paymentIntents.create({
    amount: plan.price * 100,
    currency: String(currency || "MXN").toLowerCase(),
    receipt_email: sanitize(email, 320) || undefined,
    automatic_payment_methods: { enabled: true },
    metadata: {
      plan_key: sanitize(planKey, 60),
      plan_name: plan.name,
      patient_reference: sanitize(patientReference || externalReference, 120),
      session_id: sanitize(sessionId, 120)
    }
  });

  return res.json({
    ok: true,
    publishableKey: process.env.STRIPE_PUBLIC_KEY,
    clientSecret: intent.client_secret,
    paymentIntentId: intent.id
  });
}));

app.post("/api/intake", upload.fields([
  { name: "photoFront", maxCount: 1 },
  { name: "photoLeft", maxCount: 1 },
  { name: "photoRight", maxCount: 1 }
]), asyncHandler(async (req, res) => {
  const fields = normalizeFields(req.body);
  const files = Object.entries(req.files || {}).flatMap(([fieldName, items]) =>
    items.map(file => ({
      fieldName,
      originalName: file.originalname,
      filename: file.filename,
      mimetype: file.mimetype,
      size: file.size,
      path: file.path
    }))
  );
  const reference = fields.patient_reference || `DER-${Date.now()}`;
  const plan = getPlan(fields.plan_key) || { name: fields.plan_name || "Plan no especificado" };
  const resend = new Resend(process.env.RESEND_API_KEY);

  appendCsv("patients.csv", [
    "created_at",
    "patient_reference",
    "name",
    "email",
    "phone",
    "plan_key",
    "plan_name",
    "payment_status",
    "payment_reference",
    "encrypted_payload"
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

  if (process.env.RESEND_API_KEY && adminEmail) {
    try {
      await resend.emails.send({
        from: resendFrom,
        to: adminEmail,
        subject: "Nuevo paciente DERMATIKA",
        html: `
          <h2>Nuevo paciente</h2>
          <p><b>Referencia:</b> ${fields.patient_reference || reference}</p>
          <p><b>Payment ID:</b> ${fields.payment_reference || "Sin referencia"}</p>
          <p><b>Nombre:</b> ${fields.name || ""}</p>
          <p><b>Email:</b> ${fields.email || ""}</p>
          <p><b>Teléfono:</b> ${fields.phone || ""}</p>
          <p><b>Plan:</b> ${fields.plan_key || ""}</p>
          <p><b>Pago:</b> ${fields.payment_status || "pending"}</p>
        `
      });
    } catch (error) {
      console.error("[DERMATIKA resend error]", error);
    }
  } else {
    console.warn("[DERMATIKA mail skipped] Missing RESEND_API_KEY or RESEND_TO_EMAIL/ADMIN_EMAIL");
  }

  return res.json({ ok: true, patientReference: reference, files });
}));

app.post("/api/track-event", (req, res) => {
  appendCsv("events.csv", ["created_at", "event_name", "payload"], {
    created_at: new Date().toISOString(),
    event_name: req.body?.eventName || req.body?.event || "",
    payload: JSON.stringify(req.body || {})
  });
  res.json({ ok: true });
});

app.use("/api", (_req, res) => {
  res.status(404).json({ ok: false, error: "Ruta no encontrada" });
});

app.use((error, _req, res, _next) => {
  console.error("[DERMATIKA backend error]", error);
  res.status(error.statusCode || 500).json({
    ok: false,
    error: "backend_error",
    detail: isProduction ? undefined : error.message
  });
});

app.listen(port, () => {
  console.log(`DERMATIKA backend activo en puerto ${port}`);
});
