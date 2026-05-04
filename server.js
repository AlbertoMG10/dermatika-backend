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
const historiesDir = path.join(dataDir, "historiales");
const logsDir = path.join(dataDir, "logs");
const leadsFile = path.join(dataDir, "leads.json");

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(historiesDir, { recursive: true });
fs.mkdirSync(logsDir, { recursive: true });

const app = express();

app.get("/api/config", (req, res) => {
  res.json({
    publicKey: process.env.STRIPE_PUBLIC_KEY || null,
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null
  });
});

const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const frontendOrigin = process.env.FRONTEND_ORIGIN || "http://localhost:3000";
const adminEmail = process.env.RESEND_TO_EMAIL || process.env.ADMIN_EMAIL || "mgdermalab@gmail.com";
const resendFrom = process.env.RESEND_FROM || "DERMATIKA <contacto@dermatika.mx>";
const maxEmailAttachmentBytes = Number(process.env.MAX_EMAIL_ATTACHMENT_MB || 20) * 1024 * 1024;
const pdfTimeoutMs = Number(process.env.PDF_TIMEOUT_MS || 10000);
const emailTimeoutMs = Number(process.env.EMAIL_TIMEOUT_MS || 20000);

const plans = {
  esencial: { name: "Nova Esencial", price: 1590 },
  avanzado: { name: "Nova Avanzado", price: 1890 },
  elite: { name: "Nova Elite", price: 2690 }
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
      cb(null, "upload-" + Date.now() + "-" + crypto.randomUUID() + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 5 },
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

function log(level, event, details = {}) {
  const entry = { created_at: new Date().toISOString(), level, event, details };
  fs.appendFileSync(path.join(logsDir, "app.log.jsonl"), JSON.stringify(entry) + "\n", "utf8");
  const method = level === "ERROR" ? "error" : level === "WARNING" ? "warn" : "log";
  console[method]("[DERMATIKA " + level + "] " + event, details);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

function sanitize(value, max = 2000) {
  return escapeHtml(String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/[^\S\r\n]+/g, " ")
    .trim()
    .slice(0, max));
}

function normalizeFields(body) {
  return Object.fromEntries(Object.entries(body || {}).map(([key, value]) => [key, sanitize(value)]));
}

function normalizePhone(value) {
  return String(value || "").replace(/\D/g, "").slice(-10);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
}

function isValidPhone(value) {
  return /^\d{10}$/.test(normalizePhone(value));
}

function isValidPostalCode(value) {
  return /^\d{5}$/.test(String(value || ""));
}

function validationError(res, errors, status = 400) {
  log("WARNING", "validation_failed", { errors });
  return res.status(status).json({ ok: false, error: "invalid_input", errors });
}

function validateLeadFields(fields, mode = "partial") {
  const errors = [];
  if (fields.email && !isValidEmail(fields.email)) errors.push({ field: "email", message: "Email invalido." });
  if (fields.phone && !isValidPhone(fields.phone)) errors.push({ field: "phone", message: "Telefono debe tener 10 digitos." });
  if (fields.shippingPostalCode && !isValidPostalCode(fields.shippingPostalCode)) errors.push({ field: "shippingPostalCode", message: "Codigo postal debe tener 5 digitos." });
  if (fields.age && (!/^\d{1,3}$/.test(fields.age) || Number(fields.age) < 13 || Number(fields.age) > 90)) errors.push({ field: "age", message: "Edad fuera de rango." });
  if (fields.weight && (!/^\d{2,3}$/.test(fields.weight) || Number(fields.weight) < 30 || Number(fields.weight) > 250)) errors.push({ field: "weight", message: "Peso fuera de rango." });
  if (fields.height && (!/^\d{3}$/.test(fields.height) || Number(fields.height) < 120 || Number(fields.height) > 230)) errors.push({ field: "height", message: "Estatura fuera de rango." });
  if (fields.shippingExterior && !/^\d{1,6}$/.test(fields.shippingExterior)) errors.push({ field: "shippingExterior", message: "Numero exterior invalido." });
  if (fields.shippingInterior && !/^\d{1,6}$/.test(fields.shippingInterior)) errors.push({ field: "shippingInterior", message: "Numero interior invalido." });
  if (fields.plan_key && !plans[fields.plan_key]) errors.push({ field: "plan_key", message: "Plan invalido." });
  if (mode === "identity" && (!fields.email || !fields.phone)) errors.push({ field: "identity", message: "Email y telefono son obligatorios." });
  return errors;
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => setTimeout(() => reject(new Error(label + "_timeout")), ms))
  ]);
}

function cleanupFiles(files) {
  for (const file of files || []) {
    try { if (file?.path && fs.existsSync(file.path)) fs.unlinkSync(file.path); }
    catch (error) { log("WARNING", "cleanup_failed", { path: file.path, error: error.message }); }
  }
}

function publicBaseUrl() {
  return String(process.env.PUBLIC_SITE_URL || process.env.FRONTEND_ORIGIN || frontendOrigin).replace(/\/$/, "");
}

function fileDownloadUrl(filename) {
  return publicBaseUrl() + "/api/download/" + encodeURIComponent(path.basename(filename));
}

async function verifyTurnstile(token, remoteIp = "") {
  if (!process.env.TURNSTILE_SECRET_KEY) {
    if (isProduction) return { ok: false, error: "turnstile_secret_missing" };
    log("WARNING", "turnstile_not_configured_dev", {});
    return { ok: true, skipped: true };
  }
  if (!token) return { ok: false, error: "turnstile_token_missing" };
  const body = new URLSearchParams();
  body.set("secret", process.env.TURNSTILE_SECRET_KEY);
  body.set("response", token);
  if (remoteIp) body.set("remoteip", remoteIp);
  try {
    const response = await withTimeout(fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    }), 8000, "turnstile_verify");
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result.success) {
      log("WARNING", "turnstile_failed", { status: response.status, errors: result["error-codes"] || [] });
      return { ok: false, error: "turnstile_failed" };
    }
    return { ok: true };
  } catch (error) {
    log("ERROR", "turnstile_verify_error", { error: error.message });
    return { ok: false, error: "turnstile_verify_error" };
  }
}

const leadStatuses = new Set([
  "Formulario iniciado",
  "Formulario completado",
  "Pendiente de pago",
  "Pago iniciado",
  "Pago confirmado",
  "En revisión médica",
  "Aprobado",
  "No aprobado",
  "En preparación de envío",
  "Enviado",
  "Cancelado"
]);

const paidLeadStatuses = new Set([
  "Pago confirmado",
  "En revisión médica",
  "Aprobado",
  "En preparación de envío",
  "Enviado"
]);

function isPaidLeadStatus(status) {
  return paidLeadStatuses.has(status);
}

function findExistingLeadIndex(leads, fields) {
  const requestedFolio = fields.internal_folio || fields.patient_reference || fields.folio_dermatika || fields.external_reference;
  const phone = normalizePhone(fields.phone);
  const email = normalizeEmail(fields.email);

  if (requestedFolio) {
    const byFolio = leads.findIndex(lead =>
      lead.internal_folio === requestedFolio ||
      lead.patient_reference === requestedFolio ||
      lead.folio_dermatika === requestedFolio
    );
    if (byFolio >= 0) return byFolio;
  }

  if (phone) {
    const byPhone = leads.findIndex(lead => (lead.normalized_phone || normalizePhone(lead.phone)) === phone);
    if (byPhone >= 0) return byPhone;
  }

  if (email) {
    const byEmail = leads.findIndex(lead => (lead.normalized_email || normalizeEmail(lead.email)) === email);
    if (byEmail >= 0) return byEmail;
  }

  return -1;
}

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
}

function nextInternalFolio(leads) {
  const date = new Date();
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  const prefix = "DMK-" + y + m + d + "-";
  let suffix = "";
  do {
    suffix = String(crypto.randomInt(0, 10000)).padStart(4, "0");
  } while (leads.some(lead => String(lead.internal_folio || lead.patient_reference || "") === prefix + suffix));
  return prefix + suffix;
}

function resumeToken(folio) {
  const secret = process.env.DATA_ENCRYPTION_KEY || process.env.STRIPE_SECRET_KEY || "dermatika-local-token";
  const signature = crypto.createHmac("sha256", secret).update(folio).digest("hex").slice(0, 24);
  return Buffer.from(`${folio}.${signature}`).toString("base64url");
}

function verifyResumeToken(token) {
  try {
    const decoded = Buffer.from(String(token || ""), "base64url").toString("utf8");
    const [folio, signature] = decoded.split(".");
    if (!folio || !signature) return null;
    return resumeToken(folio) === token ? folio : null;
  } catch {
    return null;
  }
}

function recoveryUrl(token) {
  const base = process.env.PUBLIC_SITE_URL || process.env.FRONTEND_ORIGIN || frontendOrigin;
  return `${String(base).replace(/\/$/, "")}/index.html?resume=${encodeURIComponent(token)}`;
}

async function sendRecoveryEmail(lead) {
  if (!process.env.RESEND_API_KEY || !lead.email || lead.recovery_email_sent_at) return lead;
  const resend = new Resend(process.env.RESEND_API_KEY);
  const token = lead.resume_token || resumeToken(lead.internal_folio);
  await resend.emails.send({
    from: resendFrom,
    to: [lead.email],
    subject: `[DERMATIKA - PENDIENTE DE PAGO] ${lead.internal_folio}`,
    html: `
      <h2>Tu información fue guardada</h2>
      <p>Tu folio es <b>${lead.internal_folio}</b>.</p>
      <p>Puedes continuar tu proceso cuando estés listo desde este enlace seguro:</p>
      <p><a href="${recoveryUrl(token)}">Continuar mi proceso DERMATIKA</a></p>
    `
  });
  return { ...lead, resume_token: token, recovery_email_sent_at: new Date().toISOString() };
}

async function saveLead(rawFields, requestedStatus = "Formulario iniciado", options = {}) {
  const fields = normalizeFields(rawFields);
  if (fields.internalFolio && !fields.internal_folio) fields.internal_folio = fields.internalFolio;
  if (fields.patientReference && !fields.patient_reference) fields.patient_reference = fields.patientReference;
  if (fields.externalReference && !fields.external_reference) fields.external_reference = fields.externalReference;
  if (fields.paymentIntentId && !fields.payment_id) fields.payment_id = fields.paymentIntentId;
  if (fields.payment_reference && !fields.payment_id) fields.payment_id = fields.payment_reference;

  const leads = readJson(leadsFile, []);
  const requested = leadStatuses.has(requestedStatus) ? requestedStatus : "Formulario iniciado";
  const existingIndex = findExistingLeadIndex(leads, fields);
  const now = new Date().toISOString();
  const existing = existingIndex >= 0 ? leads[existingIndex] : null;
  const existingPaid = existing?.payment_status === "paid" || isPaidLeadStatus(existing?.status);
  const requestedPaid = fields.payment_status === "paid" || isPaidLeadStatus(requested);
  const status = existingPaid && !requestedPaid ? existing.status : requested;
  const phone = normalizePhone(fields.phone || existing?.phone);
  const email = normalizeEmail(fields.email || existing?.email);
  const folio = existing?.internal_folio || fields.internal_folio || fields.patient_reference || fields.folio_dermatika || fields.external_reference || nextInternalFolio(leads);
  const paymentId = fields.payment_id || fields.payment_reference || existing?.payment_id || existing?.payment_reference || "";
  const activeMedicalCase = requestedPaid || existingPaid || isPaidLeadStatus(status);

  let lead = {
    ...(existing || {}),
    ...fields,
    internal_folio: folio,
    patient_reference: existing?.patient_reference || fields.patient_reference || folio,
    folio: folio,
    folio_dermatika: folio,
    normalized_phone: phone,
    normalized_email: email,
    phone: fields.phone || existing?.phone || "",
    email: fields.email || existing?.email || "",
    name: fields.name || existing?.name || fields.patientName || "",
    status,
    payment_status: activeMedicalCase ? "paid" : (fields.payment_status || existing?.payment_status || "pending"),
    payment_id: paymentId,
    payment_reference: paymentId || fields.payment_reference || existing?.payment_reference || "",
    active_medical_case: activeMedicalCase,
    patient_active: activeMedicalCase,
    reminders_active: activeMedicalCase ? false : existing?.reminders_active ?? true,
    reminders_paused: activeMedicalCase ? true : existing?.reminders_paused ?? false,
    reminder_status: activeMedicalCase ? "detenido" : existing?.reminder_status || "activo",
    reminder_stopped_at: activeMedicalCase ? existing?.reminder_stopped_at || now : existing?.reminder_stopped_at || "",
    paid_at: activeMedicalCase ? existing?.paid_at || now : existing?.paid_at || "",
    updated_at: now,
    created_at: existing?.created_at || now
  };
  lead.patient_reference = lead.patient_reference || lead.internal_folio;
  lead.resume_token = lead.resume_token || resumeToken(lead.internal_folio);
  if (options.sendRecovery && status === "Pendiente de pago" && !activeMedicalCase) {
    try {
      lead = await sendRecoveryEmail(lead);
      console.log("[DERMATIKA recovery email sent]", { internal_folio: lead.internal_folio, email: lead.email });
    } catch (error) {
      console.error("[DERMATIKA recovery email error]", error);
    }
  }
  if (existingIndex >= 0) leads[existingIndex] = lead;
  else leads.push(lead);
  writeJson(leadsFile, leads);
  return lead;
}

function valueFrom(fields, keys, fallback = "No especificado") {
  for (const key of keys) {
    if (fields[key]) return fields[key];
  }
  return fallback;
}

function moneyFromCents(amount, currency = "mxn") {
  const value = Number(amount || 0) / 100;
  return `${new Intl.NumberFormat("es-MX", { style: "currency", currency: String(currency || "mxn").toUpperCase() }).format(value)} ${String(currency || "MXN").toUpperCase()}`;
}

function generatePatientFolio() {
  const date = new Date();
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  const random = String(crypto.randomInt(0, 10000)).padStart(4, "0");
  return `DMK-${y}${m}${d}-${random}`;
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

function pdfText(value) {
  const text = String(value ?? "");
  const bytes = [0xfe, 0xff];
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    bytes.push((code >> 8) & 0xff, code & 0xff);
  }
  return `<${Buffer.from(bytes).toString("hex").toUpperCase()}>`;
}

function wrapLine(text, max = 92) {
  const words = String(text || "").replace(/\s+/g, " ").trim().split(" ");
  const lines = [];
  let line = "";
  for (const word of words) {
    if (!line) {
      line = word;
    } else if (`${line} ${word}`.length <= max) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}

function addSection(lines, title, rows) {
  lines.push("");
  lines.push(title.toUpperCase());
  lines.push("-".repeat(Math.min(title.length + 8, 80)));
  for (const [label, value] of rows) {
    for (const line of wrapLine(`${label}: ${value || "No especificado"}`)) {
      lines.push(line);
    }
  }
}

function buildMedicalHistoryLines(fields, payment, files) {
  const paymentDate = payment.created
    ? new Date(payment.created * 1000).toLocaleString("es-MX", { timeZone: "America/Mexico_City" })
    : new Date().toLocaleString("es-MX", { timeZone: "America/Mexico_City" });

  const lines = [
    "DERMATIKA",
    "Historial medico del paciente",
    `Folio: ${fields.patient_reference}`,
    `Generado: ${new Date().toLocaleString("es-MX", { timeZone: "America/Mexico_City" })}`
  ];

  addSection(lines, "1. Datos de pago", [
    ["Folio DERMATIKA", fields.patient_reference],
    ["Payment ID", payment.id],
    ["Estado del pago", "paid"],
    ["Plan comprado", valueFrom(fields, ["plan_name", "plan_key"])],
    ["Monto pagado", moneyFromCents(payment.amount_received || payment.amount, payment.currency)],
    ["Fecha de pago", paymentDate]
  ]);

  addSection(lines, "2. Datos personales", [
    ["Nombre completo", fields.name],
    ["Email", fields.email],
    ["Telefono", fields.phone],
    ["Edad", fields.age],
    ["Sexo", fields.gender],
    ["Fecha de nacimiento", fields.birthdate]
  ]);

  addSection(lines, "3. Direccion de envio", [
    ["Calle", fields.shippingStreet],
    ["Numero exterior", fields.shippingExterior],
    ["Numero interior", fields.shippingInterior || "Sin numero interior"],
    ["Colonia", fields.shippingNeighborhood],
    ["Alcaldia/Municipio", fields.shippingMunicipality],
    ["Ciudad", valueFrom(fields, ["shippingCity", "city"])],
    ["Estado", fields.shippingState],
    ["Codigo postal", fields.shippingPostalCode],
    ["Referencias de entrega", fields.shippingReferences]
  ]);

  addSection(lines, "4. Datos fisicos", [
    ["Peso", fields.weight ? `${fields.weight} kg` : ""],
    ["Estatura", fields.height ? `${fields.height} cm` : ""],
    ["Tipo de piel", fields.skin]
  ]);

  addSection(lines, "5. Historial de acne", [
    ["Tiempo con acne", fields.time],
    ["Grado de acne", fields.severity],
    ["Zonas afectadas", valueFrom(fields, ["affectedAreas", "zones"])],
    ["Tipo de lesiones", valueFrom(fields, ["lesionTypes", "lesions"])],
    ["Tratamientos previos", valueFrom(fields, ["history", "previous"])],
    ["Uso previo de isotretinoina", valueFrom(fields, ["isotretinoinUse", "previous"])],
    ["Respuesta a tratamientos anteriores", valueFrom(fields, ["treatmentResponse", "history"])],
    ["Cicatrices o manchas", valueFrom(fields, ["scarsOrSpots", "scars"])]
  ]);

  addSection(lines, "6. Seguridad medica", [
    ["Enfermedades actuales", fields.conditions],
    ["Medicamentos actuales", fields.meds],
    ["Alergias", fields.allergies],
    ["Embarazo/lactancia", fields.pregnancy],
    ["Cirugias previas", valueFrom(fields, ["surgeries", "previousSurgeries"])],
    ["Antecedentes hepaticos", valueFrom(fields, ["liverHistory", "conditions"])],
    ["Antecedentes renales", valueFrom(fields, ["kidneyHistory"])],
    ["Depresion/ansiedad", valueFrom(fields, ["mentalHealthHistory"])],
    ["Consumo de alcohol", valueFrom(fields, ["alcoholUse"])],
    ["Consentimiento informado", fields.consent1 === "true" && fields.consent2 === "true" && fields.consent3 === "true" ? "Aceptado" : "No aceptado"],
    ["Detalles medicos importantes", fields.medical]
  ]);

  addSection(lines, "7. Fotografias", [
    ["Nota", "Fotografias adjuntas al correo"],
    ["Foto frontal", files.find(file => file.fieldName === "photoFront")?.originalName || "No adjunta"],
    ["Perfil izquierdo", files.find(file => file.fieldName === "photoLeft")?.originalName || "No adjunta"],
    ["Perfil derecho", files.find(file => file.fieldName === "photoRight")?.originalName || "No adjunta"],
    ["Zona afectada cercana", files.find(file => file.fieldName === "photoClose")?.originalName || "No adjunta"],
    ["Fotos adicionales", files.filter(file => file.fieldName === "photoAdditional").map(file => file.originalName).join(", ") || "No adjuntas"]
  ]);

  return lines;
}

function writePdf(filePath, lines) {
  const objects = [];
  const addObject = body => {
    objects.push(body);
    return objects.length;
  };
  const pagesId = addObject("");
  const fontId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pageIds = [];
  const pageLines = [];
  const maxLines = 48;

  for (let i = 0; i < lines.length; i += maxLines) {
    pageLines.push(lines.slice(i, i + maxLines));
  }

  for (const page of pageLines) {
    const content = [
      "BT",
      "/F1 10 Tf",
      "48 748 Td",
      "14 TL",
      ...page.map((line, index) => `${index ? "T* " : ""}${pdfText(line)} Tj`),
      "ET"
    ].join("\n");
    const contentId = addObject(`<< /Length ${Buffer.byteLength(content, "utf8")} >>\nstream\n${content}\nendstream`);
    const pageId = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }

  objects[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
  const catalogId = addObject(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
  const chunks = ["%PDF-1.4\n"];
  const offsets = [0];

  objects.forEach((body, index) => {
    offsets[index + 1] = Buffer.byteLength(chunks.join(""), "utf8");
    chunks.push(`${index + 1} 0 obj\n${body}\nendobj\n`);
  });

  const xrefOffset = Buffer.byteLength(chunks.join(""), "utf8");
  chunks.push(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`);
  for (let i = 1; i <= objects.length; i += 1) {
    chunks.push(`${String(offsets[i]).padStart(10, "0")} 00000 n \n`);
  }
  chunks.push(`trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`);
  fs.writeFileSync(filePath, chunks.join(""), "utf8");
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
    if (!process.env.STRIPE_WEBHOOK_SECRET && isProduction) {
      log("ERROR", "stripe_webhook_secret_missing", {});
      return res.status(503).json({ ok: false, error: "stripe_webhook_secret_missing" });
    }
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
    } else {
      event = JSON.parse(req.body.toString("utf8"));
      log("WARNING", "stripe_webhook_unverified_dev", { event_type: event.type });
    }
  } catch (error) {
    log("ERROR", "stripe_webhook_invalid", { error: error.message });
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
    const plan = plans[intent.metadata?.plan_key || ""];
    const paidAmount = Number(intent.amount_received || intent.amount || 0);
    const currencyOk = String(intent.currency || "").toLowerCase() === "mxn";
    const amountOk = plan && paidAmount === plan.price * 100;
    if (!plan || !currencyOk || !amountOk) {
      log("ERROR", "stripe_payment_validation_failed", { payment_id: intent.id, plan_key: intent.metadata?.plan_key || "", amount: paidAmount, currency: intent.currency });
      return res.status(400).json({ ok: false, error: "stripe_payment_validation_failed" });
    }
    if (intent.metadata?.patient_reference) {
      await saveLead({
        internal_folio: intent.metadata.patient_reference,
        patient_reference: intent.metadata.patient_reference,
        payment_reference: intent.id,
        payment_id: intent.id,
        payment_status: "paid",
        email: intent.metadata?.patient_email || "",
        phone: intent.metadata?.patient_phone || "",
        name: intent.metadata?.patient_name || "",
        plan_key: intent.metadata?.plan_key || "",
        plan_name: intent.metadata?.plan_name || "",
        amount: String(intent.amount_received || intent.amount || "")
      }, "Pago confirmado");
    }

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

  return res.json({ received: true });
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "dermatika-backend" });
});

app.post("/api/lead-autosave", upload.none(), asyncHandler(async (req, res) => {
  const requestedStatus = sanitize(req.body?.lead_status || "Formulario iniciado", 80);
  const sendRecovery = req.body?.send_recovery === "true";
  const fields = normalizeFields(req.body);
  const errors = validateLeadFields(fields, "partial");
  if (errors.length) return validationError(res, errors);
  const lead = await saveLead(fields, requestedStatus, { sendRecovery });
  console.log("[DERMATIKA lead autosaved]", { internal_folio: lead.internal_folio, status: lead.status, email: lead.email || "" });
  return res.json({
    ok: true,
    internalFolio: lead.internal_folio,
    patientReference: lead.patient_reference,
    status: lead.status,
    resumeUrl: recoveryUrl(lead.resume_token),
    message: "Tu información fue guardada. Puedes continuar tu proceso cuando estés listo."
  });
}));

app.get("/api/resume/:token", (req, res) => {
  const folio = verifyResumeToken(req.params.token);
  if (!folio) return res.status(404).json({ ok: false, error: "resume_not_found" });
  const lead = readJson(leadsFile, []).find(item => item.internal_folio === folio);
  if (!lead) return res.status(404).json({ ok: false, error: "resume_not_found" });
  return res.json({ ok: true, lead });
});

app.get("/api/download/:filename", (req, res) => {
  const filename = path.basename(sanitize(req.params.filename, 180));
  const target = path.join(uploadDir, filename);
  if (!fs.existsSync(target)) return res.status(404).json({ ok: false, error: "file_not_found" });
  log("INFO", "download_file", { filename });
  return res.download(target);
});

app.post("/api/create-stripe-payment-intent", asyncHandler(async (req, res) => {
  const {
    planKey,
    amount,
    currency = "MXN",
    email,
    patientName,
    phone,
    patientReference,
    sessionId,
    externalReference,
    shippingPostalCode,
    turnstileToken
  } = req.body || {};
  const plan = getPlan(planKey, amount);
  const requestedFolio = sanitize(patientReference || externalReference, 120);
  const paymentErrors = validateLeadFields({ email, phone, shippingPostalCode }, "identity");

  if (paymentErrors.length) return validationError(res, paymentErrors);
  if (String(currency || "MXN").toLowerCase() !== "mxn") return validationError(res, [{ field: "currency", message: "La moneda debe ser MXN." }]);
  const turnstile = await verifyTurnstile(sanitize(turnstileToken, 2048), req.ip);
  if (!turnstile.ok) return res.status(403).json({ ok: false, error: turnstile.error || "turnstile_failed" });

  if (!process.env.STRIPE_PUBLIC_KEY) {
    return res.status(503).json({ ok: false, error: "stripe_public_key_missing" });
  }
  if (!plan) {
    return res.status(400).json({ ok: false, error: "invalid_plan" });
  }

  const lead = await saveLead({
    ...req.body,
    internal_folio: requestedFolio,
    patient_reference: requestedFolio,
    payment_status: "pending",
    plan_key: planKey,
    plan_name: plan.name,
    email,
    phone,
    name: patientName
  }, "Pago iniciado", { sendRecovery: true });

  const stripe = getStripe();
  const intent = await stripe.paymentIntents.create({
    amount: plan.price * 100,
    currency: String(currency || "MXN").toLowerCase(),
    receipt_email: sanitize(email, 320) || undefined,
    automatic_payment_methods: { enabled: true },
    metadata: {
      plan_key: sanitize(planKey, 60),
      plan_name: plan.name,
      patient_reference: lead.internal_folio,
      folio_dermatika: lead.internal_folio,
      patient_name: sanitize(patientName, 120),
      patient_email: sanitize(email, 320),
      patient_phone: sanitize(phone, 40),
      shipping_postal_code: sanitize(shippingPostalCode, 20),
      session_id: sanitize(sessionId, 120)
    }
  });

  await saveLead({
    internal_folio: lead.internal_folio,
    patient_reference: lead.internal_folio,
    payment_reference: intent.id,
    payment_id: intent.id,
    payment_status: "pending",
    plan_key: planKey,
    plan_name: plan.name,
    email,
    phone,
    name: patientName
  }, "Pago iniciado");

  return res.json({
    ok: true,
    internalFolio: lead.internal_folio,
    patientReference: lead.internal_folio,
    publishableKey: process.env.STRIPE_PUBLIC_KEY,
    clientSecret: intent.client_secret,
    paymentIntentId: intent.id
  });
}));

app.post("/api/intake", upload.fields([
  { name: "photoFront", maxCount: 1 },
  { name: "photoLeft", maxCount: 1 },
  { name: "photoRight", maxCount: 1 },
  { name: "photoClose", maxCount: 1 },
  { name: "photoAdditional", maxCount: 5 }
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
  console.log("[DERMATIKA intake received]", {
    patient_reference: fields.patient_reference || "",
    payment_reference: fields.payment_reference || "",
    plan_key: fields.plan_key || "",
    files: files.length
  });
  console.log("[DERMATIKA photos received]", files.map(file => ({ fieldName: file.fieldName, originalName: file.originalName, size: file.size, mimetype: file.mimetype })));
  const reference = fields.patient_reference;
  const plan = getPlan(fields.plan_key) || { name: fields.plan_name || "Plan no especificado" };
  const resend = new Resend(process.env.RESEND_API_KEY);
  const fieldErrors = validateLeadFields(fields, "identity");
  if (fieldErrors.length) {
    cleanupFiles(files);
    return validationError(res, fieldErrors);
  }
  const requiredFields = [
    "patient_reference",
    "payment_reference",
    "name",
    "email",
    "phone",
    "age",
    "gender",
    "birthdate",
    "shippingStreet",
    "shippingExterior",
    "shippingNeighborhood",
    "shippingMunicipality",
    "shippingState",
    "shippingPostalCode",
    "shippingReferences",
    "weight",
    "height",
    "skin",
    "severity",
    "time",
    "previous",
    "history",
    "affectedAreas",
    "lesionTypes",
    "scarsOrSpots",
    "pregnancy",
    "meds",
    "conditions",
    "allergies",
    "mentalHealthHistory",
    "alcoholUse",
    "medical",
    "plan_key",
    "plan_name"
  ];
  const missingFields = requiredFields.filter(field => !fields[field]);
  const requiredPhotos = ["photoFront", "photoLeft", "photoRight", "photoClose"];
  const missingPhotos = requiredPhotos.filter(field => !files.some(file => file.fieldName === field));

  if (missingFields.length || missingPhotos.length) {
    cleanupFiles(files);
    log("WARNING", "intake_incomplete", { missingFields, missingPhotos });
    return res.status(400).json({
      ok: false,
      error: "intake_incomplete",
      missingFields,
      missingPhotos
    });
  }
  if (fields.consent1 !== "true" || fields.consent2 !== "true" || fields.consent3 !== "true") {
    cleanupFiles(files);
    log("WARNING", "missing_informed_consent", { patient_reference: reference });
    return res.status(400).json({ ok: false, error: "missing_informed_consent" });
  }
  if (!process.env.RESEND_API_KEY || !adminEmail) {
    cleanupFiles(files);
    log("ERROR", "resend_not_configured", {});
    return res.status(503).json({ ok: false, error: "resend_not_configured" });
  }

  const stripe = getStripe();
  const paymentIntent = await stripe.paymentIntents.retrieve(fields.payment_reference);
  console.log("[DERMATIKA payment received]", { payment_reference: paymentIntent.id, status: paymentIntent.status, amount: paymentIntent.amount_received || paymentIntent.amount });
  const paid = paymentIntent?.status === "succeeded";
  const paymentFolio = paymentIntent?.metadata?.patient_reference || paymentIntent?.metadata?.folio_dermatika;
  const expectedAmount = plan?.price ? plan.price * 100 : 0;
  const paidAmount = Number(paymentIntent.amount_received || paymentIntent.amount || 0);
  const currencyOk = String(paymentIntent.currency || "").toLowerCase() === "mxn";
  const amountOk = expectedAmount > 0 && paidAmount === expectedAmount;

  if (!currencyOk || !amountOk) {
    cleanupFiles(files);
    log("ERROR", "payment_amount_currency_mismatch", { payment_reference: fields.payment_reference, amount: paidAmount, expectedAmount, currency: paymentIntent.currency });
    return res.status(409).json({ ok: false, error: "payment_amount_currency_mismatch" });
  }

  if (!paid) {
    cleanupFiles(files);
    log("WARNING", "payment_not_paid", { status: paymentIntent?.status || "unknown", payment_reference: fields.payment_reference });
    return res.status(402).json({ ok: false, error: "payment_not_paid", paymentStatus: paymentIntent?.status || "unknown" });
  }
  if (paymentFolio && paymentFolio !== reference) {
    cleanupFiles(files);
    log("ERROR", "folio_payment_mismatch", { paymentFolio, reference });
    return res.status(409).json({ ok: false, error: "folio_payment_mismatch" });
  }

  const safeReference = reference.replace(/[^A-Za-z0-9-]/g, "");
  files.forEach((file, index) => {
    const ext = path.extname(file.originalName || "") || ".jpg";
    const uniqueName = safeReference + "-" + file.fieldName + "-" + String(index + 1).padStart(2, "0") + ext.toLowerCase();
    const targetPath = path.join(uploadDir, uniqueName);
    fs.renameSync(file.path, targetPath);
    file.filename = uniqueName;
    file.path = targetPath;
  });

  fields.payment_status = "paid";
  fields.patient_reference = reference;
  fields.payment_reference = paymentIntent.id;
  fields.amount = String(paymentIntent.amount_received || paymentIntent.amount || "");
  await saveLead({
    ...fields,
    internal_folio: reference,
    patient_reference: reference,
    payment_reference: paymentIntent.id,
    payment_status: "paid",
    amount: fields.amount
  }, "Pago confirmado");

  const pdfFilename = `Historial-Medico-DERMATIKA-${reference}.pdf`;
  const pdfPath = path.join(historiesDir, pdfFilename);
  await withTimeout(Promise.resolve().then(() => writePdf(pdfPath, buildMedicalHistoryLines(fields, paymentIntent, files))), pdfTimeoutMs, "pdf_generation");
  log("INFO", "pdf_generated", { patient_reference: reference, pdf: pdfFilename });

  appendCsv("patients.csv", [
    "created_at",
    "patient_reference",
    "name",
    "email",
    "phone",
    "plan_key",
    "plan_name",
    "amount",
    "payment_status",
    "payment_reference",
    "historial_pdf",
    "encrypted_payload"
  ], {
    created_at: new Date().toISOString(),
    patient_reference: reference,
    name: fields.name,
    email: fields.email,
    phone: fields.phone,
    plan_key: fields.plan_key,
    plan_name: plan.name,
    amount: paymentIntent.amount_received || paymentIntent.amount,
    payment_status: "paid",
    payment_reference: paymentIntent.id,
    historial_pdf: pdfFilename,
    encrypted_payload: encryptPayload({ ...fields, payment: paymentIntent, files, pdfFilename })
  });

  const photoAttachments = files.map((file, index) => {
    const ext = path.extname(file.originalName || "") || ".jpg";
    return {
      filename: file.filename || (reference + "-foto-" + (index + 1) + ext),
      content: fs.readFileSync(file.path).toString("base64"),
      size: file.size,
      url: fileDownloadUrl(file.filename || path.basename(file.path))
    };
  });
  const pdfAttachment = {
    filename: pdfFilename,
    content: fs.readFileSync(pdfPath).toString("base64"),
    size: fs.statSync(pdfPath).size
  };
  const totalAttachmentBytes = pdfAttachment.size + photoAttachments.reduce((sum, file) => sum + Number(file.size || 0), 0);
  const attachments = totalAttachmentBytes <= maxEmailAttachmentBytes
    ? [pdfAttachment, ...photoAttachments.map(({ filename, content }) => ({ filename, content }))]
    : [pdfAttachment];
  const photoLinksHtml = totalAttachmentBytes > maxEmailAttachmentBytes
    ? "<p><b>Las fotos exceden el limite de adjuntos. Descargalas aqui:</b></p><ul>" + photoAttachments.map(file => "<li><a href=\"" + file.url + "\">" + file.filename + "</a></li>").join("") + "</ul>"
    : "";

  try {
    await withTimeout(resend.emails.send({
      from: resendFrom,
      to: [adminEmail],
      subject: `[DERMATIKA - PAGO CONFIRMADO] ${reference}`,
      html: `
        <h2>Nuevo historial médico DERMATIKA</h2>
        <p><b>Folio:</b> ${reference}</p>
        <p><b>Payment ID:</b> ${paymentIntent.id}</p>
        <p><b>Estado del pago:</b> paid</p>
        <p><b>Plan:</b> ${fields.plan_name || plan.name}</p>
        <p><b>Monto:</b> ${moneyFromCents(paymentIntent.amount_received || paymentIntent.amount, paymentIntent.currency)}</p>
        <p><b>Paciente:</b> ${fields.name}</p>
        <p><b>Email:</b> ${fields.email}</p>
        <p><b>Teléfono:</b> ${fields.phone}</p>
        <p><b>Dirección:</b> ${fields.shippingStreet} ${fields.shippingExterior}${fields.shippingInterior ? " Int. " + fields.shippingInterior : ""}, ${fields.shippingNeighborhood}, ${fields.shippingMunicipality}, ${fields.shippingState}, CP ${fields.shippingPostalCode}</p>
        <p>Se adjunta el PDF con el historial médico completo y las fotografías por separado.</p>
        ${photoLinksHtml}
      `,
      attachments
    }), emailTimeoutMs, "email_send");
    log("INFO", "email_sent", { patient_reference: reference, to: adminEmail, attachments: attachments.length, totalAttachmentBytes });
    if (totalAttachmentBytes <= maxEmailAttachmentBytes) cleanupFiles(files);
  } catch (error) {
    log("ERROR", "email_error", { error: error.message, patient_reference: reference });
    throw error;
  }

  return res.json({ ok: true, patientReference: reference, pdf: pdfFilename, files: files.map(file => ({ fieldName: file.fieldName, filename: file.filename })) });
}));

app.post("/api/track-event", (req, res) => {
  log("INFO", "track_event", { event: req.body?.eventName || req.body?.event || "" });
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
