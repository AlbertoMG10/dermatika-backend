'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const Stripe = require('stripe');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();

// ✅ FIX: trust proxy debe ir ANTES de rate limit y middlewares (Render/Nginx)
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ✅ Seguridad: Helmet con CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://js.stripe.com"],
      frameSrc: ["https://js.stripe.com", "https://hooks.stripe.com"],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        process.env.NETLIFY_ORIGIN || '',
        process.env.NETLIFY_PREVIEW_ORIGIN || ''
      ].filter(Boolean),
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));

// ✅ Rate limit funcional con trust proxy ya configurado
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_requests' }
});
app.use('/api', apiLimiter);

// ✅ Rate limit más estricto para rutas de pago
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_payment_requests' }
});
app.use('/api/create-stripe-payment-intent', paymentLimiter);
app.use('/api/create-payment-intent', paymentLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 5 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('invalid_file_type'));
    return cb(null, true);
  }
});

// ✅ CORS seguro: solo orígenes autorizados
const ALLOWED_ORIGINS = new Set(
  [
    'https://dermatika.mx',
    'https://www.dermatika.mx',
    process.env.NETLIFY_ORIGIN || '',
    process.env.NETLIFY_PREVIEW_ORIGIN || ''
  ].filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return next();
});

// ✅ Base de datos JSON simple
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'evaluations.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, '[]', 'utf8');

const STATES = {
  NUEVO: 'NUEVO',
  CANDIDATO: 'CANDIDATO',
  NO_CANDIDATO: 'NO_CANDIDATO',
  REINTENTO_BLOQUEADO: 'REINTENTO_BLOQUEADO',
  CHECKOUT_PENDIENTE: 'CHECKOUT_PENDIENTE',
  PAGADO: 'PAGADO'
};

const PLAN_PRICE_MAP = {
  esencial: { amount: 159000, medication: 'Neotrex', plan: 'Esencial' },
  avanzado: { amount: 189000, medication: 'Vastionin', plan: 'Avanzado' },
  elite: { amount: 269000, medication: 'Epuris', plan: 'Elite' }
};

const DAYS_30_MS = 30 * 24 * 60 * 60 * 1000;
const postalCache = new Map();

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return [];
  }
}

function writeDb(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    // Log sin exponer al usuario
    console.error('[DERMATIKA] writeDb error');
  }
}

// ✅ Sanitización: elimina caracteres peligrosos
function sanitizeText(v = '', max = 200) {
  return String(v || '').replace(/[<>"'`]/g, '').trim().slice(0, max);
}

function normalizeText(v = '') {
  return sanitizeText(v, 200).toLowerCase();
}

function normalizePhone(v = '') {
  return String(v || '').replace(/\D/g, '').slice(0, 20);
}

function makeId(prefix = 'row') {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
}

function normalizePostalPayload(data = {}) {
  let neighborhoods = [];
  let municipality = '';
  let state = '';
  let city = '';

  if (data?.response) {
    const items = Array.isArray(data.response.asentamiento) ? data.response.asentamiento : [];
    neighborhoods = items.map((item) => String(item || '').trim()).filter(Boolean);
    municipality = String(data.response.municipio || '').trim();
    state = String(data.response.estado || '').trim();
    city = String(data.response.ciudad || municipality || '').trim();
  } else if (data?.zip_code) {
    const items = Array.isArray(data.zip_code?.d_asenta) ? data.zip_code.d_asenta : [];
    neighborhoods = items.map((item) => String(item || '').trim()).filter(Boolean);
    municipality = String(data.zip_code?.d_mnpio || '').trim();
    state = String(data.zip_code?.d_estado || '').trim();
    city = String(data.zip_code?.d_ciudad || municipality || '').trim();
  }

  const uniqueNeighborhoods = [...new Set(neighborhoods)];
  if (!uniqueNeighborhoods.length || !municipality || !state) return null;
  return { neighborhoods: uniqueNeighborhoods, municipality, city: city || municipality, state };
}

async function lookupPostalCode(cp = '') {
  const zip = String(cp || '').trim();
  if (!/^\d{5}$/.test(zip)) return null;
  if (postalCache.has(zip)) return postalCache.get(zip);

  const endpoints = [
    `https://api-sepomex.hckdrk.mx/query/info_cp/${zip}?type=simplified`,
    `https://sepomex.icalialabs.com/api/v1/zip_codes/${zip}`
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint, { method: 'GET', signal: AbortSignal.timeout(5000) });
      if (!response.ok) continue;
      const data = await response.json();
      const normalized = normalizePostalPayload(data);
      if (!normalized) continue;
      postalCache.set(zip, normalized);
      setTimeout(() => postalCache.delete(zip), 3600000); // TTL 1 hora
      return normalized;
    } catch (_) {
      // intentar siguiente fuente
    }
  }
  return null;
}

function createFolio() {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const rnd = String(Math.floor(1000 + Math.random() * 9000));
  return `DERM-${date}-${rnd}`;
}

function getOrCreateFolio(raw = '') {
  const value = sanitizeText(raw, 40);
  if (/^DERM-\d{8}-\d{4}$/.test(value)) return value;
  return createFolio();
}

function matchRecord(record, payload) {
  const emailMatch = payload.correo && record.correo === payload.correo;
  const phoneMatch = payload.whatsapp && record.whatsapp === payload.whatsapp;
  const nameDobMatch = payload.fullName && payload.fechaNacimiento &&
    record.fullName === payload.fullName && record.fechaNacimiento === payload.fechaNacimiento;
  return emailMatch || phoneMatch || nameDobMatch;
}

function findLatestMatch(payload) {
  const db = readDb();
  const latest = db
    .filter((row) => matchRecord(row, payload))
    .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime())[0] || null;
  return { db, latest };
}

function normalizePlanKey(planRaw = '') {
  const p = normalizeText(planRaw);
  if (p.includes('esencial')) return 'esencial';
  if (p.includes('avanzado')) return 'avanzado';
  if (p.includes('elite')) return 'elite';
  return '';
}

// ✅ Stripe: solo si están configuradas las keys
const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const stripePublic = process.env.STRIPE_PUBLIC_KEY || '';
const stripe = stripeSecret ? new Stripe(stripeSecret, { apiVersion: '2024-04-10' }) : null;

// ── Log de arranque: verificar variables críticas ──
console.log('[CONFIG] STRIPE_SECRET_KEY:', stripeSecret ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] STRIPE_PUBLIC_KEY:', stripePublic ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] SMTP_HOST:', process.env.SMTP_HOST || '❌ FALTA');
console.log('[CONFIG] SMTP_USER:', process.env.SMTP_USER || '❌ FALTA');
console.log('[CONFIG] SMTP_PASS:', process.env.SMTP_PASS ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] INTERNAL_EMAIL_TO:', process.env.INTERNAL_EMAIL_TO || '❌ FALTA');
console.log('[CONFIG] NETLIFY_ORIGIN:', process.env.NETLIFY_ORIGIN || '❌ FALTA');

// ✅ Nodemailer: solo si está configurado SMTP
const mailTransport = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' }
        : undefined
    })
  : null;

async function sendInternalMail(subject, text, attachments = []) {
  if (!mailTransport || !process.env.INTERNAL_EMAIL_TO) {
    console.error('[MAIL] No enviado — falta SMTP_HOST o INTERNAL_EMAIL_TO');
    return false;
  }
  try {
    await mailTransport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.INTERNAL_EMAIL_TO,
      subject,
      text,
      attachments
    });
    console.log('[MAIL] ✅ Enviado:', subject);
    return true;
  } catch (err) {
    console.error('[MAIL] ❌ Error al enviar:', err.message || err);
    return false;
  }
}

// ==================== RUTAS API ====================

// Guard de evaluación (anti-duplicado, anti-reintento 30d)
app.post('/api/evaluation-guard', async (req, res) => {
  const nowIso = new Date().toISOString();
  const nowMs = Date.now();
  const payload = {
    nombre: normalizeText(req.body?.nombre),
    apellido: normalizeText(req.body?.apellido),
    fullName: normalizeText(req.body?.fullName),
    correo: normalizeText(req.body?.correo),
    whatsapp: normalizePhone(req.body?.whatsapp),
    fechaNacimiento: normalizeText(req.body?.fechaNacimiento),
    sexo: normalizeText(req.body?.sexo || req.body?.sex),
    localEligibility: normalizeText(req.body?.localEligibility),
    recommended: req.body?.recommended || null,
    submittedAt: req.body?.submittedAt || nowIso,
    folio: getOrCreateFolio(req.body?.folio || req.body?.internal_folio || req.body?.patient_reference)
  };

  const { db, latest } = findLatestMatch(payload);

  if (latest && latest.status === STATES.NO_CANDIDATO) {
    const elapsed = nowMs - new Date(latest.updatedAt || latest.createdAt || 0).getTime();
    if (elapsed < DAYS_30_MS) {
      const row = {
        id: makeId('eval'),
        ...payload,
        status: STATES.REINTENTO_BLOQUEADO,
        action: 'BLOCKED_30_DAYS',
        linkedTo: latest.id,
        createdAt: nowIso,
        updatedAt: nowIso
      };
      db.push(row);
      writeDb(db);
      await sendInternalMail(
        `Nueva evaluación DERMÁTIKA #${payload.folio} - ${sanitizeText(req.body?.nombre || 'Paciente', 80)} - REINTENTO_BLOQUEADO`,
        `FOLIO: ${payload.folio}\nEstado: ${STATES.REINTENTO_BLOQUEADO}\nMotivo: no_candidato_30d\nFecha/Hora: ${nowIso}`
      );
      return res.json({ ok: true, action: 'BLOCKED_30_DAYS', status: STATES.REINTENTO_BLOQUEADO, folio: payload.folio });
    }
  }

  if (latest && latest.status === STATES.PAGADO) {
    return res.json({ ok: true, action: 'ALREADY_PAID', status: STATES.PAGADO, folio: latest.folio || payload.folio, data: latest });
  }

  if (latest && (latest.status === STATES.CANDIDATO || latest.status === STATES.CHECKOUT_PENDIENTE)) {
    return res.json({
      ok: true,
      action: 'RESUME_CHECKOUT',
      status: STATES.CHECKOUT_PENDIENTE,
      folio: latest.folio || payload.folio,
      data: {
        nombre: latest.nombre || payload.nombre,
        plan: latest.plan || payload.recommended?.plan || 'Avanzado',
        medication: latest.medication || payload.recommended?.medication || 'Vastionin',
        price: latest.price || payload.recommended?.price || 1890
      }
    });
  }

  const status = payload.localEligibility === 'no_aprobado' ? STATES.NO_CANDIDATO : STATES.CANDIDATO;
  const row = {
    id: makeId('eval'),
    ...payload,
    status,
    plan: payload.recommended?.plan || null,
    medication: payload.recommended?.medication || null,
    price: payload.recommended?.price || null,
    createdAt: nowIso,
    updatedAt: nowIso
  };
  db.push(row);
  writeDb(db);

  await sendInternalMail(
    `Nueva evaluación DERMÁTIKA #${row.folio} - ${sanitizeText(req.body?.nombre || 'Paciente', 80)} - ${row.plan || 'Sin plan'}`,
    `FOLIO: ${row.folio}\nEstado: ${status}\nNombre: ${sanitizeText(req.body?.nombre || '', 80)} ${sanitizeText(req.body?.apellido || '', 80)}\nCorreo: ${payload.correo}\nWhatsApp: ${payload.whatsapp}\nSexo: ${payload.sexo || 'n/a'}\nPlan recomendado: ${row.plan || 'N/A'}\nMedicamento: ${row.medication || 'N/A'}\nPrecio: ${row.price || 0}\nFecha/Hora: ${nowIso}`
  );

  return res.json({ ok: true, action: 'ALLOW', status, folio: row.folio, recommendedPlan: row.plan || null, data: row });
});

// Resume por token/folio/email/teléfono
app.get('/api/resume/:token', (req, res) => {
  const token = sanitizeText(req.params.token || '', 80).toLowerCase();
  const db = readDb();
  const latest = db
    .filter((row) => {
      const folio = String(row.folio || '').toLowerCase();
      const email = String(row.correo || '').toLowerCase();
      const phone = String(row.whatsapp || '').toLowerCase();
      return token && (token === folio || token === email || token === phone);
    })
    .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0).getTime() - new Date(a.updatedAt || a.createdAt || 0).getTime())[0] || null;

  if (!latest) return res.status(404).json({ ok: false, error: 'not_found' });
  if (latest.status === STATES.NO_CANDIDATO) return res.json({ ok: true, action: 'BLOCKED_30_DAYS', status: STATES.NO_CANDIDATO, folio: latest.folio, data: latest });
  if (latest.status === STATES.PAGADO) return res.json({ ok: true, action: 'ALREADY_PAID', status: STATES.PAGADO, folio: latest.folio, data: latest });

  return res.json({
    ok: true,
    action: 'RESUME_CHECKOUT',
    status: STATES.CHECKOUT_PENDIENTE,
    folio: latest.folio,
    data: {
      nombre: latest.nombre || 'Paciente',
      plan: latest.plan || 'Avanzado',
      medication: latest.medication || 'Vastionin',
      price: latest.price || 1890
    }
  });
});

// Autosave de lead
app.post('/api/lead-autosave', (req, res) => {
  const body = req.body || {};
  const nowIso = new Date().toISOString();
  const payload = {
    nombre: normalizeText(body.nombre || body.patient_name),
    apellido: normalizeText(body.apellido),
    fullName: normalizeText(body.fullName || body.patient_name),
    correo: normalizeText(body.correo || body.email),
    whatsapp: normalizePhone(body.whatsapp || body.phone),
    fechaNacimiento: normalizeText(body.fechaNacimiento || body.birthdate),
    sexo: normalizeText(body.sexo || body.sex || body.gender),
    status: STATES.NUEVO,
    autosave: true,
    answers: body.answers_json || body.answers || null,
    plan: sanitizeText(body.plan || body.plan_name || '', 40) || null,
    medication: sanitizeText(body.medication || '', 40) || null,
    price: Number(body.price || body.plan_price || 0) || null,
    folio: getOrCreateFolio(body.folio_dermatika || body.internal_folio || body.patient_reference),
    createdAt: nowIso,
    updatedAt: nowIso,
    id: makeId('lead')
  };
  const db = readDb();
  db.push(payload);
  writeDb(db);
  return res.json({ ok: true, saved: true, folio: payload.folio, status: payload.status });
});

// Intake principal con fotos
app.post('/api/intake', upload.any(), async (req, res) => {
  console.log('[INTAKE] ← Recibido desde:', req.headers.origin || 'origen desconocido');
  const body = req.body || {};
  const nowIso = new Date().toISOString();
  const paymentStatus = normalizeText(body.payment_status || '');
  const status = paymentStatus.includes('succeeded') || paymentStatus.includes('paid')
    ? STATES.PAGADO
    : STATES.CHECKOUT_PENDIENTE;
  const folio = getOrCreateFolio(body.folio_dermatika || body.internal_folio || body.patient_reference);
  const plan = sanitizeText(body.plan || body.plan_name || '', 40) || null;
  const medication = sanitizeText(body.medication || '', 40) || null;
  const price = Number(body.price || body.plan_price || 0) || null;

  const fileSummaries = Array.isArray(req.files)
    ? req.files.map((f) => ({
        field: sanitizeText(f.fieldname || '', 40),
        name: sanitizeText(f.originalname || '', 120),
        type: sanitizeText(f.mimetype || '', 80),
        size: Number(f.size || 0)
      }))
    : [];

  const photosCountFromBody = Number(body.photos_count || 0);
  const effectivePhotosCount = Math.max(photosCountFromBody, fileSummaries.length);
  if (effectivePhotosCount < 3) {
    return res.status(400).json({ ok: false, error: 'minimum_3_photos_required' });
  }

  const payload = {
    id: makeId('intake'),
    nombre: normalizeText(body.nombre || body.patient_name),
    apellido: normalizeText(body.apellido),
    fullName: normalizeText(body.fullName || body.patient_name),
    correo: normalizeText(body.correo || body.email),
    whatsapp: normalizePhone(body.whatsapp || body.phone),
    fechaNacimiento: normalizeText(body.fechaNacimiento || body.birthdate),
    sexo: normalizeText(body.sexo || body.sex || body.gender),
    status,
    plan,
    medication,
    price,
    folio,
    shipping: body.shipping || null,
    payment_reference: sanitizeText(body.payment_reference || body.payment_intent_id || '', 120) || null,
    payment_status: sanitizeText(body.payment_status || 'pending', 80),
    answers: body.answers_json || body.answers || null,
    files: fileSummaries,
    createdAt: nowIso,
    updatedAt: nowIso
  };

  const db = readDb();
  db.push(payload);
  writeDb(db);

  const subject = `Nueva evaluación DERMÁTIKA #${folio} - ${sanitizeText(body.patient_name || body.nombre || 'Paciente', 80)} - ${plan || 'Sin plan'}`;
  const attachments = Array.isArray(req.files)
    ? req.files.map((file, idx) => ({
        filename: `${folio}-foto-${idx + 1}-${sanitizeText(file.originalname || 'imagen', 80)}`,
        content: file.buffer,
        contentType: file.mimetype
      }))
    : [];

  const emailBody = [
    `FOLIO: ${folio}`,
    `Nombre: ${sanitizeText(body.patient_name || body.nombre || '', 120)} ${sanitizeText(body.apellido || '', 120)}`.trim(),
    `Correo: ${sanitizeText(body.email || body.correo || '', 120)}`,
    `WhatsApp: ${normalizePhone(body.phone || body.whatsapp || '')}`,
    `Sexo: ${sanitizeText(body.sexo || body.sex || body.gender || '', 20) || 'n/a'}`,
    `Plan recomendado: ${plan || 'N/A'}`,
    `Medicamento: ${medication || 'N/A'}`,
    `Precio: ${price || 0}`,
    `Estado: ${status}`,
    `Estado del pago: ${sanitizeText(body.payment_status || 'pending', 80)}`,
    `Fecha/Hora: ${nowIso}`,
    `Respuestas: ${typeof body.answers_json === 'string' ? body.answers_json : JSON.stringify(body.answers || {}, null, 2)}`,
    `Fotos: ${JSON.stringify(fileSummaries, null, 2)}`
  ].join('\n');

  await sendInternalMail(subject, emailBody, attachments);
  return res.json({ ok: true, folio, status, recommendedPlan: plan || null });
});

// ✅ Crear Payment Intent con Stripe
async function createPaymentIntentHandler(req, res) {
  try {
    console.log('[STRIPE] ← Solicitud de pago recibida, plan:', req.body?.planKey);
    if (!stripe || !stripePublic) {
      console.error('[STRIPE] ❌ Stripe no configurado — faltan keys');
      return res.status(503).json({ ok: false, error: 'stripe_not_configured' });
    }
    const planKey = normalizePlanKey(req.body?.planKey || '');
    const requestedAmount = Number(req.body?.amount || 0);
    if (!planKey || !PLAN_PRICE_MAP[planKey]) {
      return res.status(400).json({ ok: false, error: 'invalid_plan' });
    }
    const expectedPlan = PLAN_PRICE_MAP[planKey];
    const expectedAmount = expectedPlan.amount;
    if (requestedAmount !== expectedAmount) {
      return res.status(400).json({ ok: false, error: 'amount_mismatch', expectedAmount });
    }
    const requestedMedication = sanitizeText(req.body?.medication || '', 60);
    if (requestedMedication && normalizeText(requestedMedication) !== normalizeText(expectedPlan.medication)) {
      return res.status(400).json({ ok: false, error: 'medication_mismatch' });
    }

    const folio = getOrCreateFolio(req.body?.patientReference || req.body?.folio || '');
    const email = sanitizeText(req.body?.email || '', 120);
    const phone = normalizePhone(req.body?.phone || '');
    const sexo = sanitizeText(req.body?.sexo || req.body?.sex || '', 20);
    const patientName = sanitizeText(req.body?.patientName || req.body?.nombre || '', 120);
    const medication = sanitizeText(req.body?.medication || '', 60);
    const planName = sanitizeText(req.body?.planName || req.body?.plan_name || planKey, 80);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: expectedAmount,
      currency: 'mxn',
      automatic_payment_methods: { enabled: true },
      metadata: {
        folio,
        nombre: patientName,
        correo: email,
        whatsapp: phone,
        plan: expectedPlan.plan,
        medicamento: expectedPlan.medication,
        precio: String(expectedAmount / 100),
        sexo,
        plan_key: planKey,
        patient_reference: folio,
        email,
        phone
      },
      receipt_email: email || undefined
    });

    return res.json({
      ok: true,
      folio,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      publishableKey: stripePublic
    });
  } catch (err) {
    console.error('[STRIPE] ❌ Error creando payment intent:', err.message || err);
    return res.status(500).json({ ok: false, error: 'stripe_error' });
  }
}

app.post('/api/create-stripe-payment-intent', createPaymentIntentHandler);
app.post('/api/create-payment-intent', createPaymentIntentHandler);

// Confirmar payment intent
app.post('/api/confirm-payment-intent', async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ ok: false, error: 'stripe_not_configured' });
    const paymentIntentId = sanitizeText(req.body?.paymentIntentId || '', 80);
    const folio = getOrCreateFolio(req.body?.folio || '');
    if (!paymentIntentId) return res.status(400).json({ ok: false, error: 'missing_payment_intent_id' });

    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
    const paid = pi?.status === 'succeeded';

    const db = readDb();
    const idx = db.findIndex((row) => String(row.folio || '').toLowerCase() === folio.toLowerCase());
    if (idx >= 0) {
      db[idx].payment_reference = paymentIntentId;
      db[idx].payment_status = paid ? 'succeeded' : String(pi?.status || 'unknown');
      db[idx].status = paid ? STATES.PAGADO : db[idx].status;
      db[idx].updatedAt = new Date().toISOString();
      writeDb(db);
    }

    return res.json({ ok: true, paid, status: pi?.status || 'unknown', folio });
  } catch {
    return res.status(500).json({ ok: false, error: 'confirm_failed' });
  }
});

// ✅ Config pública (solo public key — nunca secret key)
app.get('/api/config', (_req, res) => {
  res.json({
    ok: true,
    publicKey: stripePublic || '',
    paymentLinks: {
      esencial: process.env.PAYMENT_LINK_ESENCIAL || '',
      avanzado: process.env.PAYMENT_LINK_AVANZADO || '',
      elite: process.env.PAYMENT_LINK_ELITE || ''
    }
  });
});

// ✅ CP lookup con cache y timeout
app.get('/api/postal-code/:cp', async (req, res) => {
  const cp = sanitizeText(req.params.cp || '', 10);
  if (!/^\d{5}$/.test(cp)) {
    return res.status(400).json({ ok: false, error: 'invalid_postal_code' });
  }
  try {
    const result = await lookupPostalCode(cp);
    if (!result) {
      return res.status(404).json({ ok: false, error: 'postal_code_not_found' });
    }
    return res.json({ ok: true, cp, ...result });
  } catch {
    return res.status(500).json({ ok: false, error: 'postal_lookup_unavailable' });
  }
});

// Track eventos analytics
app.post('/api/track-event', (req, res) => {
  const body = req.body || {};
  const payload = {
    id: makeId('event'),
    event: sanitizeText(body.event || '', 80),
    source: sanitizeText(body.source || '', 80),
    timestamp: sanitizeText(body.timestamp || new Date().toISOString(), 80),
    patient_reference: sanitizeText(body.patient_reference || '', 120)
  };
  const db = readDb();
  db.push(payload);
  writeDb(db);
  res.json({ ok: true });
});

// Health check
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'dermatika-backend',
    stripeReady: Boolean(stripe && stripePublic),
    timestamp: new Date().toISOString()
  });
});

// ✅ Manejo global de errores: sin stack trace al cliente
app.use((error, _req, res, _next) => {
  if (error && error.message === 'invalid_file_type') {
    return res.status(400).json({ ok: false, error: 'invalid_file_type' });
  }
  if (error && error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ ok: false, error: 'file_too_large', message: 'Tu imagen supera el límite de 5 MB.' });
  }
  // Log interno sin exponer al cliente
  console.error('[DERMATIKA] Error interno:', error?.code || error?.message || 'unknown');
  return res.status(500).json({ ok: false, error: 'internal_error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[DERMATIKA] Backend corriendo en puerto ${PORT}`);
});
