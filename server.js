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
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api', apiLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 5 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('invalid_file_type'));
    return cb(null, true);
  }
});

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
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return next();
});

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

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return [];
  }
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function sanitizeText(v = '', max = 200) {
  return String(v || '').replace(/[<>]/g, '').trim().slice(0, max);
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
  const nameDobMatch = payload.fullName && payload.fechaNacimiento && record.fullName === payload.fullName && record.fechaNacimiento === payload.fechaNacimiento;
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

const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const stripePublic = process.env.STRIPE_PUBLIC_KEY || '';
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

const mailTransport = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined
    })
  : null;

async function sendInternalMail(subject, text, attachments = []) {
  if (!mailTransport || !process.env.INTERNAL_EMAIL_TO) return false;
  try {
    await mailTransport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.INTERNAL_EMAIL_TO,
      subject,
      text,
      attachments
    });
    return true;
  } catch {
    return false;
  }
}

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
    `FOLIO: ${row.folio}\nEstado: ${status}\nNombre: ${sanitizeText(req.body?.nombre || '', 80)} ${sanitizeText(req.body?.apellido || '', 80)}\nCorreo: ${payload.correo}\nWhatsApp: ${payload.whatsapp}\nPlan recomendado: ${row.plan || 'N/A'}\nMedicamento: ${row.medication || 'N/A'}\nPrecio: ${row.price || 0}\nFecha/Hora: ${nowIso}`
  );

  return res.json({ ok: true, action: 'ALLOW', status, folio: row.folio, recommendedPlan: row.plan || null, data: row });
});


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

app.post('/api/intake', upload.any(), async (req, res) => {
  const body = req.body || {};
  const nowIso = new Date().toISOString();
  const paymentStatus = normalizeText(body.payment_status || '');
  const status = paymentStatus.includes('succeeded') || paymentStatus.includes('paid') ? STATES.PAGADO : STATES.CHECKOUT_PENDIENTE;
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
    status,
    plan,
    medication,
    price,
    folio,
    shipping: body.shipping || null,
    payment_reference: sanitizeText(body.payment_reference || body.payment_intent_id || '', 120) || null,
    payment_status: sanitizeText(body.payment_status || '', 80),
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
    `Plan recomendado: ${plan || 'N/A'}`,
    `Medicamento: ${medication || 'N/A'}`,
    `Precio: ${price || 0}`,
    `Estado: ${status}`,
    `Fecha/Hora: ${nowIso}`,
    `Estado del pago: ${sanitizeText(body.payment_status || 'pending', 80)}`,
    `Respuestas: ${typeof body.answers_json === 'string' ? body.answers_json : JSON.stringify(body.answers || {}, null, 2)}`,
    `Fotos: ${JSON.stringify(fileSummaries, null, 2)}`
  ].join('\n');
  await sendInternalMail(subject, emailBody, attachments);

  return res.json({ ok: true, folio, status, recommendedPlan: plan || null });
});

async function createPaymentIntentHandler(req, res) {
  try {
    if (!stripe || !stripePublic) {
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
      return res.status(400).json({ ok: false, error: 'medication_mismatch', expectedMedication: expectedPlan.medication });
    }

    const folio = getOrCreateFolio(req.body?.patientReference || req.body?.folio || '');
    const email = sanitizeText(req.body?.email || '', 120);
    const phone = normalizePhone(req.body?.phone || '');
    const patientName = sanitizeText(req.body?.patientName || req.body?.nombre || '', 120);
    const medication = sanitizeText(req.body?.medication || '', 60);
    const planName = sanitizeText(req.body?.planName || req.body?.plan_name || planKey, 80);
    const price = String(Number(req.body?.plan_price || expectedAmount / 100));

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
  } catch {
    return res.status(500).json({ ok: false, error: 'stripe_error' });
  }
}

app.post('/api/create-stripe-payment-intent', createPaymentIntentHandler);
app.post('/api/create-payment-intent', createPaymentIntentHandler);


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

app.get('/api/config', (_req, res) => {
  res.json({
    ok: true,
    publicKey: stripePublic || '',
    paymentLinks: {
      esencial: process.env.PAYMENT_LINK_ESENCIAL || 'PEGAR_LINK_PAGO_ESENCIAL',
      avanzado: process.env.PAYMENT_LINK_AVANZADO || 'PEGAR_LINK_PAGO_AVANZADO',
      elite: process.env.PAYMENT_LINK_ELITE || 'PEGAR_LINK_PAGO_ELITE'
    }
  });
});

app.post('/api/track-event', (req, res) => {
  const body = req.body || {};
  const payload = {
    id: makeId('event'),
    event: sanitizeText(body.event || '', 80),
    source: sanitizeText(body.source || '', 80),
    timestamp: sanitizeText(body.timestamp || new Date().toISOString(), 80),
    patient_reference: sanitizeText(body.patient_reference || '', 120),
    meta: body
  };
  const db = readDb();
  db.push(payload);
  writeDb(db);
  res.json({ ok: true });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'dermatika-backend', stripeReady: Boolean(stripe && stripePublic) });
});

app.use((error, _req, res, _next) => {
  if (error && error.message === 'invalid_file_type') {
    return res.status(400).json({ ok: false, error: 'invalid_file_type' });
  }
  if (error && error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ ok: false, error: 'file_too_large', message: 'Tu imagen supera el límite de 5 MB. Sube una imagen más ligera.' });
  }
  return res.status(500).json({ ok: false, error: 'internal_error' });
});

app.listen(process.env.PORT || 3000, () => {
  console.log('DERMATIKA backend running');
});
