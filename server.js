const express = require('express');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const Stripe = require('stripe');

dotenv.config();

const app = express();
app.use(express.json({ limit: '2mb' }));

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
  esencial: 159000,
  avanzado: 189000,
  elite: 269000
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

app.post('/api/evaluation-guard', (req, res) => {
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
    submittedAt: req.body?.submittedAt || nowIso
  };

  const { db, latest } = findLatestMatch(payload);

  if (latest && latest.status === STATES.NO_CANDIDATO) {
    const elapsed = nowMs - new Date(latest.updatedAt || latest.createdAt || 0).getTime();
    if (elapsed < DAYS_30_MS) {
      db.push({
        id: makeId('eval'),
        ...payload,
        status: STATES.REINTENTO_BLOQUEADO,
        action: 'BLOCKED_30_DAYS',
        linkedTo: latest.id,
        createdAt: nowIso,
        updatedAt: nowIso
      });
      writeDb(db);
      return res.json({ ok: true, action: 'BLOCKED_30_DAYS', status: STATES.REINTENTO_BLOQUEADO });
    }
  }

  if (latest && latest.status === STATES.PAGADO) {
    return res.json({ ok: true, action: 'ALREADY_PAID', status: STATES.PAGADO, data: latest });
  }

  if (latest && (latest.status === STATES.CANDIDATO || latest.status === STATES.CHECKOUT_PENDIENTE)) {
    return res.json({
      ok: true,
      action: 'RESUME_CHECKOUT',
      status: STATES.CHECKOUT_PENDIENTE,
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
  return res.json({ ok: true, action: 'ALLOW', status, data: row });
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
    plan: sanitizeText(body.plan || '', 40) || null,
    medication: sanitizeText(body.medication || '', 40) || null,
    price: Number(body.price || 0) || null,
    createdAt: nowIso,
    updatedAt: nowIso,
    id: makeId('lead')
  };
  const db = readDb();
  db.push(payload);
  writeDb(db);
  return res.json({ ok: true, saved: true });
});

app.post('/api/intake', (req, res) => {
  const body = req.body || {};
  const nowIso = new Date().toISOString();
  const paymentStatus = normalizeText(body.payment_status || '');
  const status = paymentStatus.includes('succeeded') || paymentStatus.includes('paid') ? STATES.PAGADO : STATES.CHECKOUT_PENDIENTE;
  const payload = {
    id: makeId('intake'),
    nombre: normalizeText(body.nombre || body.patient_name),
    apellido: normalizeText(body.apellido),
    fullName: normalizeText(body.fullName || body.patient_name),
    correo: normalizeText(body.correo || body.email),
    whatsapp: normalizePhone(body.whatsapp || body.phone),
    fechaNacimiento: normalizeText(body.fechaNacimiento || body.birthdate),
    status,
    plan: sanitizeText(body.plan || '', 40) || null,
    medication: sanitizeText(body.medication || '', 40) || null,
    price: Number(body.price || 0) || null,
    shipping: body.shipping || null,
    payment_reference: sanitizeText(body.payment_reference || body.payment_intent_id || '', 120) || null,
    payment_status: sanitizeText(body.payment_status || '', 80),
    answers: body.answers_json || body.answers || null,
    createdAt: nowIso,
    updatedAt: nowIso
  };
  const db = readDb();
  db.push(payload);
  writeDb(db);
  return res.json({ ok: true, status });
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
    const expectedAmount = PLAN_PRICE_MAP[planKey];
    if (requestedAmount !== expectedAmount) {
      return res.status(400).json({ ok: false, error: 'amount_mismatch', expectedAmount });
    }

    const patientReference = sanitizeText(req.body?.patientReference || '', 120) || makeId('dmk');
    const email = sanitizeText(req.body?.email || '', 120);
    const phone = normalizePhone(req.body?.phone || '');
    const paymentIntent = await stripe.paymentIntents.create({
      amount: expectedAmount,
      currency: 'mxn',
      automatic_payment_methods: { enabled: true },
      metadata: {
        plan_key: planKey,
        patient_reference: patientReference,
        email,
        phone
      },
      receipt_email: email || undefined
    });

    return res.json({
      ok: true,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      publishableKey: stripePublic
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: 'stripe_error', detail: sanitizeText(error?.message || 'unknown_error', 220) });
  }
}

app.post('/api/create-stripe-payment-intent', createPaymentIntentHandler);
app.post('/api/create-payment-intent', createPaymentIntentHandler);

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'dermatika-backend', stripeReady: Boolean(stripe && stripePublic) });
});

app.listen(process.env.PORT || 3000, () => {
  console.log('DERMATIKA backend running');
});
