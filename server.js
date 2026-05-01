require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const xss = require('xss');

const app = express();
const PORT = process.env.PORT || 10000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PATIENTS_CSV = path.join(DATA_DIR, 'pacientes.csv');
const EVENTS_CSV = path.join(DATA_DIR, 'events.csv');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const FRONTEND_URL = process.env.FRONTEND_URL || '';
const allowedOrigins = [FRONTEND_URL].filter(Boolean);

app.set('trust proxy', 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origen no permitido por CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Demasiadas solicitudes. Intenta más tarde.' }
});
app.use(limiter);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomUUID()}${ext}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: (_, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Solo se aceptan imágenes JPG, PNG o WEBP'), ok);
  }
});

function sanitize(value) {
  if (value === undefined || value === null) return '';
  return xss(String(value).trim());
}

function csvEscape(value) {
  const str = sanitize(value).replace(/\r?\n|\r/g, ' ');
  return `"${str.replace(/"/g, '""')}"`;
}

function appendCsv(file, values) {
  fs.appendFileSync(file, values.map(csvEscape).join(',') + '\n', 'utf8');
}

function encrypt(text) {
  const keySource = process.env.DATA_ENCRYPTION_KEY || 'fallback-change-this-key-before-production';
  const key = crypto.createHash('sha256').update(keySource).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function validateIntake(body) {
  const required = ['name', 'age', 'phone', 'email', 'city', 'gender', 'skin', 'severity', 'consent1', 'consent2', 'consent3'];
  for (const field of required) {
    if (!sanitize(body[field])) return `Falta el campo: ${field}`;
  }
  if (!/^\d{10}$/.test(sanitize(body.phone))) return 'Teléfono inválido';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitize(body.email))) return 'Correo inválido';
  if (Number(body.age) < 13 || Number(body.age) > 90) return 'Edad inválida';
  if (body.consent1 !== 'true' || body.consent2 !== 'true' || body.consent3 !== 'true') return 'Falta aceptar consentimientos';
  return null;
}

function getTransporter() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

app.get('/health', (_, res) => res.json({ ok: true, service: 'dermatika-backend' }));

app.post('/api/intake', upload.fields([
  { name: 'photoFront', maxCount: 1 },
  { name: 'photoLeft', maxCount: 1 },
  { name: 'photoRight', maxCount: 1 }
]), async (req, res) => {
  try {
    const error = validateIntake(req.body);
    if (error) return res.status(400).json({ ok: false, error });

    const b = req.body;
    const files = Object.values(req.files || {}).flat();
    const photoNames = files.map(f => f.filename).join(' | ');
    const now = new Date().toISOString();

    appendCsv(PATIENTS_CSV, [
      now,
      b.session_id,
      encrypt(b.name),
      encrypt(b.phone),
      encrypt(b.email),
      b.age,
      b.gender,
      b.plan_name,
      '',
      encrypt(b.city),
      b.skin,
      b.severity,
      b.meds,
      encrypt(b.allergies),
      b.pregnancy,
      encrypt(`${b.history || ''} | ${b.medical || ''}`),
      photoNames,
      b.payment_status,
      b.utm_source,
      b.utm_medium,
      b.utm_campaign,
      b.time_on_page_seconds,
      'sí',
      b.payment_reference
    ]);

    const transporter = getTransporter();
    if (transporter) {
      const html = `
        <h2>Nuevo paciente DERMATIKA</h2>
        <p><b>Fecha:</b> ${sanitize(now)}</p>
        <p><b>Nombre:</b> ${sanitize(b.name)}</p>
        <p><b>Teléfono:</b> ${sanitize(b.phone)}</p>
        <p><b>Correo:</b> ${sanitize(b.email)}</p>
        <p><b>Edad:</b> ${sanitize(b.age)}</p>
        <p><b>Sexo:</b> ${sanitize(b.gender)}</p>
        <p><b>Ciudad:</b> ${sanitize(b.city)}</p>
        <p><b>Plan:</b> ${sanitize(b.plan_name)} (${sanitize(b.plan_key)})</p>
        <p><b>Pago:</b> ${sanitize(b.payment_status)} | ${sanitize(b.payment_reference)}</p>
        <hr />
        <p><b>Tipo de piel:</b> ${sanitize(b.skin)}</p>
        <p><b>Grado de acné:</b> ${sanitize(b.severity)}</p>
        <p><b>Tiempo con acné:</b> ${sanitize(b.time)}</p>
        <p><b>Tratamiento previo:</b> ${sanitize(b.previous)}</p>
        <p><b>Historial:</b> ${sanitize(b.history)}</p>
        <p><b>Embarazo/lactancia:</b> ${sanitize(b.pregnancy)}</p>
        <p><b>Medicamentos actuales:</b> ${sanitize(b.meds)}</p>
        <p><b>Condiciones:</b> ${sanitize(b.conditions)}</p>
        <p><b>Alergias:</b> ${sanitize(b.allergies)}</p>
        <p><b>Detalles médicos:</b> ${sanitize(b.medical)}</p>
      `;
      await transporter.sendMail({
        from: `DERMATIKA <${process.env.SMTP_USER}>`,
        to: process.env.ADMIN_EMAIL || process.env.SMTP_USER,
        subject: `Nuevo cuestionario DERMATIKA - ${sanitize(b.name)} - ${sanitize(b.plan_name)}`,
        html,
        attachments: files.map(f => ({ filename: f.originalname, path: f.path }))
      });
    }

    return res.json({ ok: true, message: 'Intake recibido' });
  } catch (err) {
    console.error('INTAKE_ERROR', err.message);
    return res.status(500).json({ ok: false, error: 'No se pudo procesar la información' });
  }
});

app.post('/api/track-event', (req, res) => {
  try {
    const { eventName, payload = {} } = req.body || {};
    appendCsv(EVENTS_CSV, [
      new Date().toISOString(),
      payload.session_id,
      eventName || payload.event,
      payload.page_location || payload.page_path,
      payload.plan_name || payload.plan_key,
      payload.question,
      payload.answer || '',
      payload.time_on_page_seconds,
      payload.utm_source,
      payload.utm_medium,
      payload.utm_campaign
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('TRACK_ERROR', err.message);
    res.status(500).json({ ok: false });
  }
});

app.post('/api/create-payment', (req, res) => {
  // Pendiente: conectar SDK/API real de Mercado Pago.
  // Por ahora responde sin checkoutUrl para permitir probar el flujo visual.
  res.json({
    ok: true,
    paymentId: `test-${Date.now()}`,
    status: 'pending_backend_payment_integration'
  });
});

app.post('/api/mercadopago/webhook', (req, res) => {
  console.log('MP_WEBHOOK_RECEIVED', req.body);
  res.sendStatus(200);
});

app.use((req, res) => res.status(404).json({ ok: false, error: 'Ruta no encontrada' }));

app.listen(PORT, () => {
  console.log(`DERMATIKA backend activo en puerto ${PORT}`);
});
