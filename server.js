'use strict';

const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const dotenv   = require('dotenv');
const Stripe   = require('stripe');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');
const multer   = require('multer');
const PDFDocument = require('pdfkit');

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
    'https://dermatika.netlify.app',
    process.env.NETLIFY_ORIGIN        || '',
    process.env.NETLIFY_PREVIEW_ORIGIN || '',
    process.env.FRONTEND_ORIGIN       || ''
  ].filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  // Permitir siempre dermatika.mx aunque no esté en las vars de entorno
  if (ALLOWED_ORIGINS.has(origin) || origin.endsWith('.dermatika.mx') || origin.endsWith('.netlify.app')) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

// ✅ Resend API — usa RESEND_API_KEY y ADMIN_EMAIL ya configurados en Render
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL || '';
const MAIL_FROM = 'DERMATIKA <no-reply@dermatika.mx>';

// ══════════════════════════════════════════════════════════════════
// AIRTABLE — Dos tablas: CRM ADMIN (ventas) + CRM MEDICO (doctor)
// Variables requeridas en Render:
//   AIRTABLE_API_KEY  — Personal Access Token de Airtable
//   AIRTABLE_BASE_ID  — ID de la base (appXXXXXXXXXX)
//   AIRTABLE_TABLE_ADMIN  — nombre exacto tabla admin (default: 'CRM ADMIN')
//   AIRTABLE_TABLE_MEDICO — nombre exacto tabla médico (default: 'CRM MEDICO')
// ══════════════════════════════════════════════════════════════════
const AIRTABLE_API_KEY      = process.env.AIRTABLE_API_KEY      || '';
const AIRTABLE_BASE_ID      = process.env.AIRTABLE_BASE_ID      || '';
const AIRTABLE_TABLE_ADMIN  = process.env.AIRTABLE_TABLE_ADMIN  || process.env.AIRTABLE_TABLE || 'CRM ADMIN';
const AIRTABLE_TABLE_MEDICO = process.env.AIRTABLE_TABLE_MEDICO || 'CRM MEDICO';

// Helper interno para llamadas a la API de Airtable
async function _airtableRequest(method, tableName, recordId, body) {
  const base = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(tableName)}`;
  const url  = recordId ? `${base}/${recordId}` : base;
  const res  = await fetch(url, {
    method,
    headers: {
      'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

// Buscar recordId en una tabla por valor de campo Folio
async function _findAirtableRecord(tableName, folio) {
  try {
    const filterFormula = encodeURIComponent(`{Folio}="${folio}"`);
    const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(tableName)}?filterByFormula=${filterFormula}&maxRecords=1`;
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${AIRTABLE_API_KEY}` }
    });
    const data = await res.json();
    if (res.ok && data.records && data.records.length > 0) {
      return data.records[0].id;
    }
    return null;
  } catch(e) {
    console.error('[AIRTABLE] Error buscando record:', e.message);
    return null;
  }
}

// Convertir fotos base64 a formato attachment de Airtable
// Airtable necesita una URL pública — usamos un proxy base64 via upload a imgbb o simplemente
// incluimos las fotos como URL de data (Airtable NO acepta data URLs, necesita URLs públicas)
// Por ahora guardamos el count y nombres — cuando haya CDN se actualizan las URLs
function _buildPhotoAttachments(files) {
  if (!Array.isArray(files) || files.length === 0) return [];
  // Airtable Attachments requieren { url: 'https://...' }
  // Si las fotos están en base64, necesitamos subirlas primero a un CDN
  // Por ahora retornamos array vacío — se completa cuando se implemente CDN
  // Las fotos sí van adjuntas en el correo PDF
  return [];
}

// ── GUARDAR EN CRM ADMIN (ventas/admin) ──────────────────────────
async function saveToAirtableAdmin(row, paymentIntentId) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) {
    console.warn('[AIRTABLE] Variables no configuradas — omitiendo');
    return false;
  }

  const pa = row.answers  || {};
  const sv = (v, fb = '') => {
    if (v === null || v === undefined) return fb;
    const str = String(v).trim();
    return (str === '' || str === 'undefined' || str === 'null') ? fb : str;
  };

  // Campos exactos de la tabla CRM ADMIN
  const fields = {
    'Folio':    sv(row.folio),
    'Fecha':    new Date().toISOString().split('T')[0],
    'Nombre':   (`${sv(row.nombre)} ${sv(row.apellido)}`).trim() || sv(pa.nombre),
    'Telefono': sv(row.whatsapp || pa.whatsapp || pa.phone),
    'Email':    sv(row.correo   || pa.correo   || pa.email),
    'Edad':     sv(pa.ageRange  || pa.edad     || pa.age),
    'Sexo':     sv(row.sexo     || pa.sexo     || pa.sex),
  };

  // Eliminar campos vacíos
  Object.keys(fields).forEach(k => { if (!fields[k]) delete fields[k]; });

  console.log('[AIRTABLE] Guardando en CRM ADMIN — folio:', sv(row.folio),
    '| campos:', Object.keys(fields).join(', '));

  try {
    // Verificar si ya existe el registro
    const existingId = await _findAirtableRecord(AIRTABLE_TABLE_ADMIN, sv(row.folio));
    let result;
    if (existingId) {
      result = await _airtableRequest('PATCH', AIRTABLE_TABLE_ADMIN, existingId, { fields });
      console.log('[AIRTABLE] CRM ADMIN actualizado — record id:', existingId);
    } else {
      result = await _airtableRequest('POST', AIRTABLE_TABLE_ADMIN, null, { fields });
      if (result.ok) console.log('[AIRTABLE] Registro creado correctamente — record id:', result.data.id, '| folio:', sv(row.folio));
    }
    if (!result.ok) {
      const errMsg = result.data?.error?.message || result.data?.error?.type || JSON.stringify(result.data?.error || result.data);
      console.error('[AIRTABLE ERROR]', result.status, errMsg);
      console.error('[AIRTABLE ERROR] Campos enviados:', JSON.stringify(fields));
      return false;
    }
    return result.data.id || existingId;
  } catch (err) {
    console.error('[AIRTABLE ERROR] Excepcion en CRM ADMIN:', err.message || String(err));
    return false;
  }
}

// ── GUARDAR EN CRM MEDICO (doctor) ───────────────────────────────
async function saveToAirtableMedico(row) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) return false;

  const pa = row.answers  || {};
  const pt = row.shipping || {};
  const sv = (v, fb = '') => {
    if (v === null || v === undefined) return fb;
    const str = String(v).trim();
    return (str === '' || str === 'undefined' || str === 'null') ? fb : str;
  };
  const av = v => Array.isArray(v) ? v.filter(Boolean).join(', ') : sv(v);

  // Campos exactos de la tabla CRM MEDICO — SIN Email ni Telefono
  const fields = {
    // ── Identificación ───────────────────────────────────────────
    'Folio':             sv(row.folio),
    'Fecha':             new Date().toISOString().split('T')[0],
    'Nombre':            (`${sv(row.nombre)} ${sv(row.apellido)}`).trim() || sv(pa.nombre),
    'Edad':              sv(pa.ageRange   || pa.edad || pa.age),
    'Sexo':              sv(row.sexo      || pa.sexo || pa.sex),
    'Tipo piel':         sv(pa.skinType   || pa.tipoPiel),
    'Ciudad / Estado':   sv(pa.cityState  || pt.shipCity || pt.shipState),

    // ── Plan y medicamento ────────────────────────────────────────
    'Plan':              sv(row.plan),
    'Medicamento':       sv(row.medication),

    // ── Información del acné ──────────────────────────────────────
    'Acne severidad':            sv(pa.acneSeverity    || pa.acne),
    'Tiempo con acne':           sv(pa.duration        || pa.tiempo),
    'Zonas afectadas':           av(pa.acneAreas       || pa.zonas),
    'Tipo de lesiones':          av(pa.acneType),
    'Dolor':                     sv(pa.acnePain),
    'Impacto emocional':         sv(pa.acnePsychological),
    'Ha empeorado':              sv(pa.acneWorsening),
    'Factores desencadenantes':  av(pa.acneTriggers),

    // ── Historial de tratamientos ─────────────────────────────────
    'Tratamientos previos':      av(pa.previousTreatments),
    'Respuesta a tratamientos':  sv(pa.treatmentResponse),
    'Antibioticos 3 meses':      sv(pa.antibioticDuration),
    'Isotretinaina previa':      sv(pa.isotretinoinBefore),
    'Efectos adversos previos':  av(pa.isotretinoinSideEffects),

    // ── Salud general ─────────────────────────────────────────────
    'Salud general':             sv(pa.generalHealth),
    'Condiciones cronicas':      av(pa.chronicConditions),
    'Medicamentos actuales':     sv(pa.currentMedications),
    'Detalle medicamentos':      sv(pa.currentMedicationsDetail),
    'Vitamina A Retinol':        sv(pa.vitaminA),
    'Tetraciclinas activas':     sv(pa.tetracyclines),

    // ── Contraindicaciones ────────────────────────────────────────
    'Enfermedad hepatica':       sv(pa.liverCondition),
    'Colesterol Trigliceridos':  sv(pa.lipidProfile),
    'Enfermedad renal':          sv(pa.kidneyCondition),
    'Alergias':                  sv(pa.allergies),
    'Detalle alergias':          sv(pa.allergiesDetail),
    'Cirugia reciente':          sv(pa.recentSurgery),

    // ── Salud mental ──────────────────────────────────────────────
    'Salud mental':              av(pa.mentalHealth),
    'Ideas suicidas':            sv(pa.suicidalIdeation),
    'Medicamentos psiquiatricos':sv(pa.mentalHealthMeds),

    // ── Embarazo y anticoncepción ─────────────────────────────────
    'Embarazo lactancia':        sv(pa.pregnancyStatus || pa.breastfeeding),
    'Anticoncepcion':            sv(pa.contraception),

    // ── Campos médicos (doctor los llena desde Airtable) ─────────
    'Estado medico':             'Pendiente revision',
    'Receta medica':             '',
    'Dosis indicada':            '',
    'Indicaciones skincare':     '',
    'Comentarios del medico':    '',
    'Fecha revision medica':     '',
  };

  // Eliminar campos vacíos — Airtable rechaza strings vacíos
  // Excepto los campos médicos que deben existir aunque vacíos
  const camposMedicos = [
    'Estado medico','Receta medica','Dosis indicada',
    'Indicaciones skincare','Comentarios del medico','Fecha revision medica'
  ];
  Object.keys(fields).forEach(k => {
    if (!fields[k] && !camposMedicos.includes(k)) delete fields[k];
    if (camposMedicos.includes(k) && fields[k] === '') delete fields[k];
  });

  console.log('[AIRTABLE] Guardando en CRM MEDICO — folio:', sv(row.folio),
    '| campos clinicos:', Object.keys(fields).length);

  try {
    const existingId = await _findAirtableRecord(AIRTABLE_TABLE_MEDICO, sv(row.folio));
    let result;
    if (existingId) {
      result = await _airtableRequest('PATCH', AIRTABLE_TABLE_MEDICO, existingId, { fields });
      console.log('[AIRTABLE] CRM MEDICO actualizado — record id:', existingId);
    } else {
      result = await _airtableRequest('POST', AIRTABLE_TABLE_MEDICO, null, { fields });
      if (result.ok) console.log('[AIRTABLE] Registro creado correctamente en CRM MEDICO — record id:', result.data.id);
    }
    if (!result.ok) {
      const errMsg = result.data?.error?.message || result.data?.error?.type || JSON.stringify(result.data?.error || result.data);
      console.error('[AIRTABLE ERROR]', result.status, errMsg);
      console.error('[AIRTABLE ERROR] Campos enviados:', Object.keys(fields).join(', '));
      return false;
    }
    return result.data.id || existingId;
  } catch (err) {
    console.error('[AIRTABLE ERROR] Excepcion en CRM MEDICO:', err.message || String(err));
    return false;
  }
}

// Alias para compatibilidad con el código existente
const saveToAirtable = (row, piId) => saveToAirtableAdmin(row, piId);

// ── Log de arranque: verificar variables críticas ──
console.log('[CONFIG] STRIPE_SECRET_KEY:', stripeSecret ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] STRIPE_PUBLIC_KEY:', stripePublic ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] RESEND_API_KEY:', RESEND_API_KEY ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] ADMIN_EMAIL:', ADMIN_EMAIL || '❌ FALTA');
console.log('[CONFIG] FRONTEND_ORIGIN:', process.env.FRONTEND_ORIGIN || '❌ FALTA');
console.log('[CONFIG] AIRTABLE_API_KEY:', AIRTABLE_API_KEY ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] AIRTABLE_BASE_ID:', AIRTABLE_BASE_ID || '❌ FALTA');
console.log('[CONFIG] AIRTABLE_TABLE_ADMIN:', AIRTABLE_TABLE_ADMIN);
console.log('[CONFIG] AIRTABLE_TABLE_MEDICO:', AIRTABLE_TABLE_MEDICO);

async function sendInternalMail(subject, text, attachments = [], htmlContent = null) {
  if (!RESEND_API_KEY || !ADMIN_EMAIL) {
    console.error('[MAIL] No enviado — falta RESEND_API_KEY o ADMIN_EMAIL');
    return false;
  }
  try {
    // Construir payload — Resend soporta attachments como base64
    const payload = {
      from: MAIL_FROM,
      to: [ADMIN_EMAIL],
      subject,
      text,
      ...(htmlContent ? { html: htmlContent } : {})
    };

    // Adjuntar archivos si los hay
    if (attachments && attachments.length > 0) {
      payload.attachments = attachments.map(att => ({
        filename: att.filename || 'adjunto',
        content: Buffer.isBuffer(att.content)
          ? att.content.toString('base64')
          : (typeof att.content === 'string' ? att.content : Buffer.from(att.content).toString('base64')),
        ...(att.contentType ? { type: att.contentType } : {})
      }));
    }

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      console.log('[MAIL] ✅ Enviado via Resend:', subject, '| id:', data.id, '| adjuntos:', payload.attachments?.length || 0);
      return true;
    } else {
      console.error('[MAIL] ❌ Resend error:', JSON.stringify(data));
      return false;
    }
  } catch (err) {
    console.error('[MAIL] ❌ Error fetch Resend:', err.message || err);
    return false;
  }
}

// ══════════════════════════════════════════════════════════════════
// GENERADOR DE PDF — EVALUACIÓN COMPLETA DEL PACIENTE
// ══════════════════════════════════════════════════════════════════

/**
 * Genera un PDF completo con la evaluación del paciente.
 * @returns {Promise<Buffer>} Buffer del PDF generado
 */
function generateEvaluationPDF(data) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        margin: 56,
        size: 'A4',
        bufferPages: true,
        info: { Title: 'Evaluacion DERMATIKA', Author: 'DERMATIKA' }
      });
      const chunks = [];
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // ── Medidas ───────────────────────────────────────────
      const ML = 56;           // margen izquierdo
      const MR = 56;           // margen derecho
      const PW = doc.page.width;
      const PH = doc.page.height;
      const CW = PW - ML - MR; // ancho del contenido
      const BOTTOM_MARGIN = 70;

      // ── Colores ───────────────────────────────────────────
      const C_INK   = '#0F1B2D';
      const C_TEAL  = '#4AAFC0';
      const C_MUTED = '#53657A';
      const C_LIGHT = '#F0F7FA';
      const C_LINE  = '#D0E4EA';

      // ── Helpers ───────────────────────────────────────────
      const sv = (v, fb) => {
        fb = fb !== undefined ? fb : 'N/A';
        if (v === null || v === undefined) return fb;
        const str = String(v).trim();
        if (str === '' || str === 'undefined' || str === 'null') return fb;
        return str;
      };
      const av = v => Array.isArray(v) ? v.join(', ') : sv(v);
      const money = v => v ? '$' + Number(v).toLocaleString('es-MX') + ' MXN' : 'N/A';

      // Parsear answers
      let ans = {};
      try {
        if (typeof data.answers === 'string') ans = JSON.parse(data.answers);
        else if (data.answers && typeof data.answers === 'object') ans = data.answers;
      } catch(e) {}

      const ship = data.shipping || {};

      // Buscar valor con aliases
      const ALIASES = {
        acneSeverity:     ['acneSeverity','acne'],
        duration:         ['duration','tiempo'],
        acneAreas:        ['acneAreas','zonas'],
        sex:              ['sex','sexo','gender'],
        email:            ['email','correo','leadEmail'],
        phone:            ['phone','whatsapp','leadWhatsapp'],
        shipAddress1:     ['shipAddress1','shippingStreet','address'],
        shipNeighborhood: ['shipNeighborhood','shippingNeighborhood','colonia'],
        shipZip:          ['shipZip','shippingPostalCode','zip'],
        shipMunicipality: ['shipMunicipality','shippingMunicipality','municipality'],
        shipState:        ['shipState','shippingState','state'],
      };
      const a = key => {
        const keys = [key, ...(ALIASES[key] || [])];
        for (const k of keys) {
          const v = ans?.[k] ?? data?.[k];
          if (v !== null && v !== undefined && sv(v) !== 'N/A') return v;
        }
        for (const k of keys) {
          if (ship[k] && sv(ship[k]) !== 'N/A') return ship[k];
        }
        return undefined;
      };

      const folio = sv(data.folio, 'S/N');
      const fecha = data.createdAt
        ? new Date(data.createdAt).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' })
        : new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' });

      // ── Cursor y control de pagina ────────────────────────
      let curY = ML;

      function newPage() {
        doc.addPage();
        curY = ML;
        drawPageFooter();
      }

      function checkY(needed) {
        if (curY + needed > PH - BOTTOM_MARGIN) newPage();
      }

      // ── Pie de pagina (se dibuja al final en todas las pags)
      function drawPageFooter() {
        // se agrega al terminar
      }

      // ── Encabezado ────────────────────────────────────────
      function drawHeader() {
        // Fondo oscuro
        doc.rect(0, 0, PW, 80).fill(C_INK);

        // Nombre
        doc.font('Helvetica-Bold').fontSize(20).fillColor(C_TEAL)
           .text('DERMATIKA', ML, 18);
        doc.font('Helvetica').fontSize(8).fillColor('#AABBCC')
           .text('TRATAMIENTOS DERMATOLOGICOS', ML, 44);
        doc.font('Helvetica').fontSize(7.5).fillColor('#889AAA')
           .text('Evaluacion Medica - Documento Confidencial', ML, 57);

        // Folio y fecha (derecha)
        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(C_TEAL)
           .text('Folio: ' + folio, PW - MR - 180, 22, { width: 180, align: 'right' });
        doc.font('Helvetica').fontSize(7.5).fillColor('#889AAA')
           .text(fecha, PW - MR - 180, 36, { width: 180, align: 'right' });

        curY = 96;
      }

      // ── Badge de estado ───────────────────────────────────
      function drawEstado() {
        const raw = sv(data.eligibility_status || data.status, 'candidato').toLowerCase();
        let label = 'CANDIDATO APROBADO';
        let color = '#16a34a';
        if (raw.includes('revision')) { label = 'REQUIERE REVISION MEDICA'; color = '#d97706'; }
        else if (raw.includes('no_ap') || raw.includes('no candidato')) { label = 'NO CANDIDATO'; color = '#dc2626'; }
        else if (raw.includes('pagado') || raw.includes('pago')) { label = 'PAGO CONFIRMADO'; color = '#16a34a'; }

        checkY(44);
        doc.rect(ML, curY, CW, 36).fill('#F8FAFB').stroke(C_LINE);
        doc.rect(ML, curY, 5, 36).fill(color);
        doc.font('Helvetica-Bold').fontSize(11).fillColor(color)
           .text(label, ML + 14, curY + 7);
        doc.font('Helvetica').fontSize(8).fillColor(C_MUTED)
           .text('Estado de elegibilidad para isotretinaina', ML + 14, curY + 22);
        curY += 48;
      }

      // ── Titulo de seccion ─────────────────────────────────
      function seccion(titulo) {
        checkY(40);
        curY += 10; // espacio antes del titulo
        doc.rect(ML, curY, CW, 24).fill(C_INK);
        doc.font('Helvetica-Bold').fontSize(9).fillColor('#FFFFFF')
           .text(titulo.toUpperCase(), ML + 10, curY + 7);
        curY += 30;
      }

      // ── Campo: Etiqueta: Valor ────────────────────────────
      function campo(label, valor, esArray) {
        const displayVal = esArray ? av(valor) : sv(valor);
        if (!displayVal || displayVal === 'N/A') return; // omitir vacios

        // Calcular altura necesaria
        const labelText = label + ':';
        const valText   = displayVal;

        checkY(30);

        // Etiqueta en color muted
        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(C_MUTED)
           .text(labelText, ML, curY, { width: CW, continued: false });

        curY += 13;
        checkY(20);

        // Valor en color oscuro, con wrap automatico
        const before = doc.y;
        doc.font('Helvetica').fontSize(9).fillColor(C_INK)
           .text(valText, ML + 10, curY, { width: CW - 10, lineBreap: true });

        // Avanzar cursor segun el texto renderizado
        curY = doc.y + 6;

        // Linea separadora ligera
        checkY(6);
        doc.moveTo(ML, curY).lineTo(ML + CW, curY)
           .strokeColor(C_LINE).lineWidth(0.4).stroke();
        curY += 8;
      }

      // ════════════════════════════════════════════════════════
      // GENERAR PDF
      // ════════════════════════════════════════════════════════
      drawHeader();
      drawEstado();

      // ── 1. Datos del paciente ─────────────────────────────
      seccion('1. Datos del paciente');
      campo('Nombre completo',
        (sv(data.nombre || a('fullName'), '') + ' ' + sv(data.apellido || '', '')).trim() || 'N/A');
      campo('Correo electronico', sv(data.correo || a('email')));
      campo('WhatsApp',           sv(data.whatsapp || a('phone')));
      campo('Sexo biologico',     sv(data.sexo || a('sex')));
      campo('Fecha de nacimiento',sv(data.fechaNacimiento || a('birthdate')));
      campo('Edad',               sv(a('ageRange')));
      campo('Tipo de piel',       sv(a('skinType')));

      // ── 2. Direccion de envio ─────────────────────────────
      const hayDireccion = sv(ship.shipAddress1 || a('shipAddress1'), '') !== '';
      if (hayDireccion) {
        seccion('2. Direccion de Envio');
        campo('Calle y numero',   sv(ship.shipAddress1   || a('shipAddress1')));
        campo('Numero exterior',  sv(ship.shipExterior   || a('shipExterior')));
        campo('Codigo postal',    sv(ship.shipZip        || a('shipZip')));
        campo('Colonia',          sv(ship.shipNeighborhood || a('shipNeighborhood')));
        campo('Municipio / Alcaldia', sv(ship.shipMunicipality || a('shipMunicipality')));
        campo('Ciudad',           sv(ship.shipCity        || a('shipCity')));
        campo('Estado',           sv(ship.shipState       || a('shipState')));
        campo('Referencias',      sv(ship.references     || a('references')));
      }

      // ── 3. Informacion del acne ───────────────────────────
      seccion('3. Informacion del Acne');
      campo('Gravedad del acne',   sv(a('acneSeverity')));
      campo('Tiempo con acne',     sv(a('duration')));
      campo('Zonas afectadas',     av(a('acneAreas')));
      campo('Tipo de lesiones',    av(a('acneType')));
      campo('Es doloroso',         sv(a('acnePain')));
      campo('Impacto emocional',   sv(a('acnePsychological')));
      campo('Ha empeorado',        sv(a('acneWorsening')));
      campo('Factores desencadenantes', av(a('acneTriggers')));

      // ── 4. Historial de tratamientos ──────────────────────
      seccion('4. Historial de Tratamientos');
      campo('Tratamientos previos',    av(a('previousTreatments')));
      campo('Respuesta a tratamientos',sv(a('treatmentResponse')));
      campo('Antibioticos mas de 3 meses', sv(a('antibioticDuration')));
      campo('Isotretinaina previa',    sv(a('isotretinoinBefore')));
      campo('Efectos adversos previos',av(a('isotretinoinSideEffects')));

      // ── 5. Salud general ──────────────────────────────────
      seccion('5. Salud General');
      campo('Estado de salud general', sv(a('generalHealth')));
      campo('Condiciones cronicas',    av(a('chronicConditions')));
      campo('Medicamentos actuales',   sv(a('currentMedications')));
      campo('Detalle medicamentos',    sv(a('currentMedicationsDetail')));
      campo('Vitamina A o Retinol',    sv(a('vitaminA')));
      campo('Tetraciclinas activas',   sv(a('tetracyclines')));

      // ── 6. Contraindicaciones ─────────────────────────────
      seccion('6. Contraindicaciones');
      campo('Enfermedad hepatica',     sv(a('liverCondition')));
      campo('Colesterol y Trigliceridos', sv(a('lipidProfile')));
      campo('Enfermedad renal',        sv(a('kidneyCondition')));
      campo('Alergias',                sv(a('allergies')));
      campo('Detalle alergias',        sv(a('allergiesDetail')));
      campo('Cirugia reciente',        sv(a('recentSurgery')));
      campo('Donador de sangre',       sv(a('bloodDonation')));

      // ── 7. Salud mental ───────────────────────────────────
      seccion('7. Salud Mental');
      campo('Condiciones diagnosticadas', av(a('mentalHealth')));
      campo('Ideas suicidas (12 meses)',  sv(a('suicidalIdeation')));
      campo('Medicamentos psiquiatricos', sv(a('mentalHealthMeds')));
      campo('Detalle medicamentos',       sv(a('mentalHealthMedsDetail')));

      // ── 8. Embarazo y anticoncepcion (solo si aplica) ─────
      const isFemale = sv(data.sexo || a('sex'), '').toLowerCase().includes('femen')
                    || sv(a('pregnancyStatus'), '') !== 'N/A';
      if (isFemale) {
        seccion('8. Embarazo y Anticoncepcion');
        campo('Estado de embarazo',    sv(a('pregnancyStatus')));
        campo('Lactancia',             sv(a('breastfeeding')));
        campo('Metodo anticonceptivo', sv(a('contraception')));
        campo('Prueba de embarazo',    sv(a('pregnancyTestDone')));
        campo('Consentimiento aviso',  sv(a('pregnancyConsent')));
      }

      // ── 9. Habitos ────────────────────────────────────────
      seccion('9. Habitos');
      campo('Consumo de alcohol',  sv(a('alcoholConsumption')));
      campo('Exposicion solar',    sv(a('sunExposure')));
      campo('Lentes de contacto',  sv(a('contactLenses')));

      // ── 10. Plan y pago ───────────────────────────────────
      seccion('10. Plan y Estado de Pago');
      campo('Plan seleccionado',  sv(data.plan));
      campo('Medicamento',        sv(data.medication));
      campo('Precio',             money(data.price));
      campo('Estado del pago',    sv(data.payment_status));
      campo('Referencia Stripe',  sv(data.payment_reference));
      campo('Folio DERMATIKA',    folio);
      campo('Fecha de evaluacion',fecha);

      // ── Aviso legal ───────────────────────────────────────
      checkY(70);
      curY += 12;
      doc.rect(ML, curY, CW, 52).fill('#FFFBF0');
      doc.rect(ML, curY, 4, 52).fill('#D97706');
      doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#92650A')
         .text('AVISO IMPORTANTE', ML + 12, curY + 8);
      doc.font('Helvetica').fontSize(8).fillColor('#7A5C00')
         .text(
           'Informacion sujeta a revision y aprobacion medica. Este documento es estrictamente ' +
           'confidencial y generado automaticamente. El tratamiento sera confirmado unicamente ' +
           'tras la revision por un profesional medico autorizado de DERMATIKA.',
           ML + 12, curY + 22, { width: CW - 20 }
         );
      curY += 64;

      // ── Pie de pagina en todas las paginas ────────────────
      const total = doc.bufferedPageRange().count;
      for (let i = 0; i < total; i++) {
        doc.switchToPage(i);
        doc.rect(0, PH - 26, PW, 26).fill('#0F1B2D');
        doc.font('Helvetica').fontSize(7).fillColor('#667788')
           .text(
             'DERMATIKA  |  dermatika.mx  |  Folio: ' + folio +
             '  |  Pagina ' + (i + 1) + ' de ' + total,
             ML, PH - 17, { width: CW, align: 'center' }
           );
      }

      doc.end();
    } catch(err) {
      reject(err);
    }
  });
}

// ══════════════════════════════════════════════════════════════════
// GENERADOR DE EMAIL HTML PROFESIONAL
// ══════════════════════════════════════════════════════════════════
function buildEmailHTML(data) {
  const s = (v, fb = 'N/A') =>
    (v !== null && v !== undefined && String(v).trim() !== '' && String(v).trim() !== 'undefined')
      ? String(v).trim() : fb;
  const money = v => v ? `$${Number(v).toLocaleString('es-MX')} MXN` : 'N/A';

  let answers = {};
  try {
    if (typeof data.answers === 'string') answers = JSON.parse(data.answers);
    else if (data.answers && typeof data.answers === 'object') answers = data.answers;
  } catch(e) {}

  // Buscar campo con aliases — soporta tanto keys del cuestionario como aliases del formData
  const ALIASES_E = {
    acneSeverity: ['acneSeverity','acne'],
    duration: ['duration','tiempo'],
    acneAreas: ['acneAreas','zonas'],
    sex: ['sex','sexo','gender'],
    email: ['email','correo','leadEmail'],
    phone: ['phone','whatsapp','leadWhatsapp'],
    shipAddress1: ['shipAddress1','shippingStreet'],
    shipNeighborhood: ['shipNeighborhood','shippingNeighborhood'],
    shipZip: ['shipZip','shippingPostalCode'],
    shipMunicipality: ['shipMunicipality','shippingMunicipality'],
    shipState: ['shipState','shippingState'],
  };
  const a = (key) => {
    const keys = [key, ...(ALIASES_E[key] || [])];
    const ship = data?.shipping || answers?.shipping || {};
    for (const k of keys) {
      const v = answers?.[k] ?? data?.[k] ?? ship?.[k];
      if (v !== null && v !== undefined && String(v||'').trim() !== '' && String(v||'').trim() !== 'undefined') return v;
    }
    return undefined;
  };
  const arr = (key) => {
    const v = a(key);
    return Array.isArray(v) ? v.join(', ') : s(v);
  };

  const shipping = data.shipping || {};
  const folio    = s(data.folio);
  const fecha    = data.createdAt
    ? new Date(data.createdAt).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' })
    : new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' });

  const estadoRaw = s(data.eligibility_status || data.status, 'candidato').toLowerCase();
  let estadoLabel = 'Candidato'; let estadoColor = '#16a34a'; let estadoBg = '#f0fdf4';
  if (estadoRaw.includes('revision') || estadoRaw.includes('revisión')) {
    estadoLabel = 'Requiere revisión médica'; estadoColor = '#d97706'; estadoBg = '#fffbeb';
  } else if (estadoRaw.includes('no_apto') || estadoRaw.includes('no_aprobado')) {
    estadoLabel = 'No candidato'; estadoColor = '#dc2626'; estadoBg = '#fef2f2';
  }

  const row = (label, value) =>
    `<tr><td style="padding:7px 12px;color:#53657A;font-size:13px;width:200px;border-bottom:1px solid #E5EDF0">${label}</td>` +
    `<td style="padding:7px 12px;color:#0F1B2D;font-size:13px;font-weight:600;border-bottom:1px solid #E5EDF0">${s(value)}</td></tr>`;

  const section = (title) =>
    `<tr><td colspan="2" style="background:#4AAFC0;color:#fff;font-size:11px;font-weight:800;` +
    `letter-spacing:1.5px;text-transform:uppercase;padding:8px 12px">${title}</td></tr>`;

  const isFemale = (s(data.sexo || a('sex'), '')).toLowerCase().includes('femen') || a('pregnancyStatus');

  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nueva Evaluación DERMÁTIKA</title></head>
<body style="margin:0;padding:0;background:#F6FAFC;font-family:Inter,system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F6FAFC;padding:32px 16px">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">

  <!-- Header -->
  <tr><td style="background:#0F1B2D;border-radius:16px 16px 0 0;padding:28px 32px">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td>
          <div style="color:#fff;font-size:22px;font-weight:900;letter-spacing:-0.5px">DERMÁTIKA<span style="color:#4AAFC0">*</span></div>
          <div style="color:rgba(255,255,255,0.5);font-size:11px;margin-top:4px">TRATAMIENTOS DERMATOLÓGICOS</div>
        </td>
        <td align="right">
          <div style="color:#4AAFC0;font-size:11px;font-weight:800;letter-spacing:1px">NUEVA EVALUACIÓN</div>
          <div style="color:rgba(255,255,255,0.6);font-size:10px;margin-top:4px">${fecha}</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Estado badge -->
  <tr><td style="background:${estadoBg};border-left:4px solid ${estadoColor};padding:16px 32px">
    <span style="color:${estadoColor};font-size:13px;font-weight:800">${estadoLabel}</span>
    <span style="color:#53657A;font-size:12px;margin-left:12px">Folio: <strong style="color:#0F1B2D">${folio}</strong></span>
  </td></tr>

  <!-- Resumen rápido -->
  <tr><td style="background:#fff;padding:24px 32px;border-bottom:1px solid #E5EDF0">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="text-align:center;padding:0 8px">
          <div style="font-size:11px;color:#53657A;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Plan</div>
          <div style="font-size:16px;font-weight:800;color:#0F1B2D">${s(data.plan)}</div>
        </td>
        <td style="text-align:center;padding:0 8px;border-left:1px solid #E5EDF0;border-right:1px solid #E5EDF0">
          <div style="font-size:11px;color:#53657A;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Medicamento</div>
          <div style="font-size:16px;font-weight:800;color:#0F1B2D">${s(data.medication)}</div>
        </td>
        <td style="text-align:center;padding:0 8px">
          <div style="font-size:11px;color:#53657A;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Precio</div>
          <div style="font-size:16px;font-weight:800;color:#4AAFC0">${money(data.price)}</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Pago -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Estado de Pago')}
      ${row('Estado del pago', data.payment_status)}
      ${row('Referencia Stripe', data.payment_reference)}
    </table>
  </td></tr>

  <!-- Datos personales -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Datos del Paciente')}
      ${row('Nombre', `${s(data.nombre||data.fullName)} ${s(data.apellido,'')}`)}
      ${row('Correo', s(data.correo||data.email))}
      ${row('WhatsApp', s(data.whatsapp))}
      ${row('Fecha de nacimiento', s(data.fechaNacimiento||a('birthdate')))}
      ${row('Sexo biológico', s(data.sexo||a('sex')))}
      ${row('Edad (rango)', s(a('ageRange')))}
      ${row('Tipo de piel', s(a('skinType')))}
      ${row('Ciudad / Estado', s(a('cityState')))}
    </table>
  </td></tr>

  ${shipping.address || shipping.zip ? `
  <!-- Dirección -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Dirección de Envío')}
      ${row('Calle y número', shipping.address)}
      ${row('Colonia', shipping.colonia)}
      ${row('Código postal', shipping.zip)}
      ${row('Municipio / Alcaldía', shipping.municipality)}
      ${row('Ciudad', shipping.city)}
      ${row('Estado', shipping.state)}
      ${row('Referencias', shipping.references)}
    </table>
  </td></tr>` : ''}

  <!-- Acné -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Información del Acné')}
      ${row('Gravedad', a('acneSeverity'))}
      ${row('Tiempo con acné', a('duration'))}
      ${row('Zonas afectadas', arr('acneAreas'))}
      ${row('Tipo de lesiones', arr('acneType'))}
      ${row('¿Es doloroso?', a('acnePain'))}
      ${row('Impacto emocional', a('acnePsychological'))}
      ${row('¿Ha empeorado?', a('acneWorsening'))}
      ${row('Factores desencadenantes', arr('acneTriggers'))}
    </table>
  </td></tr>

  <!-- Tratamientos previos -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Historial de Tratamientos')}
      ${row('Tratamientos previos', arr('previousTreatments'))}
      ${row('Respuesta a tratamientos', a('treatmentResponse'))}
      ${row('Antibióticos > 3 meses', a('antibioticDuration'))}
      ${row('Isotretinoína previa', a('isotretinoinBefore'))}
      ${row('Efectos adversos previos', arr('isotretinoinSideEffects'))}
    </table>
  </td></tr>

  <!-- Salud general -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Salud General y Contraindicaciones')}
      ${row('Estado de salud general', a('generalHealth'))}
      ${row('Condiciones crónicas', arr('chronicConditions'))}
      ${row('Medicamentos actuales', a('currentMedications'))}
      ${row('Detalle medicamentos', a('currentMedicationsDetail'))}
      ${row('Vitamina A / Retinol', a('vitaminA'))}
      ${row('Tetraciclinas activas', a('tetracyclines'))}
      ${row('Enfermedad hepática', a('liverCondition'))}
      ${row('Colesterol / Triglicéridos', a('lipidProfile'))}
      ${row('Enfermedad renal', a('kidneyCondition'))}
      ${row('Alergias', a('allergies'))}
      ${row('Detalle alergias', a('allergiesDetail'))}
      ${row('Cirugía reciente', a('recentSurgery'))}
    </table>
  </td></tr>

  <!-- Salud mental -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Salud Mental')}
      ${row('Condiciones diagnosticadas', arr('mentalHealth'))}
      ${row('Ideas suicidas (12 meses)', a('suicidalIdeation'))}
      ${row('Medicamentos psiquiátricos', a('mentalHealthMeds'))}
    </table>
  </td></tr>

  ${isFemale ? `
  <!-- Embarazo -->
  <tr><td style="background:#fff;padding:8px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Embarazo y Anticoncepción')}
      ${row('Estado de embarazo', a('pregnancyStatus'))}
      ${row('Lactancia', a('breastfeeding'))}
      ${row('Método anticonceptivo', a('contraception'))}
      ${row('Prueba de embarazo', a('pregnancyTestDone'))}
    </table>
  </td></tr>` : ''}

  <!-- Hábitos -->
  <tr><td style="background:#fff;padding:8px 32px 16px">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      ${section('Hábitos')}
      ${row('Consumo de alcohol', a('alcoholConsumption'))}
      ${row('Exposición solar', a('sunExposure'))}
      ${row('Donador de sangre', a('bloodDonation'))}
      ${row('Lentes de contacto', a('contactLenses'))}
    </table>
  </td></tr>

  <!-- Aviso legal -->
  <tr><td style="background:#FFF8F0;border-left:3px solid #d97706;padding:14px 32px;margin:0 0 0">
    <p style="margin:0;font-size:11px;color:#92650a;font-weight:700">⚠ AVISO MÉDICO</p>
    <p style="margin:4px 0 0;font-size:11px;color:#7a5c00;line-height:1.6">
      Información sujeta a revisión y aprobación médica. Este documento es confidencial.
      El PDF adjunto contiene el expediente completo del paciente.
    </p>
  </td></tr>

  <!-- Footer -->
  <tr><td style="background:#0F1B2D;border-radius:0 0 16px 16px;padding:16px 32px;text-align:center">
    <p style="margin:0;color:rgba(255,255,255,0.4);font-size:10px">
      DERMÁTIKA · dermatika.mx · Folio ${folio}
    </p>
  </td></tr>

</table>
</td></tr></table>
</body></html>`;
}

// ══════════════════════════════════════════════════════════════════
// HELPER: Recuperar fotos guardadas en DB y convertir a attachments
// ══════════════════════════════════════════════════════════════════
function getPhotoAttachments(row) {
  if (!Array.isArray(row.files)) return [];
  return row.files
    .filter(f => f.data)  // solo las que tienen base64
    .map((f, idx) => ({
      filename: `${row.folio || 'foto'}-foto-${idx + 1}.${(f.type || 'image/jpeg').split('/')[1] || 'jpg'}`,
      content: f.data,    // ya es base64
      contentType: f.type || 'image/jpeg'
    }));
}

// ══════════════════════════════════════════════════════════════════
// HELPER: Construir y enviar el correo completo con PDF para un row
// ══════════════════════════════════════════════════════════════════
async function sendPaymentConfirmedEmail(row, paymentIntentId) {
  const nowIso = new Date().toISOString();
  const nombre = sanitizeText(row.nombre || row.fullName || 'Paciente', 80);
  const plan   = sanitizeText(row.plan || 'N/A', 40);
  const folio  = row.folio;

  console.log('[EMAIL] answers tipo:', typeof row.answers, '| keys:', row.answers ? Object.keys(row.answers).slice(0,8).join(',') : 'vacío');
  console.log('[EMAIL] row.sexo:', row.sexo, '| row.correo:', row.correo);
  const subject = `✅ PAGO CONFIRMADO — DERMÁTIKA #${folio} — ${nombre} — ${plan}`;

  // Generar PDF
  let pdfAttachment = null;
  try {
    const pdfBuf = await generateEvaluationPDF({ ...row, eligibility_status: STATES.PAGADO });
    pdfAttachment = {
      filename: `DERMATIKA-Evaluacion-${folio}.pdf`,
      content: pdfBuf.toString('base64'),
      contentType: 'application/pdf'
    };
    console.log('[MAIL] ✅ PDF generado:', pdfAttachment.filename, '| bytes:', pdfBuf.length);
  } catch (pdfErr) {
    console.error('[MAIL] ❌ Error PDF:', pdfErr.message);
  }

  // Fotos guardadas
  const photoAttachments = getPhotoAttachments(row);
  console.log('[MAIL] Fotos adjuntas:', photoAttachments.length);

  const allAttachments = [
    ...(pdfAttachment ? [pdfAttachment] : []),
    ...photoAttachments
  ];

  // Email HTML
  const emailHTML = buildEmailHTML({ ...row, eligibility_status: STATES.PAGADO, payment_reference: paymentIntentId });

  const emailText = [
    '✅ PAGO CONFIRMADO — DERMÁTIKA',
    `Folio: ${folio}`,
    `Paciente: ${nombre}`,
    `Correo: ${row.correo || row.email || 'N/A'}`,
    `WhatsApp: ${row.whatsapp || 'N/A'}`,
    `Plan: ${plan}`,
    `Medicamento: ${sanitizeText(row.medication || 'N/A', 40)}`,
    `Precio: $${row.price || 0} MXN`,
    `Estado: PAGADO`,
    `Referencia Stripe: ${paymentIntentId || 'N/A'}`,
    `Fecha: ${nowIso}`,
    '',
    'Ver PDF adjunto para evaluación médica completa.',
    'DERMÁTIKA — dermatika.mx'
  ].join('\n');

  const sent = await sendInternalMail(subject, emailText, allAttachments, emailHTML);
  console.log('[MAIL] Correo enviado:', sent ? '✅' : '❌', '| adjuntos:', allAttachments.length);
  return sent;
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
      // ✅ NO enviar correo — el paciente no es candidato, no hay pago
      console.log('[GUARD] Reintento bloqueado 30d — folio:', payload.folio);
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

  // ✅ NO enviar correo aquí — el correo completo se envía SOLO cuando Stripe confirme el pago
  // El correo médico con PDF se dispara en /api/intake (con pago confirmado) o en el webhook
  console.log('[GUARD] Evaluación guardada como', status, '— folio:', row.folio, '— esperando pago');

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
    answers: (() => {
      try {
        const raw = body.answers_json || body.answers;
        if (!raw) return null;
        if (typeof raw === 'string') return JSON.parse(raw);
        return raw;
      } catch(e) { return body.answers_json || body.answers || null; }
    })(),
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
  const bodyKeys = Object.keys(req.body || {});
  console.log('[INTAKE] Campos recibidos:', bodyKeys.filter(k => !k.startsWith('photo_base64')).join(', '));
  console.log('[INTAKE] answers_json presente:', !!(req.body?.answers_json), '| longitud:', (req.body?.answers_json || '').length);
  console.log('[INTAKE] fotos como archivos:', req.files?.length || 0);
  console.log('[INTAKE] fotos como base64:', bodyKeys.filter(k => k.startsWith('photo_base64_')).length);
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

  // Guardar fotos como base64 — soporta tanto archivos multipart como base64 en campos
  const fileSummaries = [];

  // Opción A: archivos subidos como multipart (método principal)
  if (Array.isArray(req.files) && req.files.length > 0) {
    req.files.forEach((f) => {
      fileSummaries.push({
        field: sanitizeText(f.fieldname || '', 40),
        name: sanitizeText(f.originalname || '', 120),
        type: sanitizeText(f.mimetype || '', 80),
        size: Number(f.size || 0),
        data: f.buffer ? f.buffer.toString('base64') : null
      });
    });
    console.log('[INTAKE] Fotos recibidas como archivos:', fileSummaries.length);
  }

  // Opción B: fotos enviadas como base64 en campos photo_base64_N (fallback)
  if (fileSummaries.length === 0) {
    let idx = 1;
    while (body[`photo_base64_${idx}`]) {
      fileSummaries.push({
        field: `photo_${idx}`,
        name: sanitizeText(body[`photo_name_${idx}`] || `foto-${idx}.jpg`, 120),
        type: sanitizeText(body[`photo_type_${idx}`] || 'image/jpeg', 80),
        size: 0,
        data: body[`photo_base64_${idx}`]
      });
      idx++;
    }
    if (fileSummaries.length > 0) {
      console.log('[INTAKE] Fotos recibidas como base64:', fileSummaries.length);
    }
  }

  const photosCountFromBody = Number(body.photos_count || 0);
  const effectivePhotosCount = Math.max(photosCountFromBody, fileSummaries.length);
  console.log('[INTAKE] Fotos efectivas:', effectivePhotosCount, '| declaradas en body:', photosCountFromBody, '| en fileSummaries:', fileSummaries.length);
  // Solo bloquear si NO hay absolutamente ninguna foto (ni declarada ni recibida)
  if (effectivePhotosCount === 0 && photosCountFromBody === 0) {
    console.warn('[INTAKE] Sin fotos — continuando de todos modos para no bloquear el flujo');
    // No bloquear — permitir continuar sin fotos (el médico lo revisará)
  }

  // ── 1. Parsear answers_json (cuestionario completo) ──────────────────────
  let parsedAnswers = {};
  try {
    const raw = body.answers_json || body.answers;
    if (raw) {
      parsedAnswers = typeof raw === 'string' ? JSON.parse(raw) : raw;
      console.log('[INTAKE] answers_json parseado — keys:', Object.keys(parsedAnswers).length,
        '| muestra:', Object.keys(parsedAnswers).slice(0,8).join(','));
    } else {
      console.warn('[INTAKE] answers_json VACÍO — body keys:', Object.keys(body).filter(k=>!k.startsWith('photo')).join(','));
    }
  } catch(e) {
    console.error('[INTAKE] Error parseando answers_json:', e.message);
  }

  // ── 2. Parsear patient JSON (datos del paciente separados) ─────────────
  let patientData = {};
  try {
    const rawPatient = body.patient;
    if (rawPatient) {
      patientData = typeof rawPatient === 'string' ? JSON.parse(rawPatient) : rawPatient;
      console.log('[INTAKE] patient parseado — nombre:', patientData.nombre, '| correo:', patientData.correo);
    }
  } catch(e) {
    console.error('[INTAKE] Error parseando patient:', e.message);
  }

  // ── 3. Extraer datos del paciente — prioridad: patient > answers > body ──
  const pa = parsedAnswers;
  const pt = patientData;

  const nombre   = sanitizeText(pt.nombre   || pa.nombre   || pa.identityName  || body.nombre   || body.patient_name || '', 120);
  const apellido = sanitizeText(pt.apellido || pa.apellido || pa.identityLastName || body.apellido || '', 120);
  const correo   = sanitizeText(pt.correo   || pa.correo   || pa.email || pa.leadEmail || body.correo || body.email || '', 120);
  const whatsapp = normalizePhone(pt.whatsapp || pa.whatsapp || pa.phone || pa.leadWhatsapp || body.whatsapp || body.phone || '');
  const fechaNac = sanitizeText(pt.fechaNacimiento || pa.fechaNacimiento || pa.birthdate || body.fechaNacimiento || body.birthdate || '', 80);
  const sexo     = sanitizeText(pt.sexo || pa.sexo || pa.sex || pa.gender || body.sexo || body.sex || '', 20);

  console.log('[INTAKE] Paciente → nombre:', nombre||'(vacío)', '| correo:', correo||'(vacío)', '| sexo:', sexo||'(vacío)');
  console.log('[INTAKE] Acné → severidad:', pa.acneSeverity||pa.acne||'(vacío)', '| duración:', pa.duration||pa.tiempo||'(vacío)');
  console.log('[INTAKE] Dirección → calle:', pt.shipAddress1||pa.shipAddress1||'(vacío)', '| colonia:', pt.shipNeighborhood||pa.shipNeighborhood||'(vacío)');

  // Reconstruir shipping — prioridad: patient > answers > body
  const shippingData = (() => {
    if (pt && Object.keys(pt).some(k=>k.startsWith('ship'))) {
      // patient JSON tiene los campos de envío directamente
      const s = {};
      ['shipFullName','shipAddress1','shipExterior','shipAddress2','shipZip',
       'shipNeighborhood','shipNeighborhoodManual','shipMunicipality','shipCity','shipState','references']
        .forEach(k => { const v = pt[k]||pa[k]||body[k]; if(v&&String(v).trim()) s[k]=sanitizeText(String(v),200); });
      if (Object.keys(s).length > 0) return s;
    }
    if (pa.shipping && typeof pa.shipping === 'object') return pa.shipping;
    if (body.shipping && typeof body.shipping === 'object') return body.shipping;
    const s = {};
    const shipMap = {
      shipFullName:         [pt.shipFullName,         pa.shipFullName,         body.shipFullName],
      shipAddress1:         [pt.shipAddress1,         pa.shipAddress1,         pa.shippingStreet,  body.shipAddress1],
      shipExterior:         [pt.shipExterior,         pa.shipExterior,         body.shipExterior],
      shipZip:              [pt.shipZip,              pa.shipZip,              pa.shippingPostalCode, body.shipZip],
      shipNeighborhood:     [pt.shipNeighborhood,     pa.shipNeighborhood,     pa.shippingNeighborhood, body.shipNeighborhood],
      shipNeighborhoodManual:[pt.shipNeighborhoodManual, pa.shipNeighborhoodManual, body.shipNeighborhoodManual],
      shipMunicipality:     [pt.shipMunicipality,     pa.shipMunicipality,     pa.shippingMunicipality, body.shipMunicipality],
      shipCity:             [pt.shipCity,             pa.shipCity,             body.shipCity],
      shipState:            [pt.shipState,            pa.shipState,            pa.shippingState, body.shipState],
      references:           [pt.references,           pa.references,           body.references]
    };
    Object.entries(shipMap).forEach(([k, vals]) => {
      const v = vals.find(x => x && String(x).trim());
      if (v) s[k] = sanitizeText(String(v), 200);
    });
    return Object.keys(s).length > 0 ? s : null;
  })();
  console.log('[INTAKE] Shipping → calle:', shippingData?.shipAddress1||'(vacío)', '| CP:', shippingData?.shipZip||'(vacío)');

  const payload = {
    id: makeId('intake'),
    nombre,
    apellido,
    fullName: `${nombre} ${apellido}`.trim() || sanitizeText(body.fullName || pa.fullName || '', 200),
    correo,
    whatsapp,
    fechaNacimiento: fechaNac,
    sexo,
    status,
    plan,
    medication,
    price,
    folio,
    shipping: shippingData,
    payment_reference: sanitizeText(body.payment_reference || body.payment_intent_id || pa.payment_reference || '', 120) || null,
    payment_status: sanitizeText(body.payment_status || 'pending', 80),
    // Guardar answers completo — el PDF/email usa a() que busca aquí
    answers: parsedAnswers,
    files: fileSummaries,
    createdAt: nowIso,
    updatedAt: nowIso
  };

  const db = readDb();
  db.push(payload);
  writeDb(db);

  // ✅ Solo enviar correo si el pago viene confirmado desde el frontend
  // En la mayoría de los casos llega como "pending" — el correo real lo envía confirm-payment-intent o webhook
  if (status === STATES.PAGADO) {
    console.log('[INTAKE] Pago confirmado en intake — enviando correo con PDF + fotos');
    await sendPaymentConfirmedEmail(payload, body.payment_reference || body.payment_intent_id || '');
    payload.mail_sent_payment = true;
    payload.mail_sent_at = new Date().toISOString();
    // Actualizar registro en DB con flag de correo enviado
    const dbU = readDb();
    const idxU = dbU.findIndex(r => r.folio === folio);
    if (idxU >= 0) { dbU[idxU] = { ...dbU[idxU], ...payload }; writeDb(dbU); }
  } else {
    console.log('[INTAKE] Evaluación guardada como PENDIENTE — correo se enviará tras confirmar pago. Folio:', folio);
  }

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
    const body = req.body || {};
    const paymentIntentId = sanitizeText(body.payment_intent || body.payment_reference || body.paymentIntentId || '', 120);
    const folio = getOrCreateFolio(body.folio || '');

    // Parsear datos del paciente y cuestionario enviados desde el frontend
    let patientData = {};
    let answersData = {};
    let shippingData = {};
    let photosBase64 = [];

    try {
      if (body.patient && typeof body.patient === 'object') patientData = body.patient;
      else if (body.patient) patientData = JSON.parse(body.patient);
    } catch(e) { console.warn('[CONFIRM] Error parseando patient:', e.message); }

    try {
      if (body.questionnaire && typeof body.questionnaire === 'object') answersData = body.questionnaire;
      else if (body.answers_json) answersData = typeof body.answers_json === 'string' ? JSON.parse(body.answers_json) : body.answers_json;
    } catch(e) { console.warn('[CONFIRM] Error parseando answers:', e.message); }

    try {
      const rawShip = body.shipping || body.address;
      if (rawShip && typeof rawShip === 'object') shippingData = rawShip;
      else if (rawShip) shippingData = JSON.parse(rawShip);
    } catch(e) { console.warn('[CONFIRM] Error parseando shipping:', e.message); }

    try {
      if (Array.isArray(body.photos_base64)) photosBase64 = body.photos_base64;
    } catch(e) {}

    const planFromFE  = sanitizeText(body.plan || answersData.selectedPlan || '', 40);
    const medFromFE   = sanitizeText(body.medication || answersData.selectedMedication || '', 40);
    const priceFromFE = Number(body.price || answersData.selectedPrice || 0);

    console.log('[CONFIRM] folio:', folio, '| pi:', paymentIntentId, '| plan:', planFromFE);
    console.log('[CONFIRM] patient:', patientData.nombre||'(vacío)', patientData.apellido||'');
    console.log('[CONFIRM] answers keys:', Object.keys(answersData).length, '| shipping:', !!shippingData.shipAddress1, '| fotos base64:', photosBase64.length);
    if (!paymentIntentId) return res.status(400).json({ ok: false, error: 'missing_payment_intent_id' });

    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
    const paid = pi?.status === 'succeeded';

    const db = readDb();
    const idx = db.findIndex((row) => String(row.folio || '').toLowerCase() === folio.toLowerCase());
    let updatedRow = null;

    if (idx >= 0) {
      db[idx].payment_reference = paymentIntentId;
      db[idx].payment_status = paid ? 'succeeded' : String(pi?.status || 'unknown');
      db[idx].status = paid ? STATES.PAGADO : db[idx].status;
      db[idx].updatedAt = new Date().toISOString();
      // Actualizar datos que llegaron en confirm (más completos que en el intake inicial)
      if (planFromFE  ) db[idx].plan       = planFromFE;
      if (medFromFE   ) db[idx].medication = medFromFE;
      if (priceFromFE ) db[idx].price      = priceFromFE;
      // Enriquecer con datos del paciente si el registro los tenía vacíos
      if (patientData.nombre   && !db[idx].nombre  ) db[idx].nombre   = sanitizeText(patientData.nombre, 120);
      if (patientData.apellido && !db[idx].apellido) db[idx].apellido = sanitizeText(patientData.apellido, 120);
      if (patientData.correo   && !db[idx].correo  ) db[idx].correo   = sanitizeText(patientData.correo, 120);
      if (patientData.whatsapp && !db[idx].whatsapp) db[idx].whatsapp = sanitizeText(patientData.whatsapp, 30);
      if (patientData.sexo     && !db[idx].sexo    ) db[idx].sexo     = sanitizeText(patientData.sexo, 20);
      // Enriquecer answers si el registro los tenía vacíos
      if (Object.keys(answersData).length > 0 && (!db[idx].answers || Object.keys(db[idx].answers||{}).length === 0)) {
        db[idx].answers = answersData;
      }
      // Enriquecer shipping
      if (Object.keys(shippingData).length > 0 && !db[idx].shipping) {
        db[idx].shipping = shippingData;
      }
      // Fotos base64 si llegaron en el confirm y no había en el registro
      if (photosBase64.length > 0 && (!db[idx].files || db[idx].files.length === 0)) {
        db[idx].files = photosBase64.map((p, i) => ({
          field: `photo_${i+1}`,
          name: p.name || `foto-${i+1}.jpg`,
          type: p.type || 'image/jpeg',
          data: p.data || (typeof p === 'string' ? p : null)
        })).filter(f => f.data);
        console.log('[CONFIRM] Fotos base64 guardadas desde confirm:', db[idx].files.length);
      }
      updatedRow = db[idx];
      writeDb(db);
      console.log('[CONFIRM] Registro actualizado — nombre:', db[idx].nombre||'(vacío)',
        '| answers keys:', Object.keys(db[idx].answers||{}).length,
        '| fotos:', (db[idx].files||[]).length, '| shipping:', !!db[idx].shipping);
    } else {
      // Si no hay registro previo (corner case), crear uno nuevo con los datos que llegaron
      console.warn('[CONFIRM] Registro NO encontrado — creando nuevo con datos del confirm. folio:', folio);
      const newRow = {
        id: makeId('confirm'),
        folio, nombre: sanitizeText(patientData.nombre||'', 120),
        apellido: sanitizeText(patientData.apellido||'', 120),
        correo: sanitizeText(patientData.correo||'', 120),
        whatsapp: sanitizeText(patientData.whatsapp||'', 30),
        sexo: sanitizeText(patientData.sexo||'', 20),
        plan: planFromFE, medication: medFromFE, price: priceFromFE,
        answers: answersData, shipping: shippingData,
        files: photosBase64.map((p,i)=>({field:`photo_${i+1}`,name:p.name||`foto-${i+1}.jpg`,type:p.type||'image/jpeg',data:p.data||null})).filter(f=>f.data),
        payment_reference: paymentIntentId, payment_status: paid?'succeeded':'unknown',
        status: paid ? STATES.PAGADO : STATES.CHECKOUT_PENDIENTE,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      };
      db.push(newRow);
      writeDb(db);
      updatedRow = newRow;
    }

    // ✅ CORREO MÉDICO COMPLETO CON PDF + FOTOS — solo si el pago fue exitoso
    if (paid && updatedRow && !updatedRow.mail_sent_payment) {
      console.log('[CONFIRM] Pago exitoso — enviando correo completo con PDF y fotos. Folio:', folio);
      try {
        await sendPaymentConfirmedEmail(updatedRow, paymentIntentId);
        // Marcar correo enviado para evitar duplicados con webhook
        const db2 = readDb();
        const idx2 = db2.findIndex(r => r.folio === folio);
        if (idx2 >= 0) {
          db2[idx2].mail_sent_payment = true;
          db2[idx2].mail_sent_at = new Date().toISOString();
          writeDb(db2);
        }
      } catch (mailErr) {
        console.error('[CONFIRM] ❌ Error enviando correo:', mailErr.message || mailErr);
      }
      // Guardar en Airtable — CRM ADMIN (ventas) y CRM MEDICO (doctor)
      try {
        await saveToAirtableAdmin(updatedRow, paymentIntentId);
      } catch(atErr) {
        console.error('[AIRTABLE ERROR] Error en CRM ADMIN:', atErr.message);
      }
      try {
        await saveToAirtableMedico(updatedRow);
      } catch(atErr) {
        console.error('[AIRTABLE ERROR] Error en CRM MEDICO:', atErr.message);
      }
    } else if (!paid) {
      console.log('[CONFIRM] Pago NO exitoso — status:', pi?.status, '— NO se envía correo');
    } else {
      console.log('[CONFIRM] Correo ya enviado previamente para folio:', folio);
      // Intentar Airtable igual (puede que no se haya guardado la primera vez)
      if (updatedRow) {
        try { await saveToAirtableAdmin(updatedRow, paymentIntentId); } catch(e) {}
        try { await saveToAirtableMedico(updatedRow); } catch(e) {}
      }
    }

    return res.json({ ok: true, paid, status: pi?.status || 'unknown', folio });
  } catch (err) {
    console.error('[CONFIRM] ❌ Error:', err.message || err);
    return res.status(500).json({ ok: false, error: 'confirm_failed' });
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK DE STRIPE — Segunda línea de defensa para confirmar pago
// Evento: payment_intent.succeeded
// ══════════════════════════════════════════════════════════════════
app.post('/api/stripe-webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      if (webhookSecret && sig) {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } else {
        // Sin secreto configurado — parsear directamente (solo para testing)
        event = JSON.parse(req.body.toString());
        console.warn('[WEBHOOK] ⚠️ STRIPE_WEBHOOK_SECRET no configurado — sin verificación de firma');
      }
    } catch (err) {
      console.error('[WEBHOOK] ❌ Firma inválida:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log('[WEBHOOK] Evento recibido:', event.type);

    if (event.type === 'payment_intent.succeeded') {
      const pi = event.data.object;
      const paymentIntentId = pi.id;
      const folioMeta = pi.metadata?.folio || pi.metadata?.patient_reference || '';

      console.log('[WEBHOOK] payment_intent.succeeded — folio meta:', folioMeta, '| pi:', paymentIntentId);

      const db = readDb();
      const idx = db.findIndex((row) =>
        String(row.folio || '').toLowerCase() === folioMeta.toLowerCase() ||
        String(row.payment_reference || '') === paymentIntentId
      );

      if (idx >= 0) {
        const alreadyPaid = db[idx].status === STATES.PAGADO && db[idx].mail_sent_payment;
        if (alreadyPaid) {
          console.log('[WEBHOOK] Correo ya enviado para este folio — skip');
          return res.json({ received: true });
        }

        db[idx].payment_reference = paymentIntentId;
        db[idx].payment_status = 'succeeded';
        db[idx].status = STATES.PAGADO;
        db[idx].updatedAt = new Date().toISOString();
        const updatedRow = db[idx];
        writeDb(db);

        // Enviar correo completo con PDF + fotos
        try {
          await sendPaymentConfirmedEmail(updatedRow, paymentIntentId);
          db[idx].mail_sent_payment = true;
          db[idx].mail_sent_at = new Date().toISOString();
          writeDb(db);
          console.log('[WEBHOOK] ✅ Correo con PDF + fotos enviado. Folio:', updatedRow.folio);
        } catch (mailErr) {
          console.error('[WEBHOOK] ❌ Error enviando correo:', mailErr.message);
        }
      } else {
        console.warn('[WEBHOOK] Folio no encontrado en DB para pi:', paymentIntentId);
      }
    }

    return res.json({ received: true });
  }
);

// ══════════════════════════════════════════════════════════════════
// /api/medical-update — El médico actualiza receta, dosis e indicaciones
// Campos actualizados en CRM MEDICO de Airtable
// ══════════════════════════════════════════════════════════════════
app.post('/api/medical-update', async (req, res) => {
  try {
    const body   = req.body || {};
    const folio  = sanitizeText(body.folio || '', 40);
    const apiKey = sanitizeText(body.api_key || '', 100); // clave médico para autenticar

    if (!folio) return res.status(400).json({ ok: false, error: 'folio_requerido' });

    // Validar clave del médico
    const MEDICAL_API_KEY = process.env.MEDICAL_API_KEY || '';
    if (MEDICAL_API_KEY && apiKey !== MEDICAL_API_KEY) {
      return res.status(401).json({ ok: false, error: 'no_autorizado' });
    }

    if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) {
      return res.status(503).json({ ok: false, error: 'airtable_no_configurado' });
    }

    // Buscar el record en CRM MEDICO
    const recordId = await _findAirtableRecord(AIRTABLE_TABLE_MEDICO, folio);
    if (!recordId) {
      return res.status(404).json({ ok: false, error: 'paciente_no_encontrado', folio });
    }

    // Campos que el médico puede actualizar
    const fields = {};
    if (body.receta_medica        ) fields['Receta medica']          = sanitizeText(body.receta_medica, 2000);
    if (body.dosis_indicada       ) fields['Dosis indicada']         = sanitizeText(body.dosis_indicada, 1000);
    if (body.indicaciones_skincare) fields['Indicaciones skincare']  = sanitizeText(body.indicaciones_skincare, 2000);
    if (body.estado_medico        ) fields['Estado medico']          = sanitizeText(body.estado_medico, 100);
    if (body.comentarios_medico   ) fields['Comentarios del medico'] = sanitizeText(body.comentarios_medico, 2000);

    if (Object.keys(fields).length === 0) {
      return res.status(400).json({ ok: false, error: 'sin_campos_para_actualizar' });
    }

    console.log('[MEDICO] Actualizando expediente — folio:', folio, '| campos:', Object.keys(fields).join(', '));

    const result = await _airtableRequest('PATCH', AIRTABLE_TABLE_MEDICO, recordId, { fields });

    if (!result.ok) {
      const errMsg = result.data?.error?.message || JSON.stringify(result.data?.error || result.data);
      console.error('[MEDICO ERROR]', result.status, errMsg);
      return res.status(500).json({ ok: false, error: 'error_airtable', detail: errMsg });
    }

    console.log('[MEDICO] Expediente actualizado correctamente — folio:', folio, '| record:', recordId);

    // También guardar en DB local
    const db  = readDb();
    const idx = db.findIndex(r => String(r.folio||'').toLowerCase() === folio.toLowerCase());
    if (idx >= 0) {
      if (!db[idx].medico) db[idx].medico = {};
      if (body.receta_medica        ) db[idx].medico.receta_medica         = sanitizeText(body.receta_medica, 2000);
      if (body.dosis_indicada       ) db[idx].medico.dosis_indicada        = sanitizeText(body.dosis_indicada, 1000);
      if (body.indicaciones_skincare) db[idx].medico.indicaciones_skincare = sanitizeText(body.indicaciones_skincare, 2000);
      if (body.estado_medico        ) db[idx].medico.estado_medico         = sanitizeText(body.estado_medico, 100);
      if (body.comentarios_medico   ) db[idx].medico.comentarios_medico    = sanitizeText(body.comentarios_medico, 2000);
      db[idx].medico.updatedAt = new Date().toISOString();
      writeDb(db);
    }

    return res.json({ ok: true, folio, record_id: recordId, updated: Object.keys(fields) });
  } catch (err) {
    console.error('[MEDICO ERROR] Excepcion:', err.message || err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// /api/medical-get — El médico consulta el expediente de un paciente
app.get('/api/medical-get', async (req, res) => {
  try {
    const folio  = sanitizeText(req.query.folio  || '', 40);
    const apiKey = sanitizeText(req.query.api_key || '', 100);
    if (!folio) return res.status(400).json({ ok: false, error: 'folio_requerido' });

    const MEDICAL_API_KEY = process.env.MEDICAL_API_KEY || '';
    if (MEDICAL_API_KEY && apiKey !== MEDICAL_API_KEY) {
      return res.status(401).json({ ok: false, error: 'no_autorizado' });
    }

    // Leer de DB local
    const db  = readDb();
    const row = db.find(r => String(r.folio||'').toLowerCase() === folio.toLowerCase());
    if (!row) return res.status(404).json({ ok: false, error: 'paciente_no_encontrado' });

    const pa = row.answers || {};
    const av = v => Array.isArray(v) ? v.join(', ') : (v || 'N/A');

    // Solo datos médicos — SIN teléfono ni email
    return res.json({
      ok: true,
      expediente: {
        folio:          row.folio,
        nombre:         `${row.nombre||''} ${row.apellido||''}`.trim(),
        edad:           av(pa.ageRange || pa.edad),
        sexo:           row.sexo || pa.sex || pa.sexo || 'N/A',
        acne_severidad: pa.acneSeverity || pa.acne || 'N/A',
        acne_duracion:  pa.duration || pa.tiempo || 'N/A',
        acne_zonas:     av(pa.acneAreas || pa.zonas),
        acne_tipo:      av(pa.acneType),
        tratamientos_previos: av(pa.previousTreatments),
        isotretinoin_previa:  pa.isotretinoinBefore || 'N/A',
        salud_general:        pa.generalHealth || 'N/A',
        condiciones_cronicas: av(pa.chronicConditions),
        medicamentos_actuales: pa.currentMedications || 'N/A',
        alergias:             pa.allergies || 'N/A',
        salud_mental:         av(pa.mentalHealth),
        ideas_suicidas:       pa.suicidalIdeation || 'N/A',
        plan:           row.plan || 'N/A',
        medicamento:    row.medication || 'N/A',
        estado_pago:    row.payment_status || 'N/A',
        fecha:          row.createdAt || 'N/A',
        fotos_count:    (row.files || []).length,
        // Datos del médico
        medico: row.medico || {
          receta_medica: '',
          dosis_indicada: '',
          indicaciones_skincare: '',
          estado_medico: 'Pendiente revision',
          comentarios_medico: ''
        }
      }
    });
  } catch (err) {
    console.error('[MEDICO GET ERROR]', err.message);
    return res.status(500).json({ ok: false, error: 'server_error' });
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
