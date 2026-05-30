'use strict';
console.log("VERSION SERVER FINAL 30-MAYO-17:00");

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
      scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com", "https://connect.facebook.net", "https://www.googletagmanager.com", "https://www.google-analytics.com"],
      frameSrc: ["https://js.stripe.com", "https://hooks.stripe.com"],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://www.facebook.com",
        "https://connect.facebook.net",
        "https://www.googletagmanager.com",
        "https://www.google-analytics.com",
        process.env.NETLIFY_ORIGIN || '',
        process.env.NETLIFY_PREVIEW_ORIGIN || ''
      ].filter(Boolean),
      imgSrc: ["'self'", "data:", "https://www.facebook.com", "https://www.googletagmanager.com", "https://www.google-analytics.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({
  limit: '18mb',
  verify: (req, _res, buf) => {
    if (req.originalUrl === '/api/stripe-webhook') req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ limit: '18mb', extended: true }));

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
  esencial: { amount: 159000, price: 1590, medication: 'Neotrex', plan: 'Esencial', planLabel: 'Nova Esencial' },
  avanzado: { amount: 189000, price: 1890, medication: 'Vastionin', plan: 'Avanzado', planLabel: 'Nova Avanzado' },
  elite: { amount: 269000, price: 2690, medication: 'Epuris', plan: 'Elite', planLabel: 'Nova Elite' }
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

function normalizeWeightKg(v = '') {
  const raw = String(v || '').replace(',', '.').replace(/[^\d.]/g, '');
  const weight = Number(raw);
  if (!Number.isFinite(weight) || weight < 30 || weight > 180) return '';
  return String(Math.round(weight * 10) / 10);
}

function normalizeAge(v = '') {
  const age = Number(String(v || '').replace(/\D/g, ''));
  if (!Number.isFinite(age) || age < 1 || age > 120) return '';
  return String(Math.floor(age));
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

function normalizePlanKeyFromPrice(priceRaw = 0) {
  const price = Number(priceRaw || 0);
  if (price === 1590 || price === 159000) return 'esencial';
  if (price === 1890 || price === 189000) return 'avanzado';
  if (price === 2690 || price === 269000) return 'elite';
  return '';
}

function resolvePlanSelection(...sources) {
  const merged = Object.assign({}, ...sources.filter(Boolean));
  const rawPlan = merged.planKey || merged.plan_key || merged.plan || merged.planLabel || merged.plan_label ||
    merged.planName || merged.plan_name || merged.selectedPlan || merged.selectedPlanLabel || '';
  const key = normalizePlanKey(rawPlan) || normalizePlanKeyFromPrice(merged.price || merged.plan_price || merged.selectedPrice || 0);
  const canonical = PLAN_PRICE_MAP[key] || null;
  if (!canonical) {
    return {
      planKey: '',
      plan: sanitizeText(merged.planLabel || merged.plan_name || merged.plan || merged.selectedPlan || '', 80),
      planLabel: sanitizeText(merged.planLabel || merged.plan_label || merged.plan_name || merged.plan || merged.selectedPlan || '', 80),
      medication: sanitizeText(merged.medication || merged.selectedMedication || '', 60) || null,
      price: Number(merged.price || merged.plan_price || merged.selectedPrice || 0) || null
    };
  }
  return {
    planKey: key,
    plan: canonical.planLabel,
    planLabel: canonical.planLabel,
    medication: canonical.medication,
    price: canonical.price,
    amount: canonical.amount
  };
}

// ✅ Stripe: solo si están configuradas las keys
const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
const stripePublic = process.env.STRIPE_PUBLIC_KEY || '';
const stripeKeysAreLive = stripeSecret.startsWith('sk_live_') && stripePublic.startsWith('pk_live_') && !stripeSecret.includes('REEMPLAZAR') && !stripePublic.includes('REEMPLAZAR');
if ((stripeSecret && !stripeSecret.startsWith('sk_live_')) || (stripePublic && !stripePublic.startsWith('pk_live_'))) {
  console.error('[STRIPE] ❌ PRODUCCIÓN requiere llaves LIVE. Revisa STRIPE_SECRET_KEY=sk_live_... y STRIPE_PUBLIC_KEY=pk_live_...');
}
const stripe = stripeKeysAreLive ? new Stripe(stripeSecret, { apiVersion: '2024-04-10' }) : null;

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
const AIRTABLE_FIELD_CIUDAD = 'Ciudad';

// Helper interno para llamadas a la API de Airtable
async function _airtableRequest(method, tableName, recordId, body) {
  const base = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(tableName)}`;
  const url  = recordId ? `${base}/${recordId}` : base;
  const payload = body ? { ...body } : undefined;
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'typecast')) {
    delete payload.typecast;
  }
  const res  = await fetch(url, {
    method,
    headers: {
      'Authorization': `Bearer ${AIRTABLE_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: payload ? JSON.stringify(payload) : undefined
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

// ── HELPER: calcular edad desde birthdate ────────────────────────
function calcularEdad(birthdate) {
  if (!birthdate) return '';
  try {
    // Soporta formatos: YYYY-MM-DD, DD/MM/YYYY, texto libre
    const str = String(birthdate).trim();
    let fecha;
    if (/^\d{4}-\d{2}-\d{2}/.test(str)) {
      fecha = new Date(str);
    } else if (/^\d{2}\/\d{2}\/\d{4}/.test(str)) {
      const [d, m, y] = str.split('/');
      fecha = new Date(`${y}-${m}-${d}`);
    } else {
      fecha = new Date(str);
    }
    if (isNaN(fecha.getTime())) return '';
    const hoy  = new Date();
    let edad   = hoy.getFullYear() - fecha.getFullYear();
    const mes  = hoy.getMonth() - fecha.getMonth();
    if (mes < 0 || (mes === 0 && hoy.getDate() < fecha.getDate())) edad--;
    return edad > 0 && edad < 120 ? String(edad) : '';
  } catch(e) { return ''; }
}

// ── GUARDAR EN CRM ADMIN — campos minimalistas ───────────────────
async function saveToAirtableAdmin(row, paymentIntentId) {
  if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) {
    console.warn('[AIRTABLE] Variables no configuradas — omitiendo');
    return false;
  }

  const pa = row.answers || {};
  const sv = (v, fb = '') => {
    if (v === null || v === undefined) return fb;
    const str = String(v).trim();
    return (str === '' || str === 'undefined' || str === 'null') ? fb : str;
  };

  const edadReal = calcularEdad(row.fechaNacimiento || pa.fechaNacimiento || pa.birthdate);
  const precioNum = Number(row.price || pa.selectedPrice || 0) || undefined;

  // Campos Airtable — Estado refleja la fase del funnel
  const estadoAirtable = (() => {
    if (paymentIntentId || row.payment_status === 'paid' || row.status === 'PAGADO') return 'PAGADO';
    if (row.autosave) return 'LEAD';
    return 'EVALUACION_COMPLETA';
  })();

  const fields = {
    'Folio':        sv(row.folio),
    'Fecha':        new Date().toISOString().split('T')[0],
    'Nombre':       (`${sv(row.nombre)} ${sv(row.apellido)}`).trim() || sv(pa.nombre),
    'Telefono':     sv(row.whatsapp || pa.whatsapp || pa.phone),
    'Email':        sv(row.correo   || pa.correo   || pa.email),
    'Edad':         edadReal ? Number(edadReal) : undefined,
    'Peso':         sv(pa.weight || pa.peso),
    'Sexo':         sv(row.sexo  || pa.sexo || pa.sex),
    'Plan':         sv(row.plan),
    'Estado':       estadoAirtable,
    'Fotos':        (row.files && row.files.length > 0) ? 'Si' : 'No',
    'PDF':          estadoAirtable !== 'LEAD' ? 'Enviado por correo' : '',
  };

  // Eliminar vacíos y undefined
  Object.keys(fields).forEach(k => {
    const v = fields[k];
    if (v === undefined || v === null || v === '') delete fields[k];
  });

  console.log('[AIRTABLE] Guardando en CRM ADMIN — folio:', sv(row.folio),
    '| campos:', Object.keys(fields).join(', '));

  try {
    const existingId = await _findAirtableRecord(AIRTABLE_TABLE_ADMIN, sv(row.folio));
    const result = existingId
      ? await _airtableRequest('PATCH', AIRTABLE_TABLE_ADMIN, existingId, { fields })
      : await _airtableRequest('POST',  AIRTABLE_TABLE_ADMIN, null,       { fields });

    if (!result.ok) {
      const errMsg = result.data?.error?.message || result.data?.error?.type || JSON.stringify(result.data?.error || result.data);
      console.error('[AIRTABLE ERROR]', result.status, errMsg);
      console.error('[AIRTABLE ERROR] Campos enviados:', Object.keys(fields).join(', '));
      return false;
    }
    const rid = result.data.id || existingId;
    console.log('[AIRTABLE ADMIN OK] record:', rid, '| folio:', sv(row.folio));
    return rid;
  } catch (err) {
    console.error('[AIRTABLE ERROR] Excepcion en CRM ADMIN:', err.message || String(err));
    return false;
  }
}
// Alias para compatibilidad con el código existente
const saveToAirtable = (row, piId) => saveToAirtableAdmin(row, piId);

// ── Log de arranque: verificar variables críticas ──
console.log('[CONFIG] STRIPE_SECRET_KEY:', stripeSecret ? (stripeSecret.startsWith('sk_live_') ? '✅ live' : '❌ NO LIVE') : '❌ FALTA');
console.log('[CONFIG] STRIPE_PUBLIC_KEY:', stripePublic ? (stripePublic.startsWith('pk_live_') ? '✅ live' : '❌ NO LIVE') : '❌ FALTA');
console.log('[CONFIG] RESEND_API_KEY:', RESEND_API_KEY ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] ADMIN_EMAIL:', ADMIN_EMAIL || '❌ FALTA');
console.log('[CONFIG] FRONTEND_ORIGIN:', process.env.FRONTEND_ORIGIN || '❌ FALTA');
console.log('[CONFIG] AIRTABLE_API_KEY:', AIRTABLE_API_KEY ? '✅ configurada' : '❌ FALTA');
console.log('[CONFIG] AIRTABLE_BASE_ID:', AIRTABLE_BASE_ID || '❌ FALTA');
console.log('[CONFIG] AIRTABLE_TABLE_ADMIN:', AIRTABLE_TABLE_ADMIN);

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
      console.log('[MAIL OK] Enviado via Resend:', subject, '| id:', data.id, '| adjuntos:', payload.attachments?.length || 0);
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
      campo('Edad',               normalizeAge(data.age || data.edad || a('age') || a('edad')));
      campo('Peso',               normalizeWeightKg(data.weight || data.peso || a('weight') || a('peso') || a('pesoKg')) ? `${normalizeWeightKg(data.weight || data.peso || a('weight') || a('peso') || a('pesoKg'))} kg` : '');
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
      ${row('Edad', normalizeAge(data.age || data.edad || a('age') || a('edad')))}
      ${row('Peso', normalizeWeightKg(data.weight || data.peso || a('weight') || a('peso') || a('pesoKg')) ? `${normalizeWeightKg(data.weight || data.peso || a('weight') || a('peso') || a('pesoKg'))} kg` : '')}
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
    console.log('[PDF OK] Generado:', pdfAttachment.filename, '| bytes:', pdfBuf.length);
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
    `Edad: ${normalizeAge(row.age || row.edad || row.answers?.age || row.answers?.edad) || 'N/A'}`,
    `Peso: ${normalizeWeightKg(row.weight || row.peso || row.answers?.weight || row.answers?.peso || row.answers?.pesoKg) || 'N/A'} kg`,
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

  // FASE 1: solo Airtable, sin correo
  if ((payload.correo || payload.whatsapp) && AIRTABLE_API_KEY && AIRTABLE_BASE_ID) {
    setImmediate(async () => {
      try {
        await saveToAirtableAdmin(payload, null);
        console.log('[AUTOSAVE] \u2705 Airtable LEAD creado/actualizado. Folio:', payload.folio);
      } catch(e) { console.error('[AUTOSAVE] \u274C Airtable LEAD:', e.message); }
    });
  }

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
  const unverifiedPaidStatus = paymentStatus.includes('succeeded') || paymentStatus.includes('paid');
  const status = STATES.CHECKOUT_PENDIENTE;
  const folio = getOrCreateFolio(body.folio_dermatika || body.internal_folio || body.patient_reference);
  let plan = sanitizeText(body.planLabel || body.plan_label || body.plan_name || body.plan || '', 80) || null;
  let planLabel = sanitizeText(body.planLabel || body.plan_label || body.plan_name || body.plan || '', 80) || null;
  let planKey = normalizePlanKey(body.planKey || body.plan_key || body.plan || body.planLabel || body.plan_label || body.plan_name || '');
  let medication = sanitizeText(body.medication || '', 40) || null;
  let price = Number(body.price || body.plan_price || 0) || null;

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

  const finalPlan = resolvePlanSelection(body, parsedAnswers);
  if (finalPlan.planKey) {
    planKey = finalPlan.planKey;
    plan = finalPlan.plan;
    planLabel = finalPlan.planLabel;
    medication = finalPlan.medication;
    price = finalPlan.price;
  }
  console.log('[PLAN] seleccionado:', planLabel || plan || '(sin plan)', '| key:', planKey || '(sin key)');
  console.log('[PRECIO] seleccionado:', price || 0);

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
  const edad     = normalizeAge(pt.age || pt.edad || pa.age || pa.edad || body.age || body.edad || '');
  const sexo     = sanitizeText(pt.sexo || pa.sexo || pa.sex || pa.gender || body.sexo || body.sex || '', 20);
  const peso     = normalizeWeightKg(pt.weight || pt.peso || pa.weight || pa.peso || pa.pesoKg || body.weight || body.peso || body.pesoKg || '');

  console.log('[INTAKE] Paciente → nombre:', nombre||'(vacío)', '| correo:', correo||'(vacío)', '| edad:', edad || '(vacío)', '| sexo:', sexo||'(vacío)', '| peso:', peso || '(vacío)');
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
    age: edad || null,
    edad: edad || null,
    sexo,
    weight: peso || null,
    peso: peso || null,
    status,
    plan,
    planLabel,
    plan_key: planKey || null,
    medication,
    price,
    folio,
    shipping: shippingData,
    payment_reference: sanitizeText(body.payment_reference || body.payment_intent_id || pa.payment_reference || '', 120) || null,
    payment_status: unverifiedPaidStatus ? 'pending_unverified' : sanitizeText(body.payment_status || 'pending', 80),
    // Guardar answers completo — el PDF/email usa a() que busca aquí
    answers: parsedAnswers,
    files: fileSummaries,
    createdAt: nowIso,
    updatedAt: nowIso
  };

  const db = readDb();
  db.push(payload);
  writeDb(db);

  console.log('[INTAKE] Evaluación guardada — enviando correo de lead a admin. Folio:', folio);

  // FASE 2: Airtable actualiza + correo con PDF y fotos
  setImmediate(async () => {
    // 2a. Actualizar Airtable — upsert por folio
    try {
      await saveToAirtableAdmin(payload, null);
      console.log('[INTAKE] \u2705 Airtable EVALUACION_COMPLETA. Folio:', folio);
    } catch(atErr) { console.error('[INTAKE] \u274C Airtable:', atErr.message); }

    // 2b. Correo con PDF + fotos
    try {
      const pdfBuf = await generateEvaluationPDF({ ...payload, eligibility_status: 'candidato' });
      const pdfAttachment = {
        filename: `DERMATIKA-Lead-${folio}.pdf`,
        content: pdfBuf.toString('base64'),
        contentType: 'application/pdf'
      };

      const photoAttachments = getPhotoAttachments(payload);
      const allAttachments = [pdfAttachment, ...photoAttachments];

      const nombreCompleto = `${nombre} ${apellido}`.trim() || 'Sin nombre';
      const planTexto = planLabel || plan || 'No seleccionado';
      const precioTexto = price ? '$' + price + ' MXN' : 'N/A';
      const subject = `\u{1F195} NUEVO LEAD \u2014 DERM\u00C1TIKA #${folio} \u2014 ${nombreCompleto}`;

      const emailText = [
        '\u{1F195} NUEVO LEAD \u2014 EVALUACI\u00D3N COMPLETADA',
        `Folio: ${folio}`,
        `Paciente: ${nombreCompleto}`,
        `Correo: ${correo || 'N/A'}`,
        `WhatsApp: ${whatsapp || 'N/A'}`,
        `Edad: ${edad || 'N/A'}`,
        `Peso: ${peso ? peso + ' kg' : 'N/A'}`,
        `Sexo: ${sexo || 'N/A'}`,
        `Plan recomendado: ${planTexto}`,
        `Medicamento: ${medication || 'N/A'}`,
        `Precio: ${precioTexto}`,
        'Estado de pago: PENDIENTE',
        `Fecha: ${nowIso}`,
        '',
        'El PDF adjunto contiene la evaluaci\u00F3n m\u00E9dica completa + fotos del paciente.',
        'Si no paga en los pr\u00F3ximos d\u00EDas, da seguimiento por WhatsApp o correo.',
        '',
        'DERM\u00C1TIKA \u2014 dermatika.mx'
      ].join('\n');

      const emailHTML = buildEmailHTML({
        ...payload,
        eligibility_status: 'candidato',
        payment_status: 'pendiente'
      });

      await sendInternalMail(subject, emailText, allAttachments, emailHTML);
      console.log('[INTAKE] \u2705 Correo de lead enviado. Folio:', folio, '| fotos:', photoAttachments.length);
    } catch (mailErr) {
      console.error('[INTAKE] \u274C Error enviando correo de lead:', mailErr.message || mailErr);
    }
  });

  return res.json({ ok: true, folio, status, recommendedPlan: plan || null });
});

// ✅ Crear Payment Intent con Stripe
async function createPaymentIntentHandler(req, res) {
  try {
    if (!stripe || !stripePublic || !stripeKeysAreLive) {
      console.error('[STRIPE] ❌ Stripe LIVE no configurado — no se crea PaymentIntent');
      return res.status(503).json({ ok: false, error: 'stripe_live_keys_required' });
    }
    const requestedPlan = resolvePlanSelection(req.body || {});
    const planKey = requestedPlan.planKey;
    console.log('[STRIPE] ← Solicitud de pago recibida, plan:', planKey || req.body?.planKey || req.body?.plan);
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
    console.log('[PLAN] seleccionado:', expectedPlan.planLabel, '| key:', planKey);
    console.log('[PRECIO] seleccionado:', expectedPlan.price);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: expectedAmount,
      currency: 'mxn',
      automatic_payment_methods: { enabled: true },
      metadata: {
        folio,
        nombre: patientName,
        correo: email,
        whatsapp: phone,
        plan: planKey,
        planLabel: expectedPlan.planLabel,
        plan_name: expectedPlan.plan,
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
      client_secret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      payment_intent: paymentIntent.id,
      publishableKey: stripePublic
    });
  } catch (err) {
    console.error('[STRIPE] ❌ Error creando payment intent:', err.message || err);
    return res.status(500).json({ ok: false, error: 'stripe_error' });
  }
}

app.post('/api/create-stripe-payment-intent', createPaymentIntentHandler);
app.post('/api/create-payment-intent', createPaymentIntentHandler);

app.post('/api/create-live-validation-payment-intent', async (req, res) => {
  try {
    if (!stripe || !stripeKeysAreLive) {
      console.error('[STRIPE VALIDATION] ❌ Stripe LIVE no configurado');
      return res.status(503).json({ ok: false, error: 'stripe_live_keys_required' });
    }
    const token = sanitizeText(req.body?.validation_token || req.query?.token || '', 120);
    const expectedToken = process.env.STRIPE_LIVE_VALIDATION_TOKEN || 'dermatika-live-10mxn-8f4c2';
    if (token !== expectedToken) {
      return res.status(404).json({ ok: false, error: 'not_found' });
    }

    const folio = getOrCreateFolio(req.body?.folio || req.body?.patientReference || '');
    const email = sanitizeText(req.body?.email || process.env.VALIDATION_EMAIL || '', 120);
    const phone = normalizePhone(req.body?.phone || '');
    const patientName = sanitizeText(req.body?.patientName || 'Validacion LIVE Stripe', 120);
    const expectedPlan = PLAN_PRICE_MAP.esencial;

    const paymentIntent = await stripe.paymentIntents.create({
      amount: 1000,
      currency: 'mxn',
      automatic_payment_methods: { enabled: true },
      metadata: {
        validation_flow: 'live_10mxn',
        folio,
        patient_reference: folio,
        nombre: patientName,
        correo: email,
        whatsapp: phone,
        plan: 'esencial',
        plan_key: 'esencial',
        planLabel: expectedPlan.planLabel,
        plan_name: expectedPlan.plan,
        medicamento: expectedPlan.medication,
        precio: '10',
        source: 'stripe_live_validation_10mxn'
      },
      receipt_email: email || undefined
    });

    console.log('[STRIPE VALIDATION] PaymentIntent LIVE $10 MXN creado:', paymentIntent.id, '| folio:', folio);
    return res.json({
      ok: true,
      validation: true,
      folio,
      clientSecret: paymentIntent.client_secret,
      client_secret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      payment_intent: paymentIntent.id,
      publishableKey: stripePublic
    });
  } catch (err) {
    console.error('[STRIPE VALIDATION] ❌ Error:', err.message || err);
    return res.status(500).json({ ok: false, error: 'stripe_validation_error' });
  }
});

// Confirmar payment intent
app.post('/api/confirm-payment-intent', async (req, res) => {
  try {
    if (!stripe || !stripeKeysAreLive) return res.status(503).json({ ok: false, error: 'stripe_live_keys_required' });
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

    if (!paymentIntentId) return res.status(400).json({ ok: false, error: 'missing_payment_intent_id' });

    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
    const paid = pi?.status === 'succeeded' && pi?.livemode === true;
    const finalPlan = resolvePlanSelection(body, answersData, pi?.metadata || {});
    const isLiveValidation = pi?.metadata?.validation_flow === 'live_10mxn';
    const planFromFE  = finalPlan.plan;
    const planLabelFromFE = finalPlan.planLabel;
    const planKeyFromFE = finalPlan.planKey;
    const medFromFE   = finalPlan.medication;
    const priceFromFE = isLiveValidation ? 10 : finalPlan.price;
    const edadFromFE = normalizeAge(patientData.age || patientData.edad || answersData.age || answersData.edad || body.age || body.edad || '');
    const pesoFromFE = normalizeWeightKg(patientData.weight || patientData.peso || answersData.weight || answersData.peso || answersData.pesoKg || body.weight || body.peso || body.pesoKg || '');

    console.log('[CONFIRM] folio:', folio, '| pi:', paymentIntentId);
    console.log('[PLAN] seleccionado:', planFromFE || '(vacío)');
    console.log('[PRECIO] seleccionado:', priceFromFE || '(vacío)');
    console.log('[CONFIRM] patient:', patientData.nombre||'(vacío)', patientData.apellido||'', '| edad:', edadFromFE || '(vacío)', '| peso:', pesoFromFE || '(vacío)');
    console.log('[CONFIRM] answers keys:', Object.keys(answersData).length, '| shipping:', !!shippingData.shipAddress1, '| fotos base64:', photosBase64.length);
    console.log('[CONFIRM] plan final:', planLabelFromFE || planFromFE || '(sin plan)', '| key:', planKeyFromFE || '(sin key)', '| precio:', priceFromFE || 0);

    const db = readDb();
    const idx = db.findIndex((row) => String(row.folio || '').toLowerCase() === folio.toLowerCase());
    let updatedRow = null;

    if (idx >= 0) {
      if (paid) {
        db[idx].payment_reference = paymentIntentId;
        db[idx].payment_status = 'paid';
        db[idx].status = STATES.PAGADO;
      } else if (db[idx].payment_status !== 'paid') {
        db[idx].payment_reference = paymentIntentId;
        db[idx].payment_status = String(pi?.status || 'unknown');
      }
      db[idx].updatedAt = new Date().toISOString();
      // Actualizar datos que llegaron en confirm (más completos que en el intake inicial)
      if (planFromFE  ) db[idx].plan       = planFromFE;
      if (planLabelFromFE) db[idx].planLabel = planLabelFromFE;
      if (planKeyFromFE) db[idx].plan_key = planKeyFromFE;
      if (medFromFE   ) db[idx].medication = medFromFE;
      if (priceFromFE ) db[idx].price      = priceFromFE;
      if (isLiveValidation) db[idx].validation_flow = 'live_10mxn';
      // Enriquecer con datos del paciente si el registro los tenía vacíos
      if (patientData.nombre   && !db[idx].nombre  ) db[idx].nombre   = sanitizeText(patientData.nombre, 120);
      if (patientData.apellido && !db[idx].apellido) db[idx].apellido = sanitizeText(patientData.apellido, 120);
      if (patientData.correo   && !db[idx].correo  ) db[idx].correo   = sanitizeText(patientData.correo, 120);
      if (patientData.whatsapp && !db[idx].whatsapp) db[idx].whatsapp = sanitizeText(patientData.whatsapp, 30);
      if (patientData.sexo     && !db[idx].sexo    ) db[idx].sexo     = sanitizeText(patientData.sexo, 20);
      if (edadFromFE) {
        db[idx].age = edadFromFE;
        db[idx].edad = edadFromFE;
      }
      if (pesoFromFE) {
        db[idx].weight = pesoFromFE;
        db[idx].peso = pesoFromFE;
      }
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
        age: edadFromFE || null,
        edad: edadFromFE || null,
        weight: pesoFromFE || null,
        peso: pesoFromFE || null,
        plan: planFromFE, planLabel: planLabelFromFE, plan_key: planKeyFromFE,
        medication: medFromFE, price: priceFromFE,
        validation_flow: isLiveValidation ? 'live_10mxn' : undefined,
        answers: answersData, shipping: shippingData,
        files: photosBase64.map((p,i)=>({field:`photo_${i+1}`,name:p.name||`foto-${i+1}.jpg`,type:p.type||'image/jpeg',data:p.data||null})).filter(f=>f.data),
        payment_reference: paymentIntentId, payment_status: paid ? 'paid' : 'unknown',
        status: paid ? STATES.PAGADO : STATES.CHECKOUT_PENDIENTE,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      };
      db.push(newRow);
      writeDb(db);
      updatedRow = newRow;
    }

    // ✅ CORREO MÉDICO COMPLETO CON PDF + FOTOS — solo si el pago fue exitoso
    if (paid && updatedRow && !updatedRow.mail_sent_payment) {
      const planFinal = updatedRow.plan || planFromFE || 'N/A';
      const precioFinal = updatedRow.price || priceFromFE || 0;
      console.log('[CONFIRM] plan final:', planFinal, '| precio final:', precioFinal, '| folio:', folio);
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
    } else if (!paid) {
      console.log('[CONFIRM] Pago NO confirmado como LIVE/paid — status:', pi?.status, '| livemode:', pi?.livemode, '— NO se envía correo/PDF/CRM');
    } else {
      console.log('[CONFIRM] Correo ya enviado previamente para folio:', folio);
      // Intentar Airtable igual (puede que no se haya guardado la primera vez)
      if (updatedRow && updatedRow.payment_status === 'paid') {
        try { await saveToAirtableAdmin(updatedRow, paymentIntentId); } catch(e) {}
      }
    }

    return res.json({
      ok: true,
      paid,
      payment_status: paid ? 'paid' : String(pi?.status || 'unknown'),
      status: pi?.status || 'unknown',
      folio
    });
  } catch (err) {
    console.error('[CONFIRM] ❌ Error:', err.message || err);
    return res.status(500).json({ ok: false, error: 'confirm_failed' });
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK DE STRIPE — Segunda línea de defensa para confirmar pago
// Evento: payment_intent.succeeded / checkout.session.completed
// ══════════════════════════════════════════════════════════════════
app.post('/api/stripe-webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!stripe || !stripeKeysAreLive) {
      console.error('[WEBHOOK] ❌ Stripe LIVE no configurado — webhook rechazado');
      return res.status(503).json({ ok: false, error: 'stripe_live_keys_required' });
    }
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      if (webhookSecret && sig) {
        event = stripe.webhooks.constructEvent(req.rawBody || req.body, sig, webhookSecret);
      } else {
        console.error('[WEBHOOK] ❌ STRIPE_WEBHOOK_SECRET requerido en producción');
        return res.status(503).json({ ok: false, error: 'webhook_secret_required' });
      }
    } catch (err) {
      console.error('[WEBHOOK] ❌ Firma inválida:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log('[WEBHOOK] Evento recibido:', event.type);

    if (event.type === 'payment_intent.succeeded' || event.type === 'checkout.session.completed') {
      const stripeObject = event.data.object;
      const isCheckoutSession = event.type === 'checkout.session.completed';
      const rawPaymentIntent = isCheckoutSession ? stripeObject.payment_intent : stripeObject.id;
      const paymentIntentId = sanitizeText(
        typeof rawPaymentIntent === 'object' ? (rawPaymentIntent?.id || '') : (rawPaymentIntent || ''),
        120
      );
      const folioMeta = stripeObject.metadata?.folio || stripeObject.metadata?.patient_reference ||
        stripeObject.client_reference_id || '';
      const webhookPaymentStatus = isCheckoutSession
        ? String(stripeObject.payment_status || '').toLowerCase()
        : (stripeObject.status === 'succeeded' ? 'paid' : String(stripeObject.status || '').toLowerCase());
      const webhookPaid = webhookPaymentStatus === 'paid' && stripeObject.livemode === true;

      console.log('[WEBHOOK]', event.type, '— folio meta:', folioMeta,
        '| pi:', paymentIntentId || '(sin pi)', '| payment_status:', webhookPaymentStatus);

      if (!webhookPaid) {
        console.log('[WEBHOOK] Pago no confirmado LIVE/paid — no se muestra success ni se envía correo/PDF/CRM. payment_status:',
          webhookPaymentStatus, '| livemode:', stripeObject.livemode);
        return res.json({ received: true, payment_status: webhookPaymentStatus || 'unknown' });
      }

      const db = readDb();
      const idx = db.findIndex((row) =>
        String(row.folio || '').toLowerCase() === folioMeta.toLowerCase() ||
        (paymentIntentId && String(row.payment_reference || '') === paymentIntentId)
      );

      if (idx >= 0) {
        const alreadyPaid = db[idx].status === STATES.PAGADO && db[idx].mail_sent_payment;
        if (alreadyPaid) {
          console.log('[WEBHOOK] Correo ya enviado para este folio — skip');
          return res.json({ received: true });
        }

        db[idx].payment_reference = paymentIntentId || db[idx].payment_reference;
        db[idx].payment_status = 'paid';
        db[idx].status = STATES.PAGADO;
        db[idx].updatedAt = new Date().toISOString();
        const finalPlan = resolvePlanSelection(stripeObject.metadata || {}, db[idx].answers || {}, db[idx]);
        const isLiveValidation = stripeObject.metadata?.validation_flow === 'live_10mxn';
        if (finalPlan.planKey) {
          db[idx].plan = finalPlan.plan;
          db[idx].planLabel = finalPlan.planLabel;
          db[idx].plan_key = finalPlan.planKey;
          db[idx].medication = finalPlan.medication;
          db[idx].price = isLiveValidation ? 10 : finalPlan.price;
          if (isLiveValidation) db[idx].validation_flow = 'live_10mxn';
          console.log('[CONFIRM] plan final:', finalPlan.planLabel, '| key:', finalPlan.planKey, '| precio:', db[idx].price);
        }
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

app.get('/api/payment-confirmation/:folio', (req, res) => {
  const folio = sanitizeText(req.params.folio || '', 80);
  if (!folio) return res.status(400).json({ ok: false, paid: false, error: 'missing_folio' });
  const db = readDb();
  const row = db.find((item) => String(item.folio || '').toLowerCase() === folio.toLowerCase());
  const paid = Boolean(row && row.status === STATES.PAGADO && row.payment_status === 'paid' && row.payment_reference);
  return res.json({
    ok: true,
    paid,
    payment_status: paid ? 'paid' : (row?.payment_status || 'unknown'),
    status: row?.status || 'unknown',
    folio
  });
});

// ✅ Config pública (solo public key — nunca secret key)
app.get('/api/config', (_req, res) => {
  res.json({
    ok: true,
    stripeMode: stripeKeysAreLive ? 'live' : 'invalid',
    publicKey: stripeKeysAreLive ? stripePublic : '',
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
    stripeReady: Boolean(stripe && stripePublic && stripeKeysAreLive),
    stripeMode: stripeKeysAreLive ? 'live' : 'invalid',
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
