# DERMATIKA Backend

Backend Express para `index.html`: intake medico con fotos, tracking, PaymentIntent de Stripe y webhook firmado.

## Instalacion

```bash
cd backend
npm install
cp .env.example .env
npm start
```

Endpoints principales:

- `GET /health`
- `POST /api/intake`
- `POST /api/track-event`
- `POST /api/create-stripe-payment-intent`
- `POST /api/stripe/webhook`

## Variables

Configura `.env`:

```bash
NODE_ENV=development
PORT=3000
FRONTEND_ORIGIN=http://localhost:3000
PUBLIC_SITE_URL=http://localhost:3000
DATA_ENCRYPTION_KEY=clave-larga-aleatoria

STRIPE_PUBLIC_KEY=pk_test_xxx
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

GMAIL_USER=tu_correo@gmail.com
GMAIL_APP_PASSWORD=tu_contrasena_de_aplicacion
ADMIN_EMAIL=correo_donde_quieres_recibir@gmail.com
```

En produccion usa HTTPS real, `NODE_ENV=production`, `PUBLIC_SITE_URL=https://tu-dominio.com`, `FRONTEND_ORIGIN=https://tu-frontend.com` y llaves live solo despues de completar pruebas.

## Pago

`POST /api/create-stripe-payment-intent` usa:

```js
stripe.paymentIntents.create()
```

El frontend confirma el pago en la pagina con Stripe Elements. DERMATIKA no captura ni guarda numero de tarjeta, vencimiento o CVC.

## Fotos

`POST /api/intake` usa `multer`:

```js
const upload = multer({ dest: uploadDir })
```

Campos aceptados:

- `photoFront`
- `photoLeft`
- `photoRight`

Las fotos quedan en `backend/uploads/` y los datos del paciente en `backend/data/pacientes.csv`.

## Avisos Por Gmail

Cuando `/api/intake` guarda un paciente, el backend manda un correo con `nodemailer` al `ADMIN_EMAIL`.

Variables requeridas en Render:

```bash
GMAIL_USER=tu_correo@gmail.com
GMAIL_APP_PASSWORD=tu_contrasena_de_aplicacion
ADMIN_EMAIL=correo_donde_quieres_recibir@gmail.com
```

Usa una contrasena de aplicacion de Gmail, no tu contrasena normal.

## Webhook Stripe

Configura en Stripe:

```text
https://tu-backend.com/api/stripe/webhook
```

El webhook usa:

```js
stripe.webhooks.constructEvent()
```

Con esto se verifican firmas reales de Stripe. El evento `payment_intent.succeeded` se registra en `backend/data/payments.csv`.
