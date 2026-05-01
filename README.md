# DERMATIKA Backend

## 1. Instalar local
```bash
npm install
cp .env.example .env
npm start
```

## 2. Variables obligatorias en Render
```env
NODE_ENV=production
PORT=10000
FRONTEND_URL=https://TU-PAGINA.netlify.app
SMTP_USER=tu_correo@gmail.com
SMTP_PASS=contraseña_de_aplicación_de_Google
ADMIN_EMAIL=Dermatikainterno@gmail.com
DATA_ENCRYPTION_KEY=clave_larga_segura_de_32_caracteres_o_mas
```

## 3. Endpoints
- GET `/health`
- POST `/api/intake`
- POST `/api/track-event`
- POST `/api/create-payment`
- POST `/api/mercadopago/webhook`

## 4. CSV
- `backend/data/pacientes.csv`
- `backend/data/events.csv`

Nota: los campos sensibles se guardan cifrados en CSV. El correo se envía legible al correo interno.

## 5. Conectar con Netlify
En `dermatika-final.html`, cambia:
```js
API_BASE_URL: ""
```
por:
```js
API_BASE_URL: "https://TU-BACKEND.onrender.com"
```

## 6. Mercado Pago
Este backend deja lista la estructura, pero falta conectar el token real y la creación de preferencia/pago.
