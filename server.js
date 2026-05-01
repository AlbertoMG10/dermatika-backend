import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import nodemailer from "nodemailer";

const app = express();
const PORT = process.env.PORT || 10000;

const allowedOrigins = [
  "https://dermatika.mx",
  "https://www.dermatika.mx",
  "https://dermatika.netlify.app",
  "http://localhost:3000",
  "http://localhost:5173"
];
app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Origen no permitido por CORS"));
    }
  }
}));

app.use(express.json());

app.get("/", (req, res) => {
  res.send("DERMATIKA backend activo");
});

app.post("/api/send-email", async (req, res) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER || process.env.SMTP_USER,
        pass: process.env.EMAIL_PASS || process.env.SMTP_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER || process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER || process.env.SMTP_USER,
      subject: "Nuevo formulario DERMATIKA",
      text: JSON.stringify(req.body, null, 2)
    });

    res.json({ ok: true, message: "Correo enviado" });
  } catch (error) {
    console.error("Error enviando correo:", error);
    res.status(500).json({ ok: false, error: "No se pudo enviar el correo" });
  }
});

app.listen(PORT, () => {
  console.log(`DERMATIKA backend activo en puerto ${PORT}`);
});
