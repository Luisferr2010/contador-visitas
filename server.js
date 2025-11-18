// ===============================
//   Contador de Visitas - Node.js
// ===============================

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();

// -------------------------------
// Configuración general
// -------------------------------
app.use(express.json());
app.use(helmet());

// CORS (para permitir tu dominio)
app.use(
    cors({
        origin: ["https://www.kalamaryradio.com", "https://kalamaryradio.com"],
        methods: ["GET", "POST"],
    })
);

// Rate limit (para evitar spam)
const limiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutos
    max: 100, // 100 peticiones por IP
});
app.use(limiter);

// -------------------------------
// Base de datos SQLite
// -------------------------------
const db = new Database("visits.db");

// Crear tabla si no existe
db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// -------------------------------
// Variables de entorno
// -------------------------------
const IP_SALT = process.env.IP_SALT || "default_salt"; // asegura cambiarlo en Render
const ADMIN_PASS = process.env.ADMIN_PASS || "12345"; // cámbialo también

// Función para anonimizar IPs
function hashIP(ip) {
    return crypto
        .createHmac("sha256", IP_SALT)
        .update(ip)
        .digest("hex");
}

// -------------------------------
//     ENDPOINT: /visit (POST)
// -------------------------------
app.post("/visit", (req, res) => {
    try {
        const path = req.body.path || "/";
        const raw_ip =
            req.headers["cf-connecting-ip"] || // Cloudflare
            req.headers["x-forwarded-for"] || 
            req.socket.remoteAddress;

        const ip_hash = hashIP(raw_ip.toString());

        // Registrar visita solo si no se ha registrado en los últimos 24h
        const exists = db
            .prepare(
                "SELECT 1 FROM visits WHERE path = ? AND hash = ? AND created_at >= datetime('now','-1 day')"
            )
            .get(path, ip_hash);

        if (!exists) {
            db.prepare("INSERT INTO visits (path, hash) VALUES (?, ?)").run(
                path,
                ip_hash
            );
        }

        // Contador total
        const total = db
            .prepare("SELECT COUNT(*) AS c FROM visits WHERE path = ?")
            .get(path).c;

        res.json({ path, total });
    } catch (err) {
        console.error("Error en /visit:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// -------------------------------
//     ENDPOINT: /health (GET)
// -------------------------------
app.get("/health", (req, res) => {
    res.json({ status: "ok" });
});

// -------------------------------
//     ENDPOINT: /admin/count
// -------------------------------
app.get("/admin/count", (req, res) => {
    if (req.query.pass !== ADMIN_PASS) {
        return res.status(403).json({ error: "Forbidden" });
    }

    const total = db.prepare("SELECT COUNT(*) AS c FROM visits").get().c;

    res.json({
        total,
        msg: "OK (acceso correcto)"
    });
});

// -------------------------------
// Iniciar servidor
// -------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor contador activo en puerto ${PORT}`);
});
