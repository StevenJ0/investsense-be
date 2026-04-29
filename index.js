const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const config = require('./configs/env');

// Route modules
const authRoutes = require('./src/routes/authRoutes');

const app = express();

// ─── Core Middleware ──────────────────────────────────────────────────────────

app.use(cors({
    origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
    credentials: true, // Required so the browser sends/receives HTTP-Only cookies
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// cookie-parser must be registered BEFORE any route that reads req.cookies
app.use(cookieParser());

// ─── API Routes ───────────────────────────────────────────────────────────────

app.use('/api/v1/auth', authRoutes);

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── 404 & Global Error Handlers ─────────────────────────────────────────────

app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Route tidak ditemukan.' });
});

app.use((err, req, res, next) => {
    console.error('[GlobalError]', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────

app.listen(config.port, () => {
    console.log(`🚀 Server running on http://localhost:${config.port}`);
});
