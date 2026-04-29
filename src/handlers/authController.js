const authService = require('../services/authService');

// ─── Cookie Config ────────────────────────────────────────────────────────────
// Centralised so every route that sets/clears the cookie uses identical options.
const REFRESH_COOKIE_NAME = 'refreshToken';

const cookieOptions = {
    httpOnly: true,   // Prevents JavaScript access — XSS cannot steal the token
    secure: process.env.NODE_ENV === 'production', // HTTPS-only in prod
    sameSite: 'Strict', // CSRF protection: cookie not sent on cross-site requests
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds (matches JWT expiry)
    path: '/',
};

// ─── Register ─────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/auth/register
 * On success returns 201 with the new user profile (no tokens).
 */
const register = async (req, res) => {
    try {
        const { email, username, password } = req.body;
        const newUser = await authService.register({ email, username, password });

        return res.status(201).json({
            success: true,
            message: 'Registrasi berhasil.',
            data: newUser,
        });
    } catch (err) {
        return res.status(err.statusCode || 500).json({
            success: false,
            message: err.message || 'Terjadi kesalahan pada server.',
        });
    }
};

// ─── Login ────────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/auth/login
 * Access token → response body (short-lived, readable by client JS).
 * Refresh token → HTTP-Only cookie (long-lived, invisible to JS — XSS-safe).
 */
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const { accessToken, refreshToken } = await authService.login({ email, password });

        // Set refresh token in HTTP-Only cookie — never exposed to frontend JS
        res.cookie(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

        return res.status(200).json({
            success: true,
            message: 'Login berhasil.',
            data: { accessToken },
        });
    } catch (err) {
        return res.status(err.statusCode || 500).json({
            success: false,
            message: err.message || 'Terjadi kesalahan pada server.',
        });
    }
};

// ─── Refresh ──────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/auth/refresh
 * Reads the refresh token from the HTTP-Only cookie (never from the body).
 * Issues a new access token AND rotates the refresh token cookie.
 */
const refresh = async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
        const { newAccessToken, newRefreshToken } = await authService.refresh(incomingRefreshToken);

        // Rotate: replace old cookie with the new refresh token
        res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, cookieOptions);

        return res.status(200).json({
            success: true,
            message: 'Token berhasil diperbarui.',
            data: { accessToken: newAccessToken },
        });
    } catch (err) {
        // Clear potentially compromised cookie on failure
        res.clearCookie(REFRESH_COOKIE_NAME, { path: '/' });
        return res.status(err.statusCode || 500).json({
            success: false,
            message: err.message || 'Terjadi kesalahan pada server.',
        });
    }
};

// ─── Logout ───────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/auth/logout
 * Requires a valid access token (via authMiddleware) so we know WHICH user to log out.
 * Clears both the DB record and the HTTP-Only cookie.
 */
const logout = async (req, res) => {
    try {
        const userId = req.user?.sub;
        await authService.logout(userId);

        // Expire the cookie immediately
        res.clearCookie(REFRESH_COOKIE_NAME, { path: '/' });

        return res.status(200).json({
            success: true,
            message: 'Logout berhasil.',
        });
    } catch (err) {
        return res.status(err.statusCode || 500).json({
            success: false,
            message: err.message || 'Terjadi kesalahan pada server.',
        });
    }
};

module.exports = { register, login, refresh, logout };
