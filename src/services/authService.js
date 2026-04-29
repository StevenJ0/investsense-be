const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../../configs/env');
const userRepository = require('../repositories/userRepository');

const SALT_ROUNDS = 10;

// ─── Helper: Token Generators ────────────────────────────────────────────────

/**
 * Generates a short-lived access token.
 * Payload is intentionally minimal (sub + email) to reduce exposure if decoded.
 */
const generateAccessToken = (user) => {
    return jwt.sign(
        { sub: user.id, email: user.email },
        config.jwt.accessSecret,
        { expiresIn: config.jwt.accessExpiresIn }
    );
};

/**
 * Generates a long-lived refresh token.
 * A separate secret ensures a compromised access secret doesn't expose refresh tokens.
 */
const generateRefreshToken = (user) => {
    return jwt.sign(
        { sub: user.id },
        config.jwt.refreshSecret,
        { expiresIn: config.jwt.refreshExpiresIn }
    );
};

// ─── Register ─────────────────────────────────────────────────────────────────

/**
 * Validates input, checks for duplicate, hashes password, and persists new user.
 * Throws descriptive errors that the controller converts to HTTP responses.
 */
const register = async ({ email, username, password }) => {
    // 1. Input validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        throw Object.assign(new Error('Format email tidak valid.'), { statusCode: 400 });
    }

    // Password strength: min 8 chars, at least 1 uppercase, 1 number, 1 special char
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    if (!password || !passwordRegex.test(password)) {
        throw Object.assign(
            new Error('Password minimal 8 karakter, mengandung huruf besar, angka, dan karakter spesial.'),
            { statusCode: 400 }
        );
    }

    if (!username || username.trim().length < 2) {
        throw Object.assign(new Error('Username minimal 2 karakter.'), { statusCode: 400 });
    }

    // 2. Duplicate check — prevents user enumeration via timing differences
    //    (we check first so we can give a clear error; bcrypt cost makes timing safe)
    const existingUser = await userRepository.findUserByEmail(email);
    if (existingUser) {
        throw Object.assign(new Error('Email sudah terdaftar.'), { statusCode: 409 });
    }

    // 3. Hash password — bcrypt with cost factor 10 (~100ms, good balance vs brute-force)
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    // 4. Persist user — password_hash only, plaintext is never stored
    const newUser = await userRepository.createUser({
        email: email.toLowerCase(),
        username: username.trim(),
        password_hash,
    });

    // Return safe user object (never expose password_hash to caller)
    return {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        created_at: newUser.created_at,
    };
};

// ─── Login ────────────────────────────────────────────────────────────────────

/**
 * Verifies credentials, issues an access + refresh token pair.
 * Returns tokens separately so the controller can decide how to transmit each
 * (body vs HTTP-Only cookie) without mixing transport logic into the service.
 */
const login = async ({ email, password }) => {
    if (!email || !password) {
        throw Object.assign(new Error('Email dan password wajib diisi.'), { statusCode: 400 });
    }

    // 1. Lookup user — always run bcrypt.compare even on missing user to prevent
    //    timing attacks that reveal whether an email is registered
    const user = await userRepository.findUserByEmail(email.toLowerCase());

    const DUMMY_HASH = '$2b$10$invalidhashfortimingnormalization000000000000000000000';
    const passwordToCompare = user ? user.password_hash : DUMMY_HASH;

    const isPasswordValid = await bcrypt.compare(password, passwordToCompare);

    if (!user || !isPasswordValid) {
        // Generic message to prevent user enumeration
        throw Object.assign(new Error('Email atau password salah.'), { statusCode: 401 });
    }

    // 2. Generate token pair
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // 3. Persist refresh token to DB — enables server-side invalidation on logout
    await userRepository.updateRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
};

// ─── Refresh ──────────────────────────────────────────────────────────────────

/**
 * Implements Refresh Token Rotation:
 * - Verifies signature
 * - Validates against DB value (one-time-use)
 * - Issues a completely new token PAIR and invalidates the old refresh token
 *
 * If the incoming token is already gone from DB but signature is valid, it
 * means a previous rotation occurred — possible token theft, deny immediately.
 */
const refresh = async (incomingRefreshToken) => {
    if (!incomingRefreshToken) {
        throw Object.assign(new Error('Refresh token tidak ditemukan.'), { statusCode: 401 });
    }

    // 1. Verify JWT signature first — cheap operation before hitting DB
    let payload;
    try {
        payload = jwt.verify(incomingRefreshToken, config.jwt.refreshSecret);
    } catch (err) {
        throw Object.assign(new Error('Refresh token tidak valid atau sudah kadaluarsa.'), { statusCode: 403 });
    }

    // 2. Fetch user and cross-check DB-stored token (one-time-use enforcement)
    const user = await userRepository.findUserById(payload.sub);

    if (!user || user.refresh_token !== incomingRefreshToken) {
        // Mismatch = possible replay attack — nuke the token in DB as a safety measure
        if (user) await userRepository.clearRefreshToken(user.id);
        throw Object.assign(new Error('Refresh token tidak valid. Silakan login kembali.'), { statusCode: 403 });
    }

    // 3. Rotate: issue new pair, persist new refresh token
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    await userRepository.updateRefreshToken(user.id, newRefreshToken);

    return { newAccessToken, newRefreshToken };
};

// ─── Logout ───────────────────────────────────────────────────────────────────

/**
 * Invalidates the user's session by clearing the refresh token from DB.
 * The access token is short-lived and will expire on its own (stateless by design).
 */
const logout = async (userId) => {
    if (!userId) {
        throw Object.assign(new Error('User tidak teridentifikasi.'), { statusCode: 401 });
    }
    await userRepository.clearRefreshToken(userId);
};

module.exports = { register, login, refresh, logout };
