const jwt = require('jsonwebtoken');
const config = require('../../configs/env');

/**
 * authMiddleware — protects private routes by validating the Access Token.
 *
 * Security decisions:
 *  - Reads ONLY from the Authorization header (Bearer scheme), NOT cookies.
 *    The access token is intentionally NOT in a cookie because:
 *    (a) it must be readable by the frontend (e.g., to pass to API calls)
 *    (b) its short lifetime (15m) already limits exposure
 *  - On any failure, returns 401 so the client can trigger a /refresh call.
 *  - Decoded payload is attached to req.user for downstream handlers.
 */
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    // Reject if header is absent or malformed
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Akses ditolak. Token tidak ditemukan.',
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Verify signature and expiry using the ACCESS secret (not refresh secret)
        const decoded = jwt.verify(token, config.jwt.accessSecret);

        // Attach decoded payload { sub, email, iat, exp } to request object
        req.user = decoded;
        next();
    } catch (err) {
        // Distinguish between expired and invalid tokens for better client UX
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token sudah kadaluarsa. Silakan perbarui token.',
            });
        }
        return res.status(403).json({
            success: false,
            message: 'Token tidak valid.',
        });
    }
};

module.exports = authMiddleware;