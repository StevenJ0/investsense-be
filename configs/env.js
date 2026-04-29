require('dotenv').config();

module.exports = {
    port: process.env.PORT || 8080,
    supabase: {
        url: process.env.SUPABASE_URL,
        key: process.env.SUPABASE_KEY,
    },
    jwt: {
        accessSecret: process.env.JWT_ACCESS_SECRET,
        refreshSecret: process.env.JWT_REFRESH_SECRET,
        accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    },
};