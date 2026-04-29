const supabase = require('../../configs/supabase');

const requireAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Akses ditolak. Token tidak ditemukan.' });
        }

        const token = authHeader.split(' ')[1];

        const { data, error } = await supabase.auth.getUser(token);

        if (error || !data.user) {
            return res.status(401).json({ message: 'Token tidak valid atau sudah kedaluwarsa.' });
        }

        req.user = data.user;

        next();
    } catch (err) {
        console.error('Auth Middleware Error:', err);
        res.status(500).json({ message: 'Terjadi kesalahan pada server.' });
    }
};

module.exports = { requireAuth };