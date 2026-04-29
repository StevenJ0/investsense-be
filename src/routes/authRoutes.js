const { Router } = require('express');
const authController = require('../handlers/authController'); // Sesuaikan path-nya jika beda
const authMiddleware = require('../middlewares/authMiddleware');

const router = Router();

// Public routes (CUKUP TULIS UJUNGNYA SAJA)
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);

// Protected routes
router.post('/logout', authMiddleware, authController.logout);

module.exports = router;