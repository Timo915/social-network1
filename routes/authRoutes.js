// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/userController');
const { validateRegister, validateLogin } = require('../middleware/validationMiddleware');

// Регистрация
router.post('/register', validateRegister, async (req, res) => {
    try {
        const user = await register(req.body);
        res.status(201).json({ message: 'Пользователь успешно зарегистрирован.', user });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ message: 'Ошибка сервера. Повторите попытку позже.' });
    }
});

// Вход
router.post('/login', validateLogin, async (req, res) => {
    try {
        const { token, user } = await login(req.body);
        res.status(200).json({ message: 'Вход выполнен успешно.', token, user });
    } catch (error) {
        console.error('Ошибка входа:', error);
        if (error.name === 'AuthenticationError') {
            return res.status(401).json({ message: error.message });
        }
        res.status(500).json({ message: 'Ошибка сервера. Повторите попытку позже.' });
    }
});

module.exports = router;