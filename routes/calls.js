const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware'); // Импорт protect

router.get('/chat/:userId', protect, (req, res) => {
    const userId = req.params.userId;
    res.send(`Chat with user: ${userId}`);
});

router.get('/calls', protect, async (req, res) => {
    try {
        // Логика обработки вызовов
        res.send("Calls page");
    } catch (error) {
        res.status(500).send('Ошибка сервера');
    }
});

module.exports = router;