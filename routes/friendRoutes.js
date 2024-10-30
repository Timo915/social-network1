const express = require('express');
const { protect } = require('../middleware/authMiddleware'); // Импорт middleware защиты
const Friendship = require('../models/Friendship'); // Убедитесь, что путь правильный

const router = express.Router();

// Защита всех маршрутов под '/friends'
router.use(protect);

// Примеры маршрутов
router.post('/send-friend-request/:friendId', async (req, res) => {
    const friendId = req.params.friendId;
    const userId = req.user._id; // Используйте userId из сессии

    try {
        let friendship = new Friendship({
            userId: userId,
            friendId: friendId,
            status: 'pending',
        });
        await friendship.save();
        
        res.status(200).json({ message: `Запрос на дружбу с ${friendId} отправлен.` });
    } catch (error) {
        console.error('Ошибка при отправке запроса дружбы:', error);
        res.status(500).json({ message: 'Не удалось отправить запрос на дружбу.' });
    }
});

module.exports = router;