const express = require('express');
const { sendMessage, getMessages } = require('../controllers/messageController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/', protect, sendMessage); // Отправка сообщения
router.get('/:roomId', protect, getMessages); // Получение сообщений в комнате

module.exports = router;