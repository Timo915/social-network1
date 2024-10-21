const Message = require('../models/Message');

// Отправка сообщения
exports.sendMessage = async (req, res) => {
    const { content, roomId } = req.body;

    const message = new Message({
        sender: req.user.id,
        content,
        roomId,
    });

    await message.save();
    res.status(201).json(message);
};

// Получение сообщений для комнаты
exports.getMessages = async (req, res) => {
    const { roomId } = req.params;
    const messages = await Message.find({ roomId }).populate('sender', 'username').sort({ createdAt: -1 });
    res.json(messages);
};