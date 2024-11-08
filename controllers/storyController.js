// controllers/storyController.js
const Story = require('../models/Story');

// Создать новую историю
exports.createStory = async (req, res) => {
    try {
        const story = new Story({
            userId: req.user._id, // Предполагаем, что у вас настроена аутентификация с добавлением `req.user`
            content: req.body.content,
            mediaUrl: req.body.mediaUrl,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // История активна 24 часа
        });
        await story.save();
        res.status(201).json(story);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

// Получить истории от подписок пользователя
exports.getStories = async (req, res) => {
    try {
        const stories = await Story.find({
            userId: { $in: req.user.subscriptions }, // Предполагаем, что у пользователя есть массив подписок
            expiresAt: { $gt: new Date() } // Запрашиваем только активные истории
        }).populate('userId');
        res.json(stories);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};