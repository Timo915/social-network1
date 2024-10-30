const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware'); // Путь к вашему middleware

router.get('/home', protect, async (req, res) => {
    try {
        const userId = req.user._id; // Получаем идентификатор пользователя из проверенного токена
        const search = req.query.search || ''; // Получение значения из параметров запроса

        // Получаем текущего пользователя для доступа к его подпискам
        const currentUser = await User.findById(userId).populate('subscriptions');

        // Получаем посты от пользователей, на которых подписан текущий пользователь
        const posts = await Post.find({ userId: { $in: currentUser.subscriptions } })
            .populate('userId')
            .sort({ createdAt: -1 }); // Сортировка по времени создания

        // Поиск пользователей по имени, если есть запрос
        let users = [];
        if (search) {
            users = await User.find({ username: new RegExp(search, 'i') }); // Регистронезависимый поиск
        } else {
            // Если поиск не инициирован, получаем список всех пользователей по умолчанию
            users = await User.find();
        }

        // Получаем доступные музыкальные треки
        const musicData = [
            { title: "Song 1", artist: "Artist 1", audioUrl: "/path/to/song1.mp3" },
            { title: "Song 2", artist: "Artist 2", audioUrl: "/path/to/song2.mp3" },
        ];

        // Получаем последние видео
        const videos = await Post.find({ videoUrl: { $exists: true, $ne: null } })
            .populate('userId')
            .sort({ createdAt: -1 }); // Сортировка по времени создания видео

        // Рендерим представление с данными
        res.render('home', { users, posts, search, currentUser, music: musicData, videos });
    } catch (error) {
        console.error('Ошибка при загрузке главной страницы:', error);
        res.status(500).send('Ошибка сервера'); // Обработка ошибок сервера
    }
});

module.exports = router;