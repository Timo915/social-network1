// routes/postRoutes.js
const express = require('express');
const { createPost, getPosts, likePost, dislikePost, deletePost } = require('../controllers/postController');
const { protect } = require('../middleware/authMiddleware'); // Импортируйте middleware защиты

const router = express.Router();

// Используйте middleware защиты на всех маршрутах, где требуется аутентификация
router.use(protect); // Все следующие маршруты защищены

router.post('/', createPost); // Создание поста
router.get('/', getPosts); // Получение всех постов
router.post('/:postId/like', likePost); // Лайк поста
router.post('/:postId/dislike', dislikePost); // Дизлайк поста
router.delete('/:postId', deletePost); // Удаление поста

module.exports = router;