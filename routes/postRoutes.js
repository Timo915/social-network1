const express = require('express');
const { createPost, getPosts, likePost, dislikePost, deletePost } = require('../controllers/postController');
const { protect } = require('../middleware/authMiddleware'); // Middleware для защиты маршрутов

const router = express.Router();

router.post('/', protect, createPost); // Создание поста
router.get('/', getPosts); // Получение всех постов
router.post('/:postId/like', protect, likePost); // Лайк поста
router.post('/:postId/dislike', protect, dislikePost); // Дизлайк поста
router.delete('/:postId', protect, deletePost); // Удаление поста

module.exports = router;