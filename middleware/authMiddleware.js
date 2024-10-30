const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware для защиты маршрутов
const protect = async (req, res, next) => {
    let token;

    // Проверка заголовка Authorization
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Извлечение токена из заголовка
            token = req.headers.authorization.split(' ')[1];
            // Верификация токена
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            // Получаем пользователя в зависимости от ID токена
            req.user = await User.findById(decoded.id).select('-password'); 
            return next(); // Если все хорошо, продолжаем
        } catch (error) {
            console.error('Ошибка аутентификации:', error);
            return res.status(401).json({ message: 'Не авторизован, токен недействителен.' });
        }
    }

    // Если токен отсутствует
    return res.status(401).json({ message: 'Не авторизован, токен не найден.' });
};

module.exports = { protect };