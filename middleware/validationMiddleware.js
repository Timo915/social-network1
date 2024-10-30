// middleware/validationMiddleware.js
const { body, validationResult } = require('express-validator');

const validateRegister = [
    body('username').notEmpty().withMessage('Имя пользователя обязательно.'),
    body('email').isEmail().withMessage('Некорректный email.'),
    body('password').isLength({ min: 6 }).withMessage('Пароль должен содержать не менее 6 символов.'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

const validateLogin = [
    body('email').isEmail().withMessage('Некорректный email.'),
    body('password').notEmpty().withMessage('Пароль обязателен.'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

module.exports = {
    validateRegister,
    validateLogin
};