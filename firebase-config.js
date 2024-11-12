require('dotenv').config();
const admin = require('firebase-admin');

// Инициализация приложения Firebase с параметрами из переменных окружения
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.GOOGLE_PROJECT_ID,
        clientEmail: process.env.GOOGLE_CLIENT_EMAIL,
        privateKey: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'), // Замените символы
    }),
});

// Экспортируйте админ SDK для использования в других частях приложения
module.exports = admin;