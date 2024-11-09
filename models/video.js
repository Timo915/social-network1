const mongoose = require('mongoose');

// Определяем схему для модели Video
const videoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    path: { type: String, required: true }, // Путь к видеофайлу
    createdAt: { type: Date, default: Date.now } // Дата создания
});

// Вызываем метод pre-save для автоматической установки createdAt
videoSchema.pre('save', function (next) {
    if (!this.createdAt) {
        this.createdAt = Date.now(); // Устанавливаем время создания, если не указано
    }
    next();
});

// Создаем модель на основе схемы
const Video = mongoose.model('Video', videoSchema);

// Экспортируем модель
module.exports = Video;