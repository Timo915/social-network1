const mongoose = require('mongoose');

// Обновленный Schema для истории
const StorySchema = new mongoose.Schema({
    userId: { type: String, required: true },
    videoUrl: { type: String, required: true },
    status: { type: String, default: 'public' }, // Можно изменить на 'private'
    viewers: [{ type: String }], // Массив для хранения id пользователей, которые просмотрели историю
    expiresAt: { type: Date } // Добавлено поле для срока действия
}, {
    timestamps: true // хранит даты создания и обновления
});

module.exports = mongoose.model('Story', StorySchema);