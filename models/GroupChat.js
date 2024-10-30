const mongoose = require('mongoose');

// Определяем схему участника группы
const participantSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Ссылка на модель пользователя
        required: true,
    },
    username: {
        type: String,
        required: true,
    },
});

// Определяем схему группового чата
const groupChatSchema = new mongoose.Schema({
    chatName: {
        type: String,
        required: true,
        trim: true,
    },
    avatar: {
        type: String,  // URL или путь к загруженному аватару
        default: null,
    },
    participants: [participantSchema], // Массив участников
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// Создаем модель группового чата
const GroupChat = mongoose.model('GroupChat', groupChatSchema);

module.exports = GroupChat;