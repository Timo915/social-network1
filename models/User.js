const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    subscriptions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    subscribers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    language: { type: String, default: 'ru' }, // язык интерфейса
    messageLanguage: { type: String, default: 'ru' }, // язык сообщений
});

// Исключение поля password из вывода
userSchema.methods.toJSON = function () {
    const user = this;
    const userObject = user.toObject();
    
    delete userObject.password; // Исключите поле password
    return userObject;
};

// Имя модели должно быть уникальным
const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = User;