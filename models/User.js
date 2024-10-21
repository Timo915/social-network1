// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // Добавил уникальность
    password: { type: String, required: true }, // Храните только хэш, не отправляйте его в ответах.
});

// Исключение поля password из вывода
userSchema.methods.toJSON = function () {
    const user = this;
    const userObject = user.toObject();
    
    delete userObject.password; // Исключите поле password
    return userObject;
};

// Экспортируем модель
const User = mongoose.model('User', userSchema);
module.exports = User;