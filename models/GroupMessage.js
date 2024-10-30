const mongoose = require('mongoose');

const groupMessageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' }, // Отправитель сообщения
    groupId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Group' }, // Группа, в которой было отправлено сообщение
    content: { type: String, required: true }, // Содержимое сообщения
}, { timestamps: true }); // Добавляет поля createdAt и updatedAt

const GroupMessage = mongoose.model('GroupMessage', groupMessageSchema);
module.exports = GroupMessage;