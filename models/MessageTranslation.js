const mongoose = require('mongoose');

const messageTranslationSchema = new mongoose.Schema({
    originalContent: { type: String, required: true },
    translatedContent: { type: String, required: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

const MessageTranslation = mongoose.model('MessageTranslation', messageTranslationSchema);
module.exports = MessageTranslation;