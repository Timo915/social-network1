// models/Like.js
const mongoose = require('mongoose');

const likeSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

// Экспортируем модель
const Like = mongoose.model('Like', likeSchema);
module.exports = Like;