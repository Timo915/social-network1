const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    files: [String],
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{ content: String, userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } }],
    createdAt: { type: Date, default: Date.now }
});

// Экспортируем модель Post
module.exports = mongoose.model('Post', postSchema);