const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    commentText: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    likes: { type: Number, default: 0 }, // Счетчик лайков
    replies: [{ // Массив для хранения ответов
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        replyText: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
    }]
});

const Comment = mongoose.model('Comment', commentSchema);
module.exports = Comment;