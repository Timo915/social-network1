const mongoose = require('mongoose');

const videoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    path: { type: String, required: true }, // Путь к видеофайлу
    createdAt: { type: Date, default: Date.now }
});

const Video = mongoose.model('Video', videoSchema);
module.exports = Video;