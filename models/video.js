const mongoose = require('mongoose');

const videoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    title: { type: String, required: true },
    url: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
    // другие поля...
});

module.exports = mongoose.model('Video', videoSchema);