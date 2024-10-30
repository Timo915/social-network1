// models/music.js
const mongoose = require('mongoose');

const musicSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Ссылка на модель User
        required: true
    },
    title: {
        type: String,
        required: true
    },
    artist: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Music = mongoose.model('Music', musicSchema);
module.exports = Music;