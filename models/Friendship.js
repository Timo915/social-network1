//// models/Friendship.js

const mongoose = require('mongoose');

const FriendshipSchema = new mongoose.Schema({
    user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

const FriendshipModel = mongoose.model('Friendship', FriendshipSchema);

module.exports = FriendshipModel;