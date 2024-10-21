
const mongoose = require('mongoose');

const FriendshipSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    friendId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' },
}, { timestamps: true });

module.exports = mongoose.model('Friendship', FriendshipSchema);