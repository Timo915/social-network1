const mongoose = require('mongoose');

const CallSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    withUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    callData: {
        createdAt: { type: Date, default: Date.now }
    },
    status: { type: String, enum: ['incoming', 'outgoing', 'missed'], required: true }
});

module.exports = mongoose.model('Call', CallSchema);