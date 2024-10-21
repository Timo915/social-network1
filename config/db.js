// db.js
const mongoose = require('mongoose');

const connectDB = async () => {
    const uri = 'mongodb://newAdminUser:newAdminPassword@localhost:27017/admin'; // Убедитесь, что строка правильная
    try {
        await mongoose.connect(uri, {
            // уберите параметры, которые больше не нужны
        });
        console.log('MongoDB connected');
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

module.exports = connectDB;