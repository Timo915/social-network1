// friendsService.js
const User = require('./models/User'); // Импортируйте вашу модель User!

const getFriendsByUserId = async (userId) => {
    try {
        const user = await User.findById(userId).populate('friends', 'username'); // Замените 'username' на любые необходимые поля
        return user.friends; // Возвращаем массив друзей
    } catch (error) {
        console.error('Ошибка при получении списка друзей:', error);
        throw error; // Перебрасываем ошибку выше
    }
};

module.exports = { getFriendsByUserId }; // Экспортируйте вашу функцию