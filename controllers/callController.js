const Call = require('../models/Call'); // Импортируем модель звонков

// Функция для создания нового звонка
const createCall = async (req, res) => {
    try {
        // Извлекаем необходимые данные из тела запроса
        const { roomId, withUser } = req.body;

        // Создаем новый объект звонка
        const newCall = new Call({
            userId: req.user.id, // Идентификатор текущего пользователя
            roomId,
            withUser,
        });

        // Сохраняем новый звонок в базе данных
        await newCall.save();

        // Возвращаем созданный звонок с статусом 201
        res.status(201).json(newCall);
    } catch (error) {
        console.error('Ошибка при создании звонка:', error);
        res.status(500).send('Ошибка сервера');
    }
};

// Функция для получения истории звонков по roomId
const getCalls = async (req, res) => {
    try {
        const { roomId } = req.params; // Извлекаем roomId из параметров запроса

        // Находим звонки по roomId
        const calls = await Call.find({ roomId })
            .populate('withUser') // Заполняем данные пользователя, с которым был звонок
            .sort({ createdAt: -1 }); // Сортируем звонки по времени создания в порядке убывания

        // Возвращаем найденные звонки
        res.json(calls);
    } catch (error) {
        console.error('Ошибка при получении звонков:', error);
        res.status(500).send('Ошибка сервера');
    }
};

module.exports = { createCall, getCalls };