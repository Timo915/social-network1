// server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');
const bcrypt = require('bcryptjs'); // Используйте bcryptjs вместо bcrypt
const http = require('http');
const socketIo = require('socket.io');

const router = express.Router();
const User = require('./models/User'); // Импортируйте только один раз
const Call = require('./models/Call'); 
const callsRouter = require('./routes/calls');
const Music = require('./models/music'); // или путь к вашей модели
const Video = require('./models/video'); // Укажите правильный путь к вашей модели
const Notification = require('./models/Notification'); // Измените путь, если необходимо

const GroupChat = require('./models/GroupChat');
const GroupMessage = require('./models/GroupMessage'); // Замените на правильный путь

const { protect } = require('./middleware/authMiddleware'); // Добавьте эту строку в начало вашего файла server.js
const multer = require('multer');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Убедитесь, что эта папка существует
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Уникальное имя файла
    }
});

const upload = multer({ storage: storage });

const Comment = require('./models/Comment'); // Путь может различаться в зависимости от вашей структуры файлов
const Like = require('./models/Like'); // Путь может отличаться
const Friendship = require('./models/Friendship');
const FriendRequest = require('./models/FriendRequest'); // Путь должен быть правильным относительно вашего проекта
// Предположим, у вас есть модель Post
const Post = require('./models/Post');

// Импортируем Passport
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;



// В начале вашего server.js или в соответствующем файле
const Message = require('./models/Message');
// Инициализация приложения
const app = express();
const PORT = process.env.PORT || 5000;

// Создание сервера HTTP
const server = http.createServer(app);
const io = socketIo(server); // Инициализация Socket.IO
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Десериализация пользователя из сессии
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});
app.use(session({
    secret: 'your_jwt_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60, // 1 час
        secure: false
    }
}));
// Также можно добавить middleware для flash-сообщений
app.use(flash());
// Вы также можете настроить переменные для отображения flash-сообщений
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});
// Подключение вашего роутера





// Для парсинга application/json
app.use(express.json());

// Для парсинга application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// Подключение к MongoDB
mongoose.connect('mongodb+srv://mrborovry:Pins8hXZroPNQGVF@cluster0.vkuwm.mongodb.net/social-network?retryWrites=true&w=majority', {
    
})
.then(() => console.log('MongoDB Atlas connected'))
.catch((err) => console.error('MongoDB connection error:', err));
// Модель пользователя


// Настройка view engine на EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize()); // Подключаем Passport
app.use(passport.session()); // Подключаем сессии

app.use(express.static(path.join(__dirname, 'public')));



// Настраиваем стратегию локальной аутентификации
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            // Найти пользователя по имени
            const user = await User.findOne({ username });
            
            // Проверка на существование пользователя
            if (!user) {
                return done(null, false, { message: 'Неверное имя пользователя.' });
            }

            // Проверка на существование пароля
            if (!user.password) {
                return done(null, false, { message: 'Учетная запись пользователя не имеет пароля.' });
            }

            // Сравнить предоставленный пароль с зашифрованным паролем
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { message: 'Неверный пароль.' });
            }

            // Если все проверки пройдены, вернуть пользователя
            return done(null, user);
        } catch (error) {
            console.error('Ошибка при аутентификации пользователя:', error); // Логируем ошибку
            return done(error); // Передать ошибку в done
        }
    }
));

// Сериализация пользователя в сессию

// Обратите внимание, что ваш код для маршрутов должен быть ниже этих middleware

// Обработчик для маршрута чата
router.get('/chat/:userId', (req, res) => {
    const userId = req.params.userId;

    // здесь должен быть код для поиска чата с указанным userId
    // например, получение сообщений из базы данных

    // Пример:
    Message.find({ userId: userId })
        .then(messages => {
            res.render('chat', { messages, userId });
        })
        .catch(err => {
            res.status(500).send("Ошибка получения сообщений");
        });
});

module.exports = router;

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next(); // Если пользователь аутентифицирован, передаем управление дальше
    }
    res.redirect('/login'); // Если нет, перенаправляем на страницу логина
}

app.get('/styles.css', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/styles.css')); // Убедитесь, что путь к файлу правильный
});

app.get('/home', isAuthenticated, async (req, res) => {
    const userId = req.user._id; // Получаем id текущего пользователя
    const search = req.query.search || ''; // Считываем строку поиска
    let users = [];
    let music = [];
    let videos = [];

    try {
        // Получаем текущего пользователя с его подписками
        const currentUser = await User.findById(userId).populate('subscriptions');

        // Получаем посты от друзей (подписок текущего пользователя)
        const posts = await Post.find({
            userId: { $in: currentUser.subscriptions }
        })
        .populate('userId')
        .sort({ createdAt: -1 });

        // Поиск пользователей по имени, если строка поиска не пустая
        if (search.length > 0) { // только если длина строки поиска больше 0
            users = await User.find({ username: new RegExp(`^${search}`, 'i') }); // Изменяем на ^ (начало строки)
        } else {
            // Если строка поиска пустая, можно получить всех пользователей (исключая текущего)
            users = await User.find({ _id: { $ne: userId } });
        }

        // Получаем музыкальные треки для текущего пользователя
        music = await Music.find({ userId: userId });

        // Получаем видео для текущего пользователя
        videos = await Video.find({ userId: userId }).populate('userId');

        // Передаем данные в шаблон
        res.render('home', {
            posts,
            currentUser,
            users,
            search,
            music,
            videos
        });
    } catch (error) {
        console.error('Ошибка при загрузке главной страницы:', error);
        res.status(500).send('Ошибка сервера');
    }
});



// Главная страница, чтобы перенаправить на /home
app.get('/', (req, res) => {
    res.redirect('/home');
});

// Маршруты входа и регистрации
app.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
});

app.get('/register', (req, res) => {
    res.render('register');
});


// Обработчик для регистрации пользователя
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            req.flash('error', 'Пользователь с таким именем уже существует');
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.redirect('/login');
    } catch (error) {
        console.error("Registration error:", error);
        req.flash('error', 'Ошибка регистрации. Пожалуйста, повторите попытку.');
        res.redirect('/register');
    }
});

// Обработчик для логина
// Обработчик для логина
app.post('/login', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/login',
    failureFlash: true,
}), (req, res) => {
    req.session.user = req.user; // устанавливаем текущего пользователя в сессии
    res.redirect('/home');
});

// Socket.IO
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('initiate-voice-call', async ({ userId }) => {
        if (!userId || !socket.request.user._id) {
            console.error('Недостаточно данных для инициации голосового вызова:', { userId });
            return;
        }
        
        const newCall = new Call({
            userId: socket.request.user._id,
            withUser: userId,
            callData: {
                type: 'voice',
                createdAt: new Date()
            },
            status: 'incoming'
        });
    
        try {
            const savedCall = await newCall.save();
            console.log('Голосовой вызов инициирован:', savedCall);
            io.to(userId).emit('incoming-voice-call', {
                callerId: socket.request.user._id,
                callDetails: savedCall
            });
        } catch (error) {
            console.error('Ошибка при сохранении голосового вызова:', error);
        }
    });

    // Событие для входящего вызова
    socket.on('call', (data) => {
        // Отправка уведомления всем клиентам, кроме инициатора
        socket.broadcast.emit('incoming-call', { callerId: data.callerId, callId: data.callId });
    });

    // Пример регистрации пользователя
    socket.on('register', (userId) => {
        users[userId] = socket.id;
    });

    socket.on('connect', () => {
        console.log('Соединение установлено с сервером.');
    });
    
    socket.on('chat message', (msg) => {
        io.emit('chat message', msg); // Отправляет сообщение всем пользователям
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });

    // Обработка инициации звонка
    // Обработка входящего звонка
    socket.on('initiate-call', async ({ userId, callType }) => {
        if (!userId || !socket.request.user._id) {
            console.error('Неудовлетворительные данные для инициации вызова:', { userId });
            return;
        }

        const newCall = new Call({
            userId: socket.request.user._id,
            withUser: userId,
            callData: { type: callType, createdAt: new Date() },
            status: 'incoming'
        });

        try {
            const savedCall = await newCall.save();
            console.log('Call initiated:', savedCall);
            io.to(userId).emit('incoming-call', { callerId: socket.request.user._id, callDetails: savedCall });
        } catch (error) {
            console.error('Ошибка при сохранении звонка:', error);
        }
    });

    // Обработка принятия звонка
    socket.on('accept-call', async (callId) => {
        if (!callId) {
            console.error('Не передан ID звонка.');
            return;
        }

        try {
            const call = await Call.findByIdAndUpdate(callId, { status: 'accepted' });
            if (!call) {
                console.error('Вызов не найден с ID:', callId);
                return;
            }
            console.log('Call accepted:', call);
        } catch (error) {
            console.error('Ошибка при принятии звонка:', error);
        }
    });

    socket.on('end-call', async (call) => {
        await Call.findByIdAndUpdate(call._id, { status: 'ended' });
        socket.emit('call-ended');
        socket.to(call.withUser).emit('call-ended');
    });

    socket.on('initiate-call', (data) => {
        const { friendId } = data;
        socket.broadcast.emit('incoming-call', { callerId: socket.id });
    });


    // Пример обработчика входящего звонка
    
    

});

async function initiateVideoCall(userId) {
    try {
        if (!userId) {
            throw new Error('Необходимо указать идентификатор пользователя для видеозвонка.');
        }
        currentCallRecipientId = userId;
        document.getElementById('callRecipient').innerText = `Пользователь ${userId}`;
        document.getElementById('callInterface').style.display = 'block';
        
        currentStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        socket.emit('initiate-call', { userId }); // Инициируем звонок через сокет

        callTimer = setTimeout(handleMissedCall, 300000);  // 5 минут ожидания
        alert(`Видеозвонок с пользователем ${userId} инициализирован!`);

    } catch (error) {
        console.error('Ошибка инициации видеозвонка:', error);
        alert(error.message); // Покажите ошибку пользователю
    }
}

app.get('/incoming-calls', async (req, res) => {
    try {
        const calls = await Call.find(); // Предполагается, что ваши вызовы содержат callerId

        const enrichedCalls = await Promise.all(calls.map(async (call) => {
            const callerId = call.callerId;

            if (!callerId) {
                console.warn(`CallerId для вызова отсутствует: ${call}`);
                return { ...call.toObject(), caller: { id: null, username: 'Имя пользователя недоступно' } };
            }

            const caller = await User.findById(callerId);
            if (!caller) {
                console.warn(`Пользователь с ID ${callerId} не найден`);
                return { ...call.toObject(), caller: { id: null, username: 'Имя пользователя недоступно' } };
            }

            return { ...call.toObject(), caller: { id: caller._id, username: caller.username } };
        }));

        res.json(enrichedCalls);
    } catch (error) {
        console.error("Ошибка при получении входящих вызовов:", error);
        res.status(500).json({ message: "Внутренняя ошибка сервера." });
    }
});

app.get('/api/calls', async (req, res) => {
    try {
        const calls = await Call.find({ userId: req.user._id }) // Ваш оригинальный запрос
            .populate('withUser', 'username'); // Пополнение информации о пользователе

        return res.json(calls); // Отправка всех звонков
    } catch (error) {
        console.error('Ошибка при извлечении звонков:', error);
        return res.status(500).json({ message: 'Ошибка при извлечении звонков' });
    }
});

app.get('/calls', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }

    try {
        console.log('Current user ID:', req.user.id);

        // Получаем все звонки текущего пользователя
        const calls = await Call.find({ userId: req.user.id }).populate('withUser');
        console.log('Calls found:', calls);

        // Получаем пользователя текущего пользователя из модели User
        const user = await User.findById(req.user.id).populate('friends', 'username'); // или добавьте другие поля, которые вам нужны
        console.log('User found:', user);

        // Список друзей будет в user.friends
        const friendsArray = user.friends;

        res.render('calls', { calls, friends: friendsArray });
    } catch (error) {
        console.error('Ошибка при загрузке звонков:', error);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/api/calls', async (req, res) => {
    try {
        // Ваш код для получения данных о звонках
        const calls = await Call.find(); // пример использования Mongoose
        res.status(200).json(calls);
    } catch (error) {
        console.error('Ошибка при получении звонков:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.post('/api/mark-missed-call/:userId', isAuthenticated, async (req, res) => {
    const userId = req.params.userId;

    try {
        const call = await Call.findOne({ userId: userId, status: 'incoming' });
        if (!call) {
            return res.status(404).json({ message: 'Звонок не найден.' });
        }

        call.status = 'missed';
        await call.save();

        res.status(200).json({ message: 'Звонок помечен как пропущенный.' });
    } catch (error) {
        console.error('Ошибка при пометке звонка как пропущенного:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.post('/api/initiate-call', isAuthenticated, async (req, res) => {
    const { friendId, callType } = req.body; // Получаем friendId и callType из тела запроса

    const newCall = new Call({
        userId: req.user._id, // ID инициатора звонка
        withUser: friendId, // ID пользователя, с которым идет звонок
        callData: {
            type: callType,
            // Добавьте другие необходимые данные о звонке, если нужно
            createdAt: new Date() // Дополнительные поля, если нужно
        },
        status: callType === 'outgoing' ? 'outgoing' : 'incoming' // Определяем статус
    });

    try {
        await newCall.save();
        console.log('Call initiated:', newCall);
        res.status(201).json({ success: true, message: 'Звонок сохранен в базе данных.' });
    } catch (error) {
        console.error('Ошибка при сохранении звонка:', error);
        res.status(500).json({ success: false, message: 'Ошибка при сохранении звонка.' });
    }
});

app.post('/api/accept-call/:callId', async (req, res) => {
    try {
        const callId = req.params.callId;
        // Логика принятия звонка здесь
        // Например, обновление статуса звонка в базе данных
        const result = await acceptCall(callId, req.user.id);
        if (result.success) {
            return res.status(200).send('Звонок принят');
        } else {
            return res.status(400).send('Не удалось принять звонок');
        }
    } catch (error) {
        console.error('Ошибка при принятии звонка:', error);
        res.status(500).send('Ошибка сервера');
    }
});

// Маршрут для сохранения звонка
app.post('/api/calls', async (req, res) => {
    const { userId, withUser } = req.body; // Получаем userId (звонивший) и withUser (кому звонят)
    
    try {
        // Создание исходящего звонка
        const outgoingCall = new Call({
            userId: userId,
            withUser: withUser,
            status: 'outgoing',
            callData: { createdAt: new Date() }
        });
        
        await outgoingCall.save();
        
        // Создание входящего звонка
        const incomingCall = new Call({
            userId: withUser, // ID получателя звонка
            withUser: userId, // ID звонящего
            status: 'incoming',
            callData: { createdAt: new Date() }
        });
        
        await incomingCall.save();

        return res.status(201).json({ message: 'Calls recorded successfully' });
    } catch (error) {
        console.error('Error saving calls:', error);
        return res.status(500).json({ message: 'Error saving calls' });
    }
});

app.post('/api/mark-call-completed', async (req, res) => {
    const { callId } = req.body; // expect the callId to be sent in the request body
    // Логика для обновления статуса звонка
    try {
        // Предполагается использование вашей БД, чтобы обновить звонок
        const updatedCall = await Call.findByIdAndUpdate(callId, { status: 'completed' }, { new: true });
        return res.json(updatedCall);
    } catch (error) {
        console.error('Ошибка при обновлении статуса звонка:', error);
        return res.status(500).json({ message: 'Ошибка при обновлении статуса звонка' });
    }
});

app.get('/api/get-user/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const user = await User.findById(userId); // Предполагается использование вашей БД
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден.' });
        }
        return res.json(user);
    } catch (error) {
        console.error('Ошибка при получении пользователя:', error);
        return res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Определение функции
function getCurrentUserFromSession(req) {
    return req.session.user; // Замените в зависимости от вашей логики
}

// Ваши маршруты
app.get('/api/current-user',isAuthenticated, (req, res) => {
    console.log('Текущие данные сессии:', req.session);
    console.log('Текущий пользователь:', req.user);
    
    if (!req.user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.json(req.user); 
});
// Обработчик для создания постов


// Страница профиля
app.get('/profile/:id', async (req, res) => {
    try {
        const targetUserId = req.params.id;
        const userProfile = await User.findById(targetUserId).populate('friends').exec();
        
        if (!userProfile) {
            return res.status(404).send('Пользователь не найден.');
        }

        // Получаем текущего пользователя (если аутентифицирован)
        const currentUser = req.user || null; // Обратите внимание, что вы используете это для передачи

        // Проверка друг ли это и был ли отправлен запрос на дружбу
        const isFriend = currentUser && userProfile.friends.includes(currentUser._id);
        const isRequestSent = currentUser && currentUser.friendRequests.includes(targetUserId);

        // Получение постов пользователя
        const posts = await Post.find({ userId: targetUserId })
            .sort({ createdAt: -1 })
            .populate('likes')
            .populate('comments')
            .exec();

        // Рендеринг страницы профиля
        res.render('profile', {
            user: userProfile,
            isAuthenticated: req.isAuthenticated(),
            currentUser: currentUser, // Передаем текущего пользователя
            posts: posts,
            errorMessage: '',
            isFriend: isFriend,
            isRequestSent: isRequestSent
        });
    } catch (error) {
        console.error('Ошибка при получении профиля:', error);
        res.status(500).send('Ошибка сервера. Пожалуйста, попробуйте позже.');
    }
});



function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Необходима аутентификация' });
}

// Страница редактирования видео
app.get('/edit-video', (req, res) => {
    res.render('edit-video'); // Здесь вы можете добавить сложный видеоредактор
});


// Получение сообщений между пользователями
app.get('/messages/:recipientId', async (req, res) => {
    const recipientId = req.params.recipientId;

    // Проверяем, что пользователь аутентифицирован
    if (!req.user || !req.user.id) {
        return res.status(403).json({ message: 'Forbidden: User not authenticated.' });
    }

    try {
        // Получаем количество непрочитанных сообщений
        const unreadCount = await Message.countDocuments({
            receiverId: req.user.id,
            isRead: false
        });

        // Найдем сообщения между пользователями
        const messages = await Message.find({
            $or: [
                { senderId: req.user.id, receiverId: recipientId },
                { senderId: recipientId, receiverId: req.user.id }
            ]
        }).populate('senderId receiverId');

        // Проверяем, если сообщения найдены
        if (!messages || messages.length === 0) {
            return res.status(404).json({ message: 'No messages found.' });
        }

        // Обновляем статус сообщений как "прочитано", если они отправлены к текущему пользователю
        await Message.updateMany(
            { senderId: recipientId, receiverId: req.user.id, isRead: false },
            { $set: { isRead: true } }
        );

        // Форматируем сообщения для передачи в шаблон
        const formattedMessages = messages.map(message => ({
            id: message._id,
            sender: {
                id: message.senderId._id,
                username: message.senderId.username,
            },
            receiver: {
                id: message.receiverId._id,
                username: message.receiverId.username,
            },
            content: message.content,
            createdAt: message.createdAt,
            isRead: message.isRead
        }));

        // Отправляем рендеринг шаблона с сообщениями и количеством непрочитанных сообщений
        res.render('messages', {
            messages: formattedMessages,
            recipientId: recipientId,
            user: req.user,
            unreadCount: unreadCount // Передаем количество непрочитанных сообщений
        });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'An error occurred while fetching messages.' });
    }
});


// Отправка сообщения
app.post('/send-message/:recipientId', async (req, res) => {
    const recipientId = req.params.recipientId;
    const content = req.body.content;

    try {
        const message = new Message({
            senderId: req.user.id, // текущий пользователь
            receiverId: recipientId,
            content: content,
            isRead: false // по умолчанию - не прочитано
        });

        await message.save();
        res.redirect(`/messages/${recipientId}`); // Перенаправление на переписку с этим получателем
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'An error occurred while sending the message.' });
    }
});





app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/login');
    });
});

app.get('/history', isAuthenticated, async (req, res) => {
    const currentUserId = req.user.id;

    try {
        // Извлечение всех личных сообщений для текущего пользователя
        const messages = await Message.find({
            $or: [
                { senderId: currentUserId },
                { receiverId: currentUserId }
            ]
        })
        .populate('senderId', 'username profilePicture')  
        .populate('receiverId', 'username profilePicture')  
        .sort({ createdAt: -1 });

        const dialogues = {};

        // Обработка личных сообщений
        messages.forEach(message => {
            const otherUser = message.senderId._id.toString() === currentUserId 
                ? message.receiverId 
                : message.senderId;

            if (otherUser) {
                const otherUserId = otherUser._id.toString();
                if (!dialogues[otherUserId]) {
                    dialogues[otherUserId] = {
                        userId: otherUserId,
                        lastMessage: message.content,
                        lastMessageDate: message.createdAt,
                        userInfo: {
                            name: otherUser.username || 'Неизвестный',
                            profilePicture: otherUser.profilePicture || '/default-avatar.png',
                        },
                        isGroupChat: false,
                        unreadCount: message.isRead ? 0 : 1, // Индикатор непрочитанных сообщений
                    };
                } else {
                    // Обновление последнего сообщения, если оно более новое
                    if (message.createdAt > dialogues[otherUserId].lastMessageDate) {
                        dialogues[otherUserId].lastMessage = message.content;
                        dialogues[otherUserId].lastMessageDate = message.createdAt;
                    }
                    if (!message.isRead) {
                        dialogues[otherUserId].unreadCount++;
                    }
                }
            }
        });

        // Извлечение групповых чатов
        const groupChats = await GroupChat.find({
            'participants.userId': currentUserId
        })
        .populate('participants.userId', 'username profilePicture');

        // Добавление информации о групповых чатах
        for (const chat of groupChats) {
            const lastMessage = chat.lastMessage ? chat.lastMessage.content : 'Нет сообщений';
            const lastMessageDate = chat.lastMessage ? chat.lastMessage.createdAt : chat.createdAt;
            const unreadCount = chat.lastMessage && chat.lastMessage.isRead === false ? 1 : 0; // Индикатор непрочитанных сообщений

            dialogues[chat._id.toString()] = {
                userId: chat._id.toString(),
                lastMessage: lastMessage,
                lastMessageDate: lastMessageDate,
                userInfo: {
                    name: chat.chatName || 'Группа без названия',
                    profilePicture: chat.avatar || '/default-group-avatar.png',
                },
                isGroupChat: true,
                participantsCount: chat.participants.length,
                unreadCount: unreadCount // Количество непрочитанных сообщений группы
            };
        }

        const results = Object.values(dialogues).sort((a, b) => b.lastMessageDate - a.lastMessageDate);
        res.render('history', { dialogues: results, user: req.user });
    } catch (error) {
        console.error('Ошибка при получении истории сообщений:', error);
        return res.status(500).render('error', { message: 'Ошибка при получении истории сообщений.' });
    }
});


app.get('/api/unread-messages',isAuthenticated, async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(403).json({ message: 'Пользователь не аутентифицирован' });
    }

    try {
        const unreadCount = await getUnreadMessagesCount(req.user.id);
        res.json({ totalCount: unreadCount });
    } catch (error) {
        console.error('Ошибка при получении количества непрочитанных сообщений:', error);
        res.status(500).json({ message: 'Ошибка сервера. Не удалось получить количество сообщений.' });
    }
});

// Обработчик для создания постов
// Создание поста через POST-запрос
// Создание поста через POST-запрос
// Создание поста через POST-запрос
app.post('/api/create-post', upload.array('files'), isAuthenticated, async (req, res) => {
    try {
        const { content } = req.body;
        const userId = req.user._id; // Берем ID текущего пользователя
        const files = req.files ? req.files.map(file => file.path) : []; // Получаем массив путей к загруженным файлам

        // Проверка контента
        if (!content && files.length === 0) {
            return res.status(400).send('Необходимо указать либо контент, либо загрузить файл.');
        }

        // Создание нового поста
        const newPost = new Post({
            userId,
            content,
            files: files || [],
            likes: [],
            dislikes: [],
        });

        await newPost.save(); // Сохранение поста в базе данных
        console.log('Пост успешно создан:', newPost); // Логирование созданного поста

        res.status(201).json(newPost); // Возвращаем созданный пост в формате JSON
    } catch (error) {
        console.error('Ошибка создания поста:', error);
        res.status(500).send('Ошибка при создании поста');
    }
});

// Страница создания поста через GET-запрос
app.get('/create-post', (req, res) => {
    const user = req.session.user; // Пример получения пользователя из сессии

    // Прежде чем рендерить шаблон, вы можете добавить лог для отладки
    console.log('Данные пользователя:', user);

    res.render('create-post', { user }); // Передаем user в шаблон
});

app.get('/get-posts', isAuthenticated, async (req, res) => {
    const userId = req.session.passport.user;

    try {
        const posts = await Post.find({ userId: userId }).sort({ createdAt: -1 });
        res.json(posts);
    } catch (error) {
        console.error('Ошибка получения постов:', error);
        res.status(500).send('Ошибка получения постов');
    }
});

app.post('/posts', upload.array('files'), async (req, res) => {
    try {
        const { content } = req.body;
        const files = req.files.map(file => file.path); // Получаем массив путей к загруженным файлам

        const newPost = new Post({
            userId: req.user._id,
            content: content,
            files: files,
        });

        await newPost.save();
        res.status(201).json(newPost);
    } catch (error) {
        console.error('Ошибка при создании поста:', error);
        res.status(500).send('Ошибка сервера.');
    }
});

app.delete('/api/delete-post/:postId', async (req, res) => {
    const postId = req.params.postId;

    try {
        await Post.findByIdAndDelete(postId);
        res.status(200).json({ message: 'Пост успешно удален' });
    } catch (error) {
        console.error('Ошибка при удалении поста:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Музыкальная страница
app.get('/music', (req, res) => {
    // Вам может понадобиться загрузить данные о музыке, чартах и рекомендациях из БД
    const musicData = [
        { title: "Song 1", artist: "Artist 1", audioUrl: "path/to/song1.mp3" },
        { title: "Song 2", artist: "Artist 2", audioUrl: "path/to/song2.mp3" },
        { title: "Song 3", artist: "Artist 3", audioUrl: "path/to/song3.mp3" },
    ];

    const topCharts = [
        { title: "Hit Song 1", artist: "Famous Artist 1" },
        { title: "Hit Song 2", artist: "Famous Artist 2" },
        { title: "Hit Song 3", artist: "Famous Artist 3" },
    ];

    const recommendations = [
        { title: "Recommended Song 1", artist: "Recommender 1" },
        { title: "Recommended Song 2", artist: "Recommender 2" },
        { title: "Recommended Song 3", artist: "Recommender 3" },
    ];

    res.render('music', {
        music: musicData,
        topCharts: topCharts,
        recommendations: recommendations,
    });
});

// Пример данных для просмотра видео
app.get('/videos', async (req, res) => {
    try {
        const videos = await Post.find({ videoUrl: { $exists: true, $ne: null } })
            .populate('userId') // Замените на вашу модель пользователя
            .sort({ createdAt: -1 }); // Сортировка по дате

        res.render('video-view', { videos: videos });
    } catch (error) {
        console.error('Ошибка при получении видео:', error);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/friends', isAuthenticated, async (req, res) => {
    const userId = req.user._id;

    try {
        const user = await User.findById(userId).populate('friends', 'username'); // Заполненный массив друзей
        const friends = user.friends;

        const sentRequests = await FriendRequest.find({ senderId: userId })  // Запросы, отправленные этим пользователем
            .populate('friendId', 'username'); // Заполняем поле friendId, чтобы получить их username

        res.render('friends', { friends, sentRequests }); // Передаем данные в шаблон
    } catch (error) {
        console.error('Ошибка при получении списка друзей:', error);
        res.status(500).send('Ошибка сервера');
    }
});


async function getNotifications(userId) {
    try {
        const likes = await Like.find({ userId: userId }).populate('postId', 'title').exec(); // замените 'title' на нужное поле
        const comments = await Comment.find({ userId: userId }).populate('postId', 'title').exec(); // замените 'title' на нужное поле
        const posts = await Post.find({ userId: userId }).exec(); // Предполагаем, что вы хотите получить посты пользователя

        return {
            likes,
            comments,
            posts
        };
    } catch (err) {
        console.error(err);
        return {
            likes: [],
            comments: [],
            posts: []
        };
    }
}

async function getFriends(req, res) {
    const userId = req.user._id;

    try {
        const friendships = await Friendship.find({
            $or: [{ user1: userId }, { user2: userId }]
        }).populate('user1 user2', 'username');

        const friends = friendships.map(friendship => {
            return friendship.user1.equals(userId) ? friendship.user2 : friendship.user1;
        });

        res.json(friends);
    } catch (error) {
        console.error('Ошибка при получении списка друзей:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
}

// Подключите этот обработчик перед запуском сервера
// Пример функции для получения запросов в друзья
async function getFriendRequests(userId) {
    return await FriendRequest.find({ receiver: userId }) // Убедитесь, что здесь используется правильный идентификатор
        .populate('sender', 'username'); // Получите имя отправителя заявки
}

async function getIncomingCalls(userId) {
    return await Call.find({
        withUser: userId,
        status: 'incoming'
    }).populate('userId', 'username'); // предполагая, что вы хотите получить имя пользователя инициатора звонка
}

async function getMissedCalls(userId) {
    const missedCalls = await Call.find({ userId: userId, status: 'missed' }).populate('withUser', 'username');
    console.log('Пропущенные вызовы:', missedCalls);
    return missedCalls;
}

async function getCalls(req, res) {
    try {
        const incomingCalls = await getIncomingCalls(); // или как у вас это реализовано
        const missedCalls = await getMissedCalls();
        
        // Объедините входящие и пропущенные вызовы в один массив
        const calls = [...incomingCalls, ...missedCalls];

        // Рендерите шаблон и передавайте данные
        res.render('notifications', { calls });
    } catch (error) {
        console.error('Error fetching calls:', error);
        res.status(500).send('Internal Server Error');
    }
}

// Пример маршрута для уведомлений
// Определение функции получения пользователя
async function getUserById(userId) {
    console.log(`Запрос пользователя с ID: ${userId}`);
    const user = await User.findById(userId);
    if (!user) {
        console.log(`Пользователь с ID ${userId} не найден`);
        return { username: 'Имя пользователя недоступно' };
    }
    return { id: user._id, username: user.username };
}

// В вашем маршруте
app.get('/notifications', isAuthenticated, async (req, res) => {
    try {
        const incomingCalls = await getIncomingCalls(req.user.id);
        console.log(`Входящие вызовы: ${JSON.stringify(incomingCalls)}`);

        const enrichedIncomingCalls = await Promise.all(incomingCalls.map(async call => {
            const userId = call.userId?._id; // Используйте опциональную цепочку
            if (!userId) {
                console.log('ID пользователя не найден в объекте вызова:', call);
                return { ...call, caller: { username: 'Имя пользователя недоступно', id: null } }; // Не забудьте id
            }
            console.log(`Обработка вызова от пользователя с ID: ${userId}`);
            const user = await getUserById(userId); // Получите данные о пользователе
            return { ...call, caller: user }; // Верните объект с вызывающим пользователем
        }));

        res.render('notifications', {
            friendRequests: await getFriendRequests(req.user.id),
            incomingCalls: enrichedIncomingCalls,
            missedCalls: await getMissedCalls(req.user.id),
            notifications: await getNotifications(req.user.id)
        });
    } catch (error) {
        console.error("Ошибка при получении уведомлений:", error);
        res.status(500).send('Ошибка сервера');
    }
});

app.get('/api/unread-notifications',isAuthenticated, async (req, res) => {
    try {
        // Получение данных о новых запросах в друзья
        const friendRequests = await FriendRequest.find({ status: 'pending' }); // Найдите ожидающие запросы
        const totalCount = friendRequests.length;

        return res.json({ totalCount, friendRequests }); // Возвращаем общее количество и сами запросы
    } catch (error) {
        console.error('Ошибка получения уведомлений:', error);
        res.status(500).send('Ошибка на сервере');
    }
});

app.get('/api/unread-messages', async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(403).json({ message: 'Пользователь не аутентифицирован' });
    }

    const userId = req.user.id;

    try {
        const unreadCount = await getUnreadMessagesCount(userId);
        res.json({ totalCount: unreadCount });
    } catch (error) {
        console.error('Ошибка:', error);
        res.status(500).json({ message: 'Ошибка сервера. Не удалось получить количество сообщений.' });
    }
});

// Функция для получения количества непрочитанных сообщений
async function getUnreadMessagesCount(userId) {
    try {
        const count = await Message.countDocuments({
            receiverId: userId,
            isRead: false,
        });
        return count;
    } catch (error) {
        console.error('Ошибка при подсчете непрочитанных сообщений:', error);
        throw error;
    }
}


app.post('/api/send-friend-request', isAuthenticated, async (req, res) => {
    const senderId = req.user._id; // Получаем ID пользователя, отправляющего запрос
    const receiverId = req.body.friendId; // Получаем ID друга из тела запроса

    try {
        const existingRequest = await FriendRequest.findOne({ sender: senderId, receiver: receiverId });
        if (existingRequest) {
            return res.status(400).json({ message: 'Запрос на подписку уже отправлен' });
        }
        
        const request = new FriendRequest({ sender: senderId, receiver: receiverId });
        await request.save();

        return res.status(200).json({ message: 'Запрос на подписку отправлен' });
    } catch (error) {
        console.error('Ошибка при отправке запроса на подписку:', error);
        return res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.post('/accept-request/:requestId', isAuthenticated, async (req, res) => {
    const requestId = req.params.requestId;

    try {
        // Найти запрос на дружбу и сопоставить отправителя
        const friendRequest = await FriendRequest.findById(requestId).populate('sender');
        if (!friendRequest) {
            return res.status(404).json({ success: false, message: 'Запрос не найден.' });
        }

        const receiverId = req.user._id;
        const senderId = friendRequest.sender._id;

        // Проверить, существует ли дружба
        const existingFriendship = await Friendship.findOne({
            $or: [
                { user1: senderId, user2: receiverId },
                { user1: receiverId, user2: senderId }
            ]
        });

        if (existingFriendship) {
            return res.status(400).json({ success: false, message: 'Вы уже в друзьях.' });
        }

        // Создать новую запись о дружбе
        const friendship = new Friendship({
            user1: senderId,
            user2: receiverId
        });
        await friendship.save();

        // Обновить массив friends у обоих пользователей
        await User.updateOne({ _id: senderId }, { $addToSet: { friends: receiverId } });
        await User.updateOne({ _id: receiverId }, { $addToSet: { friends: senderId } });

        // Удалить заявку о дружбе
        await FriendRequest.deleteOne({ _id: requestId });

        // Ответ клиенту с новой дружбой
        return res.json({
            success: true,
            message: 'Запрос на дружбу принят.',
            newFriend: {
                id: friendship._id,
                user1: friendship.user1,
                user2: friendship.user2
            }
        });
    } catch (error) {
        console.error('Ошибка при принятии запроса:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера.' });
    }
});

// Маршрут для удаления друга
app.delete('/api/remove-friend/:friendId', isAuthenticated, async (req, res) => {
    const userId = req.user._id;
    const friendId = req.params.friendId;

    try {
        // Логика удаления из списка друзей
        await User.findByIdAndUpdate(userId, { $pull: { friends: friendId } });
        await User.findByIdAndUpdate(friendId, { $pull: { friends: userId } }); // Удаляем взаимную дружбу
        res.status(200).json({ message: 'Друг успешно удален.' });
    } catch (error) {
        console.error('Ошибка при удалении друга:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Маршрут для отмены отправленного запроса на дружбу
app.delete('/api/cancel-request/:requestId', isAuthenticated, async (req, res) => {
    const requestId = req.params.requestId;

    try {
        await FriendRequest.findByIdAndDelete(requestId);
        res.status(200).json({ message: 'Запрос на дружбу отменен.' });
    } catch (error) {
        console.error('Ошибка при отмене запроса:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

// Маршрут для получения списка друзей текущего пользователя
// Пример реализации endpoint в Node.js с использованием Express
app.get('/api/get-friends', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('friends', 'username');
        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        res.json(user.friends); // Возвращаем массив друзей
    } catch (error) {
        console.error('Ошибка при получении друзей:', error);
        res.status(500).json({ message: 'Ошибка на сервере' });
    }
});

// Маршрут для получения отправленных запросов на дружбу текущего пользователя
app.get('/api/get-sent-requests', isAuthenticated, async (req, res) => {
    const userId = req.user._id;

    try {
        const requests = await FriendRequest.find({ sender: userId }).populate('receiver', 'username');
        res.status(200).json(requests);
    } catch (error) {
        console.error('Ошибка при получении отправленных запросов:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});


app.post('/api/like-post/:postId', async (req, res) => {
    const postId = req.params.postId;
    const userId = req.user._id; // Предполагается, что пользователи аутентифицированы

    try {
        const post = await Post.findById(postId);

        // Если пост уже лайкнут пользователем, удаляем лайк
        if (post.likes.includes(userId)) {
            post.likes.pull(userId);
        } else {
            post.likes.push(userId);
        }

        await post.save();
        res.status(200).json({ message: 'Изменение лайка успешно', likes: post.likes });
    } catch (error) {
        console.error('Ошибка при лайке поста:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

app.post('/api/comments/:postId', async (req, res) => {
    const postId = req.params.postId;
    const { content } = req.body;

    try {
        const newComment = { content, userId: req.user._id }; // Сохраните идентификатор пользователя (текущего)
        
        // Можно хранить комментарии в модели Post
        const post = await Post.findById(postId);
        post.comments.push(newComment);
        await post.save();

        res.status(201).json(newComment); // Возвращаем комментарий с его данными
    } catch (error) {
        console.error('Ошибка при добавлении комментария:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

app.get('/create-group-chat', async (req, res) => {
    try {
        const userId = req.user.id; // Получаем ID текущего пользователя
        // Запрашиваем дружеские отношения пользователя
        const friendships = await Friendship.find({ $or: [{ user1: userId }, { user2: userId }] });
        
        // Получаем участников только с подтвержденными дружескими отношениями
        const participants = friendships
            .filter(friendship => friendship.status === 'accepted')
            .map(friendship => friendship.user1.toString() === userId ? friendship.user2 : friendship.user1);

        // Загружаем детали пользователей, которые являются участниками
        const friendsDetails = await User.find({ _id: { $in: participants } });

        // Передаем как участников, так и текущего пользователя в шаблон
        res.render('createGroupChat', { 
            participants: friendsDetails,
            user: req.user // Передаем текущего пользователя
        }); // Рендерим страницу
    } catch (error) {
        console.error('Ошибка при загрузке страницы создания группового чата:', error);
        res.status(500).send('Ошибка сервера');
    }
});

// Обработка создания группового чата
// Обработка создания группового чата
// Обработка создания группового чата
app.post('/create-group-chat', upload.single('avatar'), async (req, res) => {
    const { chatName, members } = req.body;
    const creatorId = req.user._id; // Получаем ID создателя из запроса (при условии, что пользователь аутентифицирован)

    // Проверка на заполненность названия
    if (!chatName || !members) {
        return res.status(400).json({ message: 'Название чата и участники обязательны!' });
    }

    // Проверка корректности ObjectId
    if (!mongoose.Types.ObjectId.isValid(creatorId)) {
        return res.status(400).json({ message: 'Неверный идентификатор создателя.' });
    }

    try {
        const participants = []; // Массив для хранения участников группы
        const parsedMembers = JSON.parse(members); // Парсинг строкового массива участников
        
        // Добавление создателя в список участников только если он еще не добавлен
        const creator = await User.findById(creatorId);
        if (creator) {
            participants.push({
                userId: creator._id,
                username: creator.username,
            });
        }

        // Обработка остальных участников
        for (const userId of parsedMembers) {
            const user = await User.findById(userId);
            if (user) {
                // Проверяем, добавлен ли пользователь уже в participants
                if (!participants.some(participant => participant.userId.equals(user._id))) {
                    participants.push({
                        userId: user._id,
                        username: user.username,
                    });
                }
            }
        }

        // Создаем новый групповой чат
        const newGroupChat = new GroupChat({
            chatName,
            avatar: req.file ? req.file.path : null, // Убедитесь, что у вас правильный путь к аватару
            participants,
        });

        await newGroupChat.save();
        res.status(201).json({ message: 'Групповой чат успешно создан!', groupChat: newGroupChat });
    } catch (error) {
        console.error('Ошибка при создании группового чата:', error);
        res.status(500).json({ message: 'Ошибка при создании группового чата, попробуйте позже.' });
    }
});



app.post('/remove-participant/:participantId', async (req, res) => {
    const participantId = req.params.participantId;
    // Добавьте логику для удаления участника из группы
    try {
        await GroupChat.updateOne(
            { _id: req.body.groupId }, // или используйте другой способ определения группы
            { $pull: { participants: participantId } }
        );
        res.status(200).send('Participant removed');
    } catch (error) {
        console.error('Ошибка при удалении участника:', error);
        res.status(500).send('Не удалось удалить участника');
    }
});


// Получение группы по ID
const getGroupById = async (groupId) => {
    return await GroupChat.findById(groupId).populate('participants.userId', 'username'); // Заполним поля участников
};

// Получение сообщений по ID группы
const getGroupMessagesByGroupId = async (groupId) => {
    return await GroupMessage.find({ groupId: groupId }).populate('senderId', 'username'); // Заполним поле отправителя сообщений
};

app.get('/group/:id', async (req, res) => {
    try {
        const groupId = req.params.id;
        const group = await getGroupById(groupId); // Получаем информацию о группе
        const messages = await getGroupMessagesByGroupId(groupId); // Получаем сообщения для группы
        const userId = req.user.id; // Получаем идентификатор текущего пользователя

        if (group) {
            res.render('group', { 
                groupName: group.chatName, // Используем chatName из GroupChat
                messages: messages, 
                userId: userId,
                groupId: groupId,
                users: group.participants // Передаем массив участников группы
            });
        } else {
            res.status(404).send('Группа не найдена');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Ошибка сервера');
    }
});

app.post('/group/:id/message', async (req, res) => {
    try {
        const groupId = req.params.id;
        const { senderId, content } = req.body;

        // Сохраним новое сообщение
        const newMessage = await GroupMessage.create({
            senderId: senderId,
            groupId: groupId,
            content: content,
        });

        // Отправим ответ клиенту
        res.json({
            success: true,
            message: newMessage // Возвращаем только что созданное сообщение
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Ошибка сервера' });
    }
});


// Запуск сервера
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});