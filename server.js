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

app.use('/api', callsRouter);



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
    failureFlash: true, // Включает использование flash-сообщений
}));

// Socket.IO
io.on('connection', (socket) => {
    console.log('A user connected');

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
    if (!userId || !socket.request.user._id) { // Проверяем, что оба идентификатора существуют
        console.error('Неудовлетворительные данные для инициации вызова:', { userId, requesterId: socket.request.user._id });
        return; // Завершаем функцию, если данные не валидны
    }

    const callData = { 
        type: callType,
        createdAt: new Date() // добавляем время создания вызова
    };

    const newCall = new Call({
        userId: socket.request.user._id, // Идентификатор инициатора звонка
        withUser: userId, // Идентификатор пользователя, с которым инициируется звонок
        callData: callData,
        status: 'incoming'
    });

    try {
        const savedCall = await newCall.save(); // Сохраняем вызов в базе данных
        console.log('Call initiated:', savedCall);
        
        // Уведомление о звонке
        io.to(userId).emit('incoming-call', { callerId: socket.request.user._id, callDetails: savedCall });
    } catch (error) {
        console.error('Ошибка при сохранении звонка:', error);
    }
});

// Обработка принятия звонка
socket.on('accept-call', async (callId) => {
    if (!callId) {
        console.error('Не передан ID звонка.');
        return; // Завершаем функцию, если ID звонка не предоставлен
    }

    try {
        const call = await Call.findByIdAndUpdate(callId, { status: 'accepted' }); // Обновляем статус вызова
        if (!call) {
            console.error('Вызов не найден с ID:', callId);
            return; // Завершаем, если вызов не найден
        }

        console.log('Call accepted:', call);
        // Логика после принятия вызова, например, уведомление других участников
    } catch (error) {
        console.error('Ошибка при принятии звонка:', error);
    }
});

    // Обработка завершения звонка
    socket.on('end-call', async (call) => {
        await Call.findByIdAndUpdate(call._id, { status: 'ended' });
        socket.emit('call-ended');
        socket.to(call.withUser).emit('call-ended');
    });

    socket.on('incoming-call', (data) => {
        // Это событие должно добавлять новый вызов в список на фронтенде
        const callElement = document.createElement('li');
        callElement.innerHTML = `
            <strong>Входящий вызов от: ${data.caller.username}</strong>
            <button onclick="acceptCall('${data.caller.id}')">Принять</button>
            <button onclick="rejectCall('${data.caller.id}')">Отклонить</button>
        `;
        document.getElementById('incoming-calls').insertBefore(callElement, document.getElementById('incoming-calls').firstChild);
    });
});

app.get('/api/calls', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const calls = await Call.find({ userId: req.user.id }).populate('withUser', 'username');

        // Если данные успешно найдены, отправляем их
        return res.json(calls);
    } catch (error) {
        console.error('Ошибка при получении звонков:', error);
        return res.status(500).json({ message: 'Ошибка сервера' });
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


// Главная страница


// Получение сообщений между пользователями
app.get('/messages/:recipientId', async (req, res) => {
    const recipientId = req.params.recipientId;

    // Проверяем, что пользователь аутентифицирован
    if (!req.user || !req.user.id) {
        return res.status(403).json({ message: 'Forbidden: User not authenticated.' });
    }

    try {
        const messages = await Message.find({
            $or: [
                { senderId: req.user.id, receiverId: recipientId },
                { senderId: recipientId, receiverId: req.user.id }
            ]
        }).populate('senderId receiverId'); // Если используете Mongoose

        // Обрабатываем сообщения как прежде...
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
            updatedAt: message.updatedAt
        }));

        res.render('messages', {
            messages: formattedMessages,
            recipientId: recipientId,
            user: req.user // Передаем текущего пользователя
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
        // Извлечение всех личных сообщений
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
            const otherUser = (message.senderId && message.senderId._id.toString() === currentUserId) 
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
                    };
                } else {
                    // Обновление последнего сообщения, если оно более новое
                    if (message.createdAt > dialogues[otherUserId].lastMessageDate) {
                        dialogues[otherUserId].lastMessage = message.content;
                        dialogues[otherUserId].lastMessageDate = message.createdAt;
                    }
                }
            }
        });

        // Извлечение групповых чатов
        const groupChats = await GroupChat.find({
            'participants.userId': currentUserId
        })
        .populate('participants.userId', 'username profilePicture');

        // Добавление групповых чатов в dialogues
        for (const chat of groupChats) {
            // Определяем последнее сообщение для группового чата, если оно есть
            const lastMessage = chat.lastMessage ? chat.lastMessage.content : 'Нет сообщений';
            const lastMessageDate = chat.lastMessage ? chat.lastMessage.createdAt : chat.createdAt;

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
            };
        }

        const results = Object.values(dialogues).sort((a, b) => b.lastMessageDate - a.lastMessageDate); // Сортировка по дате сообщения
        res.render('history', { dialogues: results, user: req.user });
    } catch (error) {
        console.error('Ошибка при получении истории сообщений:', error);
        return res.status(500).render('error', { message: 'Ошибка при получении истории сообщений.' });
    }
});

app.get('/api/unread-messages-count', async (req, res) => {
    if (!req.user) {
        return res.status(403).json({ message: 'User not authenticated' });
    }

    try {
        const count = await Message.countDocuments({ // Обратите внимание на "Message"
            receiverId: req.user.id,
            isRead: false,
        });

        res.json({ count });
    } catch (error) {
        console.error('Error fetching unread messages count:', error);
        res.status(500).json({ message: 'Could not fetch unread messages count.' });
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

async function getCallHistory(userId) {
    return await Call.find({
        $or: [{ userId: userId }, { withUser: userId }]
    }).populate('userId', 'username').populate('withUser', 'username'); // Получаем имя пользователей
}

// Пример маршрута для уведомлений
app.get('/notifications', async (req, res) => {
    try {
        const incomingCalls = await getIncomingCalls(req.user.id);
        const missedCalls = await getMissedCalls(req.user.id);
        const notifications = await getNotifications(req.user.id);

        res.render('notifications', {
            friendRequests: await getFriendRequests(req.user.id),
            incomingCalls,
            missedCalls,
            notifications
        });
    } catch (error) {
        console.error("Ошибка при получении уведомлений:", error);
        res.status(500).send('Ошибка сервера');
    }
});


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
app.get('/api/get-friends', isAuthenticated, async (req, res) => {
    const userId = req.user._id;

    try {
        const user = await User.findById(userId).populate('friends', 'username'); // Предполагается, что вы сохраняете id друзей
        res.status(200).json(user.friends);
    } catch (error) {
        console.error('Ошибка при получении друзей:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
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