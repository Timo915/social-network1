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
const multer = require('multer');

// Настройка multer для загрузки файлов
const upload = multer({ dest: 'uploads/' });

// Предположим, у вас есть модель Post
const Post = require('./models/Post');

// Импортируем Passport
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;


// В начале вашего server.js или в соответствующем файле
const Friendship = require('./models/Friendship');
// В начале вашего server.js или в соответствующем файле
const Message = require('./models/Message');
// Инициализация приложения
const app = express();
const PORT = process.env.PORT || 5000;

// Создание сервера HTTP
const server = http.createServer(app);
const io = socketIo(server); // Инициализация Socket.IO

// Подключение вашего роутера
app.use(router);

// Подключение к MongoDB
mongoose.connect('mongodb://localhost:27017/social-network', {
   
})
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error('MongoDB connection error:', err));

// Модель пользователя
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Настройка view engine на EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize()); // Подключаем Passport
app.use(passport.session()); // Подключаем сессии

// Также можно добавить middleware для flash-сообщений
app.use(flash());

// Настраиваем стратегию локальной аутентификации
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const user = await User.findOne({ username });
            if (!user) {
                return done(null, false, { message: 'Неверное имя пользователя.' });
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { message: 'Неверный пароль.' });
            }
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
));

// Сериализация пользователя в сессию
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

// Главная страница с меню
app.get('/home', async (req, res) => {
    let users = [];
    const search = req.query.search || '';
    
    // Поиск пользователей по имени
    if (search) {
        users = await User.find({ username: new RegExp(search, 'i') }); // Нечувствительный к регистру
    }
    
    res.render('home', { users, search });
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

    socket.on('chat message', (msg) => {
        io.emit('chat message', msg); // Отправляет сообщение всем пользователям
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

// Обработчик для создания постов


// Страница профиля
// Обработчик для страницы профиля
app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const user = req.user; // Получаем текущего пользователя
        const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 }); // Получаем посты для пользователя

        res.render('profile', { user, posts });
    } catch (error) {
        console.error(error);
        res.status(500).send("Ошибка сервера");
    }
});

function isAuthenticated(req, res, next) {
    console.log('AUTH CHECK', req.user); // Логирование
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}


// Страница редактирования видео
app.get('/edit-video', (req, res) => {
    res.render('edit-video'); // Здесь вы можете добавить сложный видеоредактор
});

// Обработчик для подписки на пользователя
app.post('/subscribe/:userId', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const userIdToSubscribe = req.params.userId;
    
    const user = await User.findById(req.session.userId);
    if (!user.subscriptions.includes(userIdToSubscribe)) {
        user.subscriptions.push(userIdToSubscribe);
        await user.save();
    }
    
    res.redirect('/home');
});

app.get('/home', async (req, res) => {
    // Проверяем, авторизован ли пользователь
    if (!req.session.userId) {
        return res.redirect('/login'); // Если не авторизован, перенаправляем на страницу входа
    }
    
    let users = [];
    const search = req.query.search || '';

    // Поиск пользователей по имени, если есть запрос
    if (search) {
        users = await User.find({ username: new RegExp(search, 'i') });
    } else {
        // Если поиск не инициирован, получаем список пользователей по умолчанию
        users = await User.find();
    }

    // Получаем текущего пользователя для доступа к подпискам
    const currentUser = await User.findById(req.session.userId).populate('subscriptions');

    // Получаем посты от пользователей, на которых подписан текущий пользователь
    const posts = await Post.find({ userId: { $in: currentUser.subscriptions } })
        .populate('userId')
        .sort({ createdAt: -1 }); // Сортировка по времени создания

    // Рендерим представление с данными
    res.render('home', { users, posts, search, currentUser });
});

// Обработчик для создания постов




// Отправка запроса в друзья
app.post('/send-friend-request/:userId', async (req, res) => {
    const { userId } = req.params;
    const friendId = userId;  // Пользователь, которому отправляется запрос дружбы
    const currentUserId = req.session.userId;  // Идентификатор текущего пользователя

    if (!currentUserId || !friendId) {
        return res.status(400).json({ message: 'User IDs are required.' });
    }

    // Проверка существования запроса дружбы
    const existingRequest = await Friendship.findOne({
        userId: currentUserId,
        friendId: friendId,
    });

    if (existingRequest) {
        return res.status(400).json({ message: 'Friend request already sent.' });
    }

    // Создание нового запроса дружбы
    const newFriendship = new Friendship({
        userId: currentUserId,
        friendId: friendId,
    });

    try {
        await newFriendship.save();
        res.status(201).json({ message: 'Friend request sent.' });
    } catch (error) {
        console.error('Error creating friendship:', error);
        res.status(500).json({ message: 'Error creating friend request.' });
    }
});

// Принять запрос в друзья
app.post('/accept-friend-request/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const requestId = req.params.id;

    const friendship = await Friendship.findById(requestId);
    if (friendship && friendship.recipient.toString() === req.session.userId) {
        friendship.status = 'accepted';
        await friendship.save();
    }

    res.redirect('/home');
});

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

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login'); // Переход на страницу логина, если не аутентифицирован
}



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
        const messages = await Message.find({
            $or: [
                { senderId: currentUserId },
                { receiverId: currentUserId }
            ]
        }).populate('senderId', 'name profilePicture')
          .populate('receiverId', 'name profilePicture')
          .sort({ createdAt: -1 });

        const dialogues = {};

        messages.forEach(message => {
            const otherUserId = message.senderId.toString() === currentUserId ? message.receiverId._id : message.senderId._id;
            if (!dialogues[otherUserId]) {
                dialogues[otherUserId] = {
                    userId: otherUserId,
                    lastMessage: message.text,
                    lastMessageDate: message.createdAt,
                    userInfo: message.senderId.toString() === currentUserId ? message.receiverId : message.senderId
                };
            }
        });

        const results = Object.values(dialogues);

        // Передаем username текущего пользователя в шаблон
        res.render('history', { dialogues: results, search: '', username: req.user.username });
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
app.post('/posts', upload.single('video'), async (req, res) => {
    console.log(req.body); // Логируем содержимое тела запроса

    const { content } = req.body;  // Извлекаем контент поста

    // Проверка, присутствует ли контент
    if (!content) {
        return res.status(400).send("Контент поста недоступен");
    }

    // Код для сохранения поста в БД
    const newPost = new Post({
        content,
        videoUrl: req.file ? req.file.path : undefined, // сохраняем путь к загруженному видео (если оно есть)
        userId: req.user._id // предполагаем, что у вас есть аутентификация и доступ к служебным данным пользователя
    });

    try {
        await newPost.save();
        res.redirect('/home'); // Перенаправление обратно на главную после создания поста
    } catch (error) {
        console.error("Ошибка при создании поста:", error);
        res.status(500).send("Ошибка при создании поста");
    }
});

// Страница создания поста
app.get('/create-post', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('create-post'); // Предполагается, что у вас есть шаблон create-post.ejs
});

// Запуск сервера
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});