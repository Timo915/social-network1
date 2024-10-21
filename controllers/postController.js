const Post = require('../models/Post');

// Создать пост
exports.createPost = async (req, res) => {
    const { content } = req.body;

    // Проверьте, отправлено ли содержимое поста
    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    const post = new Post({ userId: req.user.id, content }); // Изменено: user на userId

    try {
        await post.save();
        return res.status(201).json(post);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Получить все посты
exports.getPosts = async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('userId', 'username') // Изменено: user на userId
            .sort({ createdAt: -1 });
        return res.json(posts);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Лайк поста
exports.likePost = async (req, res) => {
    const { postId } = req.params;

    try {
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ message: 'Post not found' });

        if (!post.likes) post.likes = []; // Убедитесь, что поле likes инициализировано
        if (!post.likes.includes(req.user.id)) {
            post.likes.push(req.user.id);
            await post.save();
        }

        return res.json(post);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Дизлайк поста
exports.dislikePost = async (req, res) => {
    const { postId } = req.params;

    try {
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ message: 'Post not found' });

        if (!post.dislikes) post.dislikes = []; // Убедитесь, что поле dislikes инициализировано
        if (!post.dislikes.includes(req.user.id)) {
            post.dislikes.push(req.user.id);
            await post.save();
        }

        return res.json(post);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Удалить пост
exports.deletePost = async (req, res) => {
    const { postId } = req.params;

    try {
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ message: 'Post not found' });

        await post.remove(); // Изменено: вместо delete использовать remove
        return res.json({ message: 'Post deleted successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};