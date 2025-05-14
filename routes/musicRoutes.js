const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const multer = require('multer');
const path = require('path');

const {
    addTrack,
    getTopCharts,
    getRecommendations,
    getRadio,
    searchMusic,
    getArtists,
    getAlbums,
    getUserMusic,
} = require('../controllers/musicController');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'profile/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Routes
router.post('/add', protect, upload.single('audio'), addTrack);
router.get('/top-charts', getTopCharts);
router.get('/recommendations', getRecommendations);
router.get('/radio', getRadio);
router.get('/search', searchMusic);
router.get('/artists', getArtists);
router.get('/albums', getAlbums);
router.get('/my-music', protect, getUserMusic);

module.exports = router;
