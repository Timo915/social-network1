const Music = require('../models/music');

const addTrack = async (req, res) => {
    try {
        const { title, artist, album } = req.body;
        const audioUrl = req.file ? '/uploads/' + req.file.filename : null;

        if (!title || !artist || !audioUrl) {
            return res.status(400).json({ message: 'Title, artist, and audio file are required' });
        }

        const newTrack = new Music({
            title,
            artist,
            album: album || '',
            audioUrl,
            userId: req.user._id,
        });

        await newTrack.save();
        res.status(201).json(newTrack);
    } catch (error) {
        console.error('Error adding track:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getTopCharts = async (req, res) => {
    try {
        const topTracks = await Music.find().sort({ createdAt: -1 }).limit(10);
        res.json(topTracks);
    } catch (error) {
        console.error('Error fetching top charts:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getRecommendations = async (req, res) => {
    try {
        const count = await Music.countDocuments();
        const random = Math.floor(Math.random() * count);
        const recommendations = await Music.find().skip(random).limit(10);
        res.json(recommendations);
    } catch (error) {
        console.error('Error fetching recommendations:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getRadio = async (req, res) => {
    try {
        const tracks = await Music.find();
        res.json(tracks);
    } catch (error) {
        console.error('Error fetching radio tracks:', error);
        res.status(500).json({ message: 'Server error' });
    }
};



const searchMusic = async (req, res) => {
    const { query, source } = req.query;

    if (!query || !source) {
        return res.status(400).json({ message: 'Query and source parameters are required' });
    }

    try {
        let music = [];

        if (source === 'spotify') {
            music = [
                { title: `${query} Song 1 (Spotify)`, artist: 'Artist A', audioUrl: '/uploads/sample1.mp3' },
                { title: `${query} Song 2 (Spotify)`, artist: 'Artist B', audioUrl: '/uploads/sample2.mp3' },
            ];
        } else if (source === 'youtube') {
            music = [
                { title: `${query} Video 1 (YouTube)`, artist: 'Artist C', audioUrl: '/uploads/sample3.mp3' },
                { title: `${query} Video 2 (YouTube)`, artist: 'Artist D', audioUrl: '/uploads/sample4.mp3' },
            ];
        } else if (source === 'lastfm') {
            music = [
                { title: `${query} Track 1 (Last.fm)`, artist: 'Artist E', audioUrl: '/uploads/sample5.mp3' },
                { title: `${query} Track 2 (Last.fm)`, artist: 'Artist F', audioUrl: '/uploads/sample6.mp3' },
            ];
        } else if (source === 'local' || source === 'database') {
            // Search in local database
            music = await Music.find({
                $or: [
                    { title: { $regex: query, $options: 'i' } },
                    { artist: { $regex: query, $options: 'i' } }
                ]
            }).limit(20);
        } else {
            return res.status(400).json({ message: 'Invalid source parameter' });
        }

        res.json({ music });
    } catch (error) {
        console.error('Error searching music:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getArtists = async (req, res) => {
    try {
        const artists = await Music.distinct('artist');
        res.json(artists);
    } catch (error) {
        console.error('Error fetching artists:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getAlbums = async (req, res) => {
    try {
        const albums = await Music.distinct('album');
        res.json(albums);
    } catch (error) {
        console.error('Error fetching albums:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

const getUserMusic = async (req, res) => {
    try {
        const userId = req.user._id;
        const userMusic = await Music.find({ userId });
        res.json(userMusic);
    } catch (error) {
        console.error('Error fetching user music:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = {
    addTrack,
    getTopCharts,
    getRecommendations,
    getRadio,
    searchMusic,
    getArtists,
    getAlbums,
    getUserMusic,
};
