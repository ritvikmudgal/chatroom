const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Environment variables
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/chatroom';
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Connected to MongoDB');
}).catch(err => {
    console.error('❌ MongoDB connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, minlength: 3 },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, minlength: 6 },
    createdAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    isOnline: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false }
});

const Message = mongoose.model('Message', messageSchema);

// Conversation Schema
const conversationSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastMessage: { type: String },
    lastMessageTime: { type: Date, default: Date.now }
});

const Conversation = mongoose.model('Conversation', conversationSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }
    
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

// Verify reCAPTCHA
async function verifyRecaptcha(token) {
    try {
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`
        );
        return response.data.success;
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return false;
    }
}

// Routes

// Signup
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, email, password, recaptcha } = req.body;
        
        // Verify reCAPTCHA
        const isHuman = await verifyRecaptcha(recaptcha);
        if (!isHuman) {
            return res.status(400).json({ message: 'reCAPTCHA verification failed' });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        const user = new User({
            username,
            email,
            password: hashedPassword
        });
        
        await user.save();
        
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, recaptcha } = req.body;
        
        // Verify reCAPTCHA
        const isHuman = await verifyRecaptcha(recaptcha);
        if (!isHuman) {
            return res.status(400).json({ message: 'reCAPTCHA verification failed' });
        }
        
        // Find user
        const user = await User.findOne({
            $or: [{ username }, { email: username }]
        });
        
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Update online status
        user.isOnline = true;
        user.lastSeen = new Date();
        await user.save();
        
        // Create token
        const token = jwt.sign(
            { id: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get conversations
app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const conversations = await Conversation.find({
            participants: userId
        }).populate('participants', 'username email isOnline');
        
        const formattedConversations = conversations.map(conv => {
            const otherUser = conv.participants.find(p => p._id.toString() !== userId);
            return {
                user: {
                    id: otherUser._id,
                    username: otherUser.username,
                    email: otherUser.email,
                    isOnline: otherUser.isOnline
                },
                lastMessage: conv.lastMessage,
                timestamp: conv.lastMessageTime
            };
        });
        
        res.json({ conversations: formattedConversations });
    } catch (error) {
        console.error('Get conversations error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get messages
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const currentUserId = req.user.id;
        const otherUserId = req.params.userId;
        
        const messages = await Message.find({
            $or: [
                { senderId: currentUserId, recipientId: otherUserId },
                { senderId: otherUserId, recipientId: currentUserId }
            ]
        }).sort({ timestamp: 1 });
        
        res.json({ messages });
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { recipientId, content } = req.body;
        const senderId = req.user.id;
        
        const message = new Message({
            senderId,
            recipientId,
            content
        });
        
        await message.save();
        
        // Update or create conversation
        let conversation = await Conversation.findOne({
            participants: { $all: [senderId, recipientId] }
        });
        
        if (!conversation) {
            conversation = new Conversation({
                participants: [senderId, recipientId],
                lastMessage: content
            });
        } else {
            conversation.lastMessage = content;
            conversation.lastMessageTime = new Date();
        }
        
        await conversation.save();
        
        res.status(201).json({ message: 'Message sent', data: message });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Search users
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const query = req.query.q;
        const currentUserId = req.user.id;
        
        const users = await User.find({
            _id: { $ne: currentUserId },
            $or: [
                { username: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } }
            ]
        }).select('username email').limit(10);
        
        res.json({ users });
    } catch (error) {
        console.error('Search users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Socket.IO
const userSockets = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('user_online', async (data) => {
        userSockets.set(data.userId, socket.id);
        
        try {
            await User.findByIdAndUpdate(data.userId, { isOnline: true, lastSeen: new Date() });
            io.emit('user_status', { userId: data.userId, status: 'online' });
        } catch (error) {
            console.error('User online error:', error);
        }
    });
    
    socket.on('user_offline', async (data) => {
        userSockets.delete(data.userId);
        
        try {
            await User.findByIdAndUpdate(data.userId, { isOnline: false, lastSeen: new Date() });
            io.emit('user_status', { userId: data.userId, status: 'offline' });
        } catch (error) {
            console.error('User offline error:', error);
        }
    });
    
    socket.on('join_chat', (data) => {
        const room = [data.userId, data.recipientId].sort().join('-');
        socket.join(room);
    });
    
    socket.on('send_message', (data) => {
        const room = [data.senderId, data.recipientId].sort().join('-');
        socket.to(room).emit('receive_message', data);
    });
    
    socket.on('typing', (data) => {
        const room = [data.userId, data.recipientId].sort().join('-');
        socket.to(room).emit('typing', { userId: data.userId });
    });
    
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        for (const [userId, socketId] of userSockets.entries()) {
            if (socketId === socket.id) {
                userSockets.delete(userId);
                User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() })
                    .catch(err => console.error('Disconnect update error:', err));
                io.emit('user_status', { userId, status: 'offline' });
                break;
            }
        }
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log('📁 Serving static files from public folder');
});