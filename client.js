// Socket.IO connection
const socket = io();

// Current user data
let currentUser = null;
let currentChatUser = null;
let conversations = {};

// Check authentication on load
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupSocketListeners();
});

// Auth Functions
function checkAuth() {
    const token = localStorage.getItem('chatroom_token');
    const user = localStorage.getItem('chatroom_user');
    
    if (token && user) {
        currentUser = JSON.parse(user);
        showChatApp();
        socket.emit('user_online', { userId: currentUser.id });
    }
}

function switchToLogin() {
    document.getElementById('signupForm').classList.remove('active');
    document.getElementById('phoneForm').classList.remove('active');
    document.getElementById('loginForm').classList.add('active');
}

function switchToSignup() {
    document.getElementById('loginForm').classList.remove('active');
    document.getElementById('phoneForm').classList.remove('active');
    document.getElementById('signupForm').classList.add('active');
}

function showPhoneLogin() {
    document.getElementById('loginForm').classList.remove('active');
    document.getElementById('signupForm').classList.remove('active');
    document.getElementById('phoneForm').classList.add('active');
}

async function handleLogin(event) {
    event.preventDefault();
    
    const recaptchaResponse = grecaptcha.getResponse();
    if (!recaptchaResponse) {
        alert('Please complete the reCAPTCHA');
        return;
    }
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, recaptcha: recaptchaResponse })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('chatroom_token', data.token);
            localStorage.setItem('chatroom_user', JSON.stringify(data.user));
            currentUser = data.user;
            showChatApp();
            socket.emit('user_online', { userId: currentUser.id });
        } else {
            alert(data.message || 'Login failed');
            grecaptcha.reset();
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
        grecaptcha.reset();
    }
}

async function handleSignup(event) {
    event.preventDefault();
    
    const recaptchaResponse = grecaptcha.getResponse(1);
    if (!recaptchaResponse) {
        alert('Please complete the reCAPTCHA');
        return;
    }
    
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    
    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return;
    }
    
    try {
        const response = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, recaptcha: recaptchaResponse })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('Account created successfully! Please login.');
            switchToLogin();
        } else {
            alert(data.message || 'Signup failed');
            grecaptcha.reset(1);
        }
    } catch (error) {
        console.error('Signup error:', error);
        alert('Signup failed. Please try again.');
        grecaptcha.reset(1);
    }
}

function loginWithGoogle() {
    window.location.href = '/api/auth/google';
}

function handlePhoneLogin(event) {
    event.preventDefault();
    alert('Phone authentication will be implemented with Firebase or Twilio');
}

function showChatApp() {
    document.getElementById('authPage').classList.remove('active');
    document.getElementById('chatApp').classList.add('active');
    document.getElementById('currentUsername').textContent = currentUser.username;
    loadConversations();
}

function logout() {
    socket.emit('user_offline', { userId: currentUser.id });
    localStorage.removeItem('chatroom_token');
    localStorage.removeItem('chatroom_user');
    currentUser = null;
    document.getElementById('chatApp').classList.remove('active');
    document.getElementById('authPage').classList.add('active');
}

// Socket.IO listeners
function setupSocketListeners() {
    socket.on('connect', () => {
        console.log('Connected to server');
        if (currentUser) {
            socket.emit('user_online', { userId: currentUser.id });
        }
    });
    
    socket.on('receive_message', (data) => {
        if (currentChatUser && data.senderId === currentChatUser.id) {
            displayMessage(data, false);
        }
        updateConversationList();
    });
    
    socket.on('user_status', (data) => {
        if (currentChatUser && data.userId === currentChatUser.id) {
            updateOnlineStatus(data.status);
        }
    });
    
    socket.on('typing', (data) => {
        if (currentChatUser && data.userId === currentChatUser.id) {
            showTypingIndicator();
        }
    });
}

// Chat Functions
async function loadConversations() {
    try {
        const response = await fetch('/api/conversations', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('chatroom_token')}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayConversations(data.conversations);
        }
    } catch (error) {
        console.error('Load conversations error:', error);
    }
}

function displayConversations(convos) {
    const chatList = document.getElementById('chatList');
    chatList.innerHTML = '';
    
    if (convos.length === 0) {
        chatList.innerHTML = '<div style="padding: 2rem; text-align: center; color: #666;">No conversations yet. Add someone to start chatting!</div>';
        return;
    }
    
    convos.forEach(convo => {
        const chatItem = document.createElement('div');
        chatItem.className = 'chat-item';
        chatItem.onclick = () => openChat(convo.user);
        
        chatItem.innerHTML = `
            <div class="chat-item-avatar">👤</div>
            <div class="chat-item-info">
                <div class="chat-item-name">${convo.user.username}</div>
                <div class="chat-item-message">${convo.lastMessage || 'Start chatting...'}</div>
            </div>
            <div class="chat-item-time">${convo.timestamp ? formatTime(convo.timestamp) : ''}</div>
        `;
        
        chatList.appendChild(chatItem);
    });
}

async function openChat(user) {
    currentChatUser = user;
    
    document.getElementById('chatEmpty').style.display = 'none';
    document.getElementById('activeChat').style.display = 'flex';
    document.getElementById('activeChatName').textContent = user.username;
    
    // Mark chat as active
    document.querySelectorAll('.chat-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.closest('.chat-item')?.classList.add('active');
    
    // Load messages
    await loadMessages(user.id);
    
    // Join room
    socket.emit('join_chat', { userId: currentUser.id, recipientId: user.id });
}

async function loadMessages(userId) {
    try {
        const response = await fetch(`/api/messages/${userId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('chatroom_token')}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayMessages(data.messages);
        }
    } catch (error) {
        console.error('Load messages error:', error);
    }
}

function displayMessages(messages) {
    const container = document.getElementById('messagesContainer');
    container.innerHTML = '';
    
    messages.forEach(msg => {
        displayMessage(msg, msg.senderId === currentUser.id);
    });
    
    container.scrollTop = container.scrollHeight;
}

function displayMessage(message, isSent) {
    const container = document.getElementById('messagesContainer');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSent ? 'message-sent' : 'message-received'}`;
    
    messageDiv.innerHTML = `
        ${message.content}
        <span class="message-time">${formatTime(message.timestamp)}</span>
    `;
    
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const content = input.value.trim();
    
    if (!content || !currentChatUser) return;
    
    const message = {
        senderId: currentUser.id,
        recipientId: currentChatUser.id,
        content: content,
        timestamp: new Date()
    };
    
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('chatroom_token')}`
            },
            body: JSON.stringify(message)
        });
        
        if (response.ok) {
            socket.emit('send_message', message);
            displayMessage(message, true);
            input.value = '';
        }
    } catch (error) {
        console.error('Send message error:', error);
    }
}

function handleEnterKey(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

// Search and Add User
function showAddUserModal() {
    document.getElementById('addUserModal').classList.add('active');
}

function closeAddUserModal() {
    document.getElementById('addUserModal').classList.remove('active');
    document.getElementById('searchUsername').value = '';
    document.getElementById('userSearchResults').innerHTML = '';
}

let searchTimeout;
async function searchUsers() {
    clearTimeout(searchTimeout);
    
    const query = document.getElementById('searchUsername').value.trim();
    
    if (query.length < 2) {
        document.getElementById('userSearchResults').innerHTML = '';
        return;
    }
    
    searchTimeout = setTimeout(async () => {
        try {
            const response = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('chatroom_token')}`
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                displaySearchResults(data.users);
            }
        } catch (error) {
            console.error('Search error:', error);
        }
    }, 300);
}

function displaySearchResults(users) {
    const container = document.getElementById('userSearchResults');
    container.innerHTML = '';
    
    if (users.length === 0) {
        container.innerHTML = '<p style="padding: 1rem; text-align: center; color: #666;">No users found</p>';
        return;
    }
    
    users.forEach(user => {
        const userDiv = document.createElement('div');
        userDiv.className = 'user-result';
        userDiv.innerHTML = `
            <div>
                <strong>${user.username}</strong>
                <div style="font-size: 0.9rem; color: #666;">${user.email}</div>
            </div>
            <button onclick="startChat('${user.id}', '${user.username}')">Chat</button>
        `;
        container.appendChild(userDiv);
    });
}

async function startChat(userId, username) {
    closeAddUserModal();
    openChat({ id: userId, username: username });
    await loadConversations();
}

function searchConversations() {
    const query = document.getElementById('searchUsers').value.toLowerCase();
    const items = document.querySelectorAll('.chat-item');
    
    items.forEach(item => {
        const name = item.querySelector('.chat-item-name').textContent.toLowerCase();
        if (name.includes(query)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

// Profile
function showProfile() {
    document.getElementById('profileModal').classList.add('active');
    document.getElementById('profileUsername').textContent = currentUser.username;
    document.getElementById('profileEmail').textContent = currentUser.email;
}

function closeProfileModal() {
    document.getElementById('profileModal').classList.remove('active');
}

// Utility Functions
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function updateOnlineStatus(status) {
    const statusElement = document.getElementById('onlineStatus');
    if (status === 'online') {
        statusElement.textContent = 'Online';
        statusElement.classList.add('online');
    } else {
        statusElement.textContent = 'Offline';
        statusElement.classList.remove('online');
    }
}

function updateConversationList() {
    loadConversations();
}