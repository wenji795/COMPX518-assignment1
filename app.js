// Import required modules导入所需模块
const path = require('path');
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const BadWordsFilter = require('bad-words');
const filter = new BadWordsFilter();

// Set database connection configuration设置数据库连接配置
const dbConfig = {
    host: 'db.trex-sandwich.com',
    user: 'ws111',
    password: '1518428',
    database: 'ws111',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Create a connection pool创建一个连接池
const pool = mysql.createPool(dbConfig);

// Create an Express application创建一个Express应用
const app = express();
const port = 3000; // 服务器端口



// Parse JSON and form data 解析JSON和表单数据
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Use express.static middleware to provide static files in the public directory
// 使用express.static中间件来提供public目录下的静态文件
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/check-username', async (req, res) => {
    const { username } = req.query;
    try {
        const normalizedUsername = normalizeUsername(username.toLowerCase());
        const [users] = await pool.query('SELECT * FROM verification_users WHERE LOWER(username) = LOWER(?)', [normalizedUsername]);
        if (users.length > 0) {
            res.json({ usernameExists: true });
        } else {
            res.json({ usernameExists: false });
        }
    } catch (error) {
        console.error('Error checking username：', error);
        res.status(500).send('Internal server error.');
    }
});


// Provide 'login.html' page specifically for '/login'
// 专门为 '/login' 提供 'login.html' 页面
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// Define a function to replace numbers with letters
// 定义一个函数来替换数字为字母
function normalizeUsername(username) {
    const leetChars = {
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '0': 'o',
        '7': 't',
        '@': 'a',
        '\\$': 's',
        '\\+': 't',
        '8': 'B',
        '\\(': 'c',
        '\\|\\)': 'd', // 符号组合|)替换为字母d
        '\\|=': 'f', // 符号组合|=替换为字母f
        '6': 'g', // 数字6替换为字母g
        '\\|-\\|': 'h', // 符号组合|-|替换为字母h
        '!': 'i', // 符号!替换为字母i
        '\\|<': 'k', // 符号组合|<替换为字母k
        '\\|_': 'l', // 符号组合|_替换为字母l
        '\\|o': 'p', // 符号组合|o替换为字母p
        '\\(_\\)': 'q', // 符号组合(_)替换为字母q
        '\\|2': 'r', // 符号组合|2替换为字母r
        '2': 'z',

    };
    // Convert each character to lowercase and replace if it is a leet character
    // 将每个字符转换为小写，如果是leet字符则替换
    let normalizedUsername = username.toLowerCase();
    Object.keys(leetChars).forEach(key => {
        const regex = new RegExp(key, 'g');
        normalizedUsername = normalizedUsername.replace(regex, leetChars[key]);
    });
    return normalizedUsername;
}



// Loading a list of unsafe passwords加载不安全密码列表
let unsafePasswords = new Set();

async function loadUnsafePasswords() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'combined_passwords.csv'), 'utf-8');

        const passwords = data.split('\n').slice(1);
        passwords.forEach(password => unsafePasswords.add(password.trim()));
    } catch (error) {
        console.error('Error loading passwords:', error);
    }
}

// Load password list on server startup 在服务器启动时加载密码列表
loadUnsafePasswords();



// Register route注册路由
app.post('/register', async (req, res) => {
    try {


        let { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).send('Username and password are required.');
        }

//Username
        // Check whether the username and password meet the requirements检查用户名和密码是否满足要求
        if (username.length < 4) {
            return res.status(400).json({ error: 'Username needs to be at least 4 characters.' });
        }

        // Check if the username contains only letters, numbers and underscores检查用户名是否仅含有字母、数字和下划线
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).send('Usernames can only contain letters, numbers, and underscores.');
        }

        // Convert username to lowercase and replace leet speak将用户名转换为小写，并替换leet speak
        const cleanUsername = normalizeUsername(username.toLowerCase());

        // Check if username contains profanity检查用户名是否包含脏话
        if (filter.isProfane(cleanUsername)) {
            return res.status(400).send('Usernames must not contain inappropriate words.');
        }

        // Check if username already exists (case insensitive) 检查用户名是否已存在（不区分大小写）
        const [existingUsers] = await pool.query('SELECT * FROM verification_users WHERE LOWER(username) = LOWER(?)', [cleanUsername]);
        if (existingUsers.length > 0) {
            return res.status(409).send('Username is already taken.');
        }


//Password
        // Check password length检查密码长度
        if (password.length < 8 || password.length > 64) {
            return res.status(400).send('Password length should be between 8 and 64 characters.');
        }

        // Check if the password contains the username检查密码中是否包含用户名
        if (password.toLowerCase().includes(username.toLowerCase())) {
            return res.status(400).send('Username is not allowed in password.');
        }

        // Check if the password is in the list of unsafe passwords检查密码是否在不安全密码列表中
        if (unsafePasswords.has(password)) {
            return res.status(400).send('The password is too weak or has been compromised. Please use a different password.密码太弱，或者已经被泄露，请使用其他密码。');
        }

        // print password 仅在开发环境中打印密码
        console.log(`Registration attempt: username=${username}, password=${password}`);

        // Hashing passwords哈希处理密码
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user information into database 将新用户信息插入数据库
        await pool.query('INSERT INTO verification_users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        res.status(201).send('User registration successful.');
    } catch (error) {
        console.error('An error occurred while registering:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            // If the error is caused by a duplicate username, a specific error message is returned.如果是因为用户名重复导致的错误，返回一个具体的错误消息
            return res.status(409).send('Registration failed, username already exists.');
        }
        res.status(500).send('An internal server error occurred while registering.');
    }
});

// Login routing登录路由
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check whether the username and password meet the requirements检查用户名和密码是否满足要求
        if (username.length < 4) {
            return res.status(400).json({ error: 'Username needs to be at least 4 characters.' });
        }

        if (password.length < 8 || password.length > 64) {
            return res.status(400).json({ error: 'Password length should be between 8 and 64 characters.' });
        }

        // print password
        console.log(`Login attempt: username=${username}, password=${password}`);
        // 从数据库中检索用户信息
        const [users] = await pool.query('SELECT * FROM verification_users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).send('Retrieve user information from database');
        }

        // User exists, check password 用户存在，检查密码
        const user = users[0];
        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            return res.status(401).send('invalid username or password.');
        }



        res.send('Login successful.');
    } catch (error) {
        console.error('Error while logging in:', error);
        res.status(500).send('An error occurred while the user was logging in.');
    }
});

// Start the server启动服务器
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
