require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
 
const auth = require('./middleware/auth');

// --- 引入新套件 ---
const bcrypt = require('bcryptjs'); // 加密用的
const jwt = require('jsonwebtoken'); // 產生 Token 用的
const rateLimit = require('express-rate-limit'); // 防駭限流
/* const mongoSanitize = require('express-mongo-sanitize'); // 先暫時關閉避免報錯 */

// --- 引入 User 模型 ---
const User = require('./models/User');

const port = 3000;

app.use(cors());
app.use(express.json());

// --- 資安設定 ---
/* app.use(mongoSanitize()); */

// 登入/註冊限流器 (同一 IP，15 分鐘內只能試 100 次)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: '請求次數過多，請稍後再試'
});
app.use('/api', limiter);


// ==========================================
// 🚀 會員系統路由 (Auth Routes)
// ==========================================

// 1. [註冊 API] POST /api/register
app.post('/api/register', async (req, res) => {
    console.log("🔔 [註冊] 收到請求：", req.body);

    try {
        const { username, email, password } = req.body;

        // 檢查必填
        if (!username || !email || !password) {
            return res.status(400).json({ message: '請填寫所有欄位' });
        }

        // 檢查重複 Email
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: '此 Email 已經被註冊過了' });
        }

        // 密碼加密
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 建立使用者
        const newUser = await User.create({
            username,
            email,
            password: hashedPassword,
        });

        // 發放 Token
        const token = jwt.sign(
            { id: newUser._id }, 
            process.env.JWT_SECRET || 'secret123', 
            { expiresIn: '1d' }
        );

        // 回傳成功
        res.status(201).json({
            success: true,
            message: '註冊成功！歡迎加入微醺圖書館',
            token,
            user: {
                id: newUser._id,
                username: newUser.username,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error("註冊錯誤:", error);
        res.status(500).json({ message: '伺服器錯誤' });
    }
});


// 2. [登入 API] POST /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 檢查有無輸入
        if (!email || !password) {
            return res.status(400).json({ message: '請輸入 Email 和密碼' });
        }

        // 找使用者 (包含密碼欄位)
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({ message: 'Email 或密碼錯誤' });
        }

        // 檢查是否被鎖定 (防駭)
        if (user.lockUntil && user.lockUntil > Date.now()) {
            return res.status(403).json({ 
                message: '帳號暫時鎖定中，請 15 分鐘後再試' 
            });
        }

        // 比對密碼
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            // 密碼錯 -> 增加錯誤次數
            user.loginAttempts += 1;
            
            // 連錯 5 次鎖定
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000; // 鎖 15 分鐘
                await user.save();
                return res.status(403).json({ message: '錯誤次數過多，帳號已鎖定 15 分鐘' });
            }

            await user.save();
            return res.status(401).json({ message: 'Email 或密碼錯誤' });
        }

        // 登入成功 -> 重置錯誤計數
        user.loginAttempts = 0;
        user.lockUntil = undefined;
        await user.save();

        // 發放 Token
        const token = jwt.sign(
            { id: user._id }, 
            process.env.JWT_SECRET || 'secret123', 
            { expiresIn: '1d' }
        );

        res.status(200).json({
            success: true,
            message: '登入成功！',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("登入錯誤:", error);
        res.status(500).json({ message: '伺服器錯誤' });
    }
});


// 3. [VIP 路由] 獲取個人資料 (GET /api/me)
// 注意：我們中間插了一個 auth，這就是讓保全先檢查！
app.get('/api/me', auth, async (req, res) => {
    // 如果程式跑到這裡，代表已經通過 auth 檢查了
    // 我們可以直接用 req.user 拿到是誰
    res.status(200).json({
        success: true,
        message: '歡迎進入 VIP 區域！',
        user: req.user // 把使用者的詳細資料回傳給他看
    });
});


// ==========================================
// 🍸 酒單系統與資料庫 (Database & Cocktails)
// ==========================================

const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
    .then(() => console.log("☁️  恭喜！成功連線到 MongoDB 雲端資料庫！"))
    .catch(err => console.error("❌ 連線失敗，請檢查網址或密碼：", err));

const cocktailSchema = new mongoose.Schema({
    id: Number,
    name: String,
    base: mongoose.Schema.Types.Mixed,
    abvLevel: String,
    abvDisplay: String,
    taste: String,
    ingredients: String,
    story: String,
    img: String,
    method: String,
    glass: String,
    steps: [String]
});

const Cocktail = mongoose.model('Cocktail', cocktailSchema);

app.get('/', (req, res) => {
    res.send('<h1>微醺圖書館後端 - 資料庫連線版 🍸</h1>');
});

app.get('/api/cocktails', async (req, res) => {
    try {
        const cocktails = await Cocktail.find();
        res.json(cocktails);
    } catch (error) {
        res.status(500).json({ message: "伺服器錯誤" });
    }
});


// [收藏/取消收藏 API] POST /api/cocktails/:id/collect
// 💡 注意：這裡加了 auth，代表只有登入的人才能按收藏
app.post('/api/cocktails/:id/collect', auth, async (req, res) => {
    try {
        const cocktailId = req.params.id; // 從網址拿到酒的 ID
        const userId = req.user._id; // 從 auth 保全拿到這是誰

        // 1. 先確認這杯酒存不存在 (避免收藏到幽靈)
        const cocktail = await Cocktail.findById(cocktailId);
        if (!cocktail) {
            return res.status(404).json({ message: '找不到這杯酒' });
        }

        // 2. 找這個使用者
        const user = await User.findById(userId);

        // 3. 檢查是不是已經收藏過了
        // (使用 includes 來檢查陣列裡有沒有這個 ID)
        const isCollected = user.favorites.includes(cocktailId);

        if (isCollected) {
            // A. 如果已經收藏 -> 移除 (Filter 掉不要的)
            user.favorites = user.favorites.filter(id => id.toString() !== cocktailId);
            await user.save();
            return res.status(200).json({ 
                success: true, 
                message: '已移除收藏', 
                favorites: user.favorites 
            });
        } else {
            // B. 如果還沒收藏 -> 加入 (Push 進去)
            user.favorites.push(cocktailId);
            await user.save();
            return res.status(200).json({ 
                success: true, 
                message: '已加入收藏 ❤️', 
                favorites: user.favorites 
            });
        }

    } catch (error) {
        console.error("收藏失敗:", error);
        res.status(500).json({ message: '伺服器錯誤' });
    }
});

// 啟動伺服器
app.listen(port, () => {
    console.log(`後端伺服器運行中：http://localhost:${port}`);
});