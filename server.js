require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

const auth = require('./middleware/auth');

// --- 引入新套件 ---
const bcrypt = require('bcryptjs'); // 加密用的
const jwt = require('jsonwebtoken'); // 產生 Token 用的
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const rateLimit = require('express-rate-limit'); // 防駭限流
const crypto = require('crypto'); // 產生隨機 Token 用的
const nodemailer = require('nodemailer'); // 寄發 Email 用的
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // Stripe 金流
/* const mongoSanitize = require('express-mongo-sanitize'); // 先暫時關閉避免報錯 */

// --- 引入 User 模型 ---
const User = require('./models/User');

// 讓伺服器優先使用雲端環境指定的 PORT，如果沒有（本地端）才用 3000
const port = process.env.PORT || 3000;

app.use(cors());

// --- Stripe Webhook (必須放在 express.json 之前) ---
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const rawBody = req.body;
    const signature = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
        console.error('⚠️ 找不到 STRIPE_WEBHOOK_SECRET！');
        return res.status(400).send('Webhook Secret Not Set');
    }

    let event;
    try {
        event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
    } catch (err) {
        console.error(`⚠️ Webhook 簽章驗證失敗:`, err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata?.userId;

        if (userId) {
            try {
                // 從資料庫找出該名使用者並升級為乾爹 (使用精準更新避開驗證)
                const updateQuery = { $set: { isSponsor: true } };

                // 如果有傳回總金額，使用 $inc 自動累加
                if (session.amount_total) {
                    updateQuery.$inc = { totalDonation: session.amount_total / 100 };
                }

                const updatedUser = await User.findByIdAndUpdate(
                    userId,
                    updateQuery,
                    { new: true } // 不加 runValidators，直接強制更新
                );

                if (updatedUser) {
                    // 容錯處理：如果舊帳號沒名字，改顯示 Email
                    const displayName = updatedUser.username || updatedUser.email || '神秘客';
                    console.log(`🎉 恭喜！使用者 ${displayName} 成為微醺乾爹！`);
                } else {
                    console.log(`⚠️ 找不到使用者 ${userId}，無法升級。`);
                }
            } catch (error) {
                console.error('更新乾爹狀態失敗:', error);
            }
        }
    }
    res.json({ received: true });
});

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
                role: user.role,
                isSponsor: user.isSponsor
            }
        });

    } catch (error) {
        console.error("登入錯誤:", error);
        res.status(500).json({ message: '伺服器錯誤' });
    }
});


// 2.5 [Google 登入 API] POST /api/google-login
app.post('/api/google-login', async (req, res) => {
    try {
        const { token } = req.body; // 接收前端傳來的 Google Token

        // 1. 向 Google 驗證這張 Token 是不是真的
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        // 2. 拿出使用者的 Google 資料
        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture } = payload;

        // 3. 去我們的資料庫找找看，這個 Email 或 Google ID 註冊過了嗎？
        let user = await User.findOne({ email });

        if (!user) {
            // 4. 如果是第一次來，自動幫他註冊一個新帳號！
            user = await User.create({
                username: name,
                email: email,
                googleId: googleId,
                avatar: picture // 可以存 Google 的大頭貼
                // 注意：因為是 Google 登入，所以我們不需要存密碼
            });
        } else if (!user.googleId) {
            // 如果他以前是用帳號密碼註冊的，順便幫他綁定 Google ID
            user.googleId = googleId;
            await user.save();
        }

        // 5. 發放我們自己的微醺 Token
        const jwtToken = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET || 'secret123',
            { expiresIn: '1d' }
        );

        res.status(200).json({
            success: true,
            message: 'Google 登入成功！',
            token: jwtToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                avatar: user.avatar,
                isSponsor: user.isSponsor
            }
        });

    } catch (error) {
        console.error("Google 登入錯誤:", error);
        res.status(401).json({ message: 'Google 驗證失敗' });
    }
});


// 2.6 [忘記密碼 API] POST /api/forgot-password
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: '請輸入 Email' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: '找不到此 Email 的使用者' });
        }

        // 產生隨機 Token
        const resetToken = crypto.randomBytes(20).toString('hex');

        // 加密存入資料庫
        user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 分鐘後過期

        // 由於可能有些必填欄位在註冊時沒填(例如 googleId 註冊的使用者沒有密碼)，使用 validateBeforeSave: false 跳過驗證
        await user.save({ validateBeforeSave: false });

        // 設定 nodemailer
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        // 寄送 Email (包含指向重設密碼頁面的連結)
        // 使用 127.0.0.1:5500 作為前端網址以供 Live Server 測試
        const clientUrl = process.env.CLIENT_URL || 'http://127.0.0.1:5500';
        const resetUrl = `${clientUrl}/reset-password.html?token=${resetToken}`;

        const message = `
            <div style="background-color: #121212; color: #f5f5f7; padding: 40px 20px; font-family: 'Noto Serif TC', serif, sans-serif; text-align: center; border: 1px solid #d4af37; max-width: 600px; margin: 0 auto; border-radius: 8px;">
                <h2 style="color: #d4af37; letter-spacing: 2px;">微醺圖書館</h2>
                <hr style="border: 0; border-top: 1px solid rgba(212, 175, 55, 0.3); margin: 20px 0;">
                <h3 style="color: #f5f5f7; font-weight: normal;">忘記了通往館內的密語嗎？</h3>
                <p style="color: #a0a0a0; line-height: 1.6; margin-bottom: 30px; font-size: 15px;">
                    夜深了，別讓迷失的記憶阻擋您品酩的時光。<br>
                    我們收到了一份為您重新設定密碼的請求。<br>
                    請點擊下方的封印，以重啟您專屬的微醺之門。
                </p>
                <a href="${resetUrl}" style="background-color: #d4af37; color: #000; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; font-size: 16px; letter-spacing: 1px; transition: 0.3s; box-shadow: 0 4px 15px rgba(212, 175, 55, 0.3);">
                    點此重設您的密碼
                </a>
                <p style="margin-top: 40px; font-size: 0.8em; color: #666; line-height: 1.5;">
                    ※ 此連結的法力將於 <strong>10 分鐘</strong>後失效。<br>
                    若您未曾提出此請求，請忽略這封信件。<br><br>
                    若按鈕無法點擊，請複製以下網址至瀏覽器：<br>
                    <span style="color: #d4af37; word-break: break-all;">${resetUrl}</span>
                </p>
            </div>
        `;

        await transporter.sendMail({
            from: `"微醺圖書館" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: '微醺圖書館 - 密碼重設連結',
            html: message
        });

        res.status(200).json({ success: true, message: '重設信件已寄出，請至信箱檢查' });
    } catch (error) {
        console.error("忘記密碼錯誤:", error);

        // 如果錯誤發生，把剛才設定的 token 清掉
        if (req.body.email) {
            const user = await User.findOne({ email: req.body.email });
            if (user) {
                user.resetPasswordToken = undefined;
                user.resetPasswordExpire = undefined;
                await user.save({ validateBeforeSave: false });
            }
        }
        res.status(500).json({ message: 'Email 寄送失敗，系統錯誤' });
    }
});

// 2.7 [重設密碼 API] PATCH /api/reset-password/:token
app.patch('/api/reset-password/:token', async (req, res) => {
    try {
        // 將 URL 取得的 token 加密回原本存入資料庫的樣子，來找人
        const resetPasswordToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

        // 找尋 Token 相符且尚未過期的使用者
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Token 無效或已過期' });
        }

        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ message: '請輸入新密碼' });
        }

        // 加密新密碼
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // 清除 Token
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        res.status(200).json({ success: true, message: '密碼重設成功，請重新登入' });
    } catch (error) {
        console.error("重設密碼錯誤:", error);
        res.status(500).json({ message: '系統錯誤' });
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
        const cocktailId = req.params.id; 
        
        // 修正這裡：同時支援 req.user._id 或 req.user.id，避免 undefined
        const userId = req.user._id || req.user.id; 

        if (!userId) {
            return res.status(401).json({ success: false, message: '無法識別使用者身分，請重新登入' });
        }

        // 1. 先確認這杯酒存不存在 (避免收藏到幽靈)
        const cocktail = await Cocktail.findById(cocktailId);
        if (!cocktail) {
            return res.status(404).json({ message: '找不到這杯酒' });
        }

        // 2. 找這個使用者
        const user = await User.findById(userId);

        // 3. 檢查是不是已經收藏過了
        // 強制把所有 ID 轉成字串來比對，最安全
        const cocktailIdStr = cocktailId.toString();
        const isCollected = user.favorites.some(favId => favId.toString() === cocktailIdStr);

        if (isCollected) {
            // A. 如果已經收藏 -> 移除 (過濾掉相同的 ID)
            user.favorites = user.favorites.filter(favId => favId.toString() !== cocktailIdStr);
            
            // 💡 關鍵：加上 validateBeforeSave: false，避免其他無關欄位阻擋儲存
            await user.save({ validateBeforeSave: false });
            
            return res.status(200).json({
                success: true,
                message: '已移除收藏',
                favorites: user.favorites
            });
        } else {
            // B. 如果還沒收藏 -> 加入
            user.favorites.push(cocktailIdStr);
            
            // 💡 關鍵：同樣加上 validateBeforeSave: false
            await user.save({ validateBeforeSave: false });
            
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

// ==========================================
// 🛡️ CMS 後台管理路由 (Admin Routes)
// ==========================================

// 權限驗證：只允許總管訪問
const adminAuth = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: '權限不足：您不是微醺圖書館總管！' });
    }
};

// 1. [新增酒譜] POST /api/admin/cocktails
app.post('/api/admin/cocktails', auth, adminAuth, async (req, res) => {
    try {
        const newCocktail = new Cocktail(req.body);

        // 如果沒有輸入自訂 ID，自動抓取目前最大 ID + 1
        if (!newCocktail.id) {
            const lastCocktail = await Cocktail.findOne().sort('-id');
            newCocktail.id = lastCocktail && lastCocktail.id ? lastCocktail.id + 1 : 1;
        }

        await newCocktail.save();
        res.status(201).json({ success: true, message: '成功新增一杯酒譜！', cocktail: newCocktail });
    } catch (error) {
        console.error("【新增酒譜】錯誤:", error);
        res.status(500).json({ success: false, message: '新增失敗，伺服器發生錯誤' });
    }
});

// 2. [更新特定酒譜] PUT /api/admin/cocktails/:id
app.put('/api/admin/cocktails/:id', auth, adminAuth, async (req, res) => {
    try {
        const cocktailId = req.params.id; // 這是 MongoDB 的 _id

        // 使用 findByIdAndUpdate 更新，並設定 { new: true } 來回傳更新後的資料
        const updatedCocktail = await Cocktail.findByIdAndUpdate(
            cocktailId,
            req.body,
            { new: true, runValidators: true }
        );

        if (!updatedCocktail) {
            return res.status(404).json({ success: false, message: '找不到此特定酒譜' });
        }

        res.status(200).json({ success: true, message: '酒譜更新成功！', cocktail: updatedCocktail });
    } catch (error) {
        console.error("【更新酒譜】錯誤:", error);
        res.status(500).json({ success: false, message: '更新失敗，伺服器發生錯誤' });
    }
});

// 3. [刪除特定酒譜] DELETE /api/admin/cocktails/:id
app.delete('/api/admin/cocktails/:id', auth, adminAuth, async (req, res) => {
    try {
        const cocktailId = req.params.id; // 這是 MongoDB 的 _id
        const deletedCocktail = await Cocktail.findByIdAndDelete(cocktailId);

        if (!deletedCocktail) {
            return res.status(404).json({ success: false, message: '找不到此特定酒譜，可能已被刪除' });
        }

        res.status(200).json({ success: true, message: '酒譜已成功刪除！' });
    } catch (error) {
        console.error("【刪除酒譜】錯誤:", error);
        res.status(500).json({ success: false, message: '刪除失敗，伺服器發生錯誤' });
    }
});


// ==========================================
// 💳 贊助系統 (Stripe 金流)
// ==========================================

// [產生 Stripe 結帳頁面] POST /api/create-checkout-session
// 1. 掛載 auth，只有登入會員才能贊助
// 2. 由於這裡在 /api/ 的範圍內，已經受到 limiter (15 分鐘 100 次) 的保護
app.post('/api/create-checkout-session', auth, async (req, res) => {
    try {
        const { amount } = req.body;

        console.log("👉 [Stripe] 收到前端請求的 amount:", amount);
        console.log("👉 [Stripe] amount 的型別是:", typeof amount);

        // --- 嚴格數值清洗 (Sanitization) ---
        // 1. 檢查是否為 Number 型別 (阻擋 String, Object, Boolean)
        if (typeof amount !== 'number') {
            console.error("❌ 金流錯誤: 型別不正確!");
            return res.status(400).json({ success: false, message: '金額格式錯誤：必須為數字型態' });
        }

        // 2. 檢查是否為 NaN 或 Infinity
        if (!Number.isFinite(amount) || Number.isNaN(amount)) {
            return res.status(400).json({ success: false, message: '金額數值異常' });
        }

        // 3. 阻擋小數點與科學記號 (必須是純浮點整數)
        if (!Number.isInteger(amount)) {
            return res.status(400).json({ success: false, message: '金額必須為整數，不支援小數點' });
        }

        // 4. 驗證範圍：地板 50，天花板 100,000，防止 Overflow
        if (amount < 50) {
            return res.status(400).json({ success: false, message: '贊助金額不得低於 NTD 50' });
        }
        if (amount > 100000) {
            return res.status(400).json({ success: false, message: '單筆贊助上限為 NTD 100,000' });
        }

        // --- 呼叫 Stripe API 建立結帳會話 ---
        // 注意：TWD 為零小數貨幣，所以 amount 傳 50 就是 50 元。
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'twd',
                        product_data: {
                            name: '微醺圖書館 - 贊助支持',
                            description: '每一杯微醺，都是對我們最大的鼓勵。'
                        },
                        unit_amount: amount * 100
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            metadata: {
                userId: req.user._id.toString()
            },
            // 由於不知道具體部署網址，這裡以目前的來源 (req.headers.origin) 為主，並 fallback 到本地端
            success_url: `${req.headers.origin || 'http://localhost:5500'}?success=true`,
            cancel_url: `${req.headers.origin || 'http://localhost:5500'}?canceled=true`,
            customer_email: req.user.email // 帶入目前登入會員的 Email，可加快結帳速度
        });

        // 將結帳網址回傳給前端
        res.status(200).json({ success: true, url: session.url });

    } catch (error) {
        console.error("【Stripe 結帳】錯誤:", error.message);
        res.status(500).json({ success: false, message: '金流服務暫時無法使用，請稍後再試' });
    }
});


// 啟動伺服器
app.listen(port, () => {
    console.log(`後端伺服器運行中：http://localhost:${port}`);
});