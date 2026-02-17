const jwt = require('jsonwebtoken');
const User = require('../models/User');

// 這就是我們的「保全」函式
const auth = async (req, res, next) => {
    try {
        // 1. 檢查請求標頭 (Header) 有沒有帶 token
        // 通常格式是: "Authorization: Bearer <token>"
        let token;
        
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1]; // 取出 Bearer 後面的那串亂碼
        }

        // 2. 如果沒 token，直接擋下
        if (!token) {
            return res.status(401).json({ message: '未授權：請先登入 (No token provided)' });
        }

        // 3. 驗證 token 是否由我們發放 (驗印章真偽)
        // 這裡的 secret 必須跟發放時用的一樣
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');

        // 4. 根據印章裡的身分證字號 (id)，去資料庫找這個人還在不在
        const currentUser = await User.findById(decoded.id);
        if (!currentUser) {
            return res.status(401).json({ message: '未授權：找不到此用戶 (User no longer exists)' });
        }

        // 5. 通過檢查！把使用者資料掛在 req 上面，讓後面的程式可以用
        req.user = currentUser;
        
        // 放行！去執行下一關
        next();

    } catch (error) {
        console.error("JWT 驗證失敗:", error);
        return res.status(401).json({ message: '未授權：Token 無效或過期' });
    }
};

module.exports = auth;