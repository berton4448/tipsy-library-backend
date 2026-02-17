// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  // --- 1. 基本身分 (Identity) ---
  username: { 
    type: String, 
    required: [true, '請輸入使用者名稱'] 
  },
  email: { 
    type: String, 
    required: [true, '請輸入 Email'], 
    unique: true, // 確保 Email 不重複
    lowercase: true,
    trim: true
  },
  password: { 
    type: String,
    select: false // 資安設定：查詢時預設不顯示密碼
  },
  avatar: { 
    type: String, 
    default: "https://cdn-icons-png.flaticon.com/512/3135/3135715.png" // 預設大頭貼
  },

  // --- 2. 第三方登入 (Google Login) ---
  googleId: String, // 存 Google 給的 ID，如果有這欄位，password 可能是空的

  // --- 3. 商業邏輯 (Business Logic) ---
  role: { 
    type: String, 
    enum: ['user', 'vip', 'admin'], 
    default: 'user' 
  },
  totalDonation: { // 乾爹贊助總金額 (為金流鋪路)
    type: Number, 
    default: 0 
  },
  favorites: [ // 個人酒櫃 (關聯到 Cocktail)
    { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'Cocktail' 
    }
  ],

  // --- 4. 忘記密碼 (Forgot Password) ---
  resetPasswordToken: String, // 臨時驗證碼
  resetPasswordExpire: Date,  // 驗證碼過期時間

  // --- 5. 防駭機制 (Login Security) ---
  loginAttempts: { type: Number, default: 0 }, // 登入失敗次數
  lockUntil: Date, // 帳號被鎖定到什麼時候

  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// 建立並匯出模型
const User = mongoose.model('User', userSchema);
module.exports = User;