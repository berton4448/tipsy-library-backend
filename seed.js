const mongoose = require('mongoose');
const cocktails = require('./cocktailsData'); // 讀取剛才存好的資料檔案

// 1. 連線字串 (填入跟你 server.js 一模一樣的那串)
const MONGODB_URI = process.env.MONGODB_URI;
// 2. 定義格式 (這也要跟 server.js 裡面的一樣)
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

// 3. 執行搬運任務
async function seedDatabase() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log("☁️  雲端連線成功，準備開始搬運...");

        // 先把資料庫清空 (防止重複塞入資料)
        await Cocktail.deleteMany({});
        console.log("🗑️  舊資料已清空");

        // 一次塞入 70 幾筆資料
        await Cocktail.insertMany(cocktails);
        console.log("✅ 成功！70 幾杯調酒已經全部存入雲端倉庫了！");

        // 完成後關閉連線
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ 搬運失敗：", error);
    }
}

seedDatabase();