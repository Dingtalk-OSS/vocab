require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const app = express();

app.use(cors());
app.use(express.json({ limit: '50kb' }));
app.use(express.static(__dirname)); // 托管前端 index.html

// 简单内存限流器
const rateStore = new Map();
setInterval(() => { // 每分钟清理过期条目
  const now = Date.now();
  for (const [k, v] of rateStore) if (now > v.resetAt) rateStore.delete(k);
}, 60000);
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  let entry = rateStore.get(key);
  if (!entry || now > entry.resetAt) { entry = { count: 0, resetAt: now + windowMs }; rateStore.set(key, entry); }
  entry.count++;
  if (entry.count > max) {
    const waitMin = Math.ceil((entry.resetAt - now) / 60000);
    throw new Error(`操作过于频繁，请 ${waitMin} 分钟后重试`);
  }
}

// 用户名合法性校验
function validateUsername(name) {
  if (!name || name.length < 2 || name.length > 20) throw new Error('用户名长度需 2-20 个字符');
  if (/[<>"'&\\/]/.test(name)) throw new Error('用户名包含非法字符');
  if (/^[0-9]+$/.test(name)) throw new Error('用户名不能全为数字');
}
function sanitize(str) { return String(str).replace(/[<>"'&]/g, ''); }

// 初始化数据库
const db = new Database('data.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS practice_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    word TEXT NOT NULL,
    phonetic TEXT,
    meaning TEXT,
    extended TEXT,
    chinese_sentence TEXT,
    user_translation TEXT,
    reference_sentence TEXT,
    score_total INTEGER,
    score_grammar INTEGER,
    score_word_choice INTEGER,
    score_naturalness INTEGER,
    time_spent INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);
// 迁移：添加新字段（已有表时忽略重复）
try { db.exec('ALTER TABLE practice_logs ADD COLUMN difficulty INTEGER DEFAULT 1'); } catch(e) {}
try { db.exec('ALTER TABLE practice_logs ADD COLUMN is_practice INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT NULL'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN tagline TEXT DEFAULT NULL'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN status TEXT DEFAULT "online"'); } catch(e) {}
try { db.exec('UPDATE practice_logs SET difficulty = 1 WHERE difficulty IS NULL'); } catch(e) {}
// 登录记录表
db.exec(`CREATE TABLE IF NOT EXISTS login_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  ip TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);
// 竞赛结果表
db.exec(`CREATE TABLE IF NOT EXISTS challenge_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  duration INTEGER NOT NULL,
  score REAL NOT NULL,
  avg_score REAL NOT NULL,
  word_count INTEGER NOT NULL,
  total_time INTEGER NOT NULL,
  details TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

const JWT_SECRET = process.env.JWT_SECRET || 'vocab-push-secret-2024';

// 管理员账号（设 ADMIN_PASSWORD 环境变量可自定义密码，默认 admin123）
try {
  var adminPw = process.env.ADMIN_PASSWORD || 'admin123';
  var hash = bcrypt.hashSync(adminPw, 10);
  db.prepare('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)').run('Aaa', hash);
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, 'Aaa');
  console.log('管理员密码已更新');
} catch(e) { console.error('管理员账号初始化失败:', e.message); }

// 从 JWT 提取用户 ID
function getUserId(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('未登录');
  }
  const token = authHeader.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  return decoded.userId;
}

// 统一 AI 请求 — 仅支持国内平台
const API_PLATFORMS = {
  deepseek: { name: 'DeepSeek', baseUrl: 'https://api.deepseek.com/v1/chat/completions', model: 'deepseek-chat' },
  qwen: { name: '通义千问 (Qwen)', baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions', model: 'qwen-plus' },
  glm: { name: '智谱 (GLM)', baseUrl: 'https://open.bigmodel.cn/api/paas/v4/chat/completions', model: 'glm-4-plus' },
  moonshot: { name: '月之暗面 (Moonshot)', baseUrl: 'https://api.moonshot.cn/v1/chat/completions', model: 'moonshot-v1-8k' },
  yi: { name: '零一万物 (Yi)', baseUrl: 'https://api.lingyiwanwu.com/v1/chat/completions', model: 'yi-lightning' },
  siliconflow: { name: 'SiliconFlow', baseUrl: 'https://api.siliconflow.cn/v1/chat/completions', model: 'deepseek-ai/DeepSeek-V3' }
};
async function callAI(apiKey, messages, temperature = 1.0, platform = 'deepseek', customUrl = '', extraOpts = {}) {
  let apiUrl, model;
  if (platform === 'custom' && customUrl) {
    apiUrl = customUrl;
    model = extraOpts.model || 'default';
  } else {
    const cfg = API_PLATFORMS[platform] || API_PLATFORMS.deepseek;
    apiUrl = cfg.baseUrl;
    model = extraOpts.model || cfg.model;
  }
  const body = { model, messages, temperature };
  if (!extraOpts.skipResponseFormat) body.response_format = { type: 'json_object' };
  const resp = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`AI请求失败: ${resp.status} ${err}`);
  }
  const data = await resp.json();
  const text = data.choices[0].message.content;
  if (extraOpts.skipResponseFormat) return text;
  return JSON.parse(text.replace(/```json|```/g, ''));
}

// 注册
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    rateLimit('reg:' + ip, 3, 3600000); // 每 IP 每小时最多注册 3 次
    const username = sanitize(req.body.username || '');
    const password = req.body.password || '';
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    validateUsername(username);
    if (password.length < 4) return res.status(400).json({ error: '密码至少 4 个字符' });
    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    res.json({ message: '注册成功' });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: '用户名已存在' });
    if (e.message.includes('操作过于频繁')) return res.status(429).json({ error: e.message });
    if (e.message.includes('用户名') || e.message.includes('密码')) return res.status(400).json({ error: e.message });
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 登录
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    rateLimit('login:' + ip, 3, 900000); // 每 IP 每 15 分钟最多登录 3 次
    const username = sanitize(req.body.username || '');
    const password = req.body.password || '';
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    validateUsername(username);
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: '用户名或密码错误' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    // 记录登录
    try { db.prepare('INSERT INTO login_logs (user_id, ip) VALUES (?, ?)').run(user.id, ip); } catch(e) {}
    res.json({ token, userId: user.id, username: user.username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 测试 API 连接（无需 JWT）
app.post('/api/v1/test-connection', async (req, res) => {
  try {
    const { apiKey, platform, customUrl, model: customModel } = req.body;
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const p = platform || 'deepseek';
    await callAI(apiKey, [
      { role: 'user', content: '回复"ok"这一个字' }
    ], 0.1, p, customUrl || '', { skipResponseFormat: true, model: customModel });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message, success: false });
  }
});

const DIFFICULTY_PROMPTS = {
  1: '基础生存级：日常简单对话、标识标牌，句式简单，时态单一，语义直白。',
  2: '通用信息级：新闻简讯、旅游指南、通识科普，涉及中长句和常见习语。',
  3: '专业技术级：法律合同、医学报告、IT技术文档，术语密度高，句式程式化。',
  4: '学术论述级：学术论文、社论、政策白皮书，逻辑嵌套深，涉及抽象概念。',
  5: '文学艺术级：经典小说、散文，大量修辞手法，极具个人风格的惯用语。',
  6: '文化融汇级：品牌Slogan、广告、古诗词，文字极度凝练，需文化背景理解。'
};

// 生成单词
app.post('/api/v1/words/generate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const difficulty = parseInt(req.body.difficulty) || 1;
    const specificWord = req.body.word || '';
    const diffPrompt = DIFFICULTY_PROMPTS[difficulty] || DIFFICULTY_PROMPTS[1];
    const wordPrompt = specificWord
      ? `提供以下单词的详细信息：${specificWord}`
      : `随机生成一个匹配该难度的英语单词`;
    const result = await callAI(apiKey, [
      { role: 'system', content: '你是一个英语单词信息提供者，只输出JSON，不要其他文字。' },
      { role: 'user', content: `难度：${diffPrompt}\n${wordPrompt}，并提供：单词、音标、中文释义（简短）、延展释义（详细的中文解释或用法，不要包含任何例句或句子）。严格JSON：{"word":"...","phonetic":"...","meaning":"...","extended":"..."}` }
    ], 1.2, platform, customUrl);
    res.json({ ...result, difficulty });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 生成中文句子
app.post('/api/v1/sentences/generate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { word, meaning, difficulty } = req.body;
    if (!word || !meaning) return res.status(400).json({ error: '缺少参数' });
    const diffPrompt = DIFFICULTY_PROMPTS[parseInt(difficulty)||1] || DIFFICULTY_PROMPTS[1];
    const result = await callAI(apiKey, [
      { role: 'system', content: '你是中文出题助手，只输出JSON。' },
      { role: 'user', content: `难度：${diffPrompt}\n单词：${word}\n释义：${meaning}\n生成一个匹配该难度的中文句子，10-30字，不包含英文。JSON：{"chinese_sentence":"..."}` }
    ], 0.3, platform, customUrl);
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 翻译批改并记录
app.post('/api/v1/translations/evaluate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const { word, meaning, phonetic, extended, chinese_sentence, user_translation, time_spent, difficulty, is_practice } = req.body;
    if (!word || !meaning || !chinese_sentence || !user_translation) {
      return res.status(400).json({ error: '缺少必要参数' });
    }
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const diffPrompt = DIFFICULTY_PROMPTS[parseInt(difficulty)||1] || DIFFICULTY_PROMPTS[1];
    const result = await callAI(apiKey, [
      { role: 'system', content: '你是翻译批改专家，输出JSON。' },
      { role: 'user', content: `难度：${diffPrompt}\n单词：${word}（${meaning}）\n中文：${chinese_sentence}\n用户翻译：${user_translation}\n按对应难度标准批改并返回JSON：{
        "correction": { "natural": "地道参考句，必须使用${word}", "overall": "整体评价" },
        "differences": [ {"type":"语法/用词/自然度","severity":"high/medium/low","error_text":"错误","correction_text":"正确","explanation":"解释"} ],
        "score": {"grammar":0-100,"word_choice":0-100,"naturalness":0-100,"total":0-100}
      }` }
    ], 0.3, platform, customUrl);
    // 保存记录
    db.prepare(`INSERT INTO practice_logs (user_id, word, phonetic, meaning, extended, chinese_sentence, user_translation, reference_sentence, score_total, score_grammar, score_word_choice, score_naturalness, time_spent, difficulty, is_practice)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      userId, word, phonetic||'', meaning, extended||'', chinese_sentence, user_translation,
      result.correction.natural, result.score.total, result.score.grammar, result.score.word_choice, result.score.naturalness, time_spent||0,
      parseInt(difficulty)||1, is_practice ? 1 : 0
    );
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 排行榜：平均分（支持 ?limit=N 统计最近 N 条，?difficulty=N 按难度筛选）
app.get('/api/v1/leaderboard/avg-score', (req, res) => {
  const limit = parseInt(req.query.limit) || 0;
  const difficulty = parseInt(req.query.difficulty) || 0;
  const diffWhere = difficulty > 0 ? 'AND l.difficulty = ?' : '';
  const diffParam = difficulty > 0 ? [difficulty] : [];
  let query;
  if (limit > 0) {
    const params = [...diffParam, limit];
    query = db.prepare(`
      SELECT u.username, COUNT(l.id) as total_count, ROUND(AVG(l.score_total),1) as avg_score
      FROM users u JOIN (
        SELECT id, user_id, score_total, created_at, difficulty, is_practice,
          ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
        FROM practice_logs WHERE is_practice = 0 ${difficulty > 0 ? 'AND difficulty = ?' : ''}
      ) l ON u.id = l.user_id AND l.rn <= ?
      GROUP BY u.id HAVING COUNT(*) >= 3
      ORDER BY avg_score DESC LIMIT 20
    `).all(...params);
  } else {
    query = db.prepare(`
      SELECT u.username, COUNT(l.id) as total_count, ROUND(AVG(l.score_total),1) as avg_score
      FROM users u JOIN practice_logs l ON u.id = l.user_id
      WHERE l.is_practice = 0 ${diffWhere}
      GROUP BY u.id HAVING total_count >= 3
      ORDER BY avg_score DESC LIMIT 20
    `).all(...diffParam);
  }
  res.json(query);
});

// 排行榜：平均用时（支持 ?limit=N 统计最近 N 条，?difficulty=N 按难度筛选）
app.get('/api/v1/leaderboard/avg-time', (req, res) => {
  const limit = parseInt(req.query.limit) || 0;
  const difficulty = parseInt(req.query.difficulty) || 0;
  const diffWhere = difficulty > 0 ? 'AND l.difficulty = ?' : '';
  const diffParam = difficulty > 0 ? [difficulty] : [];
  let query;
  if (limit > 0) {
    query = db.prepare(`
      SELECT u.username, COUNT(l.id) as total_count, ROUND(AVG(l.time_spent),1) as avg_time
      FROM users u JOIN (
        SELECT id, user_id, time_spent, created_at, difficulty, is_practice,
          ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
        FROM practice_logs WHERE is_practice = 0 ${difficulty > 0 ? 'AND difficulty = ?' : ''}
      ) l ON u.id = l.user_id AND l.rn <= ?
      GROUP BY u.id HAVING COUNT(*) >= 3
      ORDER BY avg_time ASC LIMIT 20
    `).all(...diffParam, limit);
  } else {
    query = db.prepare(`
      SELECT u.username, COUNT(l.id) as total_count, ROUND(AVG(l.time_spent),1) as avg_time
      FROM users u JOIN practice_logs l ON u.id = l.user_id
      WHERE l.is_practice = 0 ${diffWhere}
      GROUP BY u.id HAVING total_count >= 3
      ORDER BY avg_time ASC LIMIT 20
    `).all(...diffParam);
  }
  res.json(query);
});

// 今日统计（需 JWT）
app.get('/api/v1/stats/today', (req, res) => {
  try {
    const userId = getUserId(req);
    const row = db.prepare(`
      SELECT COUNT(*) as count, COALESCE(ROUND(AVG(score_total)),0) as avg_score, COALESCE(SUM(time_spent),0) as total_time
      FROM practice_logs WHERE user_id = ? AND is_practice = 0 AND DATE(created_at) = DATE('now')
    `).get(userId);
    res.json(row);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 练习历史分页（需 JWT，支持 ?word=xxx 筛选）
app.get('/api/v1/practice-logs', (req, res) => {
  try {
    const userId = getUserId(req);
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;
    const wordFilter = req.query.word || '';
    const wordWhere = wordFilter ? ' AND word = ?' : '';
    const wordParams = wordFilter ? [wordFilter] : [];
    const total = db.prepare(`SELECT COUNT(*) as c FROM practice_logs WHERE user_id = ? AND is_practice = 0${wordWhere}`).get(userId, ...wordParams).c;
    const rows = db.prepare(`
      SELECT word, phonetic, meaning, score_total, score_grammar, score_word_choice, score_naturalness, time_spent, difficulty, chinese_sentence, user_translation, reference_sentence, created_at
      FROM practice_logs WHERE user_id = ? AND is_practice = 0${wordWhere}
      ORDER BY created_at DESC LIMIT ? OFFSET ?
    `).all(userId, ...wordParams, limit, offset);
    res.json({ rows, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 用户资料（需 JWT，支持 ?username=xxx 查看他人公开资料）
app.get('/api/v1/user/profile', (req, res) => {
  try {
    const viewerId = getUserId(req);
    const targetUsername = req.query.username || '';
    if (targetUsername) {
      // 查看其他用户的公开资料
      const user = db.prepare('SELECT id, username, display_name, tagline, status FROM users WHERE username = ?').get(targetUsername);
      if (!user) return res.status(404).json({ error: '用户不存在' });
      const stats = db.prepare(`SELECT COUNT(*) as total_count FROM practice_logs WHERE user_id = ? AND is_practice = 0`).get(user.id);
      const rankRow = db.prepare(`SELECT COUNT(*)+1 as rank FROM (SELECT user_id FROM practice_logs WHERE is_practice=0 GROUP BY user_id HAVING COUNT(*)>=3 AND AVG(score_total)>(SELECT AVG(score_total) FROM practice_logs WHERE user_id=? AND is_practice=0))`).get(user.id);
      res.json({ username: user.username, display_name: user.display_name, tagline: user.tagline, status: user.status, total_count: stats.total_count, rank: rankRow.rank });
    } else {
      // 查看自己的资料
      const user = db.prepare('SELECT id, username, display_name, tagline, status FROM users WHERE id = ?').get(viewerId);
      const stats = db.prepare(`SELECT COUNT(*) as total_count FROM practice_logs WHERE user_id = ? AND is_practice = 0`).get(viewerId);
      const rankRow = db.prepare(`SELECT COUNT(*)+1 as rank FROM (SELECT user_id FROM practice_logs WHERE is_practice=0 GROUP BY user_id HAVING COUNT(*)>=3 AND AVG(score_total)>(SELECT AVG(score_total) FROM practice_logs WHERE user_id=? AND is_practice=0))`).get(viewerId);
      res.json({ username: user.username, display_name: user.display_name, tagline: user.tagline, status: user.status, total_count: stats.total_count, rank: rankRow.rank });
    }
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 保存个人资料（需 JWT）
app.put('/api/v1/user/profile', (req, res) => {
  try {
    const userId = getUserId(req);
    const { display_name, tagline, status } = req.body;
    db.prepare('UPDATE users SET display_name = ?, tagline = ?, status = ? WHERE id = ?').run(display_name || null, tagline || null, status || 'online', userId);
    res.json({ success: true });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 竞赛：提交结果
app.post('/api/v1/challenge/submit', (req, res) => {
  try {
    const userId = getUserId(req);
    const { duration, score, avg_score, word_count, total_time, details } = req.body;
    if (!duration || !score) return res.status(400).json({ error: '参数不足' });
    // 只保存最高分
    const best = db.prepare('SELECT MAX(score) as best FROM challenge_results WHERE user_id = ? AND duration = ?').get(userId, duration);
    if (!best.best || score > best.best) {
      db.prepare('INSERT INTO challenge_results (user_id, duration, score, avg_score, word_count, total_time, details) VALUES (?,?,?,?,?,?,?)')
        .run(userId, duration, score, avg_score, word_count, total_time, details || '');
    }
    res.json({ success: true, is_new_best: !best.best || score > best.best });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 竞赛排行榜
app.get('/api/v1/challenge/leaderboard', (req, res) => {
  try {
    const duration = parseInt(req.query.duration) || 30;
    const rows = db.prepare(`
      SELECT u.username, u.display_name, MAX(c.score) as score, ROUND(AVG(c.avg_score)) as avg_score, MAX(c.word_count) as word_count
      FROM challenge_results c JOIN users u ON c.user_id = u.id
      WHERE c.duration = ?
      GROUP BY c.user_id
      ORDER BY score DESC, word_count DESC LIMIT 50
    `).all(duration);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 竞赛我的最佳
app.get('/api/v1/challenge/my-best', (req, res) => {
  try {
    const userId = getUserId(req);
    const rows = db.prepare(`
      SELECT duration, MAX(score) as score, AVG(avg_score) as avg_score, MAX(word_count) as word_count
      FROM challenge_results WHERE user_id = ?
      GROUP BY duration
    `).all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 导出全部数据（仅管理员 Aaa）
app.get('/api/v1/user/export-data', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username, display_name, tagline, created_at FROM users WHERE id = ?').get(userId);
    if (user.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const allUsers = db.prepare('SELECT id, username, display_name, tagline, created_at FROM users').all();
    const logs = db.prepare('SELECT user_id, word, phonetic, meaning, extended, chinese_sentence, user_translation, reference_sentence, score_total, score_grammar, score_word_choice, score_naturalness, time_spent, difficulty, is_practice, created_at FROM practice_logs ORDER BY created_at DESC').all();
    const challenges = db.prepare('SELECT user_id, duration, score, avg_score, word_count, total_time, created_at FROM challenge_results ORDER BY created_at DESC').all();
    res.json({ users: allUsers, practice_logs: logs, challenges });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 修改密码
app.put('/api/v1/auth/password', async (req, res) => {
  try {
    const userId = getUserId(req);
    const ip = req.ip || req.connection.remoteAddress;
    rateLimit('pwchange:' + ip, 3, 3600000); // 每小时最多改 3 次
    const { old_password, new_password } = req.body;
    if (!old_password || !new_password) return res.status(400).json({ error: '缺少参数' });
    if (new_password.length < 4) return res.status(400).json({ error: '密码至少 4 个字符' });
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
    const valid = await bcrypt.compare(old_password, user.password_hash);
    if (!valid) return res.status(401).json({ error: '原密码错误' });
    const hash = await bcrypt.hash(new_password, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
    res.json({ success: true });
  } catch (e) {
    if (e.message.includes('操作过于频繁')) return res.status(429).json({ error: e.message });
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 恢复数据
app.post('/api/v1/user/restore-data', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const data = req.body;
    if (!data || !data.practice_logs) return res.status(400).json({ error: '格式错误' });
    let count = 0;
    // 恢复练习记录
    if (Array.isArray(data.practice_logs)) {
      const insertLog = db.prepare('INSERT OR IGNORE INTO practice_logs (user_id, word, phonetic, meaning, extended, chinese_sentence, user_translation, reference_sentence, score_total, score_grammar, score_word_choice, score_naturalness, time_spent, difficulty, is_practice) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
      const tx = db.transaction(() => {
        for (const log of data.practice_logs) {
          insertLog.run(log.user_id || userId, log.word||'', log.phonetic||'', log.meaning||'', log.extended||'', log.chinese_sentence||'', log.user_translation||'', log.reference_sentence||'', log.score_total||0, log.score_grammar||0, log.score_word_choice||0, log.score_naturalness||0, log.time_spent||0, log.difficulty||1, log.is_practice||0);
          count++;
        }
      });
      tx();
    }
    // 恢复竞赛记录
    if (Array.isArray(data.challenges)) {
      const insertCh = db.prepare('INSERT OR IGNORE INTO challenge_results (user_id, duration, score, avg_score, word_count, total_time, details) VALUES (?,?,?,?,?,?,?)');
      for (const ch of data.challenges) {
        insertCh.run(ch.user_id || userId, ch.duration||30, ch.score||0, ch.avg_score||0, ch.word_count||0, ch.total_time||0, '');
      }
    }
    res.json({ success: true, count });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 登录记录
app.get('/api/v1/user/login-history', (req, res) => {
  try {
    const userId = getUserId(req);
    const rows = db.prepare('SELECT ip, created_at FROM login_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 忘记密码申请（无需登录）
app.post('/api/v1/auth/forgot-password', (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: '请输入用户名' });
    db.prepare('INSERT INTO password_resets (username) VALUES (?)').run(username);
    res.json({ success: true, message: '已向管理员发送重置申请' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 管理员：查看待处理的密码重置申请
app.get('/api/v1/auth/admin/pending-resets', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const rows = db.prepare("SELECT id, username, created_at FROM password_resets WHERE status = 'pending' ORDER BY created_at DESC").all();
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 管理员：重置用户密码为 123456
app.post('/api/v1/auth/admin/reset-password', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const { target_username, request_id } = req.body;
    if (!target_username) return res.status(400).json({ error: '缺少用户名' });
    const hash = bcrypt.hashSync('123456', 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, target_username);
    if (request_id) db.prepare('UPDATE password_resets SET status = ? WHERE id = ?').run('done', request_id);
    res.json({ success: true, message: '密码已重置为 123456' });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 管理员：查看注册用户列表
app.get('/api/v1/auth/admin/users', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const rows = db.prepare('SELECT id, username, display_name, created_at FROM users ORDER BY id').all();
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`后端运行在 http://localhost:${PORT}`));