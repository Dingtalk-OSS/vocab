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
  const profane = checkProfanity(name);
  if (profane) throw new Error('用户名包含违规内容');
}
function sanitize(str) { return String(str).replace(/[<>"'&]/g, ''); }

// 违禁词库（注册用户名/个性签名校验）
const PROFANITY_LIST = ['fuck','shit','damn','ass','bitch','dick','porn','sex','xxx','nigga','bastard','crap','suck','wtf','stfu','admin','root','test','尼玛','他妈','傻逼','草泥马','操你','日你','fuck','shit','asshole','bitch','dickhead','pussy','cock','cunt','whore','slut'];
function checkProfanity(text) {
  const lower = String(text).toLowerCase().trim();
  for (const word of PROFANITY_LIST) {
    if (lower === word || lower.includes(word)) return word;
  }
  return null;
}

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
db.exec(`CREATE TABLE IF NOT EXISTS chat_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  word TEXT,
  messages TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 用户AI生成记录表（用于去重）
db.exec(`CREATE TABLE IF NOT EXISTS user_generated (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);
try { db.exec('CREATE INDEX IF NOT EXISTS idx_user_generated_lookup ON user_generated(user_id, type, content)'); } catch(e) {}

// 等级考试成绩表
db.exec(`CREATE TABLE IF NOT EXISTS exam_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  difficulty TEXT NOT NULL,
  score REAL NOT NULL DEFAULT 0,
  total_possible REAL DEFAULT 300,
  passed INTEGER DEFAULT 0,
  badge_earned INTEGER DEFAULT 0,
  questions TEXT,
  answers TEXT,
  grading TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);
db.exec(`CREATE TABLE IF NOT EXISTS exam_question_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER NOT NULL,
  question_type TEXT NOT NULL,
  question_index INTEGER NOT NULL,
  user_answer TEXT,
  correct_answer TEXT DEFAULT '',
  score REAL DEFAULT 0,
  max_score REAL DEFAULT 2,
  ai_feedback TEXT DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (exam_id) REFERENCES exam_results(id)
)`);
try { db.exec('ALTER TABLE users ADD COLUMN exam_opt_out INTEGER DEFAULT 0'); } catch(e) {}

// 词库表（管理员维护的单词池）
db.exec(`CREATE TABLE IF NOT EXISTS word_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  word TEXT NOT NULL,
  difficulty TEXT NOT NULL,
  added_by TEXT DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(word, difficulty)
)`);

// 用户已练单词表（按用户+单词+难度标记已练，三字段全匹配才排除）
db.exec(`CREATE TABLE IF NOT EXISTS user_practiced_words (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  word TEXT NOT NULL,
  difficulty TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, word, difficulty),
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 预填词库（INSERT OR IGNORE 避免重复）
try {
  const insertWord = db.prepare('INSERT OR IGNORE INTO word_bank (word, difficulty) VALUES (?, ?)');
  // L1 — 基础日常
  ['hello','goodbye','thank','please','sorry','yes','no','help','water','food','eat','drink','sleep','walk','run','big','small','hot','cold','good','bad','new','old','love','happy','sad','fast','slow','hard','easy','day','night','book','door','window','chair','table','pen','paper','dog','cat','fish','bird','tree','flower','sun','moon','star','rain','snow','friend','school','home','shop','road','water','fire','hand','foot','head','eye','ear','mouth','mother','father','sister','brother','garden','kitchen','bedroom','bathroom','hospital','park','zoo'].forEach(w => insertWord.run(w, 'L1'));
  // L2 — 日常进阶
  ['information','temperature','important','different','beautiful','wonderful','dangerous','famous','favorite','popular','weather','season','holiday','vacation','traffic','accident','repair','service','receive','remember','believe','decide','expect','explain','follow','happen','improve','invite','offer','prepare','protect','suggest','support','accept','allow','continue','control','discuss','encourage','introduce','performance','knowledge','experience','practice','exercise','example','language','message','picture','problem','question','answer','person','people','family','world','country'].forEach(w => insertWord.run(w, 'L2'));
  // L3 — 中阶通用
  ['environment','education','technology','development','government','population','production','transportation','communication','entertainment','opportunity','responsibility','achievement','announcement','appointment','competition','conversation','celebration','experiment','instrument','arrangement','requirement','agreement','department','equipment','management','advertisement','conference','application','experience','condition','position','situation','relation','decision','division','connection','direction','attention','election','solution','pollution','construction','instruction','collection'].forEach(w => insertWord.run(w, 'L3'));
  // L4 — 学术论述
  ['analysis','hypothesis','methodology','perspective','theoretical','empirical','quantitative','qualitative','significant','implication','correlation','variable','phenomenon','paradigm','ideology','discourse','synthesis','evaluation','implementation','interpretation','investigation','demonstration','justification','verification','classification','modification','representation','characteristic','constitutional','controversial'].forEach(w => insertWord.run(w, 'L4'));
  // L5 — 文学艺术
  ['metaphor','allegory','narrative','protagonist','antagonist','symbolism','irony','paradox','eloquence','aesthetic','ambiguity','nostalgia','melancholy','resilience','vulnerability','compassion','contemplation','transcendence','corruption','redemption'].forEach(w => insertWord.run(w, 'L5'));
  // L6 — 文化创译
  ['juxtaposition','idiosyncrasy','effervescence','ephemeral','surreptitious','ubiquitous','dichotomy','amalgamation','disenfranchise','extrapolate'].forEach(w => insertWord.run(w, 'L6'));
  // CET4
  ['abandon','ability','abroad','absence','absolute','absorb','abstract','abundant','academic','accelerate','access','accommodate','accompany','accomplish','account','accumulate','accurate','accuse','achieve','acknowledge','acquire','adapt','adequate','adjust','administration','admit','adopt','advance','advantage','advertise','advise','affect','afford','agency','agree','agriculture','aircraft','alarm','alert','allocate','allowance','alter','alternative','ambition','amount','amuse','analyze','ancestor','angle','anniversary','announce','annual','anxiety','apparent','appeal','appetite','appliance','application','appoint','appreciate','approach','appropriate','approve','approximate','argue','arise','arrange','arrest','article','artificial','aspect','assemble','assess','assign','assist','associate','assume','assure','atmosphere','attach','attempt','attend','attitude','attract','attribute','audience','authority','automatic','available','avenue','average','avoid','award','aware','awful'].forEach(w => insertWord.run(w, 'CET4'));
  // CET6
  ['controversy','coordinate','copyright','corporate','correspond','counsel','counterpart','courtesy','criterion','crucial','cultivate','curriculum','declaration','dedicate','deficiency','deficit','defy','degenerate','delegate','deliberate','demonstrate','denote','deny','depict','deposit','deprive','derive','descend','designate','desperate','destiny','destruction','detach','deteriorate','diagnose','dictate','dignity','dilemma','diminish','diploma','directory','discard','discharge','discipline','disclose','discrimination','disguise','dismiss','disorder','disperse','displace','dispute','dissolve','distinct','distort','distract','distribute','disturbance','diverse','document','domain','domestic','dominant','donation','dramatic','drastic','duration','dynamic','elaborate','eliminate','embrace','emerge','emphasis','empirical','endeavor','enforce','engage','enhance','enormous','enterprise','enthusiasm','equivalent','erosion','essential','establish','evaluate','evident','evolve','exaggerate','exceed','exclude','execute','exemplify','exotic','exploit','explore','exposure','extend','extensive','external','extraordinary'].forEach(w => insertWord.run(w, 'CET6'));
  // 考研
  ['abolish','absorb','abstract','absurd','abundance','accelerate','accommodate','accumulate','acknowledge','acquisition','activate','adaptation','adhere','adjacent','administer','adolescent','adverse','advocate','aesthetic','affiliate','aggregate','aggravate','alienate','allege','alleviate','allocate','alternate','ambiguous','amend','amplify','analogy','anchor','applicable','appraisal','ascertain','aspiration','assert','assessment','assign','assimilate','assumption','attribute','authentic','authorize','bankruptcy','bewilder','bias','boundary','breakthrough','calculation','capability','category','certify','chronic','circulation','clarify','classification','cluster','cognitive','coincidence','collaborate','commemorate','commence','compatible','compensate','complement','compliance','component','compound','comprehensive','compulsory','conceive','conception','confine','conform','confront','conscience','conscious','consecutive','consensus','conserve','consolidate','conspicuous','constitute','consult','consume','contemplate','contemporary','contradiction','contribute','controversy','convenient','convention','converge','conversion','conviction','cooperate','coordinate','copyright','correlate','correspond','counsel','crucial','cultivate','cumulative','curriculum','database','deadline','debate','deceive','decent','decisive','declaration','decline','decorate','decrease','dedicate','deem','default','defeat','defect','deficiency','deficit','define','definite','delegate','deliberate','delicate','demonstrate','denote','deny','depict','deposit','deprive','derive','descend','describe','deserve','designate','desperate','despise','destination','destruction','detail','detain','detect','deteriorate','determine','device','devote','diagnose','dictate','differ','differentiate','diffuse','digest','dignity','dilemma','diligent','diminish','diploma','disable','disappear','disaster','discard','discern','discipline','disclose','discount','discourse','discover','discrimination','disguise','dismiss','disorder','disperse','displace','display','dispose','dispute','dissolve','distinct','distinguish','distort','distract','distribute','disturbance','diverse','divert','document','domestic','dominant','dominate','donation','dormant','dramatic','drastic','duration','dynamic','elaborate','elastic','elegance','eliminate','embrace','emerge','emergency','emission','emotion','emphasis','empirical','employee','enable','enclose','encounter','endeavor','endorse','endure','enforce','engage','enhance','enormous','enrich','ensure','enterprise','entertainment','enthusiasm','entity','entrepreneur','entry','environment','epidemic','episode','equivalent','era','erosion','essential','establish','estate','estimate','eternal','ethical','evaluate','evident','evolve','exaggerate','exceed','excel','exception','excerpt','excessive','exchange','exclude','execute','exemplify','exert','exhaust','exhibit','expand','expedition','expenditure','experiment','expertise','expiration','explicit','exploit','exploration','explosion','export','expose','exposure','extend','extensive','extent','exterior','external','extinct','extraordinary','extreme'].forEach(w => insertWord.run(w, 'kaoyan'));
  console.log('词库初始化完成');
} catch(e) { console.error('词库初始化失败:', e.message); }

const JWT_SECRET = process.env.JWT_SECRET || 'vocab-push-secret-2024';

// 管理员账号（设 ADMIN_PASSWORD 环境变量可自定义密码，默认 admin123）
try {
  var hash = bcrypt.hashSync('admin123', 10);
  var adminResult = db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, 'Aaa');
  if (adminResult.changes === 0) {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('Aaa', hash);
  }
  console.log('管理员密码: admin123');
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

// 调试管理员登录（无需限流，仅用于排查）
app.get('/api/v1/auth/debug-admin', async (req, res) => {
  try {
    const user = db.prepare('SELECT username, password_hash FROM users WHERE username = ?').get('Aaa');
    if (!user) return res.json({ exists: false, msg: 'Aaa 用户不存在' });
    const valid = await bcrypt.compare('admin123', user.password_hash);
    res.json({ exists: true, hash_matches_admin123: valid, hash_prefix: user.password_hash.substring(0, 20) + '...' });
  } catch (e) { res.json({ error: e.message }); }
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

// 智能翻译专业提示词（按标准分级）
const TRANSLATE_PROMPTS = {
  cet4: `你是一位资深的大学英语四级(CET-4)翻译专家，严格遵循以下标准：

【词汇范围】
1. 仅使用CET-4大纲词汇（约4500词），以高中词汇和四级核心词汇为主
2. 严禁使用超纲词、生僻词、低频学术词汇
3. 如原文包含超纲概念，用四级大纲内的词汇进行解释性翻译
4. 优先选择最常用、最基础的表达方式，避免炫技

【句式规范】
1. 以简单句和并列句为核心，适当使用定语从句和宾语从句
2. 单句长度控制在15-25词以内，严禁出现过长复合句
3. 使用基础时态（一般现在时、一般过去时、一般将来时、现在完成时）
4. 避免使用虚拟语气、倒装句、独立主格结构、分词的复合结构
5. 语态以主动为主，被动语态仅在必要时使用
6. 逻辑关系使用基础连接词（and, but, so, because, when, if）

【翻译原则】
1. 忠实传达原文核心意思，不增译不删译
2. 语言通顺自然，符合英语基本表达习惯
3. 正确处理中英文基本差异（中文多用主动、英文可适当用被动）
4. 中文流水句应合理拆分为英文短句
5. 注意主谓一致、名词单复数、冠词使用等基础语法

【评分标准参考】
- 90-100分：无任何语法错误，用词精准，句式得当，译文流畅
- 80-89分：极少量轻微语法瑕疵，整体表达清晰
- 70-79分：存在少量语法或用词问题，但不影响理解
- 60-69分：有较多语法错误，核心意思仍可识别
- 60分以下：严重语法错误，或偏离原文意思

请严格按照以上CET-4标准翻译以下内容，输出JSON格式：{"translation":"翻译结果","notes":"翻译要点说明（词汇/句式/技巧）"}`,

  cet6: `你是一位资深的大学英语六级(CET-6)翻译专家，严格遵循以下标准：

【词汇范围】
1. 使用CET-6大纲词汇（约6000词），合理搭配四级基础词汇和六级提升词汇
2. 适当使用学术词汇和正式书面表达（如 utilize, demonstrate, consequently 等）
3. 词汇选择注重多样性和丰富度，避免同一词汇反复出现
4. 可运用固定搭配和短语动词展示语言驾驭能力
5. 对文化负载词和习语进行恰当转化

【句式规范】
1. 允许使用多种复合句：定语从句、名词性从句、状语从句、非谓语结构
2. 可适度使用被动语态和强调句型（It is...that..., What...is...）
3. 句子结构可以有适当复杂度，但需保证清晰易懂
4. 合理运用连接词和过渡语展示逻辑层次（however, moreover, consequently, in contrast）
5. 可运用并列、对比、因果、让步等逻辑关系
6. 时态运用准确且丰富，包括完成进行时、过去完成时等

【翻译原则】
1. 准确传达原文含义，尤其注意抽象概念和文化特定概念的处理
2. 运用翻译技巧：词性转换（名词转动词等）、语序调整（定语后置等）
3. 保持原文的语体和风格，正式文体用正式英文，描述性文体用生动语言
4. 注意中英文衔接手段的差异，适当使用替代、省略、连接
5. 确保全文风格统一，语气一致

【评分标准参考】
- 90-100分：语法精准、词汇丰富、句式多样、表达地道、文体恰当
- 80-89分：少量瑕疵但不影响整体质量，翻译策略运用得当
- 70-79分：部分用词或句式可优化，但核心意思表达清楚
- 60-69分：有明显不足，多处表达可改进
- 60分以下：严重偏离评分标准

请严格按照以上CET-6标准翻译以下内容，输出JSON格式：{"translation":"翻译结果","notes":"翻译要点说明（词汇/句式/技巧）"}`,

  kaoyan: `你是一位资深的考研英语翻译专家，严格遵循以下标准：

【词汇范围】
1. 使用考研英语大纲词汇（约5500词，侧重学术词汇和正式用语）
2. 精确辨析近义词，选择最贴合语境和语体的词汇
3. 注重词汇的搭配关系和使用语境（collocation and register）
4. 正确处理一词多义、熟词生义和词义引申
5. 可适当运用成语和固定表达，但需保证准确性和恰当性
6. 学术词汇和正式表达占比应合理体现

【句式规范】
1. 允许使用长难句：多重复合句、嵌套从句、并列复合结构
2. 可运用高级语法手段：虚拟语气、倒装、强调、省略、分隔结构
3. 句子结构应有层次感和逻辑递进，主次分明
4. 合理运用语篇衔接手段：照应、替代、省略、连接、词汇衔接
5. 长短句交错，避免单调句式重复
6. 时态和语态使用精确，体现英语时体态系统的完整性

【翻译策略】
1. 词性转换：根据英语表达习惯灵活转换（中文动词→英文名词、中文形容词→英文介词短语等）
2. 语序调整：正确处理中英文核心差异（定语位置、状语顺序、否定转移、否定前置）
3. 增词减词：根据英文表达需要适当增删（增加主语、连接词；省略量词、范畴词）
4. 分译合译：中文长句合理拆分，中文短句适当合并，断句重组
5. 正反表达：正说反译、反说正译的处理
6. 文化转换：文化特定概念采用意译、解释性翻译或加注策略
7. 语篇重构：超越句子层面，在语篇层面进行结构调整和逻辑重组

【翻译原则】
1. 理解准确：深入理解原文的词汇含义、语法关系、逻辑关系和语境含义
2. 表达精炼：译文简洁有力，不说废话，不拖泥带水
3. 逻辑清晰：译文逻辑关系明确，衔接自然，层次分明
4. 风格对应：原文风格在译文中得到准确再现（正式/非正式、文学/非文学）

【评分标准参考】
- 90-100分：理解完全准确，表达精炼地道，翻译策略运用纯熟，文体恰如其分
- 80-89分：理解准确，表达流畅，翻译策略运用得当，仅个别细节可优化
- 70-79分：理解基本准确，表达尚可，部分翻译策略运用不够纯熟
- 60-69分：存在理解偏差或表达不足，需进一步提升翻译技巧
- 60分以下：严重理解错误或表达混乱

请严格按照以上考研英语标准翻译以下内容，输出JSON格式：{"translation":"翻译结果","notes":"翻译要点说明（词汇/句式/技巧）"}`,
};

// 生成单词
// 难度字符串→数值映射（用于 AI prompt 分级）
function diffToNum(s) { return {L1:1,L2:2,L3:3,L4:4,L5:5,L6:6,CET4:4,CET6:5,kaoyan:6}[s] || 1; }

app.post('/api/v1/words/generate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const diffStr = req.body.difficulty || 'L1';
    const specificWord = req.body.word || '';
    const diffPrompt = DIFFICULTY_PROMPTS[diffToNum(diffStr)] || DIFFICULTY_PROMPTS[1];

    let resultWord = '';
    let result = null;

    if (specificWord) {
      resultWord = specificWord;
    } else {
      // 从词库随机抽词，排除该用户该难度已练过的
      const row = db.prepare(`SELECT word FROM word_bank WHERE difficulty = ? AND word NOT IN (SELECT word FROM user_practiced_words WHERE user_id = ? AND difficulty = ?) ORDER BY RANDOM() LIMIT 1`).get(diffStr, userId, diffStr);
      if (row) {
        resultWord = row.word;
      } else {
        // 词库无可用词 → AI 随机生成（最多尝试 5 次避开 user_practiced_words）
        const excludeWords = [];
        let fallbackResult = null;
        for (let i = 0; i < 5; i++) {
          const hint = excludeWords.length ? `\n不要生成：${excludeWords.join('、')}` : '';
          fallbackResult = await callAI(apiKey, [
            { role:'system', content:'你是一个英语单词信息提供者，只输出JSON。' },
            { role:'user', content:`难度：${diffPrompt}\n随机生成一个匹配该难度的英语单词${hint}，并提供音标、中文释义、延展用法。JSON：{"word":"...","phonetic":"...","meaning":"...","extended":"..."}` }
          ], 1.2, platform, customUrl);
          const dup = db.prepare('SELECT id FROM user_practiced_words WHERE user_id=? AND word=? AND difficulty=?').get(userId, fallbackResult.word, diffStr);
          if (!dup) { resultWord = fallbackResult.word; result = fallbackResult; break; }
          excludeWords.push(fallbackResult.word);
        }
        if (!resultWord && fallbackResult) { resultWord = fallbackResult.word; result = fallbackResult; }
      }
    }

    // 有 resultWord 但还没调用 AI 获取信息（词库抽的词需要生成音标释义）
    if (!result) {
      result = await callAI(apiKey, [
        { role:'system', content:'你是一个英语单词信息提供者，只输出JSON。' },
        { role:'user', content:`提供以下单词的详细信息：${resultWord}。输出音标、中文释义（简短）、延展释义。JSON：{"word":"${resultWord}","phonetic":"...","meaning":"...","extended":"..."}` }
      ], 1.2, platform, customUrl);
    }

    // 保存到 user_practiced_words（仅当不是练习模式或需要记录时）
    if (resultWord) {
      db.prepare('INSERT OR IGNORE INTO user_practiced_words (user_id, word, difficulty) VALUES (?, ?, ?)').run(userId, resultWord, diffStr);
    }
    res.json({ ...result, difficulty: diffStr });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// AI 语义相似度检测（句子去重用）
async function isSentenceSimilar(apiKey, platform, customUrl, userId, newSentence) {
  const existing = db.prepare('SELECT content FROM user_generated WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT 30').all(userId, 'sentence');
  if (!existing.length) return false;
  const result = await callAI(apiKey, [
    { role: 'system', content: '判断两个句子的语义是否相同或极其相似。只输出JSON。' },
    { role: 'user', content: `已有句子：${existing.map(e => e.content).join(' || ')}\n\n新句子：${newSentence}\n\n新句子是否与任何一个已有句子的语义相同或极其相似？如果是，回答true；如果不是，回答false。JSON格式：{"is_similar":false}` }
  ], 0.1, platform, customUrl);
  return result.is_similar === true;
}

// 生成中文句子（带语义去重）
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
    // 去重生成：最多尝试 5 次（每次需额外 AI 判断语义）
    let result, attempts = 0;
    while (attempts < 5) {
      result = await callAI(apiKey, [
        { role: 'system', content: '你是中文出题助手，只输出JSON。' },
        { role: 'user', content: `难度：${diffPrompt}\n单词：${word}\n释义：${meaning}\n生成一个匹配该难度的中文句子，10-30字，不包含英文。JSON：{"chinese_sentence":"..."}` }
      ], 0.3, platform, customUrl);
      const similar = await isSentenceSimilar(apiKey, platform, customUrl, userId, result.chinese_sentence);
      if (!similar) break;
      attempts++;
    }
    // 保存到 user_generated
    db.prepare('INSERT INTO user_generated (user_id, type, content) VALUES (?, ?, ?)').run(userId, 'sentence', result.chinese_sentence);
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
      difficulty||'L1', is_practice ? 1 : 0
    );
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 排行榜：平均分（支持 ?limit=N 统计最近 N 条，?difficulty=N 按难度筛选）
function parseDiffParam(val) {
  if (!val || val === '0') return { where: '', params: [] };
  // 尝试数字匹配（L1-L6 存为数字 "1"-"6"），否则用原始字符串（CET4 等）
  const n = parseInt(val);
  if (!isNaN(n)) return { where: 'AND l.difficulty = ?', params: [n.toString()] };
  return { where: 'AND l.difficulty = ?', params: [val] };
}

app.get('/api/v1/leaderboard/avg-score', (req, res) => {
  const limit = parseInt(req.query.limit) || 0;
  const diff = parseDiffParam(req.query.difficulty);
  const diffWhere = diff.where;
  const diffParam = diff.params;
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
  const diff = parseDiffParam(req.query.difficulty);
  const diffWhere = diff.where;
  const diffParam = diff.params;
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
    if (tagline) {
      const profane = checkProfanity(tagline);
      if (profane) return res.status(400).json({ error: '个性签名包含违规内容' });
    }
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



// 考试排行榜
app.get('/api/v1/leaderboard/exam', (req, res) => {
  try {
    const difficulty = req.query.difficulty || '';
    let sql = 'SELECT u.username, COALESCE(u.display_name, u.username) as display_name, MAX(e.score) as best_score, e.difficulty, e.passed, (SELECT COUNT(*) FROM exam_results WHERE user_id = e.user_id AND passed = 1) as badge_count FROM exam_results e JOIN users u ON e.user_id = u.id';
    const params = [];
    if (difficulty) { sql += ' WHERE e.difficulty = ?'; params.push(difficulty); }
    sql += ' GROUP BY e.user_id ORDER BY best_score DESC LIMIT 50';
    const rows = db.prepare(sql).all(...params);
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

// 管理员：词库管理 — 列表
app.get('/api/v1/admin/words/list', (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user?.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const diff = req.query.difficulty || '';
    const search = req.query.search || '';
    let sql = 'SELECT word, difficulty, created_at FROM word_bank';
    const params = [];
    const wheres = [];
    if (diff) { wheres.push('difficulty = ?'); params.push(diff); }
    if (search) { wheres.push('word LIKE ?'); params.push('%' + search + '%'); }
    if (wheres.length) sql += ' WHERE ' + wheres.join(' AND ');
    sql += ' ORDER BY word LIMIT 500';
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 管理员：词库管理 — 添加单词
app.post('/api/v1/admin/words/add', async (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user?.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const { word, difficulties } = req.body;
    if (!word || !difficulties || !difficulties.length) return res.status(400).json({ error: '请填写单词和至少一个难度' });
    const validDiffs = ['L1','L2','L3','L4','L5','L6','CET4','CET6','kaoyan'];
    const toAdd = difficulties.filter(d => validDiffs.includes(d));
    if (!toAdd.length) return res.status(400).json({ error: '无效的难度标签' });
    let added = 0, skipped = 0;
    const insert = db.prepare('INSERT OR IGNORE INTO word_bank (word, difficulty, added_by) VALUES (?, ?, ?)');
    toAdd.forEach(d => {
      const r = insert.run(word.toLowerCase().trim(), d, 'Aaa');
      if (r.changes) added++; else skipped++;
    });
    res.json({ added, skipped, word });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 管理员：词库管理 — 批量添加
app.post('/api/v1/admin/words/batch', async (req, res) => {
  try {
    const userId = getUserId(req);
    const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    if (user?.username !== 'Aaa') return res.status(403).json({ error: '无权限' });
    const { words, difficulty } = req.body;
    if (!words || !words.length || !difficulty) return res.status(400).json({ error: '请提供单词列表和难度' });
    const validDiffs = ['L1','L2','L3','L4','L5','L6','CET4','CET6','kaoyan'];
    if (!validDiffs.includes(difficulty)) return res.status(400).json({ error: '无效的难度标签' });
    let added = 0, skipped = 0;
    const insert = db.prepare('INSERT OR IGNORE INTO word_bank (word, difficulty, added_by) VALUES (?, ?, ?)');
    words.forEach(w => {
      const r = insert.run(w.toLowerCase().trim(), difficulty, 'Aaa');
      if (r.changes) added++; else skipped++;
    });
    res.json({ added, skipped, difficulty });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 竞赛排行榜（直接按总分排名，不限词数）
// 智能翻译 / 深度咨询
app.post('/api/v1/ai/chat', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { message, word, save } = req.body;
    if (!message) return res.status(400).json({ error: '请输入内容' });
    const userMessage = { role: 'user', content: message };
    let history = [];
    if (word) {
      const prev = db.prepare('SELECT messages FROM chat_logs WHERE user_id = ? AND word = ? ORDER BY created_at DESC LIMIT 1').get(userId, word);
      if (prev) history = JSON.parse(prev.messages);
    }
    const allMessages = [...history, userMessage];
    const reply = await callAI(apiKey, allMessages, 0.7, platform, customUrl, { skipResponseFormat: true });
    const assistantMsg = { role: 'assistant', content: reply };
    const newMessages = [...allMessages, assistantMsg];
    if (save !== false) {
      db.prepare('INSERT INTO chat_logs (user_id, word, messages) VALUES (?, ?, ?)').run(userId, word || 'general', JSON.stringify(newMessages));
    }
    res.json({ reply, history: newMessages });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 对话记录列表
app.get('/api/v1/ai/chat-history', (req, res) => {
  try {
    const userId = getUserId(req);
    const rows = db.prepare('SELECT DISTINCT word, created_at FROM chat_logs WHERE user_id = ? ORDER BY created_at DESC').all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 单条对话记录详情
app.get('/api/v1/ai/chat-detail', (req, res) => {
  try {
    const userId = getUserId(req);
    const word = req.query.word || '';
    const log = db.prepare('SELECT messages, created_at FROM chat_logs WHERE user_id = ? AND word = ? ORDER BY created_at DESC LIMIT 1').get(userId, word);
    if (!log) return res.status(404).json({ error: '无记录' });
    res.json({ messages: JSON.parse(log.messages), created_at: log.created_at });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 智能翻译（带标准分级）
app.post('/api/v1/ai/smart-translate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { text, standard, direction } = req.body;
    if (!text) return res.status(400).json({ error: '请输入翻译内容' });
    const std = ['cet4','cet6','kaoyan'].includes(standard) ? standard : 'cet4';
    const dirLabel = direction === 'en2zh' ? '英译中' : '中译英';
    const systemPrompt = TRANSLATE_PROMPTS[std];
    const userPrompt = direction === 'en2zh'
      ? `请将以下英文翻译成中文（${dirLabel}，${std.toUpperCase()}标准）：\n\n${text}`
      : `请将以下中文翻译成英文（${dirLabel}，${std.toUpperCase()}标准）：\n\n${text}`;
    const result = await callAI(apiKey, [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ], 0.3, platform, customUrl);
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// AI 作文出题
app.post('/api/v1/ai/essay-topic', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { type } = req.body;
    const typeLabel = type === 'kaoyan' ? '考研英语' : type === 'cet6' ? '大学英语六级(CET-6)' : '大学英语四级(CET-4)';
    const result = await callAI(apiKey, [
      { role: 'system', content: `你是一位${typeLabel}作文出题专家。请出一道符合${typeLabel}考试难度和风格的作文题目。

要求：
1. 题目必须贴近真实考试风格
2. 包含清晰的题目说明和要求
3. 给出写作要点提示（3-4点）
4. 注明字数要求
5. 内容紧跟社会热点或经典话题

仅输出JSON格式：
{"topic":"作文题目","requirements":"写作要求（包含字数、结构等）","tips":["要点1","要点2","要点3"],"background":"话题背景简介（1-2句）"}` },
      { role: 'user', content: `请为${typeLabel}出一道作文题目。` }
    ], 0.7, platform, customUrl);
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 作文批改
app.post('/api/v1/ai/essay-grade', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { essay, type } = req.body;
    if (!essay) return res.status(400).json({ error: '请输入作文' });
    const typePrompt = type === 'kaoyan' ? '考研英语' : type === 'cet6' ? '大学英语六级(CET-6)' : '大学英语四级(CET-4)';
    const systemPrompt = `你是一位资深的${typePrompt}作文批改专家。请严格按以下JSON格式输出批改结果：
{
  "score": "分数(0-100)",
  "level": "优秀/良好/中等/较差/差",
  "comments": "总体评价",
  "issues": [{"type":"语法/词汇/结构/逻辑","description":"问题描述","suggestion":"修改建议"}],
  "annotated_text": "对原文逐句批注的HTML。删除的文字用<span class=\"essay-del\">标记，新增替换用<span class=\"essay-add\">标记，修改用<span class=\"essay-mod\">标记，纯新增用<span class=\"essay-ins\">标记。不包含外层div",
  "sample": "参考范文或模板"
}`;
    const result = await callAI(apiKey, [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: `请批改以下${typePrompt}作文：\n\n${essay}` }
    ], 0.3, platform, customUrl);
    res.json(result);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ==== 等级考试系统 ====

// 生成考试题目
app.post('/api/v1/exam/generate', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { difficulty } = req.body;
    if (!difficulty) return res.status(400).json({ error: '请选择难度' });
    const diffPrompt = DIFFICULTY_PROMPTS[diffToNum(difficulty)] || DIFFICULTY_PROMPTS[1];
    const result = await callAI(apiKey, [
      { role: 'system', content: `你是一位英语考试出题专家。请为${difficulty}难度生成一套翻译考试题。` },
      { role: 'user', content: `难度：${diffPrompt}
请生成以下内容，严格JSON格式：
1. 50道单句翻译题（中文→英文，每句10-25字）
2. 10道长文本翻译题（中文→英文，每段50-100字）
3. 1道作文题

JSON：{
  "sentences": [{"id":1,"chinese":"中文句子"}],
  "long_texts": [{"id":1,"chinese":"中文段落"}],
  "essay": {"topic":"作文题目","requirement":"写作要求"}
}` }
    ], 0.5, platform, customUrl);
    // 加 exam_session 标记
    res.json({ success: true, difficulty, questions: result, generated_at: Date.now() });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 提交考试批改
app.post('/api/v1/exam/submit', async (req, res) => {
  try {
    const userId = getUserId(req);
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: '缺少 API Key' });
    const platform = req.headers['x-api-platform'] || 'deepseek';
    const customUrl = req.headers['x-api-custom-url'] || '';
    const { difficulty, questions, answers } = req.body;
    if (!difficulty || !questions || !answers) return res.status(400).json({ error: '参数不完整' });

    // 构建批改请求
    const qaList = [];
    (questions.sentences || []).forEach(q => {
      const a = (answers.sentences || []).find(x => x.id === q.id);
      qaList.push(`第${q.id}题（2分）：${q.chinese}\n参考答案：${a?.translation || '未作答'}`);
    });
    (questions.long_texts || []).forEach(q => {
      const a = (answers.long_texts || []).find(x => x.id === q.id);
      qaList.push(`长篇第${q.id}题（10分）：${q.chinese}\n参考答案：${a?.translation || '未作答'}`);
    });
    const essayAnswer = answers.essay || '未作答';
    qaList.push(`作文（100分）：${questions.essay?.topic || ''}\n考生作文：${essayAnswer}`);

    const result = await callAI(apiKey, [
      { role: 'system', content: `你是一位严格的英语翻译考试阅卷专家。批改以下${difficulty}难度试卷。
评分标准：
- 单句翻译每题2分，共100分。语法正确、用词恰当满分，有错误酌情扣分
- 长文本翻译每题10分，共100分。准确传达原文意思、表达自然满分
- 作文100分。内容切题、语言通顺、结构清晰满分
- 总分300分，220分及以上为通过

输出JSON格式：
{
  "total_score": 总分,
  "passed": true/false,
  "sentence_scores": [{"id":1,"score":2,"errors":""}],
  "long_text_scores": [{"id":1,"score":8,"errors":""}],
  "essay_score": {"score":80,"comment":"评语","issues":[],"annotated_text":""},
  "summary": "总体评价"
}` },
      { role: 'user', content: qaList.join('\n\n') }
    ], 0.3, platform, customUrl);

    const passed = result.total_score >= 220;
    // 保存主结果
    const ins = db.prepare(`INSERT INTO exam_results (user_id, difficulty, score, passed, badge_earned, questions, answers, grading)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    const r = ins.run(userId, difficulty, result.total_score, passed ? 1 : 0, passed ? 1 : 0,
      JSON.stringify(questions), JSON.stringify(answers), JSON.stringify(result));
    const examId = r.lastInsertRowid;

    // 逐题保存到子表
    const qIns = db.prepare(`INSERT INTO exam_question_results (exam_id, question_type, question_index, user_answer, correct_answer, score, max_score, ai_feedback) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    (result.sentence_scores || []).forEach(s => {
      const a = (answers.sentences || []).find(x => x.id === s.id);
      const q = (questions.sentences || []).find(x => x.id === s.id);
      qIns.run(examId, 'sentence', s.id, a?.translation||'', q?.chinese||'', s.score||0, 2, s.errors||'');
    });
    (result.long_text_scores || []).forEach(s => {
      const a = (answers.long_texts || []).find(x => x.id === s.id);
      const q = (questions.long_texts || []).find(x => x.id === s.id);
      qIns.run(examId, 'long_text', s.id, a?.translation||'', q?.chinese||'', s.score||0, 10, s.errors||'');
    });
    qIns.run(examId, 'essay', 0, answers.essay||'', questions.essay?.topic||'', result.essay_score?.score||0, 100, result.essay_score?.comment||'');

    res.json({ success: true, result, passed, exam_id: examId });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 查询该用户考试成绩
app.get('/api/v1/exam/results', (req, res) => {
  try {
    const userId = getUserId(req);
    const rows = db.prepare('SELECT id, difficulty, score, passed, badge_earned, created_at FROM exam_results WHERE user_id = ? ORDER BY created_at DESC').all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 考试详情（含逐题结果）
app.get('/api/v1/exam/detail/:id', (req, res) => {
  try {
    const userId = getUserId(req);
    const exam = db.prepare('SELECT * FROM exam_results WHERE id = ? AND user_id = ?').get(req.params.id, userId);
    if (!exam) return res.status(404).json({ error: '未找到' });
    const questions = db.prepare('SELECT * FROM exam_question_results WHERE exam_id = ? ORDER BY question_type, question_index').all(exam.id);
    res.json({ exam, questions });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 考试统计数据（按类型得分率、趋势）
app.get('/api/v1/exam/stats', (req, res) => {
  try {
    const userId = getUserId(req);
    const allExams = db.prepare('SELECT id, difficulty, score, created_at FROM exam_results WHERE user_id = ? ORDER BY created_at ASC').all(userId);
    const typeStats = db.prepare(`SELECT q.question_type, AVG(q.score/q.max_score)*100 as rate, COUNT(*) as count
      FROM exam_question_results q JOIN exam_results e ON q.exam_id = e.id
      WHERE e.user_id = ? AND q.max_score > 0 GROUP BY q.question_type`).all(userId);
    res.json({ exams: allExams, typeStats });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 错题本（得分低于满分的题目）
app.get('/api/v1/exam/wrong-questions', (req, res) => {
  try {
    const userId = getUserId(req);
    const rows = db.prepare(`SELECT q.*, e.difficulty, e.created_at as exam_date
      FROM exam_question_results q JOIN exam_results e ON q.exam_id = e.id
      WHERE e.user_id = ? AND q.score < q.max_score AND q.question_type != 'essay'
      ORDER BY q.created_at DESC LIMIT 100`).all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 考试参与排行榜开关
app.put('/api/v1/user/exam-opt-out', (req, res) => {
  try {
    const userId = getUserId(req);
    const { optOut } = req.body;
    db.prepare('UPDATE users SET exam_opt_out = ? WHERE id = ?').run(optOut ? 1 : 0, userId);
    res.json({ success: true });
  } catch (e) {
    if (e.message === '未登录') return res.status(401).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// 查询用户获得的徽章// 查询用户获得的徽章
app.get('/api/v1/exam/badges', (req, res) => {
  try {
    const userId = getUserId(req) || (req.query.userId ? parseInt(req.query.userId) : 0);
    if (!userId) return res.json([]);
    const rows = db.prepare('SELECT difficulty, score, created_at FROM exam_results WHERE user_id = ? AND badge_earned = 1 ORDER BY created_at DESC').all(userId);
    res.json(rows);
  } catch (e) {
    if (e.message === '未登录') return res.json([]);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`后端运行在 http://localhost:${PORT}`));