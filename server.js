const express = require('express');
const fileUpload = require('express-fileupload');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_me';
const OWNER_KEY = process.env.OWNER_KEY || 'owner_secret_key_123';
const DB_PATH = './database.sqlite';

let db;

// ─── Helper: chạy SELECT trả về 1 row ────────────────────────────────────────
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper: chạy SELECT trả về nhiều rows
function dbAll(sql, params = []) {
  const results = [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

// ─── Init DB ──────────────────────────────────────────────────────────────────
async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    file_id TEXT UNIQUE NOT NULL,
    original_name TEXT,
    obfuscated_name TEXT,
    source_content TEXT,
    obfuscated_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  try { db.run('ALTER TABLE files ADD COLUMN obfuscated_content TEXT'); } catch (e) {}
  saveDb();
}

function saveDb() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

initDb().catch(err => { console.error('DB init error:', err); process.exit(1); });

// ─── Express setup ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(fileUpload({ limits: { fileSize: 5 * 1024 * 1024 } }));
app.use(express.static('public'));

// ─── Middleware ───────────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Thiếu token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token không hợp lệ' });
    req.user = user;
    next();
  });
}

function requireOwner(req, res, next) {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Yêu cầu quyền owner' });
  next();
}

// ─── Obfuscator ───────────────────────────────────────────────────────────────
function obfuscateLuaAdvanced(source) {
  const key = Array.from({ length: 64 }, () => Math.floor(Math.random() * 256));
  const shiftKey = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  const chunkSize = 32;

  const bytes = Array.from(Buffer.from(source, 'utf-8'));
  // Encode: layer1[gi] = (byte + key[gi%64] + gi*3) % 256
  const layer1 = bytes.map((b, gi) => (b + key[gi % 64] + gi * 3) % 256);

  const chunks = [];
  for (let i = 0; i < layer1.length; i += chunkSize)
    chunks.push(layer1.slice(i, i + chunkSize));

  // subKey per chunk
  const subKeys = chunks.map((_, idx) => {
    const off = idx * 11;
    return Array.from({ length: 12 }, (_, j) => (key[(off + j) % 64] + idx * 7 + j * 13) % 256);
  });

  // XOR encrypt: enc = layer1 ^ subKey[i%12] ^ shift[i%16]
  const encChunks = chunks.map((chunk, idx) =>
    chunk.map((byte, i) => (byte ^ subKeys[idx][i % 12] ^ shiftKey[i % 16]) % 256)
  );

  const keyStr      = key.join(',');
  const shiftStr    = shiftKey.join(',');
  const constTblStr = '{' + encChunks.map(a => '{' + a.join(',') + '}').join(',') + '}';
  const subKeysStr  = '{' + subKeys.map(s => '{' + s.join(',') + '}').join(',') + '}';
  const nChunks     = encChunks.length;

  const junkPool = [
    `local function _J1() local x=0 for i=1,8 do x=x+i end return x end`,
    `local function _J2() return math.max(1,2) end`,
    `local function _J3() local t={} for i=1,4 do t[i]=i*2 end return #t end`,
  ];
  const junk = Array.from({ length: 2 + Math.floor(Math.random() * 2) }, () =>
    junkPool[Math.floor(Math.random() * junkPool.length)]
  ).join(' ');

  // Decode trong Lua:
  // v = enc ^ shift[i%16+1] ^ sk[i%12+1]   (XOR nghịch)
  // b = (v - key[gi%64+1] - gi*3) % 256     (Lua % >= 0)
  return `local _ls=loadstring or load
local function _INIT()
  ${junk}
  local key={${keyStr}}
  local shift={${shiftStr}}
  local sub_keys=${subKeysStr}
  local const_tbl=${constTblStr}
  local CS=${chunkSize}
  local parts={}
  for idx=0,${nChunks - 1} do
    local enc=const_tbl[idx+1]
    local sk=sub_keys[idx+1]
    local chars={}
    for i=1,#enc do
      local gi=idx*CS+(i-1)
      local v=enc[i]
      v=(v~shift[i%16+1])%256
      v=(v~sk[i%12+1])%256
      v=(v-key[gi%64+1]-gi*3)%256
      chars[i]=string.char(v)
    end
    parts[idx+1]=table.concat(chars)
  end
  local code=table.concat(parts)
  local fn,err=_ls(code)
  if fn then fn() else error("obf err: "..(err or "?")) end
end
_INIT()`;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu username/password' });
    if (username.length < 3 || password.length < 4)
      return res.status(400).json({ error: 'Username >=3, password >=4' });
    if (dbGet('SELECT id FROM users WHERE username=?', [username]))
      return res.status(409).json({ error: 'Username đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password_hash) VALUES (?,?)', [username, hash]);
    saveDb();
    res.json({ success: true, message: 'Đăng ký thành công' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Lỗi server' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu username/password' });
    const user = dbGet('SELECT id, username, password_hash, role FROM users WHERE username=?', [username]);
    if (!user) return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: user.username, role: user.role });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Lỗi server' }); }
});

app.post('/api/owner/login', (req, res) => {
  const { ownerKey } = req.body;
  if (!ownerKey || ownerKey !== OWNER_KEY)
    return res.status(401).json({ error: 'Owner key không hợp lệ' });
  const token = jwt.sign({ id: 0, username: 'owner', role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: 'owner', role: 'owner' });
});

// ─── Files ────────────────────────────────────────────────────────────────────
app.get('/api/files', authenticateToken, (req, res) => {
  try {
    if (req.user.role === 'owner') {
      const files = dbAll(`
        SELECT f.file_id, f.original_name, f.obfuscated_name, f.created_at, u.username
        FROM files f JOIN users u ON f.user_id=u.id
        ORDER BY f.created_at DESC
      `);
      return res.json(files);
    }
    const files = dbAll(
      'SELECT file_id, original_name, obfuscated_name, created_at FROM files WHERE user_id=? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(files);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Lỗi server' }); }
});

app.get('/api/files/:fileId/source', authenticateToken, requireOwner, (req, res) => {
  try {
    const row = dbGet('SELECT source_content, original_name FROM files WHERE file_id=?', [req.params.fileId]);
    if (!row) return res.status(404).json({ error: 'File không tồn tại' });
    res.json({ source: row.source_content, original_name: row.original_name });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Lỗi server' }); }
});

// Public: trả file obfuscated — dùng cho loadstring(game:HttpGet(...))()
app.get('/f/:fileId', (req, res) => {
  try {
    let fileId = req.params.fileId;
    if (fileId.endsWith('.lua')) fileId = fileId.slice(0, -4);
    const row = dbGet('SELECT obfuscated_content FROM files WHERE file_id=?', [fileId]);
    if (!row || !row.obfuscated_content)
      return res.status(404).send('-- File không tồn tại hoặc đã bị xóa');
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.send(row.obfuscated_content);
  } catch (err) { console.error(err); res.status(500).send('-- Lỗi server'); }
});

app.post('/api/upload', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.luafile)
      return res.status(400).json({ error: 'Chưa chọn file' });
    const file = req.files.luafile;
    const ext = path.extname(file.name).toLowerCase();
    if (ext !== '.lua' && ext !== '.txt')
      return res.status(400).json({ error: 'Chỉ chấp nhận .lua hoặc .txt' });
    const source = file.data.toString('utf-8');
    if (!source.trim()) return res.status(400).json({ error: 'File rỗng' });

    const obfuscated = obfuscateLuaAdvanced(source);
    const fileId = uuidv4();
    db.run(
      'INSERT INTO files (user_id, file_id, original_name, obfuscated_name, source_content, obfuscated_content) VALUES (?,?,?,?,?,?)',
      [req.user.id, fileId, file.name, fileId + '.lua', source, obfuscated]
    );
    saveDb();
    res.json({ success: true, fileId, link: `/f/${fileId}.lua`, originalName: file.name });
  } catch (err) { console.error('Upload error:', err); res.status(500).json({ error: 'Lỗi server: ' + err.message }); }
});

// ─── Keep alive (tránh Render sleep) ─────────────────────────────────────────
setInterval(() => {
  console.log('[keep-alive]', new Date().toISOString());
}, 4 * 60 * 1000); // ping log mỗi 4 phút

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server chạy tại http://localhost:${PORT}`));
