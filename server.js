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
async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      file_id TEXT UNIQUE NOT NULL,
      original_name TEXT,
      obfuscated_name TEXT,
      source_content TEXT,
      obfuscated_content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  try {
    db.run('ALTER TABLE files ADD COLUMN obfuscated_content TEXT');
  } catch (e) { }
  saveDb();
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

initDb().catch(err => {
  console.error('Không thể khởi tạo database:', err);
  process.exit(1);
});

app.use(express.json());
app.use(fileUpload({ limits: { fileSize: 5 * 1024 * 1024 } }));
app.use(express.static('public'));

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
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

function obfuscateLuaAdvanced(source) {
  const key = Array.from({ length: 64 }, () => Math.floor(Math.random() * 256));
  const shiftKey = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  const garbagePool = [
    `local function _G1() local _=0 for _=1,8 do _=_+_ end return _ end`,
    `local function _G2() local _=table.pack or function(...) return {...} end return _(1,2,3) end`,
    `local function _G3() local _=math.random(1,100) return _ end`,
    `local function _G4() local _="abcdef" return #_ end`,
    `local function _G5() local _=os.clock and os.clock() or 0 return _ end`
  ];
  const junkFuncs = [];
  for (let i = 0; i < 3 + Math.floor(Math.random() * 4); i++) {
    junkFuncs.push(garbagePool[Math.floor(Math.random() * garbagePool.length)]);
  }

  const bytes = Array.from(Buffer.from(source, 'utf-8'));
  const layer1 = bytes.map((b, i) => (b + key[i % key.length] + i * 3) % 256);
  const chunks = [];
  const chunkSize = 17 + Math.floor(Math.random() * 31);
  for (let i = 0; i < layer1.length; i += chunkSize) {
    chunks.push(layer1.slice(i, i + chunkSize));
  }

  const subKeys = chunks.map((_, idx) => {
    const off = idx * 11;
    return Array.from({ length: 12 }, (_, j) => (key[(off + j) % key.length] + idx * 7 + j * 13) % 256);
  });

  const encryptedChunks = chunks.map((chunk, idx) => {
    return chunk.map((byte, i) => {
      return (byte ^ subKeys[idx][i % 12] ^ shiftKey[i % shiftKey.length]) % 256;
    });
  });

  const constTable = encryptedChunks.map(arr => arr.join(','));
  const bytecode = [];
  for (let i = 0; i < encryptedChunks.length; i++) {
    bytecode.push(1, i);
  }
  for (let i = 0; i < encryptedChunks.length - 1; i++) {
    bytecode.push(2);
  }
  bytecode.push(3);

  const fakeOps = [20, 21, 22, 23, 24];
  const finalBytecode = [];
  for (const b of bytecode) {
    finalBytecode.push(b);
    if (Math.random() < 0.4) {
      finalBytecode.push(fakeOps[Math.floor(Math.random() * fakeOps.length)]);
    }
  }

  const keyStr = key.join(',');
  const shiftStr = shiftKey.join(',');
  const constTableStr = '{' + constTable.map(c => `{${c}}`).join(',') + '}';
  const bytecodeStr = '{' + finalBytecode.join(',') + '}';
  const subKeysStr = '{' + subKeys.map(k => `{${k.join(',')}}`).join(',') + '}';
  const junkStr = junkFuncs.join(';');

  const vmLoader = `local _loadstring=loadstring or load local _INIT=function() ${junkStr} local key={${keyStr}} local shift={${shiftStr}} local sub_keys=${subKeysStr} local const_tbl=${constTableStr} local bytecode=${bytecodeStr} local stack={} local ip=1 while ip<=#bytecode do local op=bytecode[ip] if op==1 then local idx=bytecode[ip+1] local enc=const_tbl[idx+1] local sk=sub_keys[idx+1] local chars={} for i=1,#enc do local v=(enc[i]~shift[(i-1)%16+1])%256 v=(v~sk[(i-1)%12+1])%256 v=(v-idx*3)%256 v=(v-key[(i-1)%64+1])%256 chars[i]=string.char(v) end stack[#stack+1]=table.concat(chars) ip=ip+2 elseif op==2 then local b=stack[#stack] stack[#stack]=nil local a=stack[#stack] stack[#stack]=nil stack[#stack+1]=a..b ip=ip+1 elseif op==3 then local code=stack[#stack] local fn,err=_loadstring(code) if fn then fn() end return else ip=ip+1 end end end _INIT()`;
  return vmLoader;
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu username/password' });
    if (username.length < 3 || password.length < 4) return res.status(400).json({ error: 'Username >=3, password >=4' });
    const stmt = db.prepare('SELECT id FROM users WHERE username = ?');
    const existing = stmt.get([username]);
    if (existing) return res.status(409).json({ error: 'Username đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    saveDb();
    res.json({ success: true, message: 'Đăng ký thành công' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu username/password' });
    const stmt = db.prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?');
    const user = stmt.get([username]);
    if (!user) return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    const match = await bcrypt.compare(password, user[2]);
    if (!match) return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    const token = jwt.sign({ id: user[0], username: user[1], role: user[3] }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: user[1], role: user[3] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.post('/api/owner/login', (req, res) => {
  const { ownerKey } = req.body;
  if (!ownerKey || ownerKey !== OWNER_KEY) {
    return res.status(401).json({ error: 'Owner key không hợp lệ' });
  }
  const token = jwt.sign({ id: 0, username: 'owner', role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: 'owner', role: 'owner' });
});

app.get('/api/files', authenticateToken, (req, res) => {
  try {
    if (req.user.role === 'owner') {
      const results = db.exec(`
        SELECT f.file_id, f.original_name, f.obfuscated_name, f.created_at, u.username 
        FROM files f JOIN users u ON f.user_id = u.id 
        ORDER BY f.created_at DESC
      `);
      const files = results.length > 0 ? results[0].values.map(row => ({
        file_id: row[0],
        original_name: row[1],
        obfuscated_name: row[2],
        created_at: row[3],
        username: row[4]
      })) : [];
      return res.json(files);
    } else {
      const stmt = db.prepare('SELECT file_id, original_name, obfuscated_name, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC');
      const rows = stmt.getAsObject([req.user.id]);
      res.json(rows);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.get('/api/files/:fileId/source', authenticateToken, requireOwner, (req, res) => {
  try {
    const stmt = db.prepare('SELECT source_content, original_name FROM files WHERE file_id = ?');
    const row = stmt.get([req.params.fileId]);
    if (!row) return res.status(404).json({ error: 'File không tồn tại' });
    res.json({ source: row[0], original_name: row[1] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.get('/f/:fileId', (req, res) => {
  try {
    let fileId = req.params.fileId;
    if (fileId.endsWith('.lua')) fileId = fileId.slice(0, -4);
    const stmt = db.prepare('SELECT obfuscated_content FROM files WHERE file_id = ?');
    const row = stmt.get([fileId]);
    if (!row) return res.status(404).send('File không tồn tại hoặc đã bị xóa');
    res.type('text/plain').send(row[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Lỗi server');
  }
});

app.post('/api/upload', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.luafile) return res.status(400).json({ error: 'Chưa chọn file' });
    const file = req.files.luafile;
    const ext = path.extname(file.name).toLowerCase();
    if (ext !== '.lua' && ext !== '.txt') return res.status(400).json({ error: 'Chỉ chấp nhận file .lua hoặc .txt' });
    const source = file.data.toString('utf-8');
    if (source.trim().length === 0) return res.status(400).json({ error: 'File rỗng' });

    let obfuscated;
    try {
      obfuscated = obfuscateLuaAdvanced(source);
    } catch (obfErr) {
      console.error('Obfuscation error:', obfErr);
      return res.status(500).json({ error: 'Lỗi obfuscate: ' + obfErr.message });
    }

    const fileId = uuidv4();
    const obfFileName = fileId + '.lua';

    db.run('INSERT INTO files (user_id, file_id, original_name, obfuscated_name, source_content, obfuscated_content) VALUES (?, ?, ?, ?, ?, ?)', [
      req.user.id, fileId, file.name, obfFileName, source, obfuscated
    ]);
    saveDb();

    const link = `/f/${fileId}.lua`;
    res.json({ success: true, fileId, link, originalName: file.name });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Lỗi server: ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server chạy tại http://localhost:${PORT}`);
});
