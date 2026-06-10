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
  try { db.run('ALTER TABLE files ADD COLUMN obfuscated_content TEXT'); } catch (e) {}
  saveDb();
}

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

initDb().catch(err => {
  console.error('Không thể khởi tạo database:', err);
  process.exit(1);
});

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
  // Tạo key ngẫu nhiên
  const key = Array.from({ length: 64 }, () => Math.floor(Math.random() * 256));
  const shiftKey = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));

  // Chunksize cố định (không random) để Lua VM biết chính xác globalIndex
  const chunkSize = 32;

  // Bước 1: encode bytes gốc, dùng globalIndex đúng
  const bytes = Array.from(Buffer.from(source, 'utf-8'));
  const layer1 = bytes.map((b, gi) => (b + key[gi % 64] + gi * 3) % 256);

  // Bước 2: chia chunk
  const chunks = [];
  for (let i = 0; i < layer1.length; i += chunkSize) {
    chunks.push(layer1.slice(i, i + chunkSize));
  }

  // Bước 3: subkey per chunk
  const subKeys = chunks.map((_, idx) => {
    const off = idx * 11;
    return Array.from({ length: 12 }, (_, j) => (key[(off + j) % 64] + idx * 7 + j * 13) % 256);
  });

  // Bước 4: XOR encrypt từng byte trong chunk
  const encryptedChunks = chunks.map((chunk, idx) =>
    chunk.map((byte, i) =>
      (byte ^ subKeys[idx][i % 12] ^ shiftKey[i % 16]) % 256
    )
  );

  // Build Lua data strings
  const keyStr       = key.join(',');
  const shiftStr     = shiftKey.join(',');
  const constTblStr  = '{' + encryptedChunks.map(arr => '{' + arr.join(',') + '}').join(',') + '}';
  const subKeysStr   = '{' + subKeys.map(sk => '{' + sk.join(',') + '}').join(',') + '}';
  const nChunks      = encryptedChunks.length;

  // Junk functions (không ảnh hưởng runtime)
  const junkPool = [
    `local function _J1() local x=0 for i=1,8 do x=x+i end return x end`,
    `local function _J2() return math.max(1,2) end`,
    `local function _J3() local t={} for i=1,4 do t[i]=i*2 end return #t end`,
    `local function _J4() return type("lua") end`,
    `local function _J5() return string.len("obf") end`,
  ];
  const junkCount = 2 + Math.floor(Math.random() * 3);
  const junk = Array.from({ length: junkCount }, () =>
    junkPool[Math.floor(Math.random() * junkPool.length)]
  ).join(' ');

  // VM Lua: decode đúng thứ tự ngược lại với encode
  // Encode:  layer1[gi] = (b + key[gi%64] + gi*3) % 256
  //          enc[i]     = layer1 ^ subKey[i%12] ^ shift[i%16]
  // Decode:  layer1     = enc ^ shift ^ subKey   (XOR tự nghịch)
  //          b          = (layer1 - key[gi%64] - gi*3) % 256  (mod 256, Lua % luôn >= 0)
  //
  // gi = idx * chunkSize + (i-1)   (i là 1-based trong Lua)

  const vmLoader =
`local _ls=loadstring or load
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

  return vmLoader;
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu username/password' });
    if (username.length < 3 || password.length < 4)
      return res.status(400).json({ error: 'Username >=3 ký tự, password >=4 ký tự' });
    const existing = db.prepare('SELECT id FROM users WHERE username=?').get([username]);
    if (existing) return res.status(409).json({ error: 'Username đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password_hash) VALUES (?,?)', [username, hash]);
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
    const user = db.prepare('SELECT id, username, password_hash, role FROM users WHERE username=?').get([username]);
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
  if (!ownerKey || ownerKey !== OWNER_KEY)
    return res.status(401).json({ error: 'Owner key không hợp lệ' });
  const token = jwt.sign({ id: 0, username: 'owner', role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: 'owner', role: 'owner' });
});

// ─── File Routes ──────────────────────────────────────────────────────────────

app.get('/api/files', authenticateToken, (req, res) => {
  try {
    if (req.user.role === 'owner') {
      const results = db.exec(`
        SELECT f.file_id, f.original_name, f.obfuscated_name, f.created_at, u.username
        FROM files f JOIN users u ON f.user_id=u.id
        ORDER BY f.created_at DESC
      `);
      const files = results.length > 0
        ? results[0].values.map(r => ({
            file_id: r[0], original_name: r[1],
            obfuscated_name: r[2], created_at: r[3], username: r[4]
          }))
        : [];
      return res.json(files);
    }
    // user thường: dùng exec để lấy nhiều rows
    const results = db.exec(
      `SELECT file_id, original_name, obfuscated_name, created_at FROM files WHERE user_id=${req.user.id} ORDER BY created_at DESC`
    );
    const files = results.length > 0
      ? results[0].values.map(r => ({
          file_id: r[0], original_name: r[1],
          obfuscated_name: r[2], created_at: r[3]
        }))
      : [];
    res.json(files);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

app.get('/api/files/:fileId/source', authenticateToken, requireOwner, (req, res) => {
  try {
    const row = db.prepare('SELECT source_content, original_name FROM files WHERE file_id=?').get([req.params.fileId]);
    if (!row) return res.status(404).json({ error: 'File không tồn tại' });
    res.json({ source: row[0], original_name: row[1] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// Public endpoint: trả về file obfuscated
app.get('/f/:fileId', (req, res) => {
  try {
    let fileId = req.params.fileId;
    if (fileId.endsWith('.lua')) fileId = fileId.slice(0, -4);
    const row = db.prepare('SELECT obfuscated_content FROM files WHERE file_id=?').get([fileId]);
    if (!row || !row[0]) return res.status(404).send('File không tồn tại hoặc đã bị xóa');
    res.type('text/plain').send(row[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Lỗi server');
  }
});

app.post('/api/upload', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.luafile)
      return res.status(400).json({ error: 'Chưa chọn file' });
    const file = req.files.luafile;
    const ext = path.extname(file.name).toLowerCase();
    if (ext !== '.lua' && ext !== '.txt')
      return res.status(400).json({ error: 'Chỉ chấp nhận file .lua hoặc .txt' });
    const source = file.data.toString('utf-8');
    if (source.trim().length === 0)
      return res.status(400).json({ error: 'File rỗng' });

    let obfuscated;
    try {
      obfuscated = obfuscateLuaAdvanced(source);
    } catch (obfErr) {
      console.error('Obfuscation error:', obfErr);
      return res.status(500).json({ error: 'Lỗi obfuscate: ' + obfErr.message });
    }

    const fileId = uuidv4();
    db.run(
      'INSERT INTO files (user_id, file_id, original_name, obfuscated_name, source_content, obfuscated_content) VALUES (?,?,?,?,?,?)',
      [req.user.id, fileId, file.name, fileId + '.lua', source, obfuscated]
    );
    saveDb();

    res.json({ success: true, fileId, link: `/f/${fileId}.lua`, originalName: file.name });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Lỗi server: ' + err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Server chạy tại http://localhost:${PORT}`);
});
