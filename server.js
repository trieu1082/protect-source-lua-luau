const express = require('express')
const crypto = require('crypto')
const fs = require('fs-extra')
const path = require('path')
const rateLimit = require('express-rate-limit')
const pako = require('pako')
require('dotenv').config()

const app = express()
const PORT = process.env.PORT || 3000

if(!process.env.SECRET_KEY){
  console.log("❌ missing SECRET_KEY in env")
  process.exit(1)
}

const KEY = Buffer.from(process.env.SECRET_KEY,'hex')

app.use(express.json({limit:"2mb"}))
app.use(express.urlencoded({extended:true}))

// ====== STORAGE ======
const DIR = path.join(__dirname,'scripts')
fs.ensureDirSync(DIR)
const TOKENS = new Map()
const IV_LEN = 16

// ====== ENCRYPT / DECRYPT ======
function encrypt(text){
  const iv = crypto.randomBytes(IV_LEN)
  const cipher = crypto.createCipheriv('aes-256-cbc',KEY,iv)
  let enc = cipher.update(text,'utf8','hex')
  enc += cipher.final('hex')
  return iv.toString('hex')+':'+enc
}

function decrypt(data){
  const [ivHex,enc] = data.split(':')
  const iv = Buffer.from(ivHex,'hex')
  const decipher = crypto.createDecipheriv('aes-256-cbc',KEY,iv)
  let str = decipher.update(enc,'hex','utf8')
  str += decipher.final('utf8')
  return str
}

// ====== PACK / UNPACK ======
function packScript(src){
  const def = pako.deflate(src)
  const b64 = Buffer.from(def).toString('base64')
  return encrypt(b64)
}

function unpackScript(packed){
  const b64 = decrypt(packed)
  const buf = Buffer.from(b64,'base64')
  return pako.inflate(buf,{to:'string'})
}

// ====== SIGN ======
function sign(x){
  return crypto.createHmac('sha256',KEY).update(x).digest('hex')
}

// ====== FILTER UA ======
function isBadUA(ua){
  ua=(ua||'').toLowerCase()
  return ['curl','wget','python','postman','insomnia','httpclient','axios'].some(v=>ua.includes(v))
}

// ====== RATE LIMIT ======
const limiter = rateLimit({windowMs:10000,max:25})

// ====== UPLOAD ======
app.post('/upload',limiter,(req,res)=>{
  try{
    const content = req.body.content
    if(!content) return res.status(400).json({error:"no content"})

    const id = crypto.randomBytes(8).toString('hex')
    const packed = packScript(content)
    fs.writeFileSync(path.join(DIR,id+'.enc'),packed)

    const base = `${req.protocol}://${req.get('host')}`

    res.json({
      id,
      loader:`loadstring(game:HttpGet("${base}/token/${id}"))()`
    })
  }catch(e){
    res.status(500).json({error:"server"})
  }
})

// ====== TOKEN ======
app.get('/token/:id',(req,res)=>{
  if(isBadUA(req.headers['user-agent'])) return res.status(403).send('blocked')

  const id = req.params.id
  const t = crypto.randomBytes(12).toString('hex')
  const ts = Date.now()

  TOKENS.set(t,{id,time:ts,ip:req.ip,ua:req.headers['user-agent']})
  const sig = sign(t+ts)

  res.send(`
return (function()
  local t="${t}"
  local ts="${ts}"
  local sig="${sig}"
  local u="${req.protocol}://${req.get('host')}/load/${id}?t="..t.."&ts="..ts.."&sig="..sig
  return game:HttpGet(u)
end)()
`)
})

// ====== LOAD ======
app.get('/load/:id',limiter,(req,res)=>{
  try{
    const {t,ts,sig} = req.query
    const data = TOKENS.get(t)

    if(!data) return res.status(403).send('bad token')
    if(req.ip!==data.ip) return res.status(403).send('ip mismatch')
    if(Date.now()-data.time>10000){TOKENS.delete(t);return res.status(403).send('expired')}
    if(sig!==sign(t+ts)) return res.status(403).send('invalid sig')

    TOKENS.delete(t)

    const file = path.join(DIR,req.params.id+'.enc')
    if(!fs.existsSync(file)) return res.status(404).send('not found')

    const payload = fs.readFileSync(file,'utf8')
    res.setHeader('Content-Type','text/plain')

    res.send(`
-- protected loader (multi-layer)
local d="${payload}"
local Http=game:GetService("HttpService")

local function _b(x)return Http:Base64Decode(x)end
local function _d(e)local _,dat=e:match("([^:]+):(.+)") return dat end

-- anti fake executor
if not identifyexecutor then return end

-- anti hook
if rawget(game,'HttpGet')==nil then return end

-- decode
local ok,src=pcall(function() return _b(_d(d)) end)
if not ok then return end

-- junk
local _=0 for i=1,50 do _=_+i end

return loadstring(src)()
`)
  }catch(e){
    res.status(500).send('err')
  }
})

// ====== STATIC / HEALTH CHECK ======
app.get('/',(req,res)=>res.send('🚀 Protect Lua Server Running'))
app.use(express.static('public'))

app.listen(PORT,()=>console.log("✅ Server running on port "+PORT))
