const express = require('express')
const crypto = require('crypto')
const fs = require('fs-extra')
const path = require('path')
const rateLimit = require('express-rate-limit')
const pako = require('pako')
require('dotenv').config()

const app = express()
const PORT = process.env.PORT || 3000
const KEY = Buffer.from(process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex'), 'hex')

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

const DIR = path.join(__dirname, 'scripts')
fs.ensureDirSync(DIR)

const TOKENS = new Map()
const IV = 16

const enc = t => {
  const iv = crypto.randomBytes(IV)
  const c = crypto.createCipheriv('aes-256-cbc', KEY, iv)
  let e = c.update(t, 'utf8', 'hex')
  e += c.final('hex')
  return iv.toString('hex') + ':' + e
}

const dec = d => {
  const [ivh, data] = d.split(':')
  const iv = Buffer.from(ivh, 'hex')
  const dc = crypto.createDecipheriv('aes-256-cbc', KEY, iv)
  let r = dc.update(data, 'hex', 'utf8')
  r += dc.final('utf8')
  return r
}

const pack = s => enc(Buffer.from(pako.deflate(s)).toString('base64'))
const unpack = e => pako.inflate(Buffer.from(dec(e), 'base64'), { to: 'string' })

const hash = t => crypto.createHmac('sha256', KEY).update(t).digest('hex')

const badUA = ua => {
  ua = (ua||'').toLowerCase()
  return ['curl','wget','python','postman','insomnia','httpclient'].some(x=>ua.includes(x))
}

const limiter = rateLimit({ windowMs: 10000, max: 20 })

// Upload script
app.post('/upload', limiter, (req,res)=>{
  let c = req.body.content
  if(!c) return res.status(400).json({error:'no content'})
  const id = crypto.randomBytes(8).toString('hex')
  fs.writeFileSync(path.join(DIR,id+'.enc'), pack(c))
  res.json({
    id,
    loader:`loadstring(game:HttpGet("${req.protocol}://${req.get('host')}/token/${id}"))()`
  })
})

// Token endpoint
app.get('/token/:id', (req,res)=>{
  if(badUA(req.headers['user-agent'])) return res.status(403).send('denied')
  const id = req.params.id
  const token = crypto.randomBytes(12).toString('hex')
  const time = Date.now()
  TOKENS.set(token,{id,time})
  const sig = hash(token + time)
  res.send(`
return (function()
  local t="${token}"
  local ts="${time}"
  local sig="${sig}"
  local url="${req.protocol}://${req.get('host')}/load/${id}?t="..t.."&ts="..ts.."&sig="..sig
  return game:HttpGet(url)
end)()
`)
})

// Load endpoint (executor only)
app.get('/load/:id', limiter, (req,res)=>{
  const {t,ts,sig} = req.query
  const data = TOKENS.get(t)
  if(!data) return res.status(403).send('bad token')
  if(Date.now() - data.time > 10000){ TOKENS.delete(t); return res.status(403).send('expired') }
  if(sig !== hash(t + ts)) return res.status(403).send('invalid sig')
  TOKENS.delete(t)
  const file = path.join(DIR, req.params.id+'.enc')
  if(!fs.existsSync(file)) return res.status(404).send('not found')
  const payload = fs.readFileSync(file,'utf8')
  res.setHeader('Content-Type','text/plain')
  res.send(`
-- protected emoji loader
local d="${payload}"
local function b64(x) return game:GetService("HttpService"):Base64Decode(x) end
local function dec(e)
  local iv,dat=e:match("([^:]+):(.+)")
  local s=""
  for c in dat:gmatch(".") do s=s.."🤢" end
  return s
end
return loadstring(b64(dec(d)))()
`)
})

app.use(express.static('public'))

app.listen(PORT,()=>console.log("🚀 Protect Lua Server running on port "+PORT))
