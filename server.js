import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { fetch } from 'undici';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' })); // cho POST/PUT
app.use(rateLimit({ windowMs: 60_000, max: 120 })); // 120 req/phút/IP

// CORS chỉ cho phép frontend của bạn
const allow = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // cho curl/postman
    return cb(null, allow.includes(origin));
  },
  credentials: true
}));

const BASE = process.env.WOO_BASE?.replace(/\/$/, '');
const AUTH = 'Basic ' + Buffer.from(`${process.env.WOO_CK}:${process.env.WOO_CS}`).toString('base64');

// Chỉ cho phép truy cập v3; không chấp nhận client gửi consumer_key/secret ở query
app.all('/api/woo/*', async (req, res) => {
  try {
    // chặn method lạ nếu muốn an toàn hơn
    const okMethods = ['GET','POST','PUT','DELETE','OPTIONS'];
    if (!okMethods.includes(req.method)) return res.status(405).end();

    // build URL đích
    const path = req.params[0]; // phần sau /api/woo/
    const url = new URL(`${BASE}/wp-json/wc/v3/${path}`);

    // copy query string, TRỪ các khóa nhạy cảm
    for (const [k,v] of Object.entries(req.query)) {
      if (!['consumer_key','consumer_secret'].includes(String(k).toLowerCase())) {
        url.searchParams.set(k, v);
      }
    }

    const r = await fetch(url, {
      method: req.method,
      headers: {
        'Authorization': AUTH,
        'Content-Type': req.headers['content-type'] || 'application/json'
      },
      body: ['GET','HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body)
    });

    const text = await r.text();
    res.status(r.status);
    // Pass through JSON or text
    try { res.type('application/json').send(JSON.parse(text)); }
    catch { res.send(text); }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.get('/healthz', (_,res)=>res.send('ok'));
app.listen(process.env.PORT || 8080, ()=> console.log('Proxy on', process.env.PORT||8080));
