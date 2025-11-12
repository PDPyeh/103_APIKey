// index.js (DB version)
const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const mysql   = require('mysql2/promise');
require('dotenv').config();

const app  = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  user:     process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'apikeys_db',
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: true,
});

function generateApiKey(length = 40) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const buf = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < buf.length; i++) out += alphabet[buf[i] % alphabet.length];
  return `sk-${out}`;
}

app.post('/create', async (req, res) => {
  try {
    const key = generateApiKey();
    const { owner = null, ttl_minutes = null } = req.body || {};
    const expires_at = ttl_minutes ? new Date(Date.now() + Number(ttl_minutes) * 60 * 1000) : null;

    await pool.execute(
      `INSERT INTO api_keys (api_key, owner, expires_at) VALUES (:api_key, :owner, :expires_at)`,
      { api_key: key, owner, expires_at }
    );

    console.log('[CREATE] stored key =>', key);
    return res.json({ message: 'stored', api_key: key, owner, expires_at });
  } catch (e) {
    console.error('[CREATE] DB error:', e?.sqlMessage || e?.message || e);
    return res.status(500).json({ message: 'DB insert failed', detail: e?.sqlMessage || e?.message });
  }
});

app.post('/checkapi', async (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) return res.status(400).json({ valid:false, message:'Missing api_key' });

    const [rows] = await pool.execute(
      `SELECT id, revoked, expires_at FROM api_keys WHERE api_key = :api_key LIMIT 1`,
      { api_key }
    );
    if (!rows.length) return res.status(401).json({ valid:false, message:'API key not found' });

    const k = rows[0];
    if (k.revoked) return res.status(401).json({ valid:false, message:'API key revoked' });
    if (k.expires_at && new Date(k.expires_at) < new Date())
      return res.status(401).json({ valid:false, message:'API key expired' });

    return res.json({ valid:true, message:'API key is valid' });
  } catch (e) {
    console.error('[CHECK] error:', e?.sqlMessage || e?.message || e);
    return res.status(500).json({ valid:false, message:'Check failed', detail: e?.sqlMessage || e?.message });
  }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`✅ Server nyala di http://localhost:${port}`);
});
