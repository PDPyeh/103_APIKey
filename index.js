// index.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const pool = require('./db');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// util: generate api key
function generateApiKey(length = 40) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const buf = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < buf.length; i++) out += alphabet[buf[i] % alphabet.length];
  return `sk-${out}`;
}

// POST /create  -> generate + simpan ke DB
// optional body: { owner: "nama/email", ttl_minutes: 43200 }
app.post('/create', async (req, res) => {
  try {
    const key = generateApiKey(40);
    const { owner = null, ttl_minutes = null } = req.body || {};

    let expires_at = null;
    if (ttl_minutes && Number(ttl_minutes) > 0) {
      expires_at = new Date(Date.now() + Number(ttl_minutes) * 60 * 1000);
    }

    const sql = `
      INSERT INTO api_keys (api_key, owner, expires_at)
      VALUES (:api_key, :owner, :expires_at)
    `;
    await pool.execute(sql, { api_key: key, owner, expires_at });

    return res.json({
      message: 'API key generated & stored',
      api_key: key,
      owner,
      expires_at
    });
  } catch (err) {
    // kemungkinan duplicate random kecil banget, tapi handle aja
    console.error(err);
    return res.status(500).json({ message: 'Failed to create api key' });
  }
});

// POST /checkapi  -> validasi ke DB
// body: { api_key: "sk-xxxx" }
app.post('/checkapi', async (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) {
      return res.status(400).json({ valid: false, message: 'Missing api_key' });
    }

    // format basic check
    const formatOk = api_key.startsWith('sk-') &&
                     api_key.length >= 10 &&
                     /^[A-Za-z0-9-]+$/.test(api_key);
    if (!formatOk) {
      return res.status(401).json({ valid: false, message: 'Invalid key format' });
    }

    // cek DB
    const [rows] = await pool.execute(
      `SELECT id, owner, revoked, created_at, expires_at
         FROM api_keys
        WHERE api_key = :api_key
        LIMIT 1`,
      { api_key }
    );

    if (!rows.length) {
      return res.status(401).json({ valid: false, message: 'API key not found' });
    }

    const k = rows[0];
    if (k.revoked) {
      return res.status(401).json({ valid: false, message: 'API key revoked' });
    }
    if (k.expires_at && new Date(k.expires_at) < new Date()) {
      return res.status(401).json({ valid: false, message: 'API key expired' });
    }

    return res.json({
      valid: true,
      message: 'API key is valid',
      meta: {
        id: k.id,
        owner: k.owner,
        created_at: k.created_at,
        expires_at: k.expires_at
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid: false, message: 'Check failed' });
  }
});

// (opsional) revoke key
// body: { api_key: "sk-xxxx" }
app.post('/revoke', async (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) return res.status(400).json({ message: 'Missing api_key' });

    const [result] = await pool.execute(
      `UPDATE api_keys SET revoked = 1 WHERE api_key = :api_key`,
      { api_key }
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'API key not found' });
    }
    return res.json({ message: 'API key revoked' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Failed to revoke key' });
  }
});

// root kirim UI
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`✅ Server nyala di http://localhost:${port}`);
});
