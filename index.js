const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

app.use(express.json());

// Aktifkan kalau kamu akses dari origin yg beda (mis. http://127.0.0.1:5500)
// app.use(cors({ origin: true, credentials: true }));

// Serve /public (taruh index.html lu di sini)
app.use(express.static(path.join(__dirname, 'public')));

// API generate key
function generateApiKey(length = 40) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const buf = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < buf.length; i++) out += alphabet[buf[i] % alphabet.length];
  return `sk-${out}`;
}

app.post('/create', (req, res) => {
  const key = generateApiKey();
  console.log('Generated key:', key); // buat ngecek di console
  res.json({ message: 'API key generated', api_key: key });
});

app.post("/checkapi", (req, res) => {
  const clientKey = req.body.api_key;

  if (!clientKey) {
    return res.status(400).json({
      valid: false,
      message: "Missing api_key in body"
    });
  }

  // ✅ RULE VALID — contoh simple:
  // format harus mulai dengan `sk-` dan panjang minimal 10
  const isValid =
    clientKey.startsWith("sk-") &&
    clientKey.length >= 10 &&
    /^[A-Za-z0-9\-]+$/.test(clientKey);

  if (!isValid) {
    return res.status(401).json({
      valid: false,
      message: "Invalid API key format"
    });
  }

  // ✅ (NANTI BISA DI CEK DB DI SINI)
  // misalnya:
  // const exists = await db.key.findOne({ where: { key: clientKey } });
  // if (!exists) invalid

  return res.json({
    valid: true,
    message: "API key is valid"
  });
});


// (opsional) pastiin root balikin index.html
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`✅ Server nyala di http://localhost:${port}`);
});
