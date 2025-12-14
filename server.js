// Top of server.js — replace your current top duplicate-requires / app setup with this
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');        // or 'bcryptjs' if you prefer
const nodemailer = require('nodemailer');
const cors = require('cors');
const { init, run, get, all } = require('./db'); // require db helper(s) once

// create app and middleware
const app = express();
app.use(express.json());
app.use(cors()); // allow your frontend to call this server

// initialize the database tables
init();

// health check for Render
app.get('/healthz', (req, res) => res.status(200).send('ok'));
// use PORT from env and start listening
const PORT = process.env.PORT || 4000;
const BASE_URL = (process.env.BASE_URL || 'https://crajy-boys.onrender.com')
  .replace(/\/$/, '');

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`BASE_URL is ${BASE_URL}`);
});

// create transporter: if SMTP config provided use it, otherwise fall back to Ethereal for testing
async function createTransporter() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true', // true for 465
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  } else {
    // Ethereal (test)
    const testAccount = await nodemailer.createTestAccount();
    const t = nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: { user: testAccount.user, pass: testAccount.pass }
    });
    console.warn('No SMTP configured — using Ethereal test account. Email preview URLs will be logged.');
    return t;
  }
}

let transporterPromise = createTransporter();

// helper: generate token and hashed token
function genTokenAndHash() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}

// POST /register-init
// body: { name, email, dob }  — creates or updates a pending user and sends verification email
app.post('/register-init', async (req, res) => {
  try {
    const { name, email, dob } = req.body;
    if (!email || !name) return res.status(400).json({ error: 'name and email required' });

    // ensure lowercase email
    const e = String(email).toLowerCase().trim();

    // generate token
    const { token, tokenHash } = genTokenAndHash();
    const tokenExpiry = Date.now() + 1000 * 60 * 60; // 1 hour

    // insert or update user
    const now = Math.floor(Date.now() / 1000);
    const existing = await get('SELECT * FROM users WHERE email = ?', [e]);
    if (!existing) {
      await run('INSERT INTO users (name, email, dob, token_hash, token_expiry, verified, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)', [name, e, dob || null, tokenHash, tokenExpiry, now]);
    } else {
      await run('UPDATE users SET name = ?, dob = ?, token_hash = ?, token_expiry = ?, verified = 0 WHERE email = ?', [name, dob || existing.dob, tokenHash, tokenExpiry, e]);
    }

    // send verification email
    const transporter = await transporterPromise;
    const verifyUrl = `${BASE_URL.replace(/\/$/, '')}/verify?token=${token}&email=${encodeURIComponent(e)}`;
    const mail = {
      from: process.env.EMAIL_FROM || 'no-reply@crajy-boys.local',
      to: e,
      subject: 'Verify your email — Crajy Boys',
      text: `Hello ${name},\n\nClick the link to verify your email and complete registration:\n\n${verifyUrl}\n\nThis link expires in 1 hour.\n\nIf you did not request registration, ignore this email.`,
      html: `<p>Hello ${name},</p><p>Click the link to verify your email and complete registration:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>This link expires in 1 hour.</p>`
    };

    const info = await transporter.sendMail(mail);

    // If using Ethereal, include preview URL in response (for testing)
    const preview = nodemailer.getTestMessageUrl(info) || null;

    res.json({ ok: true, preview });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// GET /verify?token=...&email=...
// Verifies token, marks user verified and removes token.
app.get('/verify', async (req, res) => {
  try {
    const { token, email } = req.query;
    if (!token || !email) return res.status(400).send('Invalid request');

    const e = String(email).toLowerCase().trim();
    const user = await get('SELECT * FROM users WHERE email = ?', [e]);
    if (!user) return res.status(400).send('Invalid token or email');

    if (!user.token_hash || !user.token_expiry) return res.status(400).send('No verification pending for this email');
    if (Date.now() > Number(user.token_expiry)) return res.status(400).send('Token expired');

    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    if (tokenHash !== user.token_hash) return res.status(400).send('Invalid token');

    await run('UPDATE users SET verified = 1, token_hash = NULL, token_expiry = NULL WHERE email = ?', [e]);

    // Redirect to a frontend page if you want; by default respond with a success message.
    // If you want to redirect to your members page or a completion UI, set FRONTEND_AFTER_VERIFY env.
    const FRONTEND_AFTER_VERIFY = process.env.FRONTEND_AFTER_VERIFY || null;
    if (FRONTEND_AFTER_VERIFY) {
      // include email in query so front-end knows which account verified (do not include sensitive info)
      const redirectUrl = `${FRONTEND_AFTER_VERIFY.replace(/\/$/, '')}/?verified=1&email=${encodeURIComponent(e)}`;
      return res.redirect(302, redirectUrl);
    }

    res.send('Email verified. You can now complete registration (POST /complete-registration).');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// POST /complete-registration
// body: { email, password }
app.post('/complete-registration', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const e = String(email).toLowerCase().trim();
    const user = await get('SELECT * FROM users WHERE email = ?', [e]);
    if (!user) return res.status(400).json({ error: 'No such user' });
    if (!user.verified) return res.status(400).json({ error: 'Email not verified' });

    // Hash password
    const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
    const hash = await bcrypt.hash(password, saltRounds);

    await run('UPDATE users SET password_hash = ? WHERE email = ?', [hash, e]);

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// GET /members — returns verified members (name, email, dob)
app.get('/members', async (req, res) => {
  try {
    const rows = await all('SELECT name, email, dob, created_at FROM users WHERE verified = 1 ORDER BY created_at DESC');
    res.json({ members: rows || [] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log(`BASE_URL is ${BASE_URL}`);
});
