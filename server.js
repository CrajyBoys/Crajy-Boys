require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { init, run, get, all } = require('./db');

// --------------------
// App setup
// --------------------
const app = express();
app.use(express.json());
app.use(cors());

// --------------------
// Init database
// --------------------
init();

// --------------------
// Config
// --------------------
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || 'https://crajy-boys-t46o.onrender.com';
const APP_PASSWORD = process.env.APP_PASSWORD;

if (!APP_PASSWORD) {
  console.warn('⚠️ Warning: APP_PASSWORD is not set! /members route is unprotected.');
}

// --------------------
// Health check (Render)
// --------------------
app.get('/healthz', (_req, res) => {
  res.status(200).send('ok');
});

// --------------------
// Email transporter
// --------------------
async function createTransporter() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }
  // Fallback: Ethereal (dev only)
  const testAccount = await nodemailer.createTestAccount();
  console.warn('⚠️ SMTP not configured — using Ethereal test account');
  return nodemailer.createTransport({
    host: testAccount.smtp.host,
    port: testAccount.smtp.port,
    secure: testAccount.smtp.secure,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass
    }
  });
}
const transporterPromise = createTransporter();

// --------------------
// Helpers
// --------------------
function generateToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}

// --------------------
// Routes
// --------------------

// Register (step 1) - Improved version
app.post('/register-init', async (req, res) => {
  try {
    const { name, email, dob } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const { token, tokenHash } = generateToken();
    const tokenExpiry = Date.now() + 60 * 60 * 1000; // 1 hour

    const existing = await get(
      'SELECT * FROM users WHERE email = ?',
      [cleanEmail]
    );

    if (!existing) {
      await run(
        `INSERT INTO users
         (name, email, dob, token_hash, token_expiry, verified)
         VALUES (?, ?, ?, ?, ?, 0)`,
        [name, cleanEmail, dob || null, tokenHash, tokenExpiry]
      );
    } else {
      await run(
        `UPDATE users
         SET name=?, dob=?, token_hash=?, token_expiry=?, verified=0
         WHERE email=?`,
        [name, dob || existing.dob, tokenHash, tokenExpiry, cleanEmail]
      );
    }

    const transporter = await transporterPromise;
    const verifyUrl = `${BASE_URL}/verify?token=${token}&email=${encodeURIComponent(cleanEmail)}`;

    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'no-reply@crajy-boys.local',
      to: cleanEmail,
      subject: 'Verify your email — Crajy Boys',
      html: `
        <p>Hello <b>${name}</b>,</p>
        <p>Please verify your email:</p>
        <p><a href="${verifyUrl}">Verify Email</a></p>
        <p>This link expires in 1 hour.</p>
      `
    });

    console.log('✅ Verification email sent to:', cleanEmail);
    res.json({ 
      ok: true, 
      message: "Verification email sent successfully" 
    });

  } catch (err) {
    console.error('❌ Email sending failed:', err.message);
    res.status(500).json({
      error: 'Failed to send verification email',
      details: err.message
    });
  }
});

// Verify email
app.get('/verify', async (req, res) => {
  try {
    const { token, email } = req.query;
    if (!token || !email) return res.status(400).send('Invalid request');
    const cleanEmail = email.toLowerCase().trim();
    const user = await get(
      'SELECT * FROM users WHERE email = ?',
      [cleanEmail]
    );
    if (!user) return res.status(400).send('Invalid link');
    if (Date.now() > Number(user.token_expiry)) {
      return res.status(400).send('Link expired');
    }
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    if (tokenHash !== user.token_hash) {
      return res.status(400).send('Invalid token');
    }
    await run(
      `UPDATE users
       SET verified=1, token_hash=NULL, token_expiry=NULL
       WHERE email=?`,
      [cleanEmail]
    );
    res.send('✅ Email verified. You may now return to the website.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Complete registration (password)
app.post('/complete-registration', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const cleanEmail = email.toLowerCase().trim();
    const user = await get(
      'SELECT * FROM users WHERE email = ?',
      [cleanEmail]
    );
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!user.verified) return res.status(400).json({ error: 'Email not verified' });
    const rounds = Number(process.env.BCRYPT_ROUNDS || 12);
    const passwordHash = await bcrypt.hash(password, rounds);
    await run(
      'UPDATE users SET password_hash=? WHERE email=?',
      [passwordHash, cleanEmail]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Members list
app.get('/members', async (_req, res) => {
  try {
    const members = await all(
      `SELECT name, email, dob, created_at
       FROM users
       WHERE verified = 1
       ORDER BY created_at DESC`
    );
    res.json({ members });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
