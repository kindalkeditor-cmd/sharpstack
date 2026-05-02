require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Init database tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      is_pro BOOLEAN DEFAULT FALSE,
      stripe_customer_id VARCHAR(255),
      stripe_subscription_id VARCHAR(255),
      extractions_used INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Database ready');
}
initDB();

// Security
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
const extractLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20 });

const JWT_SECRET = process.env.JWT_SECRET || 'sharpstack-secret-key-change-in-production';
const FREE_LIMIT = 3;
const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY;

// ---- AUTH MIDDLEWARE ----
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) { req.user = null; return next(); }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    req.user = null;
    next();
  }
}

// ---- SIGNUP ----
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, is_pro, extractions_used',
      [email.toLowerCase(), hashed]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { email: user.email, isPro: user.is_pro, extractionsUsed: user.extractions_used } });
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Signup failed' });
  }
});

// ---- LOGIN ----
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { email: user.email, isPro: user.is_pro, extractionsUsed: user.extractions_used } });
  } catch(e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ---- GET USER STATUS ----
app.get('/auth/me', authMiddleware, async (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  try {
    const result = await pool.query('SELECT email, is_pro, extractions_used FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.json({ loggedIn: false });
    res.json({
      loggedIn: true,
      email: user.email,
      isPro: user.is_pro,
      extractionsUsed: user.extractions_used,
      remaining: user.is_pro ? 999 : Math.max(0, FREE_LIMIT - user.extractions_used)
    });
  } catch(e) {
    res.json({ loggedIn: false });
  }
});

// ---- EXTRACT ----
app.post('/extract', extractLimiter, authMiddleware, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'No title provided' });

  let isPro = false;
  let userId = null;

  if (req.user) {
    const result = await pool.query('SELECT is_pro, extractions_used FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'User not found' });
    isPro = user.is_pro;
    userId = req.user.id;

    if (!isPro && user.extractions_used >= FREE_LIMIT) {
      return res.status(403).json({ error: 'free_limit_reached' });
    }
  } else {
    return res.status(401).json({ error: 'login_required' });
  }

  const prompt = `You are a brutal book distiller for entrepreneurs. Extract ONLY actionable insights. No fluff, no stories.

For the book: "${title}"

Return ONLY valid JSON, no markdown:
{
  "title": "exact book title",
  "author": "author name",
  "core_idea": "the single most important idea in one sentence",
  "key_points": ["point 1","point 2","point 3","point 4","point 5"],
  "action_steps": ["do this first","then this","then this"],
  "one_liner": "one sentence to remember forever"
}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    // Increment usage
    if (!isPro) {
      await pool.query('UPDATE users SET extractions_used = extractions_used + 1 WHERE id = $1', [userId]);
    }

    const updatedUser = await pool.query('SELECT extractions_used FROM users WHERE id = $1', [userId]);
    const used = updatedUser.rows[0]?.extractions_used || 0;
    const remaining = isPro ? 999 : Math.max(0, FREE_LIMIT - used);

    res.json({ ...parsed, isPro, remaining });
  } catch(e) {
    res.status(500).json({ error: 'Extraction failed' });
  }
});

// ---- STRIPE CHECKOUT ----
app.post('/create-checkout', authMiddleware, async (req, res) => {
  const { plan } = req.body;
  const isAnnual = plan === 'annual';
  const email = req.user?.email;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: email,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: isAnnual ? 'Sharp-Stack Pro — Annual' : 'Sharp-Stack Pro — Monthly',
            description: 'Unlimited book extractions + weekly curated drops'
          },
          unit_amount: isAnnual ? 7900 : 900,
          recurring: { interval: isAnnual ? 'year' : 'month' }
        },
        quantity: 1
      }],
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/`
    });
    res.json({ url: session.url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- VERIFY PAYMENT ----
app.post('/verify-payment', authMiddleware, async (req, res) => {
  const { session_id } = req.body;
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status === 'paid' || session.status === 'complete') {
      if (req.user) {
        await pool.query(
          'UPDATE users SET is_pro = TRUE, stripe_customer_id = $1, stripe_subscription_id = $2 WHERE id = $3',
          [session.customer, session.subscription, req.user.id]
        );
      }
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- EMAIL CAPTURE ----
app.post('/save-email', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  console.log(`Email captured: ${email}`);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sharp-Stack running at http://localhost:${PORT}`));

// ---- ADMIN MIDDLEWARE ----
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'sharpstack-admin-2026';

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET + '-admin');
    if (decoded.role !== 'admin') return res.status(401).json({ error: 'Unauthorized' });
    next();
  } catch(e) {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// ---- ADMIN LOGIN ----
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET + '-admin', { expiresIn: '24h' });
  res.json({ token });
});

// ---- ADMIN STATS ----
app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM users');
    const pro = await pool.query('SELECT COUNT(*) FROM users WHERE is_pro = TRUE');
    const free = await pool.query('SELECT COUNT(*) FROM users WHERE is_pro = FALSE');
    const extractions = await pool.query('SELECT SUM(extractions_used) FROM users');
    const recent = await pool.query('SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL \'7 days\'');

    res.json({
      totalUsers: parseInt(total.rows[0].count),
      proUsers: parseInt(pro.rows[0].count),
      freeUsers: parseInt(free.rows[0].count),
      mrr: parseInt(pro.rows[0].count) * 9,
      totalExtractions: parseInt(extractions.rows[0].sum) || 0,
      newThisWeek: parseInt(recent.rows[0].count)
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- ADMIN USERS ----
app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const { search, page = 1 } = req.query;
    const limit = 20;
    const offset = (page - 1) * limit;

    let query = 'SELECT id, email, is_pro, extractions_used, created_at FROM users';
    let params = [];

    if (search) {
      query += ' WHERE email ILIKE $1';
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const result = await pool.query(query, params);
    res.json({ users: result.rows });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- ADMIN GRANT PRO ----
app.post('/admin/grant-pro', adminAuth, async (req, res) => {
  const { userId, isPro } = req.body;
  try {
    await pool.query('UPDATE users SET is_pro = $1 WHERE id = $2', [isPro, userId]);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
