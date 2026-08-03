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
const multer = require('multer');
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');

// FFmpeg setup
const ffmpegInstaller = require('@ffmpeg-installer/ffmpeg');
const ffprobeInstaller = require('@ffprobe-installer/ffprobe');
const ffmpeg = require('fluent-ffmpeg');
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
ffmpeg.setFfprobePath(ffprobeInstaller.path);
console.log('FFmpeg:', ffmpegInstaller.path);
console.log('FFprobe:', ffprobeInstaller.path);







const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ limit: '500mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
const extractLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20 });

const JWT_SECRET = process.env.JWT_SECRET || 'sharpstack-secret-key';
const FREE_LIMIT = 3;
const ADMIN_PASSWORD = process.env.SS_ADMIN_PASS || 'sharpstack-admin-2026';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) { req.user = null; return next(); }
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { req.user = null; next(); }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET + '-admin');
    if (decoded.role !== 'admin') return res.status(401).json({ error: 'Unauthorized' });
    next();
  } catch(e) { res.status(401).json({ error: 'Unauthorized' }); }
}

// ---- AUTH ----
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
  } catch(e) { res.status(500).json({ error: 'Login failed' }); }
});

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
  } catch(e) { res.json({ loggedIn: false }); }
});

// ---- EXTRACT ----
app.post('/extract', extractLimiter, authMiddleware, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'No title provided' });
  if (!req.user) return res.status(401).json({ error: 'login_required' });

  const result = await pool.query('SELECT is_pro, extractions_used FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'User not found' });

  if (!user.is_pro && user.extractions_used >= FREE_LIMIT) {
    return res.status(403).json({ error: 'free_limit_reached' });
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
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
    });

    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    if (!user.is_pro) {
      await pool.query('UPDATE users SET extractions_used = extractions_used + 1 WHERE id = $1', [req.user.id]);
    }

    const updated = await pool.query('SELECT extractions_used FROM users WHERE id = $1', [req.user.id]);
    const used = updated.rows[0]?.extractions_used || 0;
    const remaining = user.is_pro ? 999 : Math.max(0, FREE_LIMIT - used);

    res.json({ ...parsed, isPro: user.is_pro, remaining });
    // Log for trending
    try { await pool.query("INSERT INTO extractions_log (title) VALUES ($1)", [title]); } catch(e) {}
    if (req.user) { updateStreak(req.user.id); }
  } catch(e) { res.status(500).json({ error: 'Extraction failed' }); }
});

// ---- APPLY-IT PROMPTS ----
app.post('/apply-it', extractLimiter, authMiddleware, async (req, res) => {
  const { title, core_idea, key_points, action_steps, business_context } = req.body;
  if (!title) return res.status(400).json({ error: 'Missing book title' });
  if (!req.user) return res.status(401).json({ error: 'login_required' });

  const result = await pool.query('SELECT is_pro FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'User not found' });
  if (!user.is_pro) return res.status(403).json({ error: 'pro_required' });

  const context = business_context ? `The user's business context: "${business_context}"` : 'No specific business context provided — give general entrepreneur advice.';

  const prompt = `You are an elite business coach. A founder just read the key insights from "${title}".

Book core idea: ${core_idea || 'Not provided'}
Key points: ${(key_points || []).join(', ')}
Action steps from book: ${(action_steps || []).join(', ')}
${context}

Create a brutally practical 3-step plan to apply THIS book's lessons to THEIR business TODAY.
Be specific. Be direct. No fluff. Each step must be something they can START in the next 24 hours.

Return ONLY valid JSON, no markdown:
{
  "plan_title": "short punchy title for their plan",
  "step_1": { "action": "specific action to take", "time": "how long it takes", "why": "why this first" },
  "step_2": { "action": "specific action to take", "time": "how long it takes", "why": "why this second" },
  "step_3": { "action": "specific action to take", "time": "how long it takes", "why": "why this third" },
  "warning": "the one mistake most people make applying this book",
  "first_move": "the single thing to do in the next 60 minutes"
}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: 'Failed to generate plan' }); }
});


// ---- SAVE & LIBRARY ----
app.post('/library/save', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const { title, author, core_idea, key_points, action_steps, one_liner } = req.body;
  if (!title) return res.status(400).json({ error: 'Missing title' });
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS library (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT, author TEXT, core_idea TEXT,
      key_points JSONB, action_steps JSONB, one_liner TEXT,
      saved_at TIMESTAMP DEFAULT NOW()
    )`);
    const existing = await pool.query('SELECT id FROM library WHERE user_id=$1 AND title=$2', [req.user.id, title]);
    if (existing.rows.length > 0) return res.json({ saved: false, message: 'Already saved' });
    await pool.query(
      'INSERT INTO library (user_id, title, author, core_idea, key_points, action_steps, one_liner) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [req.user.id, title, author, core_idea, JSON.stringify(key_points), JSON.stringify(action_steps), one_liner]
    );
    res.json({ saved: true });
  } catch(e) { res.status(500).json({ error: 'Failed to save' }); }
});

app.get('/library', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const search = req.query.search || '';
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS library (
      id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT, author TEXT, core_idea TEXT, key_points JSONB, action_steps JSONB, one_liner TEXT,
      saved_at TIMESTAMP DEFAULT NOW()
    )`);
    let query = 'SELECT * FROM library WHERE user_id=$1';
    const params = [req.user.id];
    if (search) { query += ' AND (title ILIKE $2 OR author ILIKE $2)'; params.push('%' + search + '%'); }
    query += ' ORDER BY saved_at DESC';
    const result = await pool.query(query, params);
    res.json({ books: result.rows });
  } catch(e) { res.status(500).json({ error: 'Failed to load library' }); }
});

app.delete('/library/:id', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  try {
    await pool.query('DELETE FROM library WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ deleted: true });
  } catch(e) { res.status(500).json({ error: 'Failed to delete' }); }
});

// ---- TRENDING ----
app.get('/trending', async (req, res) => {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS extractions_log (
      id SERIAL PRIMARY KEY, title TEXT, extracted_at TIMESTAMP DEFAULT NOW()
    )`);
    const result = await pool.query(
      "SELECT title, COUNT(*) as count FROM extractions_log WHERE extracted_at > NOW() - INTERVAL '7 days' GROUP BY title ORDER BY count DESC LIMIT 6"
    );
    res.json({ trending: result.rows });
  } catch(e) { res.json({ trending: [] }); }
});

// ---- COMPARE BOOKS ----
app.post('/compare', extractLimiter, authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const result = await pool.query('SELECT is_pro FROM users WHERE id=$1', [req.user.id]);
  if (!result.rows[0]?.is_pro) return res.status(403).json({ error: 'pro_required' });
  const { book1, book2 } = req.body;
  if (!book1 || !book2) return res.status(400).json({ error: 'Two books required' });
  const prompt = `You are an expert business book analyst. Compare "${book1}" and "${book2}" for entrepreneurs.
Return ONLY valid JSON, no markdown:
{
  "book1": "${book1}",
  "book2": "${book2}",
  "same_goal": "what both books ultimately want you to achieve",
  "key_difference": "the fundamental difference in their approach",
  "book1_wins_when": "specific situation where book1's advice is better",
  "book2_wins_when": "specific situation where book2's advice is better",
  "combined_insight": "the most powerful idea you get by reading both",
  "read_first": "which to read first and why in one sentence"
}`;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 800, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: 'Comparison failed' }); }
});

// ---- LOG EXTRACTION FOR TRENDING ----

// ---- LIVE COUNTER ----
app.get('/stats/counter', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as total FROM extractions_log');
    const users = await pool.query('SELECT COUNT(*) as total FROM users');
    res.json({ extractions: parseInt(result.rows[0].total) || 0, users: parseInt(users.rows[0].total) || 0 });
  } catch(e) { res.json({ extractions: 0, users: 0 }); }
});

// ---- STREAK ----
app.get('/streak', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  try {
    const result = await pool.query('SELECT * FROM streaks WHERE user_id=$1', [req.user.id]);
    if (!result.rows.length) return res.json({ current: 0, longest: 0 });
    const s = result.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const last = s.last_extraction_date ? s.last_extraction_date.toISOString().split('T')[0] : null;
    const active = last === today;
    res.json({ current: s.current_streak, longest: s.longest_streak, active });
  } catch(e) { res.json({ current: 0, longest: 0 }); }
});

// Update streak on extract - called internally
async function updateStreak(userId) {
  try {
    const today = new Date().toISOString().split('T')[0];
    const result = await pool.query('SELECT * FROM streaks WHERE user_id=$1', [userId]);
    if (!result.rows.length) {
      await pool.query('INSERT INTO streaks (user_id, current_streak, last_extraction_date, longest_streak) VALUES ($1,1,$2,1)', [userId, today]);
      return;
    }
    const s = result.rows[0];
    const last = s.last_extraction_date ? s.last_extraction_date.toISOString().split('T')[0] : null;
    if (last === today) return;
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const newStreak = last === yesterday ? s.current_streak + 1 : 1;
    const longest = Math.max(newStreak, s.longest_streak);
    await pool.query('UPDATE streaks SET current_streak=$1, last_extraction_date=$2, longest_streak=$3 WHERE user_id=$4', [newStreak, today, longest, userId]);
  } catch(e) {}
}

// ---- REFERRAL ----
app.post('/referral/generate', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  try {
    const existing = await pool.query('SELECT code FROM referrals WHERE referrer_id=$1 AND used=false LIMIT 1', [req.user.id]);
    if (existing.rows.length) return res.json({ code: existing.rows[0].code });
    const code = require('crypto').randomBytes(6).toString('hex');
    await pool.query('INSERT INTO referrals (referrer_id, code) VALUES ($1,$2)', [req.user.id, code]);
    res.json({ code });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/referral/use', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });
  try {
    const ref = await pool.query('SELECT * FROM referrals WHERE code=$1 AND used=false', [code]);
    if (!ref.rows.length) return res.status(404).json({ error: 'Invalid or used code' });
    const referral = ref.rows[0];
    if (referral.referrer_id === req.user.id) return res.status(400).json({ error: 'Cannot use your own code' });
    await pool.query('UPDATE referrals SET used=true, referred_email=$1 WHERE code=$2', [req.user.email, code]);
    // Grant 30 days pro to both
    await pool.query('UPDATE users SET is_pro=true WHERE id=$1 OR id=$2', [req.user.id, referral.referrer_id]);
    res.json({ success: true, message: 'Both you and your friend got 30 days Pro free!' });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// ---- TEAM/B2B ----
app.post('/team/create', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const { name } = req.body;
  try {
    const existing = await pool.query('SELECT id FROM teams WHERE owner_id=$1', [req.user.id]);
    if (existing.rows.length) return res.json({ team: existing.rows[0] });
    const result = await pool.query('INSERT INTO teams (name, owner_id) VALUES ($1,$2) RETURNING *', [name || 'My Team', req.user.id]);
    await pool.query('INSERT INTO team_members (team_id, user_id, joined) VALUES ($1,$2,true)', [result.rows[0].id, req.user.id]);
    res.json({ team: result.rows[0] });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/team/invite', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  const { email } = req.body;
  try {
    const team = await pool.query('SELECT * FROM teams WHERE owner_id=$1', [req.user.id]);
    if (!team.rows.length) return res.status(404).json({ error: 'No team found' });
    const members = await pool.query('SELECT COUNT(*) as count FROM team_members WHERE team_id=$1', [team.rows[0].id]);
    if (parseInt(members.rows[0].count) >= team.rows[0].seats) return res.status(400).json({ error: 'Team is full' });
    await pool.query('INSERT INTO team_members (team_id, invited_email) VALUES ($1,$2) ON CONFLICT DO NOTHING', [team.rows[0].id, email]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/team', authMiddleware, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login_required' });
  try {
    const team = await pool.query('SELECT * FROM teams WHERE owner_id=$1', [req.user.id]);
    if (!team.rows.length) return res.json({ team: null });
    const members = await pool.query('SELECT tm.*, u.email FROM team_members tm LEFT JOIN users u ON tm.user_id=u.id WHERE tm.team_id=$1', [team.rows[0].id]);
    res.json({ team: team.rows[0], members: members.rows });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// ---- ELEVENLABS PROXY ----
app.post('/generate-voiceover', adminAuth, async (req, res) => {
  const { text, voiceId } = req.body;
  if (!text || !voiceId) return res.status(400).json({ error: 'Missing text or voiceId' });

  try {
    const response = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`, {
      method: 'POST',
      headers: {
        'xi-api-key': process.env.ELEVENLABS_KEY,
        'Content-Type': 'application/json',
        'Accept': 'audio/mpeg'
      },
      body: JSON.stringify({
        text,
        model_id: 'eleven_turbo_v2_5',
        voice_settings: { stability: 0.3, similarity_boost: 0.85, style: 0.5, use_speaker_boost: true }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error('ElevenLabs error ' + response.status + ': ' + errText);
    }
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    res.set('Content-Type', 'audio/mpeg');
    res.set('Content-Length', buffer.length);
    res.send(buffer);
  } catch(e) {
    console.error('ElevenLabs error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- STRIPE ----
app.post('/create-checkout', authMiddleware, async (req, res) => {
  const { plan } = req.body;
  const isAnnual = plan === 'annual';
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: req.user?.email,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: isAnnual ? 'Sharp-Stack Pro — Annual' : 'Sharp-Stack Pro — Monthly', description: 'Unlimited book extractions + weekly curated drops' },
          unit_amount: isAnnual ? 7900 : 900,
          recurring: { interval: isAnnual ? 'year' : 'month' }
        },
        quantity: 1
      }],
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/`
    });
    res.json({ url: session.url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

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
    } else { res.json({ success: false }); }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/save-email', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  console.log(`Email captured: ${email}`);
  res.json({ success: true });
});

// ---- ADMIN ----
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET + '-admin', { expiresIn: '24h' });
  res.json({ token });
});

app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM users');
    const pro = await pool.query('SELECT COUNT(*) FROM users WHERE is_pro = TRUE');
    const free = await pool.query('SELECT COUNT(*) FROM users WHERE is_pro = FALSE');
    const extractions = await pool.query('SELECT SUM(extractions_used) FROM users');
    const recent = await pool.query("SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '7 days'");
    res.json({
      totalUsers: parseInt(total.rows[0].count),
      proUsers: parseInt(pro.rows[0].count),
      freeUsers: parseInt(free.rows[0].count),
      mrr: parseInt(pro.rows[0].count) * 9,
      totalExtractions: parseInt(extractions.rows[0].sum) || 0,
      newThisWeek: parseInt(recent.rows[0].count)
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const { search, page = 1 } = req.query;
    const limit = 20;
    const offset = (page - 1) * limit;
    let query = 'SELECT id, email, is_pro, extractions_used, created_at FROM users';
    let params = [];
    if (search) { query += ' WHERE email ILIKE $1'; params.push(`%${search}%`); }
    query += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const result = await pool.query(query, params);
    res.json({ users: result.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/grant-pro', adminAuth, async (req, res) => {
  const { userId, isPro } = req.body;
  try {
    await pool.query('UPDATE users SET is_pro = $1 WHERE id = $2', [isPro, userId]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ---- VIDEO STUDIO ----
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 500 * 1024 * 1024 } }); // 500MB limit

app.post('/generate-video', adminAuth, upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'audio', maxCount: 1 }
]), async (req, res) => {
  const { hookText } = req.body;
  if (!req.files?.video || !req.files?.audio) {
    return res.status(400).json({ error: 'Video and audio files required' });
  }

  const videoPath = req.files.video[0].path;
  const audioPath = req.files.audio[0].path;
  const outputPath = `${os.tmpdir()}/sharpstack-output-${Date.now()}.mp4`;

  try {
    // Get audio duration using fluent-ffmpeg
    const getAudioDuration = () => new Promise((resolve, reject) => {
      ffmpeg.ffprobe(audioPath, (err, metadata) => {
        if (err) reject(err);
        else resolve(metadata.format.duration);
      });
    });

    const getVideoDuration = () => new Promise((resolve, reject) => {
      ffmpeg.ffprobe(videoPath, (err, metadata) => {
        if (err) reject(err);
        else resolve(metadata.format.duration);
      });
    });

    const audioDuration = await getAudioDuration();
    const videoDuration = await getVideoDuration();
    const loops = Math.ceil(audioDuration / videoDuration);

    // Build the video using fluent-ffmpeg
    await new Promise((resolve, reject) => {
      let cmd = ffmpeg()
        .input(videoPath)
        .inputOptions([`-stream_loop ${loops}`])
        .input(audioPath)
        .outputOptions([
          '-c:v libx264',
          '-preset fast',
          '-crf 23',
          '-c:a aac',
          `-t ${audioDuration}`,
          '-shortest'
        ]);

      // Add hook text overlay if provided
      // Hook text overlay removed - add text in TikTok editor instead

      cmd
        .output(outputPath)
        .on('end', resolve)
        .on('error', reject)
        .run();
    });

    res.download(outputPath, 'sharpstack-tiktok.mp4', () => {
      try { fs.unlinkSync(videoPath); } catch(e) {}
      try { fs.unlinkSync(audioPath); } catch(e) {}
      try { fs.unlinkSync(outputPath); } catch(e) {}
    });

  } catch(e) {
    console.error('Video generation error:', e.message);
    try { fs.unlinkSync(videoPath); } catch(err) {}
    try { fs.unlinkSync(audioPath); } catch(err) {}
    res.status(500).json({ error: 'Video generation failed: ' + e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sharp-Stack running at http://localhost:${PORT}`));
