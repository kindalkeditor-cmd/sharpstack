require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
app.set('trust proxy', 1);

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- RATE LIMITING ----
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please slow down.' },
  validate: { xForwardedForHeader: false }
}));

const extractLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Hourly extraction limit reached. Upgrade to Pro for unlimited access.' },
  validate: { xForwardedForHeader: false }
});

// ---- SERVER-SIDE USAGE TRACKING ----
const freeUsage = {};
const proTokens = new Set();
const emailList = new Set();

const FREE_LIMIT = 3;

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
}

// ---- EXTRACT ENDPOINT ----
app.post('/extract', extractLimiter, async (req, res) => {
  const { title, token } = req.body;
  if (!title) return res.status(400).json({ error: 'No title provided' });

  const ip = getIP(req);
  const isPro = token && proTokens.has(token);

  if (!isPro) {
    const used = freeUsage[ip] || 0;
    if (used >= FREE_LIMIT) {
      return res.status(403).json({ error: 'free_limit_reached' });
    }
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
        'x-api-key': process.env.ANTHROPIC_KEY,
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

    if (!isPro) {
      freeUsage[ip] = (freeUsage[ip] || 0) + 1;
    }

    const remaining = isPro ? 999 : Math.max(0, FREE_LIMIT - (freeUsage[ip] || 0));
    res.json({ ...parsed, isPro, remaining });

  } catch (e) {
    res.status(500).json({ error: 'Extraction failed. Try again.' });
  }
});

// ---- EMAIL CAPTURE ----
app.post('/save-email', rateLimit({ windowMs: 60*60*1000, max: 5, validate: { xForwardedForHeader: false } }), async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  emailList.add(email);
  console.log(`New email: ${email} (total: ${emailList.size})`);
  res.json({ success: true });
});

// ---- STRIPE CHECKOUT ----
app.post('/create-checkout', async (req, res) => {
  const { plan } = req.body;
  const isAnnual = plan === 'annual';

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{
        price: isAnnual
          ? 'price_1TPQcmCsPE5vWH8Z5ymSC5RO'
          : 'price_1TPQbTCsPE5vWH8ZgevVEBf4',
        quantity: 1
      }],
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/`
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- VERIFY PAYMENT ----
app.post('/verify-payment', async (req, res) => {
  const { session_id } = req.body;
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status === 'paid' || session.status === 'complete') {
      const token = session.subscription || session.id;
      proTokens.add(token);
      res.json({ success: true, token });
    } else {
      res.json({ success: false });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- CHECK STATUS ----
app.post('/status', (req, res) => {
  const { token } = req.body;
  const ip = getIP(req);
  const isPro = token && proTokens.has(token);
  const used = freeUsage[ip] || 0;
  const remaining = isPro ? 999 : Math.max(0, FREE_LIMIT - used);
  res.json({ isPro, remaining, used });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sharp-Stack running at http://localhost:${PORT}`));
