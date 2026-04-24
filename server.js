require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);

const supabase = createClient(
  'https://vhgirrgawajyefjrwdnk.supabase.co',
  'sb_secret_UCsF6U7LrhKb6FHFr4-Adw_0Qhv8otY'
);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

const freeUsage = {};
const FREE_LIMIT = 3;

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
}

async function getUserFromToken(token) {
  if (!token) return null;
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return null;
    const { data: profile } = await supabase
      .from('users')
      .select('is_pro')
      .eq('id', user.id)
      .single();
    return { ...user, isPro: profile?.is_pro || false };
  } catch (e) {
    return null;
  }
}

// ---- EXTRACT ENDPOINT ----
app.post('/extract', extractLimiter, async (req, res) => {
  const { title, token } = req.body;
  if (!title) return res.status(400).json({ error: 'No title provided' });

  const ip = getIP(req);
  const user = await getUserFromToken(token);
  const isPro = user?.isPro || false;

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

// ---- AUTH: REGISTER ----
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    // Create user profile
    await supabase.from('users').insert({
      id: data.user.id,
      email: data.user.email,
      is_pro: false
    });

    res.json({ success: true, token: data.session?.access_token, user: { email: data.user.email } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- AUTH: LOGIN ----
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    const { data: profile } = await supabase
      .from('users')
      .select('is_pro')
      .eq('id', data.user.id)
      .single();

    res.json({
      success: true,
      token: data.session.access_token,
      user: { email: data.user.email, isPro: profile?.is_pro || false }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- AUTH: STATUS ----
app.post('/status', async (req, res) => {
  const { token } = req.body;
  const ip = getIP(req);
  const user = await getUserFromToken(token);
  const isPro = user?.isPro || false;
  const used = freeUsage[ip] || 0;
  const remaining = isPro ? 999 : Math.max(0, FREE_LIMIT - used);
  res.json({ isPro, remaining, used, email: user?.email || null });
});

// ---- STRIPE CHECKOUT ----
app.post('/create-checkout', async (req, res) => {
  const { plan, token } = req.body;
  const isAnnual = plan === 'annual';
  const user = await getUserFromToken(token);

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: user?.email || undefined,
      line_items: [{
        price: isAnnual
          ? 'price_1TPQcmCsPE5vWH8Z5ymSC5RO'
          : 'price_1TPQbTCsPE5vWH8ZgevVEBf4',
        quantity: 1
      }],
      metadata: { user_id: user?.id || '' },
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
      const userId = session.metadata?.user_id;
      if (userId) {
        await supabase.from('users').update({
          is_pro: true,
          stripe_customer_id: session.customer,
          stripe_subscription_id: session.subscription
        }).eq('id', userId);
      }
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
// ---- ADMIN MIDDLEWARE ----
async function isAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { data: { user } } = await supabase.auth.getUser(token);
    if (user?.email !== 'amadejgkladnik@gmail.com') return res.status(403).json({ error: 'Forbidden' });
    req.adminUser = user;
    next();
  } catch (e) { res.status(401).json({ error: 'Unauthorized' }); }
}

// ---- ADMIN: GET ALL USERS ----
app.get('/admin/users', isAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ users: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- ADMIN: TOGGLE PRO ----
app.post('/admin/toggle-pro', isAdmin, async (req, res) => {
  const { userId, isPro } = req.body;
  try {
    const { error } = await supabase.from('users').update({ is_pro: isPro }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- ADMIN: RESET PASSWORD ----
app.post('/admin/reset-password', isAdmin, async (req, res) => {
  const { userId, password } = req.body;
  try {
    const { error } = await supabase.auth.admin.updateUserById(userId, { password });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- ADMIN: DELETE USER ----
app.post('/admin/delete-user', isAdmin, async (req, res) => {
  const { userId } = req.body;
  try {
    await supabase.from('users').delete().eq('id', userId);
    const { error } = await supabase.auth.admin.deleteUser(userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.listen(PORT, () => console.log(`Sharp-Stack running at http://localhost:${PORT}`));
