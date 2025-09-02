
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'client'))); 

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'rate_my_store',
  waitForConnections: true,
  connectionLimit: 10,
});

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this';
const PORT = process.env.PORT || 4000;


function validateSignup(data) {
  const { name, email, password, address } = data;
  if (!name || name.length < 10 || name.length > 60) return 'Name must be 20-60 characters';
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRe.test(email)) return 'Invalid email';
  const pwdRe = /^(?=.*[A-Z])(?=.*[!@#$%^&*()_\-+={}[\]|\\:;"'<>,.?/]).{8,16}$/;
  if (!password || !pwdRe.test(password)) return 'Password must be 8-16 chars, include an uppercase and a special character';
  if (address && address.length > 400) return 'Address too long (max 400)';
  return null;
}


function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; 
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}



// Signup (normal user)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const errMsg = validateSignup(req.body);
    if (errMsg) return res.status(400).json({ error: errMsg });
    const { name, email, password, address } = req.body;

    const [exists] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Email already in use' });

    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (name, email, password_hash, address, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, password_hash, address || null, 'USER']
    );

    const token = jwt.sign({ id: result.insertId, role: 'USER' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const [rows] = await pool.execute('SELECT id, password_hash, role, name FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- USER INFO ---------- */
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, name, email, role, address, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- STORE ROUTES ---------- */

// Create store (owner or admin)
app.post('/api/stores', requireAuth, requireRole('OWNER', 'ADMIN'), async (req, res) => {
  try {
    const { name, email, address } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email required' });

    const [exists] = await pool.execute('SELECT id FROM stores WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Store email already exists' });

    const ownerId = req.user.role === 'OWNER' ? req.user.id : (req.body.owner_id || null);
    const [result] = await pool.execute(
      'INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)',
      [name, email, address || null, ownerId]
    );
    const [store] = await pool.execute('SELECT * FROM stores WHERE id = ?', [result.insertId]);
    res.json(store[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// List stores with average rating, search, sort
app.get('/api/stores', async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const sort = req.query.sort || 'avg_desc'; 
    let where = '';
    const params = [];
    if (q) {
      where = 'WHERE s.name LIKE ? OR s.address LIKE ?';
      params.push(`%${q}%`, `%${q}%`);
    }

    // Build order
    let orderBy = 'ORDER BY avg_score DESC';
    if (sort === 'avg_asc') orderBy = 'ORDER BY avg_score ASC';
    if (sort === 'name_asc') orderBy = 'ORDER BY s.name ASC';
    if (sort === 'name_desc') orderBy = 'ORDER BY s.name DESC';

    const sql = `
      SELECT s.id, s.name, s.email, s.address, s.owner_id,
             IFNULL(ROUND(AVG(r.score),1), 0) as avg_score,
             COUNT(r.id) as total_ratings
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      ${where}
      GROUP BY s.id
      ${orderBy}
      LIMIT 200
    `;
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get store rating breakdown / results
app.get('/api/stores/:id/results', async (req, res) => {
  try {
    const storeId = req.params.id;
    const [avgRow] = await pool.execute('SELECT IFNULL(ROUND(AVG(score),1),0) AS average, COUNT(*) as count FROM ratings WHERE store_id = ?', [storeId]);
    const [counts] = await pool.execute(`
      SELECT score, COUNT(*) as count
      FROM ratings
      WHERE store_id = ?
      GROUP BY score
      ORDER BY score DESC
    `, [storeId]);
    res.json({ average: avgRow[0].average, total: avgRow[0].count, breakdown: counts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Rate a store (user). One rating per user per store; update if exists.
app.post('/api/stores/:id/rate', requireAuth, requireRole('USER', 'ADMIN'), async (req, res) => {
  try {
    const storeId = req.params.id;
    const score = parseInt(req.body.score, 10);
    if (!score || score < 1 || score > 5) return res.status(400).json({ error: 'Score must be 1-5' });

    // Prevent owners from rating their own stores
    const [storeRows] = await pool.execute('SELECT owner_id FROM stores WHERE id = ?', [storeId]);
    if (!storeRows.length) return res.status(404).json({ error: 'Store not found' });
    if (storeRows[0].owner_id === req.user.id) {
      return res.status(403).json({ error: 'Owners cannot rate their own stores' });
    }

    // Check if user already rated
    const [existing] = await pool.execute('SELECT id FROM ratings WHERE store_id = ? AND user_id = ?', [storeId, req.user.id]);
    if (existing.length) {
      await pool.execute('UPDATE ratings SET score = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?', [score, existing[0].id]);
    } else {
      await pool.execute('INSERT INTO ratings (store_id, user_id, score) VALUES (?, ?, ?)', [storeId, req.user.id, score]);
    }

    // return new average
    const [avgRow] = await pool.execute('SELECT IFNULL(ROUND(AVG(score),1) ,0) as avg_score, COUNT(*) as total FROM ratings WHERE store_id = ?', [storeId]);
    res.json({ avg: avgRow[0].avg_score, total: avgRow[0].total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- ADMIN ROUTES ---------- */

// Create user (admin only) - admin can create Admin, Owner, User
app.post('/api/admin/create-user', requireAuth, requireRole('ADMIN'), async (req, res) => {
  try {
    const { name, email, password, address, role } = req.body;
    
    const errMsg = validateSignup({ name, email, password, address });
    if (errMsg) return res.status(400).json({ error: errMsg });
    if (!['ADMIN', 'USER', 'OWNER'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const [exists] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Email exists' });

    const password_hash = await bcrypt.hash(password, 10);
    await pool.execute('INSERT INTO users (name, email, password_hash, address, role) VALUES (?, ?, ?, ?, ?)', [name, email, password_hash, address || null, role]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get users (admin)
app.get('/api/admin/users', requireAuth, requireRole('ADMIN'), async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 500');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- Start server ---------- */
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
