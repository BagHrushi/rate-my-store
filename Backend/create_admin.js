
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

(async () => {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
  });

  const name = "System Administrator Example Name"; 
  const email = "admin@example.com";
  const password = "Admin@1234"; 
  const address = "Admin address";

  const hash = await bcrypt.hash(password, 10);
  const [exists] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
  if (exists.length) {
    console.log('Admin already exists');
    return process.exit(0);
  }
  await pool.execute('INSERT INTO users (name, email, password_hash, address, role) VALUES (?, ?, ?, ?, ?)', [name, email, hash, address, 'ADMIN']);
  console.log('Admin created: ', email, 'password:', password);
  process.exit(0);
})();
