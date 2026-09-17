const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, 'dsuka.sqlite');

// Hapus DB lama jika ada, untuk inisialisasi ulang yang bersih
if (fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
  console.log('Database lama dihapus.');
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error membuka database:', err.message);
    process.exit(1);
  }
  console.log('Berhasil terhubung ke database dsuka.sqlite.');
});

db.serialize(() => {
  // 1. Buat Tabel Admins
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )`);

  // 2. Buat Tabel Menu Items
  db.run(`CREATE TABLE IF NOT EXISTS menu_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price INTEGER NOT NULL,
    image_path TEXT,
    is_favorite BOOLEAN DEFAULT 0
  )`);

  // 3. Buat Tabel Reservations
  db.run(`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT NOT NULL,
    wa_number TEXT NOT NULL,
    res_date DATE NOT NULL,
    res_time TIME NOT NULL,
    pax INTEGER NOT NULL,
    seating TEXT NOT NULL,
    notes TEXT,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // 4. Buat Tabel Orders
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT NOT NULL,
    wa_number TEXT NOT NULL,
    total_price INTEGER NOT NULL,
    notes TEXT,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // 5. Buat Tabel Order Items
  db.run(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    menu_name TEXT NOT NULL,
    qty INTEGER NOT NULL,
    price INTEGER NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id)
  )`);

  console.log('Semua tabel berhasil dibuat.');

  // Seeding: Admin default
  // Catatan: Untuk produksi, gunakan bcrypt. Ini sekadar simulasi.
  db.run(`INSERT INTO admins (username, password_hash) VALUES ('admin', 'password123')`);
  
  // Seeding: Menu dummy sesuai index.html
  const menus = [
    ['Chiken Karage Sambal Matah', 'Makanan', 18000, 'assets/menu-2.jpeg', 0],
    ['Telur Kribo Tahu', 'Makanan', 17000, 'assets/menu-3.jpeg', 0],
    ['Ayam Geprek', 'Makanan', 18500, 'assets/menu-4.jpeg', 1],
    ['Sate Katsu', 'Makanan', 18000, 'assets/menu-5.jpeg', 0],
    ['Tahu Cabai Garam', 'Snack', 15000, 'assets/menu-6.jpeg', 0],
    ['Moji Melon', 'Minuman', 15000, 'assets/menu-17.jpeg', 1],
    ['Pan Brownies Kecil', 'Dessert', 16500, 'assets/menu-10.jpeg', 0]
  ];

  const stmt = db.prepare(`INSERT INTO menu_items (name, category, price, image_path, is_favorite) VALUES (?, ?, ?, ?, ?)`);
  menus.forEach(m => stmt.run(m));
  stmt.finalize();

  console.log('Seeding data awal berhasil (Admin dan beberapa menu).');
});

db.close((err) => {
  if (err) {
    console.error('Error menutup database:', err.message);
  } else {
    console.log('Database berhasil disiapkan dan ditutup.');
  }
});
