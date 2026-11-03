const Database=require('better-sqlite3'),bcrypt=require('bcryptjs');
const db=new Database(process.env.DB_PATH||'shop.db');
db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,phone TEXT NOT NULL,hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,slug TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,name TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,description TEXT DEFAULT '',price INTEGER NOT NULL CHECK(price>=0),sale_price INTEGER,stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0),image TEXT,active INTEGER DEFAULT 1,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS wishlist(user_id INTEGER,product_id INTEGER,PRIMARY KEY(user_id,product_id));
CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,type TEXT CHECK(type IN('percent','fixed')),value INTEGER NOT NULL,min_total INTEGER DEFAULT 0,max_uses INTEGER,used INTEGER DEFAULT 0,expires TEXT,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,user_id INTEGER REFERENCES users(id),subtotal INTEGER,discount INTEGER,shipping INTEGER,total INTEGER,coupon TEXT,payment TEXT,payment_status TEXT DEFAULT 'unpaid',status TEXT DEFAULT 'pending',addr TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER REFERENCES orders(id),product_id INTEGER,name TEXT,price INTEGER,qty INTEGER);
`);
if(!db.prepare('SELECT 1 FROM categories').get())for(const n of['Men’s Clothing','Women’s Clothing','Kids’ Clothing'])db.prepare('INSERT INTO categories(name,slug) VALUES(?,?)').run(n,n.toLowerCase().replace(/[^a-z0-9]+/g,'-'));
const{ADMIN_EMAIL:e,ADMIN_PASSWORD:p}=process.env;
if(e&&p&&p.length>=10&&!db.prepare("SELECT 1 FROM users WHERE role='admin'").get())db.prepare("INSERT INTO users(name,email,phone,hash,role) VALUES('Admin',?,'01700000000',?,'admin')").run(e.toLowerCase(),bcrypt.hashSync(p,12));
module.exports=db;
