# SSS ZONE — Fashion Store (Node.js + Express + SQLite)

## Run locally
1. Install Node 18+. `cd bd-shop && npm install`
2. `cp .env.example .env`, then set `JWT_SECRET` (32+ random chars), `ADMIN_EMAIL`, `ADMIN_PASSWORD` (10+ chars).
3. `npm start` → store at http://localhost:3000, admin at http://localhost:3000/admin
   (the first admin is created from .env on first start; change the password afterwards and remove it from .env).
4. In Admin: manage Men’s Clothing, Women’s Clothing and Kids’ Clothing categories → add products (price in ৳, stock, image) → create coupons.

## Structure
- `server.js` – API, auth, validation, order logic, SEO meta/sitemap. `db.js` – schema + seed.
- `public/` – storefront (`app.js`), admin (`admin.js`), shared `style.css`. Edit text/colours in `style.css` (`:root`) and `index.html`.
- Uploaded images go to `uploads/` (back this folder up).

## Security as built
bcrypt passwords; JWT in httpOnly SameSite=Strict cookie (Secure in production); admin role re-checked in DB on every admin call; prices, stock, coupons and delivery fee computed only on the server inside a DB transaction (stock cannot go negative); parameterised SQL; helmet + CSP; rate-limited login/register/track; uploads limited to JPG/PNG/WebP ≤2 MB; no secrets in frontend.

## Payments — NOT configured
Only **Cash on Delivery** works. bKash / Nagad / SSLCommerz are shown as disabled and the server rejects them (HTTP 501); no payment is ever marked "paid" except COD when admin marks Delivered. To add one: create a payment route that (1) creates the order as `payment_status='unpaid'`, (2) starts a session with the gateway **server-side** using sandbox keys from `.env`, (3) marks paid only after server-to-server verification (SSLCommerz IPN + validation API; bKash tokenized "execute/query"; Nagad verify). Never trust the browser redirect.

## Deploy (VPS, e.g. Ubuntu)
`npm ci --omit=dev`, set `NODE_ENV=production`, run with `pm2 start server.js`, put Nginx in front with HTTPS (Let's Encrypt) proxying to port 3000, set `SITE_URL`. SQLite needs a persistent disk (not serverless); back up `shop.db` and `uploads/` daily. For multiple servers/high traffic, migrate to PostgreSQL and S3-style image storage.

## Known gaps
Password reset / email notifications, product reviews, multi-image galleries, order-item invoice printing, wishlist removal button, automated tests, and a CSRF token (SameSite=Strict cookies are the current defence).
