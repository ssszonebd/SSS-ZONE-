require('dotenv').config();
const express=require('express'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),cookieParser=require('cookie-parser'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),multer=require('multer'),path=require('path'),fs=require('fs'),crypto=require('crypto');
const{JWT_SECRET}=process.env,PORT=process.env.PORT||3000;
if(!JWT_SECRET||JWT_SECRET.length<32){console.error('Set JWT_SECRET (32+ chars) in .env');process.exit(1)}
const db=require('./db'),app=express(),UP=path.join(__dirname,'uploads');fs.mkdirSync(UP,{recursive:true});
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],imgSrc:["'self'",'data:'],scriptSrc:["'self'"],styleSrc:["'self'"],objectSrc:["'none'"]}}}));
app.use(express.json({limit:'100kb'}),cookieParser());
const fail=(m,c=400)=>{const e=new Error(m);e.status=c;throw e};
const int=(v,min=0)=>{const n=Number(v);if(!Number.isInteger(n)||n<min||n>1e9)fail('Invalid number');return n};
const str=(v,max=200,req=true)=>{v=String(v??'').trim();if(req&&!v)fail('Please fill all required fields');if(v.length>max)fail('Text too long');return v};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
const slugify=n=>n.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')+'-'+crypto.randomBytes(2).toString('hex');
const PHONE=/^(\+?88)?01[3-9]\d{8}$/,lim=rateLimit({windowMs:15*6e4,limit:30});
// ---- auth (JWT in httpOnly, SameSite=Strict cookie) ----
const pub=u=>({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role});
const issue=(s,u)=>s.cookie('t',jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:6048e5});
const auth=(q,s,n)=>{try{q.user=db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(q.cookies.t,JWT_SECRET).id);if(!q.user)throw 0}catch{return s.status(401).json({error:'Please log in'})}n()};
const admin=(q,s,n)=>auth(q,s,()=>q.user.role==='admin'?n():s.status(403).json({error:'Forbidden'}));
app.post('/api/register',lim,(q,s)=>{const b=q.body||{},name=str(b.name,80),email=str(b.email,120).toLowerCase(),phone=str(b.phone,16);
 if(!/^\S+@\S+\.\S+$/.test(email))fail('Invalid email');if(!PHONE.test(phone))fail('Enter a valid Bangladeshi mobile number');
 if(String(b.password||'').length<8)fail('Password must be at least 8 characters');
 if(db.prepare('SELECT 1 FROM users WHERE email=?').get(email))fail('Email already registered',409);
 const id=db.prepare('INSERT INTO users(name,email,phone,hash) VALUES(?,?,?,?)').run(name,email,phone,bcrypt.hashSync(b.password,12)).lastInsertRowid;
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(id);issue(s,u);s.status(201).json(pub(u))});
app.post('/api/login',lim,(q,s)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(q.body?.email||'').toLowerCase());
 if(!u||!bcrypt.compareSync(String(q.body.password||''),u.hash))fail('Wrong email or password',401);issue(s,u);s.json(pub(u))});
app.post('/api/logout',(q,s)=>s.clearCookie('t').json({ok:1}));
app.get('/api/me',(q,s)=>{try{const u=db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(q.cookies.t,JWT_SECRET).id);s.json(u?pub(u):null)}catch{s.json(null)}});
// ---- catalogue ----
const SORT={new:'p.id DESC',low:'eff ASC',high:'eff DESC',name:'p.name ASC'};
const COLS='p.id,p.name,p.slug,p.price,p.sale_price,COALESCE(p.sale_price,p.price) eff,p.stock,p.image';
app.get('/api/categories',(q,s)=>s.json(db.prepare('SELECT * FROM categories ORDER BY name').all()));
app.get('/api/products',(q,s)=>{const{q:term,category,sort,min,max,ids}=q.query,w=['p.active=1'],a=[];
 if(term){w.push('(p.name LIKE ? OR p.description LIKE ?)');a.push(`%${term}%`,`%${term}%`)}
 if(category){w.push('c.slug=?');a.push(String(category))}
 if(min){w.push('COALESCE(p.sale_price,p.price)>=?');a.push(int(min))}
 if(max){w.push('COALESCE(p.sale_price,p.price)<=?');a.push(int(max))}
 if(ids){const l=String(ids).split(',').slice(0,50).map(Number).filter(Number.isInteger);w.push(`p.id IN (${l.map(()=>'?').join()||'NULL'})`);a.push(...l)}
 s.json(db.prepare(`SELECT ${COLS},c.name cat FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE ${w.join(' AND ')} ORDER BY ${SORT[sort]||SORT.new} LIMIT 100`).all(...a))});
const one=slug=>db.prepare('SELECT p.*,COALESCE(p.sale_price,p.price) eff,c.name cat FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.slug=? AND p.active=1').get(slug);
app.get('/api/products/:slug',(q,s)=>{const p=one(q.params.slug);if(!p)fail('Product not found',404);s.json(p)});
app.get('/api/wishlist',auth,(q,s)=>s.json(db.prepare(`SELECT ${COLS} FROM wishlist w JOIN products p ON p.id=w.product_id WHERE w.user_id=? AND p.active=1`).all(q.user.id)));
app.post('/api/wishlist/:id',auth,(q,s)=>{db.prepare('INSERT OR IGNORE INTO wishlist VALUES(?,?)').run(q.user.id,int(q.params.id,1));s.json({ok:1})});
app.delete('/api/wishlist/:id',auth,(q,s)=>{db.prepare('DELETE FROM wishlist WHERE user_id=? AND product_id=?').run(q.user.id,int(q.params.id,1));s.json({ok:1})});
// ---- coupons & orders (all prices computed server-side from the DB) ----
function discount(code,sub){if(!code)return{d:0};const c=db.prepare('SELECT * FROM coupons WHERE code=? AND active=1').get(String(code).trim().toUpperCase());
 if(!c||(c.expires&&c.expires<new Date().toISOString().slice(0,10))||(c.max_uses&&c.used>=c.max_uses))fail('Invalid or expired coupon');
 if(sub<c.min_total)fail(`Minimum order ৳${c.min_total} for this coupon`);
 return{c,d:Math.min(sub,c.type==='percent'?Math.floor(sub*c.value/100):c.value)}}
app.post('/api/coupons/check',lim,(q,s)=>s.json({discount:discount(q.body?.code,int(q.body?.subtotal)).d}));
const SHIP=d=>/^dhaka$/i.test(d)?60:120;
app.post('/api/orders',auth,(q,s)=>{const b=q.body||{};
 if(b.payment!=='cod')return s.status(501).json({error:'bKash, Nagad and SSLCommerz are not configured yet. Please choose Cash on Delivery.'});
 if(!Array.isArray(b.items)||!b.items.length||b.items.length>50)fail('Your cart is empty');
 const a=b.address||{},addr={name:str(a.name,80),phone:str(a.phone,16),division:str(a.division,40),district:str(a.district,40),upazila:str(a.upazila,60),line:str(a.line,200),postcode:str(a.postcode,4,false)};
 if(!PHONE.test(addr.phone))fail('Enter a valid Bangladeshi mobile number');
 const code='BD'+Date.now().toString(36).toUpperCase()+crypto.randomBytes(2).toString('hex').toUpperCase();
 const total=db.transaction(()=>{let sub=0;const lines=[];
  for(const it of b.items){const id=int(it.id,1),qty=int(it.qty,1);if(qty>20)fail('Maximum 20 per item');
   const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(id);if(!p)fail('A product in your cart is no longer available');
   if(!db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(qty,id,qty).changes)fail(`Not enough stock for ${p.name}`,409);
   const price=p.sale_price??p.price;sub+=price*qty;lines.push([p.id,p.name,price,qty])}
  const{c,d}=discount(b.coupon,sub),ship=SHIP(addr.district),t=sub-d+ship;
  const oid=db.prepare('INSERT INTO orders(code,user_id,subtotal,discount,shipping,total,coupon,payment,addr) VALUES(?,?,?,?,?,?,?,?,?)').run(code,q.user.id,sub,d,ship,t,c?.code||null,'cod',JSON.stringify(addr)).lastInsertRowid;
  for(const l of lines)db.prepare('INSERT INTO order_items VALUES(?,?,?,?,?)').run(oid,...l);
  if(c)db.prepare('UPDATE coupons SET used=used+1 WHERE id=?').run(c.id);
  return t})();
 s.status(201).json({code,total})});
const withItems=o=>({...o,addr:JSON.parse(o.addr),items:db.prepare('SELECT name,price,qty FROM order_items WHERE order_id=?').all(o.id)});
app.get('/api/orders',auth,(q,s)=>s.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(q.user.id).map(withItems)));
app.get('/api/track',lim,(q,s)=>{const o=db.prepare("SELECT * FROM orders WHERE code=? AND json_extract(addr,'$.phone')=?").get(str(q.query.code,30).toUpperCase(),str(q.query.phone,16));
 if(!o)fail('No order found for that code and phone',404);const w=withItems(o);s.json({code:w.code,status:w.status,payment:w.payment,payment_status:w.payment_status,total:w.total,created:w.created,items:w.items})});
// ---- admin ----
const IMG={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'};
const upload=multer({storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,crypto.randomBytes(8).toString('hex')+IMG[f.mimetype])}),limits:{fileSize:2e6},fileFilter:(q,f,cb)=>cb(null,!!IMG[f.mimetype])});
const pf=b=>{const f={category_id:b.category_id?int(b.category_id,1):null,name:str(b.name,150),description:str(b.description,3000,false),price:int(b.price),sale_price:b.sale_price?int(b.sale_price):null,stock:int(b.stock),active:b.active==='0'?0:1};
 if(f.sale_price!==null&&f.sale_price>f.price)fail('Sale price cannot exceed price');return f};
app.get('/api/admin/products',admin,(q,s)=>s.json(db.prepare('SELECT p.*,c.name cat FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.id DESC').all()));
app.post('/api/admin/products',admin,upload.single('image'),(q,s)=>{const f=pf(q.body);
 db.prepare('INSERT INTO products(category_id,name,slug,description,price,sale_price,stock,image,active) VALUES(?,?,?,?,?,?,?,?,?)').run(f.category_id,f.name,slugify(f.name),f.description,f.price,f.sale_price,f.stock,q.file?'/uploads/'+q.file.filename:null,f.active);s.status(201).json({ok:1})});
app.put('/api/admin/products/:id',admin,upload.single('image'),(q,s)=>{const f=pf(q.body);
 db.prepare('UPDATE products SET category_id=?,name=?,description=?,price=?,sale_price=?,stock=?,active=?,image=COALESCE(?,image) WHERE id=?').run(f.category_id,f.name,f.description,f.price,f.sale_price,f.stock,f.active,q.file?'/uploads/'+q.file.filename:null,int(q.params.id,1));s.json({ok:1})});
app.delete('/api/admin/products/:id',admin,(q,s)=>{const id=int(q.params.id,1);db.prepare('DELETE FROM wishlist WHERE product_id=?').run(id);db.prepare('DELETE FROM products WHERE id=?').run(id);s.json({ok:1})});
app.post('/api/admin/categories',admin,(q,s)=>{const n=str(q.body.name,60);db.prepare('INSERT INTO categories(name,slug) VALUES(?,?)').run(n,slugify(n));s.status(201).json({ok:1})});
app.delete('/api/admin/categories/:id',admin,(q,s)=>{db.prepare('DELETE FROM categories WHERE id=?').run(int(q.params.id,1));s.json({ok:1})});
app.get('/api/admin/orders',admin,(q,s)=>s.json(db.prepare('SELECT o.*,u.name cust FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200').all().map(withItems)));
const ST=['pending','confirmed','shipped','delivered','cancelled'];
app.put('/api/admin/orders/:id',admin,(q,s)=>{const o=db.prepare('SELECT * FROM orders WHERE id=?').get(int(q.params.id,1)),st=q.body.status;
 if(!o)fail('Order not found',404);if(!ST.includes(st))fail('Invalid status');if(o.status==='cancelled'&&st!=='cancelled')fail('Cancelled orders cannot be reopened');
 db.transaction(()=>{if(st==='cancelled'&&o.status!=='cancelled')for(const i of db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id))db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty,i.product_id);
  db.prepare('UPDATE orders SET status=?,payment_status=? WHERE id=?').run(st,st==='delivered'&&o.payment==='cod'?'paid':o.payment_status,o.id)})();s.json({ok:1})});
app.get('/api/admin/customers',admin,(q,s)=>s.json(db.prepare("SELECT id,name,email,phone,created,(SELECT COUNT(*) FROM orders WHERE user_id=users.id) orders FROM users WHERE role='customer' ORDER BY id DESC").all()));
app.get('/api/admin/coupons',admin,(q,s)=>s.json(db.prepare('SELECT * FROM coupons ORDER BY id DESC').all()));
app.post('/api/admin/coupons',admin,(q,s)=>{const b=q.body;if(!['percent','fixed'].includes(b.type))fail('Invalid type');const v=int(b.value,1);if(b.type==='percent'&&v>100)fail('Percent max 100');
 db.prepare('INSERT INTO coupons(code,type,value,min_total,max_uses,expires) VALUES(?,?,?,?,?,?)').run(str(b.code,30).toUpperCase(),b.type,v,int(b.min_total||0),b.max_uses?int(b.max_uses,1):null,b.expires||null);s.status(201).json({ok:1})});
app.delete('/api/admin/coupons/:id',admin,(q,s)=>{db.prepare('DELETE FROM coupons WHERE id=?').run(int(q.params.id,1));s.json({ok:1})});
app.get('/api/admin/stats',admin,(q,s)=>{const g=x=>db.prepare(x).get();s.json({revenue:g("SELECT COALESCE(SUM(total),0) n FROM orders WHERE status!='cancelled'").n,orders:g('SELECT COUNT(*) n FROM orders').n,pending:g("SELECT COUNT(*) n FROM orders WHERE status='pending'").n,customers:g("SELECT COUNT(*) n FROM users WHERE role='customer'").n,
 low:db.prepare('SELECT name,stock FROM products WHERE stock<=5 AND active=1 ORDER BY stock').all(),days:db.prepare("SELECT date(created) d,SUM(total) t FROM orders WHERE status!='cancelled' AND created>=date('now','-6 day') GROUP BY d ORDER BY d").all()})});
// ---- pages & SEO (server injects per-page meta so crawlers see it) ----
const tpl=fs.readFileSync(path.join(__dirname,'public/index.html'),'utf8');
const DESC='Shop online in Bangladesh. Cash on Delivery across all 64 districts.';
app.get('/p/:slug',(q,s)=>{const p=one(q.params.slug);if(!p)return s.status(404).send(tpl.replace('<!--META-->','<title>Not found</title>'));
 s.send(tpl.replace('<!--META-->',`<title>${esc(p.name)} | SSS ZONE</title><meta name="description" content="${esc(p.description.slice(0,155)||DESC)}"><meta property="og:title" content="${esc(p.name)}">${p.image?`<meta property="og:image" content="${esc(p.image)}">`:''}<script type="application/ld+json">${JSON.stringify({'@context':'https://schema.org','@type':'Product',name:p.name,offers:{'@type':'Offer',priceCurrency:'BDT',price:p.eff,availability:p.stock>0?'https://schema.org/InStock':'https://schema.org/OutOfStock'}}).replace(/</g,'\\u003c')}</script>`))});
app.get(['/','/cart','/checkout','/login','/account','/track'],(q,s)=>s.send(tpl.replace('<!--META-->',`<title>SSS ZONE – Fashion for Everyone</title><meta name="description" content="${DESC}">`)));
app.get('/robots.txt',(q,s)=>s.type('text').send('User-agent: *\nDisallow: /admin\nDisallow: /api/\nSitemap: '+(process.env.SITE_URL||'')+'/sitemap.xml'));
app.get('/sitemap.xml',(q,s)=>{const b=process.env.SITE_URL||`${q.protocol}://${q.get('host')}`;s.type('xml').send(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${esc(b)}/</loc></url>${db.prepare('SELECT slug FROM products WHERE active=1').all().map(p=>`<url><loc>${esc(b)}/p/${p.slug}</loc></url>`).join('')}</urlset>`)});
app.get('/admin',(q,s)=>s.sendFile(path.join(__dirname,'public/admin.html')));
app.use('/uploads',express.static(UP,{maxAge:'7d'}));
app.use(express.static(path.join(__dirname,'public'),{index:false}));
app.use('/api',(q,s)=>s.status(404).json({error:'Not found'}));
app.use((e,q,s,n)=>{if(e.status)return s.status(e.status).json({error:e.message});if(e.name==='MulterError')return s.status(400).json({error:'Image must be JPG/PNG/WebP under 2 MB'});
 if(String(e.code).startsWith('SQLITE_CONSTRAINT'))return s.status(409).json({error:'Already exists or invalid reference'});console.error(e);s.status(500).json({error:'Server error'})});
app.listen(PORT,()=>console.log('Shop running on http://localhost:'+PORT));
