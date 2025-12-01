mkdir profitvault-server
cd profitvault-server
npm init -y
npm i express mongoose dotenv stripe jsonwebtoken bcryptjs body-parser nodemailer aws-sdk cors
# dev
npm i -D nodemon
PORT=4000
MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/profitvault?retryWrites=true&w=majority

JWT_SECRET=super_secret_jwt_key
ADMIN_USERNAME=you@domain.com
ADMIN_PASSWORD_HASH=$2a$10$...   # or create admin signup route

STRIPE_SECRET_KEY=sk_live_or_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

SENDGRID_API_KEY=SG.xxxxx
EMAIL_FROM=admin@yourdomain.com

AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name

APP_BASE_URL=https://your-frontend.com   # used for redirect after checkout
SERVER_BASE_URL=https://your-server.com  # use for webhook registration and presigned links
const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, index: true },
  description: String,
  price: { type: Number, required: true }, // in USD
  currency: { type: String, default: 'usd' },
  fileKey: String, // S3 object key or internal path
  category: String,
  thumbnail: String,
  oldPrice: Number,
  discount: Number,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Product', ProductSchema);
const mongoose = require('mongoose');

const SubSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Subscription', SubSchema);
const mongoose = require('mongoose');
const OrderSchema = new mongoose.Schema({
  stripeSessionId: String,
  productId: String,
  customerEmail: String,
  delivered: { type: Boolean, default: false },
  deliveredAt: Date,
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Order', OrderSchema);
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const Stripe = require('stripe');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const aws = require('aws-sdk');

const Product = require('./models/Product');
const Subscription = require('./models/Subscription');
const Order = require('./models/Order');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors());
app.use(bodyParser.json({
  verify: function (req, res, buf) {
    // keep rawBody for webhook verification
    req.rawBody = buf.toString();
  }
}));

// connect mongo
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(()=> console.log('Mongo connected'))
.catch(e=>{ console.error(e); process.exit(1) });

// AWS S3 setup
aws.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});
const s3 = new aws.S3();

// ---------- helpers ----------
function authAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (e) {
    res.status(401).send({ error: 'Invalid token' });
  }
}

// create signed download link (token)
function createDownloadToken(productId, orderId, expiresInSeconds = 60*60) {
  const payload = { productId, orderId };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: expiresInSeconds });
}

// ---------- API routes ----------

// public: list products
app.get('/api/products', async (req, res) => {
  const prods = await Product.find().sort({createdAt: -1});
  res.json(prods);
});

// public: get product
app.get('/api/products/:id', async (req, res) => {
  const p = await Product.findById(req.params.id);
  if (!p) return res.status(404).send({ error: 'Not found' });
  res.json(p);
});

// admin: create product (expects fileKey referencing S3 key)
app.post('/api/admin/products', authAdmin, async (req, res) => {
  const body = req.body;
  const p = await Product.create(body);
  res.json(p);
});

// subs endpoint (Save email + send welcome)
app.post('/api/subscribe', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send({ error: 'Email required' });
  try {
    await Subscription.updateOne({ email }, { $setOnInsert: { email } }, { upsert: true });
    // send welcome email via SendGrid or nodemailer
    // (example using nodemailer + SendGrid SMTP or SendGrid API)
    // For brevity: just return success
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send({ error: 'Server error' });
  }
});

// create Stripe Checkout session
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { productId, customerEmail } = req.body;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).send({ error: 'product not found' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: product.currency || 'usd',
          product_data: { name: product.title, description: product.description },
          unit_amount: Math.round(product.price * 100),
        },
        quantity: 1
      }],
      success_url: `${process.env.APP_BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_BASE_URL}/cancel`,
      metadata: { productId: String(product._id), email: customerEmail || '' },
      customer_email: customerEmail || undefined,
    });

    // Optionally save order record
    await Order.create({ stripeSessionId: session.id, productId: product._id, customerEmail: customerEmail || '' });

    res.json({ url: session.url, id: session.id });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: 'stripe error' });
  }
});

// stripe webhook to confirm payment and "deliver" file
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const productId = session.metadata?.productId;
    const order = await Order.findOne({ stripeSessionId: session.id });
    // generate a signed token and send email with download link
    if (productId && order) {
      const token = createDownloadToken(productId, order._id, 60*60*24*7); // 7 days token
      const downloadUrl = `${process.env.SERVER_BASE_URL}/api/download?token=${token}`;
      // send email with the downloadUrl using SendGrid / nodemailer
      // mark order delivered
      order.delivered = true;
      order.deliveredAt = new Date();
      await order.save();
      // (send mail code omitted here — integrate SendGrid)
      console.log('Deliver link:', downloadUrl);
    }
  }

  res.json({ received: true });
});

// protected download route (validates token and returns presigned S3 URL or streams file)
app.get('/api/download', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('token required');

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const { productId, orderId } = payload;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).send('product not found');

    if (!product.fileKey) return res.status(400).send('file not configured');

    // generate S3 presigned URL (valid short time)
    const params = {
      Bucket: process.env.S3_BUCKET,
      Key: product.fileKey,
      Expires: 60 // link valid for 60 seconds for direct download
    };
    const url = s3.getSignedUrl('getObject', params);
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.status(401).send('invalid or expired token');
  }
});

// admin login route (simple: compare env ADMIN_USERNAME + password)
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USERNAME) return res.status(401).send({ error: 'Invalid credentials' });

  // if you stored hashed password in env or DB, compare:
  // here we assume ADMIN_PASSWORD_HASH is bcrypt hash
  const ok = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).send({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// start
const port = process.env.PORT || 4000;
app.listen(port, ()=> console.log('Server listening on', port));
npm i @sendgrid/mail
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendDeliveryEmail(to, downloadUrl, productTitle) {
  const msg = {
    to,
    from: process.env.EMAIL_FROM,
    subject: `your purchase: ${productTitle} — Download link`,
    html: `<p>Thanks for your purchase. Click the link to download:</p>
           <p><a href="${downloadUrl}">${downloadUrl}</a></p>
           <p>Link expiry: 7 days.</p>`
  };
  await sgMail.send(msg);
}
// get-presigned (admin)
app.post('/api/admin/presign', authAdmin, async (req, res) => {
  const { filename, contentType } = req.body;
  const key = `products/${Date.now()}_${filename}`;
  const params = { Bucket: process.env.S3_BUCKET, Key: key, Expires: 60, ContentType: contentType };
  const url = s3.getSignedUrl('putObject', params);
  res.json({ url, key });
});
