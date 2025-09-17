// Combined server: static files + MongoDB + GridFS + simple auth (register/login) + profile/docs API
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// session (dev only). For production use connect-mongo or similar.
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// Configuration
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/pharmaportal';
const STATIC_DIR = path.join(__dirname, '..', 'styles');

// Serve static front-end
app.use('/', express.static(STATIC_DIR, { extensions: ['html', 'htm'] }));

// MongoDB + GridFS
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const conn = mongoose.connection;
let gfsBucket;
conn.once('open', () => {
  gfsBucket = new mongoose.mongo.GridFSBucket(conn.db, { bucketName: 'uploads' });
  console.log('MongoDB connected, GridFS ready');
});
conn.on('error', err => console.error('Mongo connection error:', err));

// Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const ProfileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  pharmacyName: String,
  licenseNumber: String,
  phone: String,
  address: String,
  lang: String,
  docs: {
    drugLicense: mongoose.Schema.Types.ObjectId,
    gstCertificate: mongoose.Schema.Types.ObjectId,
    pharmacistRegistration: mongoose.Schema.Types.ObjectId
  }
}, { timestamps: true });
const Profile = mongoose.model('Profile', ProfileSchema);

const upload = multer({ storage: multer.memoryStorage() });
const SALT_ROUNDS = 10;

// Helpers
async function createProfileForUser(userId) {
  let p = await Profile.findOne({ userId });
  if (!p) {
    p = new Profile({ userId, pharmacyName: '', licenseNumber: '', phone: '', address: '', lang: 'en', docs: {} });
    await p.save();
  }
  return p;
}

// Auth endpoints
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'email already registered' });
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = new User({ email, passwordHash: hash });
    await user.save();
    // create profile associated with this user
    await createProfileForUser(user._id);
    req.session.userId = user._id.toString();
    res.json({ ok: true, id: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    req.session.userId = user._id.toString();
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'logout failed' });
    res.json({ ok: true });
  });
});

// Middleware to require auth for profile actions
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'unauthenticated' });
  next();
}

// Profile endpoints (user-scoped)
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const profile = await createProfileForUser(req.session.userId);
    const docs = {};
    for (const k of ['drugLicense','gstCertificate','pharmacistRegistration']) {
      const id = profile.docs?.[k];
      docs[k] = id ? { id: id.toString(), url: `/api/files/${id}` } : null;
    }
    res.json({
      pharmacyName: profile.pharmacyName,
      licenseNumber: profile.licenseNumber,
      phone: profile.phone,
      address: profile.address,
      lang: profile.lang,
      docs
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/profile', requireAuth, async (req, res) => {
  try {
    const { pharmacyName, licenseNumber, phone, address, lang } = req.body || {};
    const profile = await createProfileForUser(req.session.userId);
    if (pharmacyName !== undefined) profile.pharmacyName = pharmacyName;
    if (licenseNumber !== undefined) profile.licenseNumber = licenseNumber;
    if (phone !== undefined) profile.phone = phone;
    if (address !== undefined) profile.address = address;
    if (lang !== undefined) profile.lang = lang;
    await profile.save();
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'save failed' });
  }
});

// Upload docs (user-scoped)
app.post('/api/profile/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!gfsBucket) return res.status(503).json({ error: 'storage not ready' });
    const docKey = req.query.doc;
    if (!['drugLicense','gstCertificate','pharmacistRegistration'].includes(docKey)) {
      return res.status(400).json({ error: 'invalid doc param' });
    }
    if (!req.file || !req.file.buffer) return res.status(400).json({ error: 'file required' });

    const filename = `${Date.now()}_${req.file.originalname}`;
    const uploadStream = gfsBucket.openUploadStream(filename, { metadata: { field: docKey, mimetype: req.file.mimetype } });
    uploadStream.end(req.file.buffer);

    uploadStream.on('finish', async (file) => {
      try {
        const profile = await createProfileForUser(req.session.userId);
        const oldId = profile.docs?.[docKey];
        if (oldId) {
          try { gfsBucket.delete(oldId); } catch (e) { /* ignore */ }
        }
        profile.docs = profile.docs || {};
        profile.docs[docKey] = file._id;
        await profile.save();
        res.json({ ok: true, fileId: file._id, filename: file.filename, url: `/api/files/${file._id}` });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'save failed' });
      }
    });

    uploadStream.on('error', (err) => {
      console.error('upload error', err);
      res.status(500).json({ error: 'upload failed' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Stream file by id
app.get('/api/files/:id', requireAuth, async (req, res) => {
  try {
    if (!gfsBucket) return res.status(503).send('storage not ready');
    const id = new mongoose.Types.ObjectId(req.params.id);
    const downloadStream = gfsBucket.openDownloadStream(id);
    downloadStream.on('error', (err) => {
      console.error(err);
      res.status(404).send('Not found');
    });
    downloadStream.pipe(res);
  } catch (err) {
    console.error(err);
    res.status(400).send('invalid id');
  }
});

// Expose main pages for convenience
app.get('/home', (req, res) => res.sendFile(path.join(STATIC_DIR, 'Home.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(STATIC_DIR, 'profile.html')));
app.get('/login', (req, res) => res.sendFile(path.join(STATIC_DIR, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(STATIC_DIR, 'register.html')));

// Start
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});