const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const mongoose = require('mongoose');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY: Hardcoded JWT Secret
const JWT_SECRET = 'mysupersecretkey123';

// VULNERABILITY: MongoDB connection without authentication
mongoose.connect('mongodb://localhost/vulnerable_db', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// Define user schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // VULNERABILITY: Password stored in plaintext
  isAdmin: Boolean
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Setup file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/')
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname)
  }
});
const upload = multer({ storage: storage });

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// VULNERABILITY: No rate limiting on login attempts
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // VULNERABILITY: NoSQL Injection
    const user = await User.findOne({ username: username, password: password });
    
    if (user) {
      const token = jwt.sign({ id: user._id, username: user.username, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
      return res.json({ token });
    }
    
    res.status(401).json({ message: 'Invalid credentials' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// VULNERABILITY: Insecure Direct Object Reference
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  
  // No authentication check
  User.findById(userId)
    .then(user => {
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json(user);
    })
    .catch(err => res.status(500).json({ message: 'Server error' }));
});

// VULNERABILITY: Command Injection
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  
  if (!host) {
    return res.status(400).json({ message: 'Host parameter is required' });
  }
  
  // Dangerous command execution
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ result: stdout });
  });
});

// VULNERABILITY: Path Traversal
app.get('/api/read-file', (req, res) => {
  const filename = req.query.filename;
  
  if (!filename) {
    return res.status(400).json({ message: 'Filename parameter is required' });
  }
  
  // Dangerous file reading, allows path traversal
  fs.readFile(filename, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ content: data });
  });
});

// VULNERABILITY: Server-Side Template Injection
app.get('/api/template', (req, res) => {
  const name = req.query.name || '';
  
  // Insecure template rendering
  const template = `<h1>Hello, ${name}!</h1>`;
  const rendered = ejs.render(template);
  
  res.send(rendered);
});

// VULNERABILITY: Unrestricted File Upload
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }
  
  // No validation of file type or content
  res.json({ 
    message: 'File uploaded successfully',
    filename: req.file.filename
  });
});

// VULNERABILITY: Information Disclosure in Errors
app.use((err, req, res, next) => {
  console.error(err.stack);
  // Sending detailed error information to client
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});

// Function to create an initial admin user
async function createAdminUser() {
  const adminExists = await User.findOne({ username: 'admin' });
  
  if (!adminExists) {
    const admin = new User({
      username: 'admin',
      password: 'admin123', // VULNERABILITY: Weak password
      isAdmin: true
    });
    
    await admin.save();
    console.log('Admin user created');
  }
}

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  try {
    await createAdminUser();
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
}); 