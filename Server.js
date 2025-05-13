const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Joi = require('joi');

const app = express();
app.use(express.json());
app.use(cors({ origin: ['http://10.0.2.2:56966', 'http://192.168.50.7:56966'] }));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Trip Schema
const tripSchema = new mongoose.Schema({
  source: String,
  destination: String,
  departureDate: String, // Format: DD-MMM-YYYY
  departureTime: String,
  duration: Number, // in minutes
  price: Number, // in VND
  busType: String, // e.g., Sleeper, Limousine, Standard, Minivan
  operator: String,
  operatorType: String, // e.g., Small, Large
  amenities: [String],
  rating: Number,
  availableSeats: Number,
  recommendation: String,
  sourceStation: {
    name: String,
    address: String,
  },
  destinationStation: {
    name: String,
    address: String,
  },
});
const Trip = mongoose.model('Trip', tripSchema);

// Validation Schema for User Registration
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('user', 'admin').default('user'),
});

// Validation Schema for Trip Search
const searchTripSchema = Joi.object({
  source: Joi.string().required(),
  destination: Joi.string().required(),
  date: Joi.string().required(), // Expected format: DD-MMM-YYYY
  passengers: Joi.number().integer().min(1).required(),
  maxBudget: Joi.number().optional(),
  preferredBusType: Joi.string().valid('Sleeper', 'Limousine', 'Standard', 'Minivan').optional(),
  operatorType: Joi.string().valid('Small', 'Large').optional(),
  maxResults: Joi.number().integer().min(1).default(5),
});

// Register Endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const { email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, role });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_secret_key', { expiresIn: '1h' });
    res.status(201).json({ success: true, token, userId: user._id });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_secret_key', { expiresIn: '1h' });
    res.json({ success: true, token, userId: user._id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Token Verification Endpoint
app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    res.json({ success: true, userId: user._id });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
});
app.post('/refresh-token', (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const newAccessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});
// Trip Search Endpoint
app.post('/api/trips/search', async (req, res) => {
  try {
    const { error } = searchTripSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message });

    const {
      source,
      destination,
      date,
      passengers,
      maxBudget,
      preferredBusType,
      operatorType,
      maxResults,
    } = req.body;

    // Build query
    let query = {
      source: new RegExp(source, 'i'), // Case-insensitive search
      destination: new RegExp(destination, 'i'),
      departureDate: date,
      availableSeats: { $gte: passengers },
    };

    // Optional filters
    if (maxBudget) {
      query.price = { $lte: maxBudget };
    }
    if (preferredBusType) {
      query.busType = preferredBusType;
    }
    if (operatorType) {
      query.operatorType = operatorType;
    }

    // Fetch trips from MongoDB
    const trips = await Trip.find(query)
      .limit(maxResults)
      .lean();

    res.json(trips);
  } catch (error) {
    console.error('Trip search error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://vanderspeare:009.00@cluster0.3ido8bh.mongodb.net/busData?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(3000, () => console.log('Server running on port 3000'));
  })
  .catch(err => console.error('MongoDB connection error:', err));
