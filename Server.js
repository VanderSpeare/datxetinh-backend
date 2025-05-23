const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: ['*'],
  credentials: true,
}));

// Logging setup
const logger = {
  info: (msg) => console.log(`INFO: ${msg}`),
  warning: (msg) => console.warn(`WARNING: ${msg}`),
  error: (msg) => console.error(`ERROR: ${msg}`),
  debug: (msg) => console.log(`DEBUG: ${msg}`),
};

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  name: { type: String },
  phone: { type: String },
});
const User = mongoose.model('User', userSchema);

// Refresh Token Schema
const refreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
});
const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

// Trip Schema
const tripSchema = new mongoose.Schema({
  startingPoint: String,
  destination: String,
  departureDate: String, // Format: DD-MMM-YYYY
  departureTime: String,
  duration: Number, // in minutes
  price: Number, // in thousands VND (e.g., 250 for 250,000 VND)
  busType: String, // e.g., Sleeper, Limousine, Standard, Minivan
  operator: String,
  operatorType: String, // e.g., Small, Medium, Large
  amenities: [String],
  rating: Number,
  rankScore: Number,
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
  sourceStationId: String,
  destinationStationId: String,
});
const Trip = mongoose.model('Trip', tripSchema, 'buses');

const bookingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tripId: { type: mongoose.Schema.Types.ObjectId, ref: 'Trip', required: true },
  seats: [Number],
  createdAt: { type: Date, default: Date.now },
  paymentStatus: { type: String, default: 'pending', enum: ['pending', 'paid', 'failed'] },
  paymentTransactionNo: { type: String },
});
const Booking = mongoose.model('Booking', bookingSchema);
// Validation Schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('user', 'admin').default('user'),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const searchTripSchema = Joi.object({
  source: Joi.string().allow('', null), // Không bắt buộc
  destination: Joi.string().required(), // Bắt buộc
  date: Joi.string().allow('', null), // Không sử dụng
  passengers: Joi.number().integer().min(1).default(1),
  maxBudget: Joi.number().min(0).allow(null),
  preferredBusType: Joi.string().allow(null),
  operatorType: Joi.string().allow(null),
  maxResults: Joi.number().integer().min(1).default(5),
});

const bookingSchemaValidator = Joi.object({
  userId: Joi.string().required(),
  tripId: Joi.string().required(),
  seats: Joi.array().items(Joi.number()).required(),
});

// Environment Variables
const JWT_SECRET = process.env.JWT_SECRET || 'my_very_secure_secret_2025';
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://vanderspeare:009.00@cluster0.3ido8bh.mongodb.net/busData?retryWrites=true&w=majority';

// Middleware to verify token
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      logger.warning('No token provided');
      return res.status(401).json({ success: false, message: 'Không có token được cung cấp' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      logger.warning(`User not found for userId: ${decoded.userId}`);
      return res.status(401).json({ success: false, message: 'Không tìm thấy người dùng' });
    }
    req.userId = decoded.userId;
    logger.info(`Verified userId: ${req.userId}`);
    next();
  } catch (error) {
    logger.error(`Token verification error: ${error}`);
    res.status(401).json({ success: false, message: 'Token không hợp lệ hoặc đã hết hạn' });
  }
};

// Register Endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) {
      logger.warning(`Validation error in register: ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warning(`Email already exists: ${email}`);
      return res.status(400).json({ success: false, message: 'Email đã tồn tại' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, role });
    await user.save();

    const accessToken = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' });

    await new RefreshToken({
      token: refreshToken,
      userId: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    }).save();

    logger.info(`User registered: ${email}`);
    res.status(201).json({ success: true, token: accessToken, refreshToken, userId: user._id.toString() });
  } catch (error) {
    logger.error(`Register error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      logger.warning(`Validation error in login: ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      logger.warning(`Invalid credentials for email: ${email}`);
      return res.status(400).json({ success: false, message: 'Thông tin đăng nhập không hợp lệ' });
    }

    const accessToken = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' });

    await new RefreshToken({
      token: refreshToken,
      userId: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    }).save();

    logger.info(`User logged in: ${email}`);
    res.json({ success: true, token: accessToken, refreshToken, userId: user._id.toString() });
  } catch (error) {
    logger.error(`Login error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Refresh Token Endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warning('No refresh token provided');
      return res.status(401).json({ success: false, message: 'Không có refresh token được cung cấp' });
    }

    const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
      logger.warning('Invalid or expired refresh token');
      return res.status(403).json({ success: false, message: 'Refresh token không hợp lệ hoặc đã hết hạn' });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      logger.warning(`User not found for userId: ${decoded.userId}`);
      return res.status(403).json({ success: false, message: 'Không tìm thấy người dùng' });
    }

    const newAccessToken = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    logger.info(`Token refreshed for userId: ${user._id}`);
    res.json({ success: true, token: newAccessToken });
  } catch (error) {
    logger.error(`Refresh token error: ${error}`);
    res.status(403).json({ success: false, message: 'Refresh token không hợp lệ' });
  }
});

// Token Verification Endpoint
app.get('/api/auth/verify', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    logger.info(`Token verified for userId: ${req.userId}`);
    res.json({ success: true, userId: user._id.toString() });
  } catch (error) {
    logger.error(`Token verification error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Trip Search Endpoint (POST)
app.post('/api/trips/search', async (req, res) => {
  try {
    const { error } = searchTripSchema.validate(req.body);
    if (error) {
      logger.warning(`Validation error in trip search: ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { source, destination, maxResults } = req.body;

    // Validate required field
    if (!destination) {
      logger.warning('Destination is required in trip search');
      return res.status(400).json({ success: false, message: 'Vui lòng cung cấp địa điểm đến (destination).' });
    }

    // Build MongoDB query with raw input values
    let query = { $and: [] };
    if (source) {
      query.$and.push({ startingPoint: new RegExp(source, 'i') });
    }
    query.$and.push({ destination: new RegExp(destination, 'i') });

    logger.info(`MongoDB query: ${JSON.stringify(query)}`);

    let trips = await Trip.find(query)
      .sort({ rankScore: -1, price: 1 })
      .limit(parseInt(maxResults) || 5)
      .lean();

    let recommendations = trips.map(trip => ({
      id: trip._id.toString(),
      source: trip.startingPoint || 'N/A',
      destination: trip.destination || 'N/A',
      source_station_id: trip.sourceStationId || '',
      destination_station_id: trip.destinationStationId || '',
      source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
      destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
      source_station_address: trip.sourceStation?.address || '',
      destination_station_address: trip.destinationStation?.address || '',
      departure_time: trip.departureTime || 'N/A',
      departure_date: trip.departureDate || 'N/A',
      price: Number(trip.price || 0),
      duration: Number(trip.duration || 0),
      bus_type: trip.busType || 'Standard',
      operator: trip.operator || 'N/A',
      operator_type: trip.operatorType || 'Small',
      amenities: trip.amenities || [],
      rating: Number(trip.rating || 0),
      rank_score: Number(trip.rankScore || trip.rating || 0),
      available_seats: Number(trip.availableSeats || 30),
      recommendation: trip.recommendation || 'Phù hợp với tiêu chí tìm kiếm',
    }));

    logger.info(`Found ${recommendations.length} trips`);

    // Fallback query if no results (only destination)
    if (!recommendations.length) {
      let fallbackQuery = { $and: [] };
      if (source) {
        fallbackQuery.$and.push({ startingPoint: new RegExp(source, 'i') });
      }
      fallbackQuery.$and.push({ destination: new RegExp(destination, 'i') });

      logger.info(`Fallback query: ${JSON.stringify(fallbackQuery)}`);
      trips = await Trip.find(fallbackQuery)
        .sort({ rankScore: -1, price: 1 })
        .limit(parseInt(maxResults) || 5)
        .lean();

      recommendations = trips.map(trip => ({
        id: trip._id.toString(),
        source: trip.startingPoint || 'N/A',
        destination: trip.destination || 'N/A',
        source_station_id: trip.sourceStationId || '',
        destination_station_id: trip.destinationStationId || '',
        source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
        destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
        source_station_address: trip.sourceStation?.address || '',
        destination_station_address: trip.destinationStation?.address || '',
        departure_time: trip.departureTime || 'N/A',
        departure_date: trip.departureDate || 'N/A',
        price: Number(trip.price || 0),
        duration: Number(trip.duration || 0),
        bus_type: trip.busType || 'Standard',
        operator: trip.operator || 'N/A',
        operator_type: trip.operatorType || 'Small',
        amenities: trip.amenities || [],
        rating: Number(trip.rating || 0),
        rank_score: Number(trip.rankScore || trip.rating || 0),
        available_seats: Number(trip.availableSeats || 30),
        recommendation: 'Kết quả dự phòng dựa trên tiêu chí tối thiểu.',
      }));
      logger.info(`Fallback found ${recommendations.length} trips`);
    }

    if (!recommendations.length) {
      logger.warning(`No trips found for request: ${JSON.stringify(req.body)}`);
      return res.status(404).json({
        success: false,
        message: `Không tìm thấy chuyến đi phù hợp cho điểm đi: ${source || 'bất kỳ'}, điểm đến: ${destination}.`,
      });
    }

    logger.info(`Returning ${recommendations.length} trip recommendations`);
    res.json(recommendations);
  } catch (error) {
    logger.error(`Trip search error: ${error}`);
    res.status(500).json({ success: false, message: `Lỗi server: ${error.message}` });
  }
});
// Trip Search Endpoint (GET)
app.get('/api/trips/search', async (req, res) => {
  try {
    const { error } = searchTripSchema.validate(req.query);
    if (error) {
      logger.warning(`Validation error in trip search (GET): ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { source, destination, maxResults } = req.query;

    // Validate required field
    if (!destination) {
      logger.warning('Destination is required in trip search (GET)');
      return res.status(400).json({ success: false, message: 'Vui lòng cung cấp địa điểm đến (destination).' });
    }

    // Build MongoDB query with raw input values
    let query = { $and: [] };
    if (source) {
      query.$and.push({ startingPoint: new RegExp(source, 'i') });
    }
    query.$and.push({ destination: new RegExp(destination, 'i') });

    logger.info(`MongoDB query (GET): ${JSON.stringify(query)}`);

    let trips = await Trip.find(query)
      .sort({ rankScore: -1, price: 1 })
      .limit(parseInt(maxResults) || 5)
      .lean();

    let recommendations = trips.map(trip => ({
      id: trip._id.toString(),
      source: trip.startingPoint || 'N/A',
      destination: trip.destination || 'N/A',
      source_station_id: trip.sourceStationId || '',
      destination_station_id: trip.destinationStationId || '',
      source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
      destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
      source_station_address: trip.sourceStation?.address || '',
      destination_station_address: trip.destinationStation?.address || '',
      departure_time: trip.departureTime || 'N/A',
      departure_date: trip.departureDate || 'N/A',
      price: Number(trip.price || 0),
      duration: Number(trip.duration || 0),
      bus_type: trip.busType || 'Standard',
      operator: trip.operator || 'N/A',
      operator_type: trip.operatorType || 'Small',
      amenities: trip.amenities || [],
      rating: Number(trip.rating || 0),
      rank_score: Number(trip.rankScore || trip.rating || 0),
      available_seats: Number(trip.availableSeats || 30),
      recommendation: trip.recommendation || 'Phù hợp với tiêu chí tìm kiếm',
    }));

    logger.info(`Found ${recommendations.length} trips (GET)`);

    // Fallback query if no results (only destination)
    if (!recommendations.length) {
      let fallbackQuery = { $and: [] };
      if (source) {
        fallbackQuery.$and.push({ startingPoint: new RegExp(source, 'i') });
      }
      fallbackQuery.$and.push({ destination: new RegExp(destination, 'i') });

      logger.info(`Fallback query (GET): ${JSON.stringify(fallbackQuery)}`);
      trips = await Trip.find(fallbackQuery)
        .sort({ rankScore: -1, price: 1 })
        .limit(parseInt(maxResults) || 5)
        .lean();

      recommendations = trips.map(trip => ({
        id: trip._id.toString(),
        source: trip.startingPoint || 'N/A',
        destination: trip.destination || 'N/A',
        source_station_id: trip.sourceStationId || '',
        destination_station_id: trip.destinationStationId || '',
        source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
        destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
        source_station_address: trip.sourceStation?.address || '',
        destination_station_address: trip.destinationStation?.address || '',
        departure_time: trip.departureTime || 'N/A',
        departure_date: trip.departureDate || 'N/A',
        price: Number(trip.price || 0),
        duration: Number(trip.duration || 0),
        bus_type: trip.busType || 'Standard',
        operator: trip.operator || 'N/A',
        operator_type: trip.operatorType || 'Small',
        amenities: trip.amenities || [],
        rating: Number(trip.rating || 0),
        rank_score: Number(trip.rankScore || trip.rating || 0),
        available_seats: Number(trip.availableSeats || 30),
        recommendation: 'Kết quả dự phòng dựa trên tiêu chí tối thiểu.',
      }));
      logger.info(`Fallback found ${recommendations.length} trips (GET)`);
    }

    if (!recommendations.length) {
      logger.warning(`No trips found for request (GET): ${JSON.stringify(req.query)}`);
      return res.status(404).json({
        success: false,
        message: `Không tìm thấy chuyến đi phù hợp cho điểm đi: ${source || 'bất kỳ'}, điểm đến: ${destination}.`,
      });
    }

    logger.info(`Returning ${recommendations.length} trip recommendations (GET)`);
    res.json(recommendations);
  } catch (error) {
    logger.error(`Trip search error (GET): ${error}`);
    res.status(500).json({ success: false, message: `Lỗi server: ${error.message}` });
  }
});

// Get Trip by ID
app.get('/api/trips/:id', async (req, res) => {
  try {
    const trip = await Trip.findById(req.params.id).lean();
    if (!trip) {
      logger.warning(`Trip not found for id: ${req.params.id}`);
      return res.status(404).json({ success: false, message: 'Không tìm thấy chuyến đi' });
    }
    res.json({
      id: trip._id.toString(),
      source: trip.startingPoint || 'N/A',
      destination: trip.destination || 'N/A',
      source_station_id: trip.sourceStationId || '',
      destination_station_id: trip.destinationStationId || '',
      source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
      destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
      source_station_address: trip.sourceStation?.address || '',
      destination_station_address: trip.destinationStation?.address || '',
      departure_time: trip.departureTime || 'N/A',
      departure_date: trip.departureDate || 'N/A',
      price: Number(trip.price || 0),
      duration: Number(trip.duration || 0),
      bus_type: trip.busType || 'Standard',
      operator: trip.operator || 'N/A',
      operator_type: trip.operatorType || 'Small',
      amenities: trip.amenities || [],
      rating: Number(trip.rating || 0),
      rank_score: Number(trip.rankScore || trip.rating || 0),
      available_seats: Number(trip.availableSeats || 30),
      recommendation: trip.recommendation || 'N/A',
    });
  } catch (error) {
    logger.error(`Get trip error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Get All Trips
app.get('/api/trips', async (req, res) => {
  try {
    const trips = await Trip.find().lean();
    res.json(trips.map(trip => ({
      id: trip._id.toString(),
      source: trip.startingPoint || 'N/A',
      destination: trip.destination || 'N/A',
      source_station_id: trip.sourceStationId || '',
      destination_station_id: trip.destinationStationId || '',
      source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
      destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
      source_station_address: trip.sourceStation?.address || '',
      destination_station_address: trip.destinationStation?.address || '',
      departure_time: trip.departureTime || 'N/A',
      departure_date: trip.departureDate || 'N/A',
      price: Number(trip.price || 0),
      duration: Number(trip.duration || 0),
      bus_type: trip.busType || 'Standard',
      operator: trip.operator || 'N/A',
      operator_type: trip.operatorType || 'Small',
      amenities: trip.amenities || [],
      rating: Number(trip.rating || 0),
      rank_score: Number(trip.rankScore || trip.rating || 0),
      available_seats: Number(trip.availableSeats || 30),
      recommendation: trip.recommendation || 'N/A',
    })));
  } catch (error) {
    logger.error(`Get trips error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Book Trip
app.post('/api/bookings', verifyToken, async (req, res) => {
  try {
    const { error } = bookingSchemaValidator.validate(req.body);
    if (error) {
      logger.warning(`Validation error in booking: ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { userId, tripId, seats } = req.body;
    if (userId !== req.userId) {
      logger.warning(`Unauthorized booking attempt by userId: ${req.userId}`);
      return res.status(403).json({ success: false, message: 'Không được phép' });
    }

    const trip = await Trip.findById(tripId);
    if (!trip || trip.availableSeats < seats.length) {
      logger.warning(`Invalid trip or insufficient seats for tripId: ${tripId}`);
      return res.status(400).json({ success: false, message: 'Chuyến đi không hợp lệ hoặc không đủ ghế' });
    }

    const booking = new Booking({ userId, tripId, seats });
    await booking.save();

    trip.availableSeats -= seats.length;
    await trip.save();

    logger.info(`Booking created: ${booking._id} for userId: ${userId}`);
    res.status(201).json({ success: true, bookingId: booking._id.toString() });
  } catch (error) {
    logger.error(`Book trip error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Get User Bookings
app.get('/api/bookings/user/:userId', verifyToken, async (req, res) => {
  try {
    if (req.params.userId !== req.userId) {
      logger.warning(`Unauthorized booking access by userId: ${req.userId}`);
      return res.status(403).json({ success: false, message: 'Không được phép' });
    }
    const bookings = await Booking.find({ userId: req.params.userId }).populate('tripId').lean();
    res.json(bookings.map(booking => ({
      id: booking._id.toString(),
      userId: booking.userId.toString(),
      tripId: booking.tripId._id.toString(),
      trip: {
        id: booking.tripId._id.toString(),
        source: booking.tripId.startingPoint || 'N/A',
        destination: booking.tripId.destination || 'N/A',
        source_station: booking.tripId.sourceStation?.name || booking.tripId.startingPoint || 'N/A',
        destination_station: booking.tripId.destinationStation?.name || booking.tripId.destination || 'N/A',
        source_station_address: booking.tripId.sourceStation?.address || '',
        destination_station_address: booking.tripId.destinationStation?.address || '',
        departure_time: booking.tripId.departureTime || 'N/A',
        departure_date: booking.tripId.departureDate || 'N/A',
        price: Number(booking.tripId.price || 0),
        bus_type: booking.tripId.busType || 'Standard',
      },
      seats: booking.seats,
      createdAt: booking.createdAt,
    })));
  } catch (error) {
    logger.error(`Get bookings error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Cancel Booking
app.delete('/api/bookings/:id', verifyToken, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking || booking.userId.toString() !== req.userId) {
      logger.warning(`Unauthorized or booking not found for id: ${req.params.id}`);
      return res.status(403).json({ success: false, message: 'Không được phép hoặc không tìm thấy đặt chỗ' });
    }
    const trip = await Trip.findById(booking.tripId);
    if (trip) {
      trip.availableSeats += booking.seats.length;
      await trip.save();
    }
    await booking.deleteOne();
    logger.info(`Booking cancelled: ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    logger.error(`Cancel booking error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Get User Profile
app.get('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.params.id !== req.userId) {
      logger.warning(`Unauthorized profile access by userId: ${req.userId}`);
      return res.status(403).json({ success: false, message: 'Không được phép' });
    }
    const user = await User.findById(req.params.id).select('-password').lean();
    if (!user) {
      logger.warning(`User not found for id: ${req.params.id}`);
      return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
    }
    res.json({ success: true, user });
  } catch (error) {
    logger.error(`Get user error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Update User Profile
app.put('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.params.id !== req.userId) {
      logger.warning(`Unauthorized profile update by userId: ${req.userId}`);
      return res.status(403).json({ success: false, message: 'Không được phép' });
    }
    const { name, phone } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name, phone },
      { new: true, select: '-password' }
    ).lean();
    if (!user) {
      logger.warning(`User not found for id: ${req.params.id}`);
      return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
    }
    logger.info(`User profile updated: ${req.params.id}`);
    res.json({ success: true, user });
  } catch (error) {
    logger.error(`Update user error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Get Locations
app.get('/api/locations', async (req, res) => {
  try {
    const locations = await Trip.distinct('startingPoint').lean();
    const destinationLocations = await Trip.distinct('destination').lean();
    const allLocations = [...new Set([...locations, ...destinationLocations])];
    res.json({ success: true, locations: allLocations });
  } catch (error) {
    logger.error(`Get locations error: ${error}`);
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  logger.info('Health check endpoint called');
  res.json({ status: 'healthy' });
});

// WebSocket Server
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  logger.info('WebSocket connection established');
  ws.on('message', async (data) => {
    try {
      let requestData;
      try {
        requestData = JSON.parse(data);
      } catch (err) {
        logger.warning('Invalid JSON received, using default query');
        requestData = {
          destination: 'Vũng Tàu',
          maxResults: 5,
        };
      }

      const { source, destination, date, maxResults = 5 } = requestData;

      // Validate required field
      if (!destination) {
        logger.warning('Destination is required in WebSocket request');
        ws.send(JSON.stringify({ error: 'Vui lòng cung cấp địa điểm đến (destination).' }));
        return;
      }

      // Build MongoDB query with raw input values
      const query = { $and: [] };
      if (source) {
        query.$and.push({ startingPoint: new RegExp(source, 'i') });
      }
      query.$and.push({ destination: new RegExp(destination, 'i') });
      if (date) {
        query.$and.push({ departureDate: date });
      }

      logger.info(`WebSocket MongoDB query: ${JSON.stringify(query)}`);

      const trips = await Trip.find(query)
        .sort({ rankScore: -1, price: 1 })
        .limit(parseInt(maxResults))
        .lean();

      const tripList = trips.map(trip => ({
        id: trip._id.toString(),
        source: trip.startingPoint || 'N/A',
        destination: trip.destination || 'N/A',
        source_station_id: trip.sourceStationId || '',
        destination_station_id: trip.destinationStationId || '',
        source_station: trip.sourceStation?.name || trip.startingPoint || 'N/A',
        destination_station: trip.destinationStation?.name || trip.destination || 'N/A',
        source_station_address: trip.sourceStation?.address || '',
        destination_station_address: trip.destinationStation?.address || '',
        departure_time: trip.departureTime || 'N/A',
        departure_date: trip.departureDate || 'N/A',
        price: Number(trip.price || 0),
        duration: Number(trip.duration || 0),
        bus_type: trip.busType || 'Standard',
        operator: trip.operator || 'N/A',
        operator_type: trip.operatorType || 'Small',
        amenities: trip.amenities || [],
        rating: Number(trip.rating || 0),
        rank_score: Number(trip.rankScore || trip.rating || 0),
        available_seats: Number(trip.availableSeats || 30),
        recommendation: trip.recommendation || 'Cập nhật qua WebSocket',
      }));

      logger.info(`WebSocket sending ${tripList.length} trips for destination: ${destination}`);

      if (!tripList.length) {
        ws.send(JSON.stringify({
          success: false,
          error: `Không tìm thấy chuyến đi phù hợp cho điểm đi: ${source || 'bất kỳ'}, điểm đến: ${destination}, ngày: ${date || 'bất kỳ'}.`,
        }));
        return;
      }

      ws.send(JSON.stringify({ success: true, trips: tripList }));
    } catch (error) {
      logger.error(`WebSocket error: ${error}`);
      ws.send(JSON.stringify({ success: false, error: `Lỗi WebSocket: ${error.message}` }));
    }
  });

  ws.on('close', () => {
    logger.info('WebSocket connection closed');
  });
});

// MongoDB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    logger.info('Kết nối thành công đến MongoDB');
  })
  .catch(err => logger.error(`Lỗi kết nối MongoDB: ${err}`));

const crypto = require('crypto');
const querystring = require('querystring');

// Validation Schema cho yêu cầu thanh toán
const createPaymentSchema = Joi.object({
  bookingId: Joi.string().required(),
  amount: Joi.number().min(10000).required(), // Tối thiểu 10,000 VND
  userId: Joi.string().required(),
});

// Endpoint tạo URL thanh toán VNPAY
app.post('/api/vnpay/create-payment', verifyToken, async (req, res) => {
  try {
    const { error } = createPaymentSchema.validate(req.body);
    if (error) {
      logger.warning(`Validation error in create payment: ${error.details[0].message}`);
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { bookingId, amount, userId } = req.body;

    // Kiểm tra quyền truy cập
    if (userId !== req.userId) {
      logger.warning(`Unauthorized payment attempt by userId: ${req.userId}`);
      return res.status(403).json({ success: false, message: 'Không được phép' });
    }

    // Kiểm tra booking
    const booking = await Booking.findById(bookingId).populate('tripId');
    if (!booking || booking.userId.toString() !== userId) {
      logger.warning(`Invalid or unauthorized booking: ${bookingId}`);
      return res.status(400).json({ success: false, message: 'Đặt chỗ không hợp lệ' });
    }

    // Chuẩn bị tham số thanh toán
    const date = new Date();
    const createDate = date.toISOString().replace(/[-:T.]/g, '').slice(0, 14); // YYYYMMDDHHMMSS
    const orderId = `${bookingId}_${Date.now()}`; // Mã đơn hàng duy nhất
    const ipAddr = req.ip || '127.0.0.1';

    const params = {
      vnp_Version: '2.1.0',
      vnp_Command: 'pay',
      vnp_TmnCode: VNPAY_TMN_CODE,
      vnp_Amount: amount * 100, // VNPAY yêu cầu số tiền * 100 (VD: 300,000 VND = 30000000)
      vnp_CurrCode: 'VND',
      vnp_TxnRef: orderId,
      vnp_OrderInfo: `Thanh toan dat ve ${bookingId}`,
      vnp_OrderType: '250000', // Mã ngành hàng (vận tải)
      vnp_Locale: 'vn',
      vnp_CreateDate: createDate,
      vnp_IpAddr: ipAddr,
      vnp_ReturnUrl: 'https://your-frontend.com/payment-result', // URL frontend xử lý kết quả
    };

    // Sắp xếp tham số theo thứ tự alphabet
    const sortedParams = Object.keys(params)
      .sort()
      .reduce((obj, key) => {
        obj[key] = params[key];
        return obj;
      }, {});

    // Tạo chuỗi ký tự để checksum
    const signData = querystring.stringify(sortedParams, { encode: false });
    const vnp_SecureHash = crypto
      .createHmac('sha512', VNPAY_HASH_SECRET)
      .update(signData)
      .digest('hex')
      .toUpperCase();

    // Thêm secure hash vào tham số
    sortedParams.vnp_SecureHash = vnp_SecureHash;

    // Tạo URL thanh toán
    const vnpUrl = `${VNPAY_URL}?${querystring.stringify(sortedParams)}`;

    logger.info(`Created VNPAY payment URL for booking: ${bookingId}`);

    res.json({ success: true, paymentUrl: vnpUrl, orderId });
  } catch (error) {
    logger.error(`Create VNPAY payment error: ${error.message}`);
    res.status(500).json({ success: false, message: `Lỗi server: ${error.message}` });
  }
});

// Validation Schema cho IPN
const ipnSchema = Joi.object({
  vnp_TxnRef: Joi.string().required(),
  vnp_Amount: Joi.number().required(),
  vnp_ResponseCode: Joi.string().required(),
  vnp_TransactionNo: Joi.string().allow('', null),
  vnp_SecureHash: Joi.string().required(),
});

// Endpoint IPN
app.post('/api/vnpay/ipn', async (req, res) => {
  try {
    const { error } = ipnSchema.validate(req.body);
    if (error) {
      logger.warning(`Validation error in IPN: ${error.details[0].message}`);
      return res.status(400).json({ RspCode: '97', Message: 'Invalid request' });
    }

    const {
      vnp_TxnRef,
      vnp_Amount,
      vnp_ResponseCode,
      vnp_TransactionNo,
      vnp_SecureHash,
      ...otherParams
    } = req.body;

    // Kiểm tra checksum
    const sortedParams = Object.keys(otherParams)
      .sort()
      .reduce((obj, key) => {
        obj[key] = otherParams[key];
        return obj;
      }, {});
    const signData = querystring.stringify(sortedParams, { encode: false });
    const calculatedHash = crypto
      .createHmac('sha512', VNPAY_HASH_SECRET)
      .update(signData)
      .digest('hex')
      .toUpperCase();

    if (calculatedHash !== vnp_SecureHash) {
      logger.warning(`Invalid checksum for IPN: ${vnp_TxnRef}`);
      return res.status(200).json({ RspCode: '97', Message: 'Invalid checksum' });
    }

    // Lấy bookingId từ vnp_TxnRef (loại bỏ phần timestamp)
    const bookingId = vnp_TxnRef.split('_')[0];
    const booking = await Booking.findById(bookingId);

    if (!booking) {
      logger.warning(`Booking not found for IPN: ${vnp_TxnRef}`);
      return res.status(200).json({ RspCode: '01', Message: 'Order not found' });
    }

    // Kiểm tra số tiền
    const expectedAmount = booking.tripId.price * booking.seats.length * 100; // Giá * số ghế * 100
    if (Number(vnp_Amount) !== expectedAmount) {
      logger.warning(`Invalid amount for IPN: ${vnp_TxnRef}, expected: ${expectedAmount}, received: ${vnp_Amount}`);
      return res.status(200).json({ RspCode: '04', Message: 'Invalid amount' });
    }

    // Cập nhật trạng thái thanh toán
    if (vnp_ResponseCode === '00') {
      booking.paymentStatus = 'paid';
      booking.paymentTransactionNo = vnp_TransactionNo;
      await booking.save();
      logger.info(`Payment successful for booking: ${bookingId}, transaction: ${vnp_TransactionNo}`);
      return res.status(200).json({ RspCode: '00', Message: 'Success' });
    } else {
      booking.paymentStatus = 'failed';
      await booking.save();
      logger.warning(`Payment failed for booking: ${bookingId}, response code: ${vnp_ResponseCode}`);
      return res.status(200).json({ RspCode: vnp_ResponseCode, Message: 'Transaction failed' });
    }
  } catch (error) {
    logger.error(`IPN error: ${error.message}`);
    return res.status(200).json({ RspCode: '99', Message: 'Unknown error' });
  }
});

