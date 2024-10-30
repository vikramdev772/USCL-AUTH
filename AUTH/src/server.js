// server.js
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');
const flash = require('connect-flash');
const path = require('path');

// Load environment variables
dotenv.config();



// Passport configuration
require('./config/passport')(passport);

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('\n\t MongoDB connected...  🍏'))
  .catch((err) => console.log(err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Express session middleware
app.use(
  session({
    secret: 'your_session_secret',
    resave: false,
    saveUninitialized: false,
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
app.use(flash());

// Global variables for flash messages
app.use(function (req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.use('/auth', require('./routes/authRoutes'));
app.use('/auth', require('./routes/dataRoute')); // Include dataRoute

app.get('/', (req, res) => res.json({ msg: 'Server is started 🔥' }));

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n\t Server started on port ${PORT} 💻\n`);
  console.log(`\n\t http://127.0.0.1:${PORT} \n`);
});
