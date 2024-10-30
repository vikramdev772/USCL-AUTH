// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { ensureAuthenticated } = require('../middleware/auth');

// Load User model
const User = require('../models/User');

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER, // Ensure these are set in your .env file
    pass: process.env.EMAIL_PASS,
  },
});

router.get('/test', (req, res) => {
  res.send('Backend is working');
});

// Render login page
router.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

// Render signup page
router.get('/signup', (req, res) => {
  res.render('signup', { message: req.flash('error') });
});

// Render forgot password page
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { message: req.flash('error') });
});

// Render reset password page
router.get('/reset-password', (req, res) => {
  res.render('reset-password', { message: req.flash('error') });
});

// Render dashboard page
router.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Logout route
router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/auth/login');
});

// Registration route
router.post('/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash('error', 'Email already registered');
      return res.redirect('/auth/signup');
    }

    const newUser = new User({ name, email, phone, password });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    newUser.password = await bcrypt.hash(password, salt);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    newUser.otp = otp;
    newUser.otpExpires = Date.now() + 3600000; // 1 hour

    await newUser.save();

    // Send verification email
    const mailOptions = {
      to: email,
      subject: 'Account Verification OTP',
      text: `Your OTP is ${otp}`,
    };
    transporter.sendMail(mailOptions);

    req.flash('success_msg', 'Registration successful. Check your email for OTP.');
    res.redirect('/auth/verify-otp');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Server error');
    res.redirect('/auth/signup');
  }
});

// Render OTP verification page
router.get('/verify-otp', (req, res) => {
  res.render('verify-otp', { message: req.flash('error') });
});

// Handle OTP verification
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
    if (!user) {
      req.flash('error', 'Invalid or expired OTP');
      return res.redirect('/auth/verify-otp');
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    req.flash('success_msg', 'Account verified successfully. You can now log in.');
    res.redirect('/auth/login');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Server error');
    res.redirect('/auth/verify-otp');
  }
});

// Login route
router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      req.flash('error', 'Server error');
      return next(err);
    }
    if (!user) {
      req.flash('error', info.message);
      return res.redirect('/auth/login');
    }

    // Check if user is verified
    if (!user.isVerified) {
      req.flash('error', 'Account not verified');
      return res.redirect('/auth/login');
    }

    req.logIn(user, function (err) {
      if (err) {
        req.flash('error', 'Login failed');
        return next(err);
      }
      return res.redirect('/auth/dashboard');
    });
  })(req, res, next);
});

// Google authentication
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google callback
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  (req, res) => {
    // Successful authentication
    res.redirect('/auth/dashboard');
  }
);

// GitHub authentication
router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));

// GitHub callback
router.get(
  '/github/callback',
  passport.authenticate('github', { failureRedirect: '/auth/login' }),
  (req, res) => {
    // Successful authentication
    res.redirect('/auth/dashboard');
  }
);

// Forgot Password route
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      req.flash('error', 'Email not registered');
      return res.redirect('/auth/forgot-password');
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    // Send email
    const mailOptions = {
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}`,
    };
    transporter.sendMail(mailOptions);

    req.flash('success_msg', 'OTP sent to your email');
    res.redirect('/auth/reset-password');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Server error');
    res.redirect('/auth/forgot-password');
  }
});

// Reset Password route
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
    if (!user) {
      req.flash('error', 'Invalid or expired OTP');
      return res.redirect('/auth/reset-password');
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    req.flash('success_msg', 'Password reset successful. You can now log in.');
    res.redirect('/auth/login');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Server error');
    res.redirect('/auth/reset-password');
  }
});

module.exports = router;
