// routes/dataRoute.js
const express = require('express');
const router = express.Router();
const ensureAdmin = require('../middleware/ensureAdmin');

// Load User model
const User = require('../models/User');

// @route   GET /auth/data
// @desc    Display user data in a table
router.get('/data', ensureAdmin, async (req, res) => {
  try {
    const users = await User.find().lean(); // Fetch all users from the database

    res.render('data', { users });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
