// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  password: String,
  googleId: String,
  githubId: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: String,
  otpExpires: Date,
  role: {
    type: String,
    default: 'user', // Default role is 'user'
  },
});

module.exports = mongoose.model('User', UserSchema);
