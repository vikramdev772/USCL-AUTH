// createAdmin.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from the root directory
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// Load User model
const User = require('./models/User');

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected...');

    // Create admin user
    createAdminUser();
  })
  .catch((err) => console.log(err));

async function createAdminUser() {
  const email = 'admin@2024';
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    console.log('Admin user already exists');
    mongoose.disconnect();
    return;
  }

  const newUser = new User({
    name: 'Admin',
    email: email,
    phone: '1234567890',
    password: 'password', // We'll hash it below
    isVerified: true,
    role: 'admin',
  });

  // Hash password
  const salt = await bcrypt.genSalt(10);
  newUser.password = await bcrypt.hash(newUser.password, salt);

  await newUser.save();
  console.log('Admin user created successfully');
  mongoose.disconnect();
}
