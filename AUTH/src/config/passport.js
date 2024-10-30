// config/passport.js
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');

// Load User model
const User = require('../models/User');

module.exports = function (passport) {
  // Local Strategy
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
      // Match user
      try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'That email is not registered' });

        // Match password
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) return done(null, user);
        else return done(null, false, { message: 'Password incorrect' });
      } catch (err) {
        return done(err);
      }
    })
  );

  // Google Strategy
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        // Handle user data
        const { id, displayName, emails } = profile;
        try {
          let user = await User.findOne({ googleId: id });
          if (user) return done(null, user);
          else {
            user = new User({
              name: displayName,
              email: emails[0].value,
              googleId: id,
              isVerified: true, // Social logins are considered verified
            });
            await user.save();
            return done(null, user);
          }
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // GitHub Strategy
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: '/auth/github/callback',
      },
      async (accessToken, refreshToken, profile, done) => {
        // Handle user data
        const { id, username, emails } = profile;
        try {
          let user = await User.findOne({ githubId: id });
          if (user) return done(null, user);
          else {
            user = new User({
              name: username,
              email: emails && emails[0] ? emails[0].value : null,
              githubId: id,
              isVerified: true, // Social logins are considered verified
            });
            await user.save();
            return done(null, user);
          }
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // Serialize and Deserialize User
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
};
