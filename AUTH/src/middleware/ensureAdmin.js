// middleware/ensureAdmin.js

module.exports = function (req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
      return next();
    }
    req.flash('error_msg', 'Access denied: Admins only');
    res.redirect('/auth/dashboard');
  };
  