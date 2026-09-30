const jwt = require("jsonwebtoken");
const User = require("../models/User");

/**
 * protect
 * Verifies the JWT sent in the Authorization header (Bearer token)
 * or in the httpOnly cookie. Attaches req.user on success.
 */
const protect = async (req, res, next) => {
  try {
    let token;

    // 1. Try Authorization header first
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer ")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }
    // 2. Fallback to httpOnly cookie
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authorised. No token provided.",
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user to request (exclude password)
    const user = await User.findById(decoded.id).select("-password -__v");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User belonging to this token no longer exists.",
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Please contact support.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ success: false, message: "Invalid token." });
    }
    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ success: false, message: "Token has expired. Please log in again." });
    }
    return res.status(500).json({ success: false, message: "Server error during authentication." });
  }
};

/**
 * adminOnly
 * Must be used AFTER protect. Restricts access to admin-role users.
 */
const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    return next();
  }
  return res.status(403).json({
    success: false,
    message: "Access denied. Admins only.",
  });
};

module.exports = { protect, adminOnly };
