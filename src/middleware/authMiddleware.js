import jwt from "jsonwebtoken";
import User from "../models/User.js";

// 1. Extract token from Authorization header
// 2. Verify token
// 3. Find user
// 4. Attach user to req.user
// 5. Call next()
// 6. If invalid → return 401

const authMiddleware = async (req, res, next) => {
  try {
    // 1️⃣ Extract token
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Not authorized" });
    }

    const token = authHeader.split(" ")[1];

    // 2️⃣ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3️⃣ Find user (exclude password)
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // 4️⃣ Attach user to request
    req.user = user;

    // 5️⃣ Continue
    next();
  } catch (error) {
    // 6️⃣ Invalid token
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

export default authMiddleware;