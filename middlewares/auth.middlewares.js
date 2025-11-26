import jwt from "jsonwebtoken";

export const authMiddleware = (req, res, next) => {
  const token =
    req.cookies.accessToken ||
    (req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.split(" ")[1]
      : null);

  if (!token) {
    console.log("Auth error: no token provided");
    return res.status(401).json({ error: "No token provided" });
  }

  console.log("Token provided:", token);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.log("Auth error: invalid or expired token");
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};
