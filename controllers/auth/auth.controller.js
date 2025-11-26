import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { log } from "console";

const prisma = new PrismaClient();

// ---------------- Token Helpers ----------------
const generateAccessToken = (user) =>
  jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "5m" }
  );

const generateRefreshToken = () =>
  crypto.randomBytes(64).toString("hex");

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

// ---------------- Cookie Options ----------------
const accessCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 5 * 60 * 1000, // 5 minutes
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};


// ---------------- SignUp ----------------
export const signUp = async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "Email already exists" });

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: { fullName, email, passwordHash },
    });

    const refreshToken = generateRefreshToken();
    const hashedRefreshToken = hashToken(refreshToken);

    await prisma.session.create({
      data: { userId: user.id, refreshToken: hashedRefreshToken },
    });

    const accessToken = generateAccessToken(user);

    res
      .cookie("accessToken", accessToken, accessCookieOptions)
      .cookie("refreshToken", refreshToken, refreshCookieOptions)
      .status(201)
      .json({
        message: "User created",
        user: {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          role: user.role
        }
      });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};



// ---------------- SignIn ----------------
export const signIn = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const accessToken = generateAccessToken(user);

    const refreshToken = generateRefreshToken();
    const hashedRefreshToken = hashToken(refreshToken);

    await prisma.session.create({
      data: { userId: user.id, refreshToken: hashedRefreshToken },
    });

    res
      .cookie("accessToken", accessToken, accessCookieOptions)
      .cookie("refreshToken", refreshToken, refreshCookieOptions)
      .json({
        message: "Logged in",
        user: {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          role: user.role
        }
      });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};


//----------------- Get Current User ----------------
export const getMe = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: "No token provided" });

    const hashedToken = hashToken(token);

    const session = await prisma.session.findFirst({
      where: { refreshToken: hashedToken },
      include: { user: true }
    });

    if (!session) return res.status(401).json({ error: "Invalid token" });

    const accessToken = generateAccessToken(session.user);

    res.json({ user: session.user, accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};



// ---------------- Refresh Token ----------------
export const refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: "No refresh token" });

  try {
    const hashedToken = hashToken(token);

    const session = await prisma.session.findFirst({
      where: { refreshToken: hashedToken },
      include: { user: true }
    });

    if (!session) return res.status(403).json({ error: "Invalid refresh token" });

    const newRefreshToken = generateRefreshToken();
    const newHashedToken = hashToken(newRefreshToken);

    await prisma.session.update({
      where: { id: session.id },
      data: { refreshToken: newHashedToken }
    });

    const newAccessToken = generateAccessToken(session.user);

    res
      .cookie("accessToken", newAccessToken, accessCookieOptions)
      .cookie("refreshToken", newRefreshToken, refreshCookieOptions)
      .json({ message: "Token refreshed" });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};

// ---------------- Logout ----------------
export const logout = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (token) {
    await prisma.session.deleteMany({
      where: { refreshToken: hashToken(token) }
    });
  }

  res
    .clearCookie("accessToken", accessCookieOptions)
    .clearCookie("refreshToken", refreshCookieOptions)
    .json({ message: "Logged out" });
};
