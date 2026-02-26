require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.use(cors());
app.use(express.json());

/* ================= DATABASE CONNECTION ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ================= CREATE TABLES ================= */

// USERS TABLE
pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(20) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  profile_picture TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).then(() => console.log("Users table ready"))
.catch(err => console.error("Users table error:", err));

// POSTS TABLE
pool.query(`
CREATE TABLE IF NOT EXISTS posts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).then(() => console.log("Posts table ready"))
.catch(err => console.error("Posts table error:", err));

// MESSAGES TABLE
pool.query(`
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`).then(() => console.log("Messages table ready"))
.catch(err => console.error("Messages table error:", err));


/* ================= AUTH MIDDLEWARE ================= */

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}


/* ================= BASIC ROUTE ================= */

app.get("/", (req, res) => {
  res.send("Verse Backend Running Securely 🚀");
});


/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  try {
    const { email, phone, password, username } = req.body;

    if (!email || !phone || !password || !username) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existing = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users(email, phone, password, username) VALUES($1,$2,$3,$4)",
      [email, phone, hashed, username]
    );

    res.status(201).json({ message: "Registered successfully" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  const { emailOrPhone, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR phone=$1",
      [emailOrPhone]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Login failed" });
  }
});


/* ================= SEARCH USERS ================= */

app.get("/search-users/:query", authenticateToken, async (req, res) => {
  const search = `%${req.params.query}%`;

  try {
    const result = await pool.query(
      "SELECT id, username FROM users WHERE username ILIKE $1 LIMIT 10",
      [search]
    );

    res.json(result.rows);

  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ message: "Search failed" });
  }
});


/* ================= GET OLD MESSAGES ================= */

app.get("/messages/:receiverId", authenticateToken, async (req, res) => {
  const receiverId = req.params.receiverId;

  try {
    const result = await pool.query(
      `SELECT * FROM messages
       WHERE (sender_id=$1 AND receiver_id=$2)
       OR (sender_id=$2 AND receiver_id=$1)
       ORDER BY created_at ASC`,
      [req.user.id, receiverId]
    );

    res.json(result.rows);

  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ message: "Failed to load messages" });
  }
});


/* ================= SOCKET.IO REAL-TIME CHAT ================= */

const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*" },
});

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("join", (userId) => {
    socket.join(userId);
    console.log("User joined room:", userId);
  });

  socket.on("send_message", async (data) => {
    const { senderId, receiverId, message } = data;

    try {
      await pool.query(
        "INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1,$2,$3)",
        [senderId, receiverId, message]
      );

      io.to(receiverId).emit("receive_message", {
        senderId,
        message,
        created_at: new Date()
      });

    } catch (err) {
      console.error("Socket message error:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});


/* ================= START SERVER ================= */

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});