const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());

// ================= DATABASE =================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= AUTO CREATE TABLES =================

const createTables = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100),
  email VARCHAR(150) UNIQUE NOT NULL,
  phone VARCHAR(20),
  password VARCHAR(255) NOT NULL,
  bio TEXT,
  profile_image TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reels (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  video_url TEXT NOT NULL,
  caption TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  message TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;

pool.query(createTables)
  .then(() => console.log("✅ All tables ready"))
  .catch(err => console.error(err));

// ================= JWT SECRET =================

const JWT_SECRET = "super_secret_key";

// ================= AUTH MIDDLEWARE =================

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ================= REGISTER =================

app.post("/register", async (req, res) => {
  try {
    const { username, email, phone, password } = req.body;

    const check = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (check.rows.length > 0)
      return res.status(400).json({ message: "Email exists" });

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username,email,phone,password) VALUES ($1,$2,$3,$4)",
      [username, email, phone, hashed]
    );

    res.status(200).json({ message: "Registered successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= LOGIN =================

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0)
      return res.status(400).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET);

    res.json({ token, user });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= PROFILE =================

app.get("/profile/:id", async (req, res) => {
  const user = await pool.query(
    "SELECT id,username,email,phone,bio,profile_image FROM users WHERE id=$1",
    [req.params.id]
  );
  res.json(user.rows[0]);
});

// ================= UPDATE PROFILE =================

app.put("/profile", authenticateToken, async (req, res) => {
  const { bio, profile_image } = req.body;

  await pool.query(
    "UPDATE users SET bio=$1, profile_image=$2 WHERE id=$3",
    [bio, profile_image, req.user.id]
  );

  res.json({ message: "Profile updated" });
});

// ================= CREATE REEL =================

app.post("/reels", authenticateToken, async (req, res) => {
  const { video_url, caption } = req.body;

  await pool.query(
    "INSERT INTO reels (user_id,video_url,caption) VALUES ($1,$2,$3)",
    [req.user.id, video_url, caption]
  );

  res.json({ message: "Reel uploaded" });
});

// ================= GET REELS =================

app.get("/reels", async (req, res) => {
  const reels = await pool.query(`
    SELECT reels.*, users.username 
    FROM reels 
    JOIN users ON reels.user_id = users.id
    ORDER BY reels.created_at DESC
  `);
  res.json(reels.rows);
});

// ================= SAVE CHAT MESSAGE =================

app.post("/messages", authenticateToken, async (req, res) => {
  const { receiver_id, message } = req.body;

  await pool.query(
    "INSERT INTO messages (sender_id,receiver_id,message) VALUES ($1,$2,$3)",
    [req.user.id, receiver_id, message]
  );

  res.json({ message: "Message sent" });
});

// ================= GET CHAT =================

app.get("/messages/:userId", authenticateToken, async (req, res) => {
  const messages = await pool.query(`
    SELECT * FROM messages
    WHERE (sender_id=$1 AND receiver_id=$2)
       OR (sender_id=$2 AND receiver_id=$1)
    ORDER BY created_at ASC
  `, [req.user.id, req.params.userId]);

  res.json(messages.rows);
});

// ================= SOCKET.IO REALTIME =================

io.on("connection", (socket) => {
  console.log("User connected");

  socket.on("sendMessage", (data) => {
    io.emit("receiveMessage", data);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

// ================= ROOT =================

app.get("/", (req, res) => {
  res.send("Social Media Backend Running 🚀");
});

// ================= START SERVER =================

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});