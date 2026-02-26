require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;

// ================= JWT MIDDLEWARE =================
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { email, phone, password, username } = req.body;

    if (!email || !phone || !password || !username) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingEmail = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (existingEmail.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const existingUsername = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (existingUsername.rows.length > 0) {
      return res.status(400).json({ message: "Username already taken" });
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

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= PROFILE =================
app.get("/profile/:id", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, username, phone, bio, profile_image FROM users WHERE id=$1",
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= FOLLOW =================
app.post("/follow/:id", verifyToken, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO followers(follower_id, following_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Followed" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= UNFOLLOW =================
app.delete("/unfollow/:id", verifyToken, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM followers WHERE follower_id=$1 AND following_id=$2",
      [req.user.id, req.params.id]
    );
    res.json({ message: "Unfollowed" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= CREATE POST =================
app.post("/posts", verifyToken, async (req, res) => {
  try {
    const { content, image_url } = req.body;

    await pool.query(
      "INSERT INTO posts(user_id, content, image_url) VALUES($1,$2,$3)",
      [req.user.id, content, image_url]
    );

    res.json({ message: "Post created" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= FEED =================
app.get("/feed", verifyToken, async (req, res) => {
  try {
    const posts = await pool.query(`
      SELECT posts.*, users.username
      FROM posts
      JOIN users ON posts.user_id = users.id
      ORDER BY posts.created_at DESC
    `);

    res.json(posts.rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= LIKE =================
app.post("/like/:postId", verifyToken, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO likes(user_id, post_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
      [req.user.id, req.params.postId]
    );
    res.json({ message: "Liked" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= COMMENT =================
app.post("/comment/:postId", verifyToken, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO comments(user_id, post_id, comment) VALUES($1,$2,$3)",
      [req.user.id, req.params.postId, req.body.comment]
    );
    res.json({ message: "Comment added" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= REELS =================
app.post("/reels", verifyToken, async (req, res) => {
  try {
    const { video_url, caption } = req.body;

    await pool.query(
      "INSERT INTO reels(user_id, video_url, caption) VALUES($1,$2,$3)",
      [req.user.id, video_url, caption]
    );

    res.json({ message: "Reel uploaded" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ================= CHAT =================
io.on("connection", (socket) => {
  socket.on("sendMessage", async (data) => {
    const { senderId, receiverId, message } = data;

    await pool.query(
      "INSERT INTO messages(sender_id, receiver_id, message) VALUES($1,$2,$3)",
      [senderId, receiverId, message]
    );

    io.emit("receiveMessage", data);
  });
});

// ================= ROOT =================
app.get("/", (req, res) => {
  res.send("Backend running successfully 🚀");
});

server.listen(PORT, () => {
  console.log("Server started on port", PORT);
});