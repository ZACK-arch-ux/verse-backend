const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

/* ===========================
   DATABASE CONNECTION
=========================== */

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",        // <-- put your MySQL password here
    database: "verse_db"
});

/* ===========================
   REGISTER API
=========================== */

app.post("/api/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "All fields required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            [email, hashedPassword]
        );

        res.json({ message: "User registered successfully" });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Server error" });
    }
});

/* ===========================
   LOGIN API
=========================== */

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "All fields required" });
    }

    try {
        const [rows] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({ message: "Invalid email" });
        }

        const user = rows[0];

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: "Invalid password" });
        }

        res.json({
            message: "Login success",
            userId: user.id,
            email: user.email
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Server error" });
    }
});

/* ===========================
   UPDATE PROFILE PICTURE
=========================== */

app.post("/api/user/profile/picture", async (req, res) => {
    const { userId, image } = req.body;

    if (!userId || !image) {
        return res.status(400).json({ message: "Missing data" });
    }

    try {
        await db.query(
            "UPDATE users SET profile_image = ? WHERE id = ?",
            [image, userId]
        );

        res.json({ message: "Profile picture updated successfully" });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Server error" });
    }
});

/* ===========================
   CHANGE PASSWORD
=========================== */

app.post("/api/user/password", async (req, res) => {
    const { userId, oldPassword, newPassword } = req.body;

    if (!userId || !oldPassword || !newPassword) {
        return res.status(400).json({ message: "Missing fields" });
    }

    try {
        const [rows] = await db.query(
            "SELECT password FROM users WHERE id = ?",
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const match = await bcrypt.compare(oldPassword, rows[0].password);

        if (!match) {
            return res.status(401).json({ message: "Old password incorrect" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.query(
            "UPDATE users SET password = ? WHERE id = ?",
            [hashedPassword, userId]
        );

        res.json({ message: "Password updated successfully" });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Server error" });
    }
});

/* ===========================
   SERVER START
=========================== */

app.listen(5000, () => {
    console.log("Server running on http://localhost:5000");
});
=======
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

/* ================= DATABASE CONNECTION ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

/* ================= AUTH MIDDLEWARE ================= */

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

/* ================= TEST ROUTE ================= */

app.get("/", (req, res) => {
  res.send("Verse Backend Running Securely 🚀");
});

/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2)",
      [email, hashedPassword]
    );

    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration failed" });
  }
});

/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
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
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token: token,
      user: {
        id: user.id,
        email: user.email,
        profile_picture: user.profile_picture,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ================= UPDATE PROFILE PICTURE ================= */

app.post("/update-profile-picture", authenticateToken, async (req, res) => {
  const { profile_picture } = req.body;

  try {
    await pool.query(
      "UPDATE users SET profile_picture = $1 WHERE id = $2",
      [profile_picture, req.user.id]
    );

    res.json({ message: "Profile picture updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Update failed" });
  }
});

/* ================= CHANGE PASSWORD ================= */

app.post("/change-password", authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [req.user.id]
    );

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(oldPassword, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "Old password incorrect" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password = $1 WHERE id = $2",
      [hashedNewPassword, req.user.id]
    );

    res.json({ message: "Password changed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Password change failed" });
  }
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});