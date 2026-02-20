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