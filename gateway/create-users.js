require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("./db");

async function createUsers() {
    try {
        const adminHash = await bcrypt.hash("admin123", 12);
        const userHash = await bcrypt.hash("user123", 12);

        await pool.query(
            `INSERT INTO users (username, password_hash, role)
             VALUES ($1, $2, $3), ($4, $5, $6)
             ON CONFLICT (username) DO NOTHING`,
            [
                "admin",
                adminHash,
                "Admin",
                "user",
                userHash,
                "User"
            ]
        );

        console.log("Users created successfully");

        const result = await pool.query(
            "SELECT id, username, role, created_at FROM users ORDER BY id"
        );

        console.table(result.rows);
    } catch (error) {
        console.error("User creation failed:", error.message);
    } finally {
        await pool.end();
    }
}

createUsers();