const express = require("express");

const app = express();
const PORT = 4000;

app.use(express.json());

app.get("/api/users", (req, res) => {
    res.json({
        message: "User data from backend",
        users: [
            { id: 1, name: "Ali" },
            { id: 2, name: "User2" }
        ]
    });
});

app.get("/api/data", (req, res) => {
    res.json({
        message: "Protected data from backend"
    });
});

app.post("/api/data", (req, res) => {
    res.json({
        message: "Data received successfully",
        data: req.body
    });
});

app.listen(PORT, () => {
    console.log(`Backend API running on http://localhost:${PORT}`);
});