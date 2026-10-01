const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User");

const app = express();

app.use(express.json());
app.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword
        });

        await newUser.save();

        res.status(201).json({
            msg: "User created successfully"
        });
    } catch (err) {
        res.status(500).json({
            error: err.message
        });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(400).json({
            msg: "User not found"
        });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(400).json({
            msg: "Invalid credentials"
        });
    }

    const token = jwt.sign(
        { id: user._id },
        "secretkey",
        { expiresIn: "1h" }
    );

    res.json({
        msg: "Login successful",
        token
    });
});


function auth(req, res, next) {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
        return res.status(401).json({
            msg: "No token, access denied"
        });
    }

    try {
        const verified = jwt.verify(token, "secretkey");

        req.user = verified;

        next();
    } catch (err) {
        res.status(400).json({
            msg: "Invalid token"
        });
    }
}

app.get("/profile", auth, async (req, res) => {
    const user = await User.findById(req.user.id).select("-password");

    res.json(user);
});
mongoose
    .connect("mongodb://127.0.0.1:27017/authdb")
    .then(() => {
        console.log("MongoDB Connected");

        app.listen(3000, () => {
            console.log("Server running on http://localhost:3000");
        });
    })
    .catch((err) => {
        console.log("MongoDB Connection Error:", err);
    });