require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

// ✅ Connect to MongoDB using ENV variable
async function main() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ Connected to MongoDB");
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err);
    }
}

// ✅ Session using ENV secret
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// ✅ User Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

// ✅ Secret Schema
const secretSchema = new mongoose.Schema({
    secret: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const Secret = mongoose.model("Secret", secretSchema);

// Middleware for session access in views
app.use((req, res, next) => {
    res.locals.session = req.session;
    next();
});

// ✅ ROUTES

app.get('/', (req, res) => res.render("home"));

app.get('/register', (req, res) => {
    res.render("register", { message: null });
});

app.get('/login', (req, res) => {
    const showMessage = req.query.registered === 'true';
    res.render("login", { message: showMessage ? "Registration successful. Please log in." : null });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.render("register", { message: "All fields are required." });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) {
        return res.render("register", { message: "Enter a valid email address." });
    }

    if (password.length < 6) {
        return res.render("register", { message: "Password must be at least 6 characters." });
    }

    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
        return res.render("register", { message: "User already exists. Please login." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email: username, password: hashedPassword });
        await newUser.save();
        res.redirect("/login?registered=true");
    } catch (err) {
        console.error(err);
        res.render("register", { message: "Registration error. Try again." });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const foundUser = await User.findOne({ email: username });

        if (foundUser && await bcrypt.compare(password, foundUser.password)) {
            req.session.user = foundUser;
            res.render("submit", {
                userEmail: foundUser.email,
                userPassword: foundUser.password,
                secrets: []
            });
        } else {
            res.render("login", { message: "Invalid email or password." });
        }
    } catch (err) {
        console.error(err);
        res.render("login", { message: "Login error. Try again." });
    }
});

app.get('/submit', async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    let secrets = [];
    if (req.query.show === 'true') {
        secrets = await Secret.find({ userId: req.session.user._id });
    }

    res.render("submit", {
        userEmail: req.session.user.email,
        userPassword: req.session.user.password,
        secrets
    });
});

app.post('/submit', async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    const secret = new Secret({
        secret: req.body.secret,
        userId: req.session.user._id
    });

    try {
        await secret.save();
        res.redirect("/submit");
    } catch (err) {
        console.error(err);
        res.send("Error saving secret.");
    }
});

app.get('/secrets', async (req, res) => {
    if (!req.session.user) return res.redirect("/login");

    try {
        const secrets = await Secret.find({ userId: req.session.user._id });
        res.render("secrets", { secrets });
    } catch (err) {
        console.error(err);
        res.send("Error loading secrets.");
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error(err);
        res.redirect("/");
    });
});

main();

app.listen(3000, () => console.log("🚀 Server running on port 3000"));
