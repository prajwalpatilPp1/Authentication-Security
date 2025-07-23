

const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require('bcryptjs');
const session = require("express-session");
const app = express();

const { connect } = require("mongoose");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// MongoDB connection
async function main() {
    try {
        await connect("mongodb+srv://prajwalpatil:prajwalpatil@cluster0.cmnmaeq.mongodb.net/todolistDB?retryWrites=true&w=majority&appName=Cluster0");
        console.log("✅ Connected to MongoDB");
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err);
    }
}
// Mongoose schema and model with encryption
const tryschema = new mongoose.Schema({
    email: String,
    password: String
});

app.use(express.json());

// Set up session middleware
app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: false
}));

const secret = "ThisIsLittlesecret";


const User = mongoose.model("User", tryschema);

// Define Secret Schema for saving secrets
const secretSchema = new mongoose.Schema({
    secret: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const Secret = mongoose.model("Secret", secretSchema);

// Routes

app.use((req, res, next) => {
    res.locals.session = req.session;
    next();
});

app.get('/register', function (req, res) {
    res.render("register"); // Render the registration page
});


app.get('/', function (req, res) {
    res.render("home");
});

app.get('/login', function (req, res) {
    const showMessage = req.query.registered === 'true';
    res.render("login", { message: showMessage ? "Registration successful. Please log in." : null });
});




app.post('/register', async function (req, res) {
    try {
        const { username, password } = req.body;

        // ✅ Empty field check
        if (!username || !password) {
            return res.render("register", { message: "All fields are required." });
        }

        // ✅ Basic email format check
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(username)) {
            return res.render("register", { message: "Please enter a valid email address." });
        }

        // ✅ Password length check
        if (password.length < 6) {
            return res.render("register", { message: "Password must be at least 6 characters." });
        }

        const existingUser = await User.findOne({ email: username });
        if (existingUser) {
            return res.render("register", { message: "User already exists. Please login." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            email: username,
            password: hashedPassword
        });

        await newUser.save();
        res.redirect("/login?registered=true");

    } catch (err) {
        console.error(err);
        res.render("register", { message: "An error occurred during registration." });
    }
});





app.post('/login', async function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

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
            res.render("login", { message: "Invalid email or password." }); // Optional error message
        }
    } catch (err) {
        res.render("login", { message: "Something went wrong." });
    }
});




app.get('/submit', async function (req, res) {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    let secrets = [];

    // Only fetch secrets if ?show=true
    if (req.query.show === 'true') {
        secrets = await Secret.find({ userId: req.session.user._id });
    }

    res.render("submit", {
        userEmail: req.session.user.email,
        userPassword: req.session.user.password, // ⚠️ Just for display, not secure
        secrets: secrets
    });
});



app.post('/submit', async function (req, res) {
    if (!req.session.user) {
        return res.redirect("/login");  // Redirect to login if not logged in
    }

    const secret = req.body.secret;

    // Create a new secret
    const newSecret = new Secret({
        secret: secret,
        userId: req.session.user._id  // Link secret to logged-in user
    });

    try {
        // Save the secret in the database using await
        await newSecret.save();

        // Redirect to the secrets page where secrets are displayed
        res.redirect("/submit");

    } catch (err) {
        console.log(err);
        return res.send("Error saving the secret.");
    }
});

app.get('/secrets', async function (req, res) {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    try {
        // ✅ Show only secrets submitted by the logged-in user:
        const secrets = await Secret.find({ userId: req.session.user._id });
        res.render("secrets", { secrets: secrets });
    } catch (err) {
        console.log(err);
        res.send("Error retrieving secrets.");
    }
});



app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        } else {
            res.redirect('/');
        }
    });
});
main(); // ← You forgot to call this!


app.listen(3000, function () {
    console.log("Server started on port 3000");
});
