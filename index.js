const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/User");
const Resources = require("./models/Resources");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const fs = require("fs");
const dotenv=require("dotenv");
const app = express();

dotenv.config();

// CORS configuration to allow multiple origins
const allowedOrigins = [
  "https://notes-app-client-weld.vercel.app",
  "https://notes-app-client-eqdslye1g-kshitizgupta31s-projects.vercel.app",
  "http://localhost:3000" // For local development
];

app.use(cors({ 
  credentials: true, 
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json());
app.use(cookieParser());

const uploadMiddleware = multer({ dest: "uploads/" });
const secret = process.env.secret || "default-secret-key";
const MONGO_URI = process.env.url || "mongodb://localhost:27017/sky-notes";

const connect = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("Mongodb connected");
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
};

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Token is missing" });
  }
  jwt.verify(token, secret, (err, info) => {
    if (err) {
      return res.status(403).json({ error: "Token is invalid" });
    }
    req.user = info;
    next();
  });
};

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;
  console.log("req.body: ", username + " " + email + " " + password);
  try {
    let isAdmin = false;
    if (username === "yashpredator" || username === "saransh") isAdmin = true;
    const hashPass = bcrypt.hashSync(password, 10);
    const userDoc = await User.create({
      username,
      email,
      password: hashPass,
      isAdmin: isAdmin,
    });
    console.log("userDoc: ", userDoc);
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) {
    return res.status(400).json("wrong credentials");
  }
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie("token", token).json({
        id: userDoc._id,
        username,
        isAdmin: userDoc.isAdmin,
      });
    });
  } else {
    res.status(400).json("wrong credentials");
  }
});

app.post("/resources", uploadMiddleware.single("file"), verifyToken, async (req, res) => {
  try {
    let coverPath = "";
    
    // Handle file upload if provided
    if (req.file) {
      const { originalname, path } = req.file;
      const parts = originalname.split(".");
      const ext = parts[parts.length - 1];
      const newPath = path + "." + ext;
      fs.renameSync(path, newPath);
      coverPath = newPath;
    }

    const { title, summary, content, cloudpath, website } = req.body;
    
    // Use cloudpath if provided, otherwise use local file path
    const finalCoverPath = cloudpath || coverPath;
    
    const postDoc = await Resources.create({
      title,
      summary,
      cloudpath: finalCoverPath,
      content,
      cover: finalCoverPath,
      website: website,
      author: req.user.id,
    });

    console.log("Resource created successfully:", postDoc._id);
    res.json(postDoc);
  } catch (error) {
    console.error("Error creating resource:", error);
    res.status(500).json({ error: "Failed to create resource" });
  }
});

app.get("/profile", verifyToken, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  const userDoc = await User.findById(req.user._id);
  if (!userDoc) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ username: userDoc.username, isAdmin: userDoc.isAdmin });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    sameSite: "none",
    secure: true,
  });
  res.status(200).json({ message: "Logged out successfully" });
});

app.get("/resources", async (req, res) => {
  res.json(
    await Resources.find()
      .populate("author", ["username"])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

app.get("/resources/:id", async (req, res) => {
  const { id } = req.params;
  const postDoc = await Resources.findById(id).populate("author", ["username"]);
  res.json(postDoc);
});

app.get("/", (req, res) => {
  res.send("Sky_Notes Server");
});

app.listen(4000, () => {
  connect();
  console.log(`Server Running on Port:4000`);
});
