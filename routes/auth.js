const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
require("dotenv").config();

const NEW_REFRESH_SECRET = "asdfasdfasdfasdf";
const NEW_ACCESS_TOKEN_SECRET = "LFSLDJK";
const NEW_ACCESS_TOKEN_EXPIRY_TIME = 883600000;
const NEW_REFRESH_TOKEN_EXPIRY_TIME = 888640000;

const newRefreshTokens = [];

router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }
    const newUser = new User({
      name,
      email,
      password,
    });
    const salt = await bcrypt.genSalt(10);
    newUser.password = await bcrypt.hash(password, salt);
    await newUser.save();

    const _user = {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email,
    };
    const token = generateAccessToken(_user);
    const refreshToken = generateRefreshToken(_user);
    res.status(200).json({
      token,
      refreshToken,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const _user = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    const token = generateAccessToken(_user);
    const refreshToken = generateRefreshToken(_user);
    newRefreshTokens.push(refreshToken);

    res.status(200).json({
      refreshToken,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post("/getAccessToken", Authenticate, (req, res) => {
  try {
    console.log(req.body);
    const userData = req.user;
    const JWT_TOKEN = generateAccessToken({
      id: userData.id,
      name: userData.name,
      email: userData.email,
    });
    res.status(200).json({ token: JWT_TOKEN });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: err.message });
  }
});

function Authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null)
    return res
      .sendStatus(401)
      .json({ message: "Unauthorized! No Token Found" });

  try {
    const user = jwt.verify(token, NEW_ACCESS_TOKEN_SECRET);
    console.log(`################################################################
        Request Initiated  
        -- Name   : ${user.name}  
        -- Email  : ${user.email}  
        -- Host   : ${req.get("Host")}
        -- IP     : "${req.clientIp}" 
        -- Method : ${req.method} 
        -- Path   : "${
          req.path
        }"\n################################################################`);

    req.user = user;
    next();
  } catch (err) {
    console.log("Invalid Token ", err.message);
    return res.status(403).json({ message: err.message });
  }
}

function generateAccessToken(user) {
  return jwt.sign(user, NEW_ACCESS_TOKEN_SECRET, {
    expiresIn: NEW_ACCESS_TOKEN_EXPIRY_TIME,
  });
}

function generateRefreshToken(user) {
  return jwt.sign(user, NEW_REFRESH_SECRET, {
    expiresIn: NEW_REFRESH_TOKEN_EXPIRY_TIME,
  });
}

module.exports = { router: router, Authenticate: Authenticate };
