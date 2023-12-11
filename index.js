const express = require("express");
const app = express();
const cors = require("cors");
app.use(cors());
require("dotenv").config();
const mongoose = require("mongoose");

const requestIp = require("request-ip");
//importing routes
const { router: Auth } = require("./routes/auth");
const Budget = require("./routes/budget");

//authentication
const { Authenticate } = require("./routes/auth");

//connecting to database
mongoose.connect(
  "mongodb+srv://kshitijvarshney92:ZemmR3a7Kc2FqINy@cluster0.cjxz35u.mongodb.net/?retryWrites=true&w=majority"
);
const db = mongoose.connection;
db.on("error", (error) => {
  console.error("Connection error:", error);
});
db.once("open", () => {
  console.log("Connected to the database");
});

// parsing json
app.use(express.json());
app.use(requestIp.mw());
// parsing urlencoded data
app.use(express.urlencoded({ extended: false }));

// static files
// app.use('/', express.static(path.join(__dirname, 'public')));
app.get("/favicon.ico", (req, res) => {
  // You can send a default favicon or an empty response
  res.status(204).end();
});
app.get("/", (req, res) => {
  res.json({
    message: "Welcome to the Budget Api",
  });
});
//Test
app.get("/api/v1/test", Authenticate, (req, res) => {
  res.send("Hello World!");
});

// routes
app.use("/api/v1/auth", Auth);
// app.use('/api/v1/budget', Budget);
app.use("/api/v1/budget", Authenticate, Budget);

// error handling
app.use((req, res, next) => {
  const error = new Error("Not found");
  error.status = 404;
  next();
});

app.use((error, req, res, next) => {
  res.status(error.status || 500).json({
    message: error.message,
  });
});

// server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
