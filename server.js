require("dotenv").config();

const cors = require("cors");
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();


app.use(cors({
  origin: "http://localhost:5173"
}));

app.use(express.json());
app.use(express.json());

const PORT = process.env.PORT || 5000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.query("SELECT NOW()")
  .then(() => {
    console.log("Database connected successfully");
  })
  .catch((error) => {
    console.error("Database connection error:", error.message);
  });

  function authenticateToken(req, res, next) {

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Access denied. No token provided."
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (error, user) => {

    if (error) {
      return res.status(403).json({
        message: "Invalid or expired token"
      });
    }

    req.user = user;
    next();
  });
}

  app.post("/api/auth/register", async (req, res) => {

  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "Name, email and password are required"
    });
  }

  try {

    const existingUser = await pool.query(
  "SELECT id FROM users WHERE email = $1",
  [email]
);

if (existingUser.rows.length > 0) {
  return res.status(409).json({
    message: "Email already registered"
  });
}
  const hashedPassword = await bcrypt.hash(password, 10);

  const result = await pool.query(
    `INSERT INTO users (name, email, password)
     VALUES ($1, $2, $3)
     RETURNING id, name, email, role, status, created_at`,
    [name, email, hashedPassword]
  );

  res.status(201).json({
    message: "Student registered successfully",
    user: result.rows[0]
  });

} catch (error) {
  console.error(error);

  res.status(500).json({
    message: "Server error"
  });
}

});

app.post("/api/auth/login", async (req, res) => {

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required"
    });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    if (user.status !== "ACTIVE") {
      return res.status(403).json({
        message: "Account is inactive"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});


function authorizeAdmin(req, res, next) {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({
      message: "Admin access required"
    });
  }

  next();
}

function authorizeStudent(req, res, next) {
  if (req.user.role !== "STUDENT") {
    return res.status(403).json({
      message: "Student access required"
    });
  }

  next();
}

app.get(
  "/api/admin/dashboard",
  authenticateToken,
  authorizeAdmin,
  (req, res) => {
    res.json({
      message: "Welcome to the Admin Dashboard",
      user: req.user
    });
  }
);

app.get(
  "/api/student/dashboard",
  authenticateToken,
  authorizeStudent,
  (req, res) => {
    res.json({
      message: "Welcome to the Student Dashboard",
      user: req.user
    });
  }
);

app.get(
  "/api/auth/profile",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {

  try {
    const result = await pool.query(
      `SELECT id, name, email, role, status, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.get("/", (req, res) => {
  res.send("Quiz Management API is running");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});