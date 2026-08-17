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
  "/api/admin/statistics",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE role = 'STUDENT')::int AS total_students,
          COUNT(*) FILTER (
            WHERE role = 'STUDENT' AND status = 'ACTIVE'
          )::int AS active_students,
          COUNT(*) FILTER (
            WHERE role = 'STUDENT' AND status = 'INACTIVE'
          )::int AS inactive_students,
          COUNT(*) FILTER (WHERE role = 'ADMIN')::int AS total_admins
        FROM users
      `);

      res.json({
        statistics: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.get(
  "/api/admin/users",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT id, name, email, role, status, created_at
        FROM users
        ORDER BY created_at DESC
      `);

      res.json({
        users: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.patch(
  "/api/admin/users/:id/status",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const userId = Number(req.params.id);
    const { status } = req.body;

    if (!["ACTIVE", "INACTIVE"].includes(status)) {
      return res.status(400).json({
        message: "Status must be ACTIVE or INACTIVE"
      });
    }

    if (userId === req.user.id) {
      return res.status(400).json({
        message: "You cannot deactivate your own account"
      });
    }

    try {
      const result = await pool.query(
        `UPDATE users
         SET status = $1
         WHERE id = $2 AND role = 'STUDENT'
         RETURNING id, name, email, role, status`,
        [status, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Student not found"
        });
      }

      res.json({
        message: `Student ${status.toLowerCase()} successfully`,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

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

app.get(
  "/api/admin/categories",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT id, name, description
        FROM categories
        ORDER BY name
      `);

      res.json({
        categories: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.get(
  "/api/admin/quizzes",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          q.id,
          q.title,
          q.description,
          q.category_id,
          c.name AS category_name,
          q.difficulty,
          q.duration,
          q.passing_score,
          q.max_attempts,
          q.status,
          q.created_at,
          q.updated_at
        FROM quizzes q
        JOIN categories c ON q.category_id = c.id
        ORDER BY q.created_at DESC
      `);

      res.json({
        quizzes: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.post(
  "/api/admin/quizzes",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const {
      title,
      description,
      category_id,
      difficulty,
      duration,
      passing_score,
      max_attempts
    } = req.body;

    if (
      !title ||
      !category_id ||
      !difficulty ||
      !duration ||
      passing_score === undefined ||
      !max_attempts
    ) {
      return res.status(400).json({
        message: "Please provide all required quiz fields"
      });
    }

    try {
      const result = await pool.query(
        `INSERT INTO quizzes (
          title,
          description,
          category_id,
          difficulty,
          duration,
          passing_score,
          max_attempts
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *`,
        [
          title,
          description,
          category_id,
          difficulty,
          duration,
          passing_score,
          max_attempts
        ]
      );

      res.status(201).json({
        message: "Quiz created successfully",
        quiz: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.put(
  "/api/admin/quizzes/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const quizId = Number(req.params.id);

    const {
      title,
      description,
      category_id,
      difficulty,
      duration,
      passing_score,
      max_attempts
    } = req.body;

    if (
      !title ||
      !category_id ||
      !difficulty ||
      !duration ||
      passing_score === undefined ||
      !max_attempts
    ) {
      return res.status(400).json({
        message: "Please provide all required quiz fields"
      });
    }

    try {
      const result = await pool.query(
        `UPDATE quizzes
         SET title = $1,
             description = $2,
             category_id = $3,
             difficulty = $4,
             duration = $5,
             passing_score = $6,
             max_attempts = $7,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $8
         RETURNING *`,
        [
          title,
          description,
          category_id,
          difficulty,
          duration,
          passing_score,
          max_attempts,
          quizId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Quiz not found"
        });
      }

      res.json({
        message: "Quiz updated successfully",
        quiz: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.delete(
  "/api/admin/quizzes/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const quizId = Number(req.params.id);

    try {
      const result = await pool.query(
        `DELETE FROM quizzes
         WHERE id = $1
         RETURNING id`,
        [quizId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Quiz not found"
        });
      }

      res.json({
        message: "Quiz deleted successfully"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.patch(
  "/api/admin/quizzes/:id/status",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const quizId = Number(req.params.id);

    try {
      const result = await pool.query(
        `UPDATE quizzes
         SET status = CASE
           WHEN status = 'PUBLISHED' THEN 'UNPUBLISHED'
           ELSE 'PUBLISHED'
         END,
         updated_at = CURRENT_TIMESTAMP
         WHERE id = $1
         RETURNING *`,
        [quizId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Quiz not found"
        });
      }

      res.json({
        message: `Quiz ${result.rows[0].status.toLowerCase()} successfully`,
        quiz: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.get("/", (req, res) => {
  res.send("Quiz Management API is running");
});



app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});