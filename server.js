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

app.post(
  "/api/admin/categories",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({
        message: "Category name is required"
      });
    }

    try {
      const result = await pool.query(
        `INSERT INTO categories (name, description)
         VALUES ($1, $2)
         RETURNING *`,
        [name, description]
      );

      res.status(201).json({
        message: "Category created successfully",
        category: result.rows[0]
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          message: "Category name already exists"
        });
      }

      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.put(
  "/api/admin/categories/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const categoryId = Number(req.params.id);
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({
        message: "Category name is required"
      });
    }

    try {
      const result = await pool.query(
        `UPDATE categories
         SET name = $1, description = $2
         WHERE id = $3
         RETURNING *`,
        [name, description, categoryId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Category not found"
        });
      }

      res.json({
        message: "Category updated successfully",
        category: result.rows[0]
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          message: "Category name already exists"
        });
      }

      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

app.delete(
  "/api/admin/categories/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const categoryId = Number(req.params.id);

    try {
      const result = await pool.query(
        `DELETE FROM categories
         WHERE id = $1
         RETURNING id`,
        [categoryId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Category not found"
        });
      }

      res.json({
        message: "Category deleted successfully"
      });
    } catch (error) {
      if (error.code === "23503") {
        return res.status(409).json({
          message: "Cannot delete a category used by a quiz"
        });
      }

      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);

// Get all questions with their quiz and options
app.get(
  "/api/admin/questions",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          q.id,
          q.quiz_id,
          qu.title AS quiz_title,
          q.question_text,
          q.marks,
          q.explanation,
          q.difficulty,
          q.created_at,
          COALESCE(
            json_agg(
              json_build_object(
                'id', o.id,
                'option_text', o.option_text,
                'is_correct', o.is_correct
              )
              ORDER BY o.id
            ) FILTER (WHERE o.id IS NOT NULL),
            '[]'::json
          ) AS options
        FROM questions q
        JOIN quizzes qu ON q.quiz_id = qu.id
        LEFT JOIN options o ON o.question_id = q.id
        GROUP BY q.id, qu.title
        ORDER BY q.created_at DESC
      `);

      res.json({
        questions: result.rows,
      });
    } catch (error) {
      console.error("Get questions error:", error);

      res.status(500).json({
        message: "Server error while fetching questions",
      });
    }
  }
);

// Create a question with answer options
app.post(
  "/api/admin/questions",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const {
      quiz_id,
      question_text,
      marks,
      explanation,
      difficulty,
      options,
    } = req.body;

    // Validate the question details
    if (!quiz_id || !question_text?.trim() || !difficulty) {
      return res.status(400).json({
        message: "Quiz, question text and difficulty are required",
      });
    }

    // Remove options containing only empty spaces
    const validOptions = Array.isArray(options)
      ? options.filter((option) => option.option_text?.trim())
      : [];

    if (validOptions.length < 2) {
      return res.status(400).json({
        message: "A question must have at least two options",
      });
    }

    const correctOptions = validOptions.filter(
      (option) => option.is_correct === true
    );

    if (correctOptions.length !== 1) {
      return res.status(400).json({
        message: "Select exactly one correct answer",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const questionResult = await client.query(
        `INSERT INTO questions
          (quiz_id, question_text, marks, explanation, difficulty)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [
          quiz_id,
          question_text.trim(),
          marks || 1,
          explanation?.trim() || null,
          difficulty,
        ]
      );

      const question = questionResult.rows[0];

      for (const option of validOptions) {
        await client.query(
          `INSERT INTO options
            (question_id, option_text, is_correct)
           VALUES ($1, $2, $3)`,
          [
            question.id,
            option.option_text.trim(),
            option.is_correct === true,
          ]
        );
      }

      await client.query("COMMIT");

      res.status(201).json({
        message: "Question created successfully",
        question,
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Create question error:", error);

      res.status(500).json({
        message: "Server error while creating question",
      });
    } finally {
      client.release();
    }
  }
);

// Update a question and its options
app.put(
  "/api/admin/questions/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { id } = req.params;

    const {
      quiz_id,
      question_text,
      marks,
      explanation,
      difficulty,
      options,
    } = req.body;

    if (!quiz_id || !question_text?.trim() || !difficulty) {
      return res.status(400).json({
        message: "Quiz, question text and difficulty are required",
      });
    }

    const validOptions = Array.isArray(options)
      ? options.filter((option) => option.option_text?.trim())
      : [];

    if (validOptions.length < 2) {
      return res.status(400).json({
        message: "A question must have at least two options",
      });
    }

    const correctOptions = validOptions.filter(
      (option) => option.is_correct === true
    );

    if (correctOptions.length !== 1) {
      return res.status(400).json({
        message: "Select exactly one correct answer",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const questionResult = await client.query(
        `UPDATE questions
         SET quiz_id = $1,
             question_text = $2,
             marks = $3,
             explanation = $4,
             difficulty = $5
         WHERE id = $6
         RETURNING *`,
        [
          quiz_id,
          question_text.trim(),
          marks || 1,
          explanation?.trim() || null,
          difficulty,
          id,
        ]
      );

      if (questionResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          message: "Question not found",
        });
      }

      // Remove the previous options
      await client.query(
        "DELETE FROM options WHERE question_id = $1",
        [id]
      );

      // Insert the updated options
      for (const option of validOptions) {
        await client.query(
          `INSERT INTO options
            (question_id, option_text, is_correct)
           VALUES ($1, $2, $3)`,
          [
            id,
            option.option_text.trim(),
            option.is_correct === true,
          ]
        );
      }

      await client.query("COMMIT");

      res.json({
        message: "Question updated successfully",
        question: questionResult.rows[0],
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Update question error:", error);

      res.status(500).json({
        message: "Server error while updating question",
      });
    } finally {
      client.release();
    }
  }
);

// Delete a question
app.delete(
  "/api/admin/questions/:id",
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { id } = req.params;

    try {
      const result = await pool.query(
        `DELETE FROM questions
         WHERE id = $1
         RETURNING id`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Question not found",
        });
      }

      res.json({
        message: "Question deleted successfully",
      });
    } catch (error) {
      console.error("Delete question error:", error);

      res.status(500).json({
        message: "Server error while deleting question",
      });
    }
  }
);

// Get published quizzes for students
app.get(
  "/api/student/quizzes",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          q.id,
          q.title,
          q.description,
          q.difficulty,
          q.duration,
          q.passing_score,
          q.max_attempts,
          q.status,
          c.name AS category_name,
          COUNT(questions.id)::INTEGER AS question_count
        FROM quizzes q
        JOIN categories c ON c.id = q.category_id
        LEFT JOIN questions ON questions.quiz_id = q.id
        WHERE q.status = 'PUBLISHED'
        GROUP BY q.id, c.name
        ORDER BY q.created_at DESC
      `);

      res.json({
        quizzes: result.rows,
      });
    } catch (error) {
      console.error("Get student quizzes error:", error);

      res.status(500).json({
        message: "Server error while fetching quizzes",
      });
    }
  }
);

// Get details of one published quiz
app.get(
  "/api/student/quizzes/:id",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    const { id } = req.params;

    try {
      const result = await pool.query(
        `SELECT
           q.id,
           q.title,
           q.description,
           q.difficulty,
           q.duration,
           q.passing_score,
           q.max_attempts,
           q.status,
           c.name AS category_name,
           COUNT(questions.id)::INTEGER AS question_count
         FROM quizzes q
         JOIN categories c ON c.id = q.category_id
         LEFT JOIN questions ON questions.quiz_id = q.id
         WHERE q.id = $1
           AND q.status = 'PUBLISHED'
         GROUP BY q.id, c.name`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          message: "Published quiz not found",
        });
      }

      const attemptResult = await pool.query(
        `SELECT COUNT(*)::INTEGER AS attempt_count
         FROM attempts
         WHERE quiz_id = $1
           AND user_id = $2`,
        [id, req.user.id]
      );

      res.json({
        quiz: {
          ...result.rows[0],
          attempt_count: attemptResult.rows[0].attempt_count,
        },
      });
    } catch (error) {
      console.error("Get quiz details error:", error);

      res.status(500).json({
        message: "Server error while fetching quiz details",
      });
    }
  }
);

// Start a quiz attempt
app.post(
  "/api/student/quizzes/:id/start",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    const quizId = req.params.id;
    const userId = req.user.id;

    try {
      const quizResult = await pool.query(
        `SELECT id, title, duration, max_attempts
         FROM quizzes
         WHERE id = $1
           AND status = 'PUBLISHED'`,
        [quizId]
      );

      if (quizResult.rows.length === 0) {
        return res.status(404).json({
          message: "Published quiz not found",
        });
      }

      const quiz = quizResult.rows[0];
const questionCountResult = await pool.query(
  `SELECT COUNT(*)::INTEGER AS question_count
   FROM questions
   WHERE quiz_id = $1`,
  [quizId]
);

if (questionCountResult.rows[0].question_count === 0) {
  return res.status(400).json({
    message: "This quiz does not contain any questions",
  });
}



      // Continue an attempt that is already in progress
      let attemptResult = await pool.query(
        `SELECT id, started_at, status
         FROM attempts
         WHERE quiz_id = $1
           AND user_id = $2
           AND status = 'IN_PROGRESS'
         ORDER BY started_at DESC
         LIMIT 1`,
        [quizId, userId]
      );

      let attempt;

      if (attemptResult.rows.length > 0) {
        attempt = attemptResult.rows[0];
      } else {
        const countResult = await pool.query(
          `SELECT COUNT(*)::INTEGER AS attempt_count
           FROM attempts
           WHERE quiz_id = $1
             AND user_id = $2`,
          [quizId, userId]
        );

        if (countResult.rows[0].attempt_count >= quiz.max_attempts) {
          return res.status(403).json({
            message: "Maximum quiz attempts reached",
          });
        }

        attemptResult = await pool.query(
          `INSERT INTO attempts (quiz_id, user_id)
           VALUES ($1, $2)
           RETURNING id, started_at, status`,
          [quizId, userId]
        );

        attempt = attemptResult.rows[0];
      }

      const questionsResult = await pool.query(
        `SELECT
           q.id,
           q.question_text,
           q.marks,
           q.difficulty,
           COALESCE(
             json_agg(
               json_build_object(
                 'id', o.id,
                 'option_text', o.option_text
               )
               ORDER BY o.id
             ) FILTER (WHERE o.id IS NOT NULL),
             '[]'::json
           ) AS options
         FROM questions q
         LEFT JOIN options o ON o.question_id = q.id
         WHERE q.quiz_id = $1
         GROUP BY q.id
         ORDER BY q.id`,
        [quizId]
      );

      if (questionsResult.rows.length === 0) {
        return res.status(400).json({
          message: "This quiz does not contain any questions",
        });
      }

      const expiresAt = new Date(
  new Date(attempt.started_at).getTime() +
    Number(quiz.duration) * 60 * 1000
).toISOString();

attempt.expires_at = expiresAt;

      res.status(201).json({
        message: "Quiz attempt started",
        quiz: {
          id: quiz.id,
          title: quiz.title,
          duration: quiz.duration,
        },
        attempt,
        questions: questionsResult.rows,
      });
    } catch (error) {
      console.error("Start quiz error:", error);

      res.status(500).json({
        message: "Server error while starting quiz",
      });
    }
  }
);

// Submit a quiz attempt and calculate the result
app.post(
  "/api/student/attempts/:attemptId/submit",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    const { attemptId } = req.params;
    const { answers = [] } = req.body;
    const userId = req.user.id;

    if (!Array.isArray(answers)) {
      return res.status(400).json({
        message: "Answers must be provided as an array",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const attemptResult = await client.query(
        `SELECT
           a.id,
           a.quiz_id,
           a.status,
           a.started_at,
           q.title AS quiz_title,
           q.duration,
           q.passing_score
         FROM attempts a
         JOIN quizzes q ON q.id = a.quiz_id
         WHERE a.id = $1
           AND a.user_id = $2
         FOR UPDATE`,
        [attemptId, userId]
      );

      if (attemptResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          message: "Quiz attempt not found",
        });
      }

      const attempt = attemptResult.rows[0];

      if (attempt.status === "COMPLETED") {
        await client.query("ROLLBACK");

        return res.status(400).json({
          message: "This quiz attempt has already been submitted",
        });
      }

      const questionsResult = await client.query(
        `SELECT
           q.id AS question_id,
           q.marks,
           json_agg(
             json_build_object(
               'id', o.id,
               'is_correct', o.is_correct
             )
             ORDER BY o.id
           ) AS options
         FROM questions q
         JOIN options o ON o.question_id = q.id
         WHERE q.quiz_id = $1
         GROUP BY q.id
         ORDER BY q.id`,
        [attempt.quiz_id]
      );

      const submittedAnswers = new Map(
        answers.map((answer) => [
          Number(answer.question_id),
          answer.selected_option_id === null ||
          answer.selected_option_id === undefined
            ? null
            : Number(answer.selected_option_id),
        ])
      );

      let score = 0;
      let totalMarks = 0;
      let correctAnswers = 0;
      let incorrectAnswers = 0;
      let unanswered = 0;

      await client.query(
        "DELETE FROM answers WHERE attempt_id = $1",
        [attemptId]
      );

      for (const question of questionsResult.rows) {
        const questionId = Number(question.question_id);
        const questionMarks = Number(question.marks);
        const selectedOptionId =
          submittedAnswers.get(questionId) ?? null;

        totalMarks += questionMarks;

        if (selectedOptionId === null) {
          unanswered += 1;

          await client.query(
            `INSERT INTO answers
              (attempt_id, question_id, selected_option_id, is_correct)
             VALUES ($1, $2, NULL, NULL)`,
            [attemptId, questionId]
          );

          continue;
        }

        const selectedOption = question.options.find(
          (option) => Number(option.id) === selectedOptionId
        );

        if (!selectedOption) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            message: `Invalid option selected for question ${questionId}`,
          });
        }

        const isCorrect = selectedOption.is_correct === true;

        if (isCorrect) {
          correctAnswers += 1;
          score += questionMarks;
        } else {
          incorrectAnswers += 1;
        }

        await client.query(
          `INSERT INTO answers
            (attempt_id, question_id, selected_option_id, is_correct)
           VALUES ($1, $2, $3, $4)`,
          [attemptId, questionId, selectedOptionId, isCorrect]
        );
      }

      const percentage =
        totalMarks > 0
          ? Number(((score / totalMarks) * 100).toFixed(2))
          : 0;

      const result =
        percentage >= Number(attempt.passing_score)
          ? "PASS"
          : "FAIL";

      const elapsedSeconds = Math.floor(
        (Date.now() - new Date(attempt.started_at).getTime()) / 1000
      );

      const timeTaken = Math.min(
        Math.max(elapsedSeconds, 0),
        Number(attempt.duration) * 60
      );

      await client.query(
        `UPDATE attempts
         SET score = $1,
             percentage = $2,
             correct_answers = $3,
             incorrect_answers = $4,
             unanswered = $5,
             time_taken = $6,
             status = 'COMPLETED',
             completed_at = CURRENT_TIMESTAMP
         WHERE id = $7`,
        [
          score,
          percentage,
          correctAnswers,
          incorrectAnswers,
          unanswered,
          timeTaken,
          attemptId,
        ]
      );

      await client.query("COMMIT");

      res.json({
        message: "Quiz submitted successfully",
        result: {
          attempt_id: Number(attemptId),
          quiz_title: attempt.quiz_title,
          score,
          total_marks: totalMarks,
          percentage,
          correct_answers: correctAnswers,
          incorrect_answers: incorrectAnswers,
          unanswered,
          time_taken: timeTaken,
          status: result,
        },
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Submit quiz error:", error);

      res.status(500).json({
        message: "Server error while submitting quiz",
      });
    } finally {
      client.release();
    }
  }
);

// Get one completed attempt with answer review
app.get(
  "/api/student/attempts/:attemptId/result",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    const { attemptId } = req.params;
    const userId = req.user.id;

    try {
      const attemptResult = await pool.query(
        `SELECT
           a.id AS attempt_id,
           a.quiz_id,
           q.title AS quiz_title,
           q.passing_score,
           a.score,
           a.percentage,
           a.correct_answers,
           a.incorrect_answers,
           a.unanswered,
           a.time_taken,
           a.started_at,
           a.completed_at,
           CASE
             WHEN a.percentage >= q.passing_score THEN 'PASS'
             ELSE 'FAIL'
           END AS result_status,
           COALESCE(SUM(questions.marks), 0)::INTEGER AS total_marks
         FROM attempts a
         JOIN quizzes q ON q.id = a.quiz_id
         LEFT JOIN questions ON questions.quiz_id = q.id
         WHERE a.id = $1
           AND a.user_id = $2
           AND a.status = 'COMPLETED'
         GROUP BY a.id, q.id`,
        [attemptId, userId]
      );

      if (attemptResult.rows.length === 0) {
        return res.status(404).json({
          message: "Completed quiz result not found",
        });
      }

      const reviewResult = await pool.query(
        `SELECT
           q.id AS question_id,
           q.question_text,
           q.explanation,
           q.marks,
           a.selected_option_id,
           a.is_correct,
           selected_option.option_text AS selected_option_text,
           correct_option.id AS correct_option_id,
           correct_option.option_text AS correct_option_text
         FROM questions q
         LEFT JOIN answers a
           ON a.question_id = q.id
          AND a.attempt_id = $1
         LEFT JOIN options selected_option
           ON selected_option.id = a.selected_option_id
         JOIN options correct_option
           ON correct_option.question_id = q.id
          AND correct_option.is_correct = TRUE
         WHERE q.quiz_id = $2
         ORDER BY q.id`,
        [attemptId, attemptResult.rows[0].quiz_id]
      );

      res.json({
        result: attemptResult.rows[0],
        review: reviewResult.rows,
      });
    } catch (error) {
      console.error("Get result error:", error);

      res.status(500).json({
        message: "Server error while fetching the result",
      });
    }
  }
);

// Get the logged-in student's completed attempt history
app.get(
  "/api/student/attempts",
  authenticateToken,
  authorizeStudent,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           a.id AS attempt_id,
           a.quiz_id,
           q.title AS quiz_title,
           c.name AS category_name,
           a.score,
           a.percentage,
           a.correct_answers,
           a.incorrect_answers,
           a.unanswered,
           a.time_taken,
           a.started_at,
           a.completed_at,
           CASE
             WHEN a.percentage >= q.passing_score THEN 'PASS'
             ELSE 'FAIL'
           END AS result_status
         FROM attempts a
         JOIN quizzes q ON q.id = a.quiz_id
         JOIN categories c ON c.id = q.category_id
         WHERE a.user_id = $1
           AND a.status = 'COMPLETED'
         ORDER BY a.completed_at DESC`,
        [req.user.id]
      );

      res.json({
        attempts: result.rows,
      });
    } catch (error) {
      console.error("Get attempt history error:", error);

      res.status(500).json({
        message: "Server error while fetching attempt history",
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