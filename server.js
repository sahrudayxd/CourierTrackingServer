const express = require("express");
const sqlite3 = require("sqlite3");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Initialize Express application
const app = express();
app.use(express.json());

app.use(cors());

// Define database path
const dbPath = "server.db";
const db = new sqlite3.Database(dbPath);

const generateJWTToken = (payload) => {
  return jwt.sign(payload, "whoCares", { expiresIn: 30 });
};

// Sign-up API
app.post("/signUp", async (request, response) => {
  const { username, password, isAdmin } = request.body;

  // Check if the username already exists
  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (error, user) => {
      if (error) {
        return response
          .status(500)
          .send({ message: "Server Error: Unable to fetch User" });
      }

      if (user) {
        return response.status(400).send({
          message: "Username already exists. Try another Username.",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user into database
      const insertUserQuery = `
        INSERT INTO users (username, password, is_admin)
        VALUES (?, ?, ?)
      `;

      db.run(insertUserQuery, [username, hashedPassword, isAdmin]);

      const jwtToken = generateJWTToken({ username });
      response.status(200).send({
        message: "User signed up successfully.",
        jwtToken,
        userDetails: {
          username,
          isAdmin,
        },
      });
    }
  );
});

// Sign-In API
app.post("/signIn", async (request, response) => {
  const { username, password } = request.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (error, user) => {
      if (error) {
        return response
          .status(500)
          .send({ message: "Server Error: Unable to fetch User" });
      }

      if (!user) {
        return response
          .status(400)
          .send("Invalid username. Enter a valid username.");
      }

      // Check if password matches
      const isPasswordMatched = await bcrypt.compare(password, user.password);
      if (!isPasswordMatched) {
        return response
          .status(400)
          .send("Invalid password. Enter valid password.");
      }

      const jwtToken = generateJWTToken({ username });
      response.status(200).send({
        message: "User signed up successfully.",
        jwtToken,
        userDetails: {
          username,
          isAdmin: user.is_admin,
        },
      });
    }
  );
});

const PORT = 3005;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
