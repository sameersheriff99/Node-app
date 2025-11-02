const express = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const db = require("./db");

const app = express();
app.use(express.json());
const cors = require("cors");
app.use(cors());

// ✅ Middleware for authentication
function auth(role = null) {
  return (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ message: "No token" });

      const user = jwt.verify(token, process.env.JWT_SECRET);
      req.user = user;

      if (role && user.role !== role) {
        return res.status(403).json({ message: "Forbidden" });
      }

      next();
    } catch (err) {
      console.error("Auth error:", err);
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

// ✅ AUTH ROUTES
app.post("/auth/signup", (req, res) => {
  const { name, email, password, role = "user" } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password are required" });
  }

  db.query(
    "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
    [name, email, password, role],
    (err) => {
      if (err) {
        console.error("Signup DB error:", err);
        return res.status(500).json({ message: "Database error", error: err });
      }

      const user = { name, email, role };
      const token = jwt.sign(user, process.env.JWT_SECRET);

      res.status(201).json({ user, token });
    }
  );
});

app.post("/auth/signin", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  console.log("Signin request received:", { email, password });

  db.query("SELECT * FROM users WHERE email=?", [email], (err, rows) => {
    if (err) {
      console.error("Signin DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }

    if (rows.length === 0) {
      console.log("User not found in DB");
      return res.status(404).json({ message: "User not found" });
    }

    const user = rows[0];
    console.log("User fetched from DB:", user);

    if (password !== user.password) {
      console.log("Password mismatch! Provided:", password, "Stored:", user.password);
      return res.status(401).json({ message: "Wrong password" });
    }

    console.log("Password matched, signing JWT...");
    delete user.password;
    const token = jwt.sign(user, process.env.JWT_SECRET);

    console.log("JWT generated:", token);
    res.json({ user, token });
  });
});

// ✅ PRODUCT ROUTES
app.get("/products", auth(), (req, res) => {
  db.query("SELECT * FROM products", (err, rows) => {
    if (err) {
      console.error("Get products DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.json(rows);
  });
});

app.post("/products", auth("admin"), (req, res) => {
  const { name, price } = req.body;
  if (!name || price === undefined) {
    return res.status(400).json({ message: "Name and price are required" });
  }

  db.query("INSERT INTO products (name, price) VALUES (?, ?)", [name, price], (err) => {
    if (err) {
      console.error("Create product DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.status(201).json({ message: "Product created" });
  });
});

app.put("/products/:id", auth("admin"), (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;

  if (!name || price === undefined) {
    return res.status(400).json({ message: "Name and price are required" });
  }

  db.query("UPDATE products SET name=?, price=? WHERE id=?", [name, price, id], (err, result) => {
    if (err) {
      console.error("Update product DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json({ message: "Product updated" });
  });
});

app.delete("/products/:id", auth("admin"), (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM products WHERE id=?", [id], (err, result) => {
    if (err) {
      console.error("Delete product DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json({ message: "Product deleted" });
  });
});

// ✅ USER ROUTES
app.get("/users", auth("admin"), (req, res) => {
  db.query("SELECT id, name, email, role FROM users", (err, rows) => {
    if (err) {
      console.error("Get users DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.json(rows);
  });
});

app.put("/users/:id", auth("admin"), (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;
  if (!name || !email || !role) {
    return res.status(400).json({ message: "Name, email, and role are required" });
  }

  db.query("UPDATE users SET name=?, email=?, role=? WHERE id=?", [name, email, role, id], (err, result) => {
    if (err) {
      console.error("Update user DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User updated" });
  });
});

app.delete("/users/:id", auth("admin"), (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM users WHERE id=?", [id], (err, result) => {
    if (err) {
      console.error("Delete user DB error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted" });
  });
});

// ✅ Start server
app.listen(3000, () => console.log("✅ Server running on port 3000"));
