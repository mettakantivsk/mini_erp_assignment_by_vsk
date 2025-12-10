const express = require("express");
const app = express();
app.use(express.json());
const cors = require("cors");
app.use(cors());

const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const dbPath = path.join(__dirname, "construction_erp.db");

let db;

let startTheServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => console.log("server started!!"));
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
};

startTheServer();


// ---------------- AUTH MIDDLEWARE ----------------
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        next();
      }
    });
  }
};

// ---------------- AUTH ROUTES ----------------
app.post("/auth/register",async  (req, res) => {
  const { name, email, password, role } = req.body;
  const password_hash = bcrypt.hashSync(password, 10);

  let userExits = await db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email]
  );
  if (userExits) {
    return res.status(200).json({ message: "Email already exists" });
  }

  await db.run(
    `INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)`,
    [name, email, password_hash, role],
    function (err) {
      if (err) {
        if (err.code === "SQLITE_CONSTRAINT") {
          return res.status(200).json({ message: "Email already exists" });
        }
        return res.status(200).json({ error: err.message });
      }

      res.send(JSON.stringify({ message: "User registered successfully", id: this.lastID }));
    }
  );
});


app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);

  try {
    const user = await db.get(
      `SELECT * FROM users WHERE email = ?`,
      [email]
    );
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const payload = { id: user.id, email: user.email, role: user.role };
    const token = jwt.sign(payload, "MY_SECRET_TOKEN", { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "DB error" });
  }
});


// ---------------- USERS CRUD ----------------
app.post("/users",authenticateToken, (req, res) => {
  const { name, email, password_hash, role } = req.body;

  db.run(
    `INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)`,
    [name, email, password_hash, role],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, message: "User created" });
    }
  );
});


app.get("/users", authenticateToken, async (req, res) => {
   let all_users =  await db.all(`SELECT * FROM users`);
   res.send(JSON.stringify({users: all_users}));
});

app.get("/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  let user = await db.get(`SELECT * FROM users WHERE id=${id}`);
  res.send(JSON.stringify({user}));
});

app.put("/users/:id", authenticateToken, async (req, res) => {
  const { name, email, role } = req.body;

  await db.run(
    `UPDATE users SET name=?, email=?, role=? WHERE id=?`,
    [name, email, role, req.params.id],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: "User updated" });
    }
  );
});

app.delete("/users/:id", authenticateToken, async (req, res) => {
await db.run(`DELETE FROM users WHERE id=?`, [req.params.id], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ message: "User deleted" });
  });
});


// ---------------- PROJECTS CRUD ----------------
app.post("/projects", authenticateToken, async (req, res) => {
  const { name, budget, spent, progress, status } = req.body;

  await db.run(
    `INSERT INTO projects (name, budget, spent, progress, status)
     VALUES (?,?,?,?,?)`,
    [name, budget, spent, progress, status],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.send(JSON.stringify({ id: this.lastID, message: "Project created" }));
    }
  );
});

app.get("/projects", authenticateToken, async (req, res) => {
  let all_projects =  await db.all(`SELECT * FROM projects`);
  res.send(JSON.stringify({projects: all_projects}));
});

app.put("/projects/:id", authenticateToken, async (req, res) => {
  const { name, budget, spent, progress, status } = req.body;

   await db.run(
    `UPDATE projects SET name=?, budget=?, spent=?, progress=?, status=? WHERE id=?`,
    [name, budget, spent, progress, status, req.params.id],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: "Project updated" });
    }
  );
});

app.delete("/projects/:id", authenticateToken, async (req, res) => {
  await db.run(`DELETE FROM projects WHERE id=?`, [req.params.id], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ message: "Project deleted" });
  });
});

// ---------------- AI ON RISK ANALYSIS ----------------
app.get("/ai/project-risk/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  const project = await db.get(`SELECT * FROM projects WHERE id = ?`, [id]);
  console.log(project);

  if (!project) {
    return res.status(404).json({ message: "Project not found" });
  }

  let riskScore = 0;
  let riskLevel = "Low";

  const budgetUsedPercent = (project.spent / project.budget) * 100;

  if (budgetUsedPercent > project.progress + 20) {
    riskScore += 50;
  }
 

  if (riskScore > 60) riskLevel = "Critical";
  else if (riskScore > 30) riskLevel = "High";
  else riskLevel = "Medium";

  res.json({
    projectId: project.id,
    budget: project.budget,
    spent: project.spent,
    progress: project.progress,
    risk_score: riskScore,
    risk_level: riskLevel,
  });
});

