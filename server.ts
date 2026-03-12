import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import Database from "better-sqlite3";

const app = express();
const PORT = 3000;
const db = new Database("scans.db");

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_code TEXT,
    fixed_code TEXT,
    summary TEXT,
    issue_count INTEGER,
    changes_json TEXT,
    test_script TEXT,
    test_result TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

app.use(express.json({ limit: '50mb' }));

// API Routes
app.get("/api/history", (req, res) => {
  try {
    const history = db.prepare("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50").all();
    res.json(history);
  } catch (error) {
    console.error("History fetch error:", error);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

app.post("/api/scan", (req, res) => {
  console.log("Incoming scan save request...");
  const { original_code, fixed_code, summary, issue_count, changes_json, test_script, test_result } = req.body;
  
  if (!original_code || !fixed_code) {
    console.warn("Missing required fields in scan save request");
    return res.status(400).json({ error: "Missing code fields" });
  }

  try {
    const info = db.prepare("INSERT INTO scans (original_code, fixed_code, summary, issue_count, changes_json, test_script, test_result) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(original_code, fixed_code, summary, issue_count, changes_json, test_script, test_result);
    console.log("Scan saved successfully, ID:", info.lastInsertRowid);
    res.json({ id: info.lastInsertRowid, status: "shield_active" });
  } catch (error) {
    console.error("Scan save error:", error);
    res.status(500).json({ error: "Shield logging failed" });
  }
});

app.delete("/api/history", (req, res) => {
  try {
    db.prepare("DELETE FROM scans").run();
    res.json({ status: "history_cleared" });
  } catch (error) {
    res.status(500).json({ error: "Failed to clear history" });
  }
});

async function startServer() {
  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
