// server.js
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { kill } = require('process');

const app = express();
app.use(cors());
app.use(express.json());

// Database setup (SQLite in-memory)
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS process_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pid INTEGER NOT NULL,
      name TEXT NOT NULL,
      result TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

let currentProcess = null;

// Helper functions
function getCurrentPid() {
  return process.pid;
}

function killProcessAndPythonTasks(processName = "process_monitor.exe") {
  return new Promise((resolve) => {
    exec('tasklist', (error, stdout) => {
      const killed = [];
      const lines = stdout.split('\n');
      
      lines.forEach(line => {
        if (line.includes(processName)) {
          const pid = line.split(/\s+/)[1];
          try {
            kill(parseInt(pid));
            killed.push(processName);
          } catch (e) {
            console.error(`Failed to kill ${processName}: ${e}`);
          }
        } else if (line.includes("python.exe")) {
          const pid = line.split(/\s+/)[1];
          if (pid && pid !== getCurrentPid().toString()) {
            try {
              kill(parseInt(pid));
              killed.push(`python.exe (PID: ${pid})`);
            } catch (e) {
              console.error(`Failed to kill python.exe: ${e}`);
            }
          }
        }
      });
      
      resolve(killed);
    });
  });
}

// Endpoints
app.post('/start', async (req, res) => {
  try {
    // Check if process is already running
    exec('tasklist | find "process_monitor.exe"', (error) => {
      if (!error) {
        return res.status(400).json({ error: "Process is already running" });
      }

      const parentPid = getCurrentPid();
      const scriptDir = __dirname;
      const exePath = path.join(scriptDir, "process_monitor.exe");
      
      currentProcess = exec(`"${exePath}" ${parentPid}`, (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: `Failed to start process: ${err.message}` });
        }
      });

      res.json({
        message: "Process started successfully",
        pid: currentProcess.pid,
        parent_pid: parentPid
      });
    });
  } catch (err) {
    res.status(500).json({ error: `Failed to start process: ${err.message}` });
  }
});

app.post('/stop', async (req, res) => {
  try {
    const killedProcesses = await killProcessAndPythonTasks();
    
    if (killedProcesses.length === 0) {
      return res.status(404).json({ error: "No processes found to kill" });
    }
    
    currentProcess = null;
    
    res.json({
      message: "Processes killed successfully",
      killed_processes: killedProcesses
    });
  } catch (err) {
    res.status(500).json({ error: `Failed to stop processes: ${err.message}` });
  }
});

app.post('/pid', (req, res) => {
  const { pid, name, result } = req.body;
  
  db.run(
    "INSERT INTO process_data (pid, name, result) VALUES (?, ?, ?)",
    [pid, name, result],
    function(err) {
      if (err) {
        return res.status(500).json({ error: `Failed to store PID data: ${err.message}` });
      }
      res.json({ message: "PID data stored successfully" });
    }
  );
});

app.get('/pid', (req, res) => {
  db.all("SELECT * FROM process_data ORDER BY timestamp DESC", [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: `Failed to retrieve PID data: ${err.message}` });
    }
    res.json({
      data: rows.map(row => ({
        id: row.id,
        pid: row.pid,
        name: row.name,
        result: row.result,
        timestamp: row.timestamp
      }))
    });
  });
});

const PORT = 8000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});