import os
import sqlite3
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import psutil
import subprocess
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

# Updated Pydantic model with name field
class PIDData(BaseModel):
    pid: int
    name: str  # New field
    result: str

# Database setup (in-memory SQLite) with name column
def setup_database():
    conn = sqlite3.connect(':memory:')  # Non-persistent database
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS process_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER NOT NULL,
            name TEXT NOT NULL,  
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    return conn

# Lifespan events for FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup database when starting
    app.state.db_conn = setup_database()
    yield
    # Cleanup when shutting down
    app.state.db_conn.close()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

current_process = None

# Helper functions (unchanged)
def get_current_pid():
    return os.getpid()

def kill_process_and_python_tasks(process_name="process_monitor.exe"):
    current_pid = get_current_pid()
    killed = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == process_name:
                proc.kill()
                killed.append(proc.info['name'])
            elif proc.info['name'] == "python.exe" and proc.info['pid'] != current_pid:
                proc.kill()
                killed.append(f"python.exe (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return killed

# Endpoints (unchanged except /pid)
@app.post("/start")
async def start_process():
    global current_process
    
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == "process_monitor.exe":
            raise HTTPException(status_code=400, detail="Process is already running")
    
    try:
        p = os.getpid()  # Get the parent PID
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exe_path = os.path.join(script_dir, "process_monitor.exe")
        # Pass the parent PID as argument
        current_process = subprocess.Popen([exe_path, str(p)])
        return JSONResponse(
            status_code=200,
            content={
                "message": "Process started successfully", 
                "pid": current_process.pid,
                "parent_pid": p  # Also return parent PID in response
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start process: {str(e)}")
    
@app.post("/stop")
async def stop_process():
    global current_process
    
    killed_processes = kill_process_and_python_tasks()
    
    if not killed_processes:
        raise HTTPException(status_code=404, detail="No processes found to kill")
    
    if current_process:
        current_process = None
    
    return JSONResponse(
        status_code=200,
        content={
            "message": "Processes killed successfully",
            "killed_processes": killed_processes
        }
    )

# Updated /pid endpoint to handle name field
@app.post("/pid")
async def receive_pid_data(data: PIDData):
    try:
        cursor = app.state.db_conn.cursor()
        cursor.execute(
            "INSERT INTO process_data (pid, name, result) VALUES (?, ?, ?)",
            (data.pid, data.name, data.result)
        )
        app.state.db_conn.commit()
        return {"message": "PID data stored successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store PID data: {str(e)}")

# Updated /pid GET endpoint to include name
@app.get("/pid")
async def get_pid_data():
    try:
        cursor = app.state.db_conn.cursor()
        cursor.execute("SELECT * FROM process_data ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        return {
            "data": [
                {
                    "id": row[0], 
                    "pid": row[1], 
                    "name": row[2],  # New field
                    "result": row[3], 
                    "timestamp": row[4]
                }
                for row in rows
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve PID data: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)