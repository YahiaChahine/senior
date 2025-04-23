import sys
import psutil
import requests

def get_process_name(pid):
    """Get process name by PID"""
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "unknown"

def send_pid_data(pid, name):
    """Send PID data to the monitoring server"""
    url = "http://localhost:8000/pid"  # Update if your server is elsewhere
    data = {
        "pid": pid,
        "name": name,
        "result": "0"  # Marking all as safe (0)
    }
    
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        print(f"Successfully sent: PID {pid} ({name})")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send PID {pid}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python test.py <pid1> <pid2> <pid3> ...")
        sys.exit(1)
    
    # Get PIDs from command line arguments (skip first arg which is script name)
    pids = [int(pid) for pid in sys.argv[1:]]
    
    print(f"Processing {len(pids)} PIDs...")
    
    success_count = 0
    for pid in pids:
        name = get_process_name(pid)
        if send_pid_data(pid, name):
            success_count += 1
    
    print(f"\nSummary:")
    print(f"Total PIDs processed: {len(pids)}")
    print(f"Successfully reported: {success_count}")
    print(f"Failed: {len(pids) - success_count}")

if __name__ == "__main__":
    main()