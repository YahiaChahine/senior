import frida
import psutil
import csv
import time
import sys
import signal
from contextlib import contextmanager
import psutil
import time
import matplotlib.pyplot as plt
from threading import Thread
import pandas as pd
import numpy as np
from joblib import load
import os
import subprocess
import requests
import time
import random

# Configuration
API_URL = "http://localhost:8000"  # Update if your server is running elsewhere

def send_pid_data(pid: int, name: str, is_threat: int):
    """Send PID data to the monitoring server"""
    data = {
        "pid": pid,
        "name": name,
        "result": "1" if is_threat else "0"  # "1" for threat, "0" for safe
    }
    
    try:
        response = requests.post(f"{API_URL}/pid", json=data)
        response.raise_for_status()
        print(f"Successfully sent data for {name} (PID: {pid})")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send PID data: {e}")
        return False

API_CALLS_TO_MONITOR = ['NtOpenThread', 'ExitWindowsEx', 'FindResourceW', 'CryptExportKey', 'CreateRemoteThreadEx', 'MessageBoxTimeoutW', 'InternetCrackUrlW', 'StartServiceW', 'GetFileSize', 'GetVolumeNameForVolumeMountPointW', 'GetFileInformationByHandle', 'CryptAcquireContextW', 'RtlDecompressBuffer', 'SetWindowsHookExA', 'RegSetValueExW', 'LookupAccountSidW', 'SetUnhandledExceptionFilter', 'InternetConnectA', 'GetComputerNameW', 'RegEnumValueA', 'NtOpenFile', 'NtSaveKeyEx', 'HttpOpenRequestA', 'recv', 'GetFileSizeEx', 'LoadStringW', 'SetInformationJobObject', 'WSAConnect', 'CryptDecrypt', 'GetTimeZoneInformation', 'InternetOpenW', 'CoInitializeEx', 'CryptGenKey', 'GetAsyncKeyState', 'NtQueryInformationFile', 'GetSystemMetrics', 'NtDeleteValueKey', 'NtOpenKeyEx', 'sendto', 'IsDebuggerPresent', 'RegQueryInfoKeyW', 'NetShareEnum', 'InternetOpenUrlW', 'WSASocketA', 'CopyFileExW', 'connect', 'ShellExecuteExW', 'SearchPathW', 'GetUserNameA', 'InternetOpenUrlA', 'LdrUnloadDll', 'EnumServicesStatusW', 'EnumServicesStatusA', 'WSASend', 'CopyFileW', 'NtDeleteFile', 'CreateActCtxW', 'timeGetTime', 'MessageBoxTimeoutA', 'CreateServiceA', 'FindResourceExW', 'WSAAccept', 'InternetConnectW', 'HttpSendRequestA', 'GetVolumePathNameW', 'RegCloseKey', 'InternetGetConnectedStateExW', 'GetAdaptersInfo', 'shutdown', 'NtQueryMultipleValueKey', 'NtQueryKey', 'GetSystemWindowsDirectoryW', 'GlobalMemoryStatusEx', 'GetFileAttributesExW', 'OpenServiceW', 'getsockname', 'LoadStringA', 'UnhookWindowsHookEx', 'NtCreateUserProcess', 'Process32NextW', 'CreateThread', 'LoadResource', 'GetSystemTimeAsFileTime', 'SetStdHandle', 'CoCreateInstanceEx', 'GetSystemDirectoryA', 'NtCreateMutant', 'RegCreateKeyExW', 'IWbemServices_ExecQuery', 'NtDuplicateObject', 'Thread32First', 'OpenSCManagerW', 'CreateServiceW', 'GetFileType', 'MoveFileWithProgressW', 'NtDeviceIoControlFile', 'GetFileInformationByHandleEx', 'CopyFileA', 'NtLoadKey', 'GetNativeSystemInfo', 'NtOpenProcess', 'CryptUnprotectMemory', 'InternetWriteFile', 'ReadProcessMemory', 'gethostbyname', 'WSASendTo', 'NtOpenSection', 'listen', 'WSAStartup', 'socket', 'OleInitialize', 'FindResourceA', 'RegOpenKeyExA', 'RegEnumKeyExA', 'NtQueryDirectoryFile', 'CertOpenSystemStoreW', 'ControlService', 'LdrGetProcedureAddress', 'GlobalMemoryStatus', 'NtSetInformationFile', 'OutputDebugStringA', 'GetAdaptersAddresses', 'CoInitializeSecurity', 'RegQueryValueExA', 'NtQueryFullAttributesFile', 'DeviceIoControl', '__anomaly__', 'DeleteFileW', 'GetShortPathNameW', 'NtGetContextThread', 'GetKeyboardState', 'RemoveDirectoryA', 'InternetSetStatusCallback', 'NtResumeThread', 'SetFileInformationByHandle', 'NtCreateSection', 'NtQueueApcThread', 'accept', 'DecryptMessage', 'GetUserNameExW', 'SizeofResource', 'RegQueryValueExW', 'SetWindowsHookExW', 'HttpOpenRequestW', 'CreateDirectoryW', 'InternetOpenA', 'GetFileVersionInfoExW', 'FindWindowA', 'closesocket', 'RtlAddVectoredExceptionHandler', 'IWbemServices_ExecMethod', 'GetDiskFreeSpaceExW', 'TaskDialog', 'WriteConsoleW', 'CryptEncrypt', 'WSARecvFrom', 'NtOpenMutant', 'CoGetClassObject', 'NtQueryValueKey', 'NtDelayExecution', 'select', 'HttpQueryInfoA', 'GetVolumePathNamesForVolumeNameW', 'RegDeleteValueW', 'InternetCrackUrlA', 'OpenServiceA', 'InternetSetOptionA', 'CreateDirectoryExW', 'bind', 'NtShutdownSystem', 'DeleteUrlCacheEntryA', 'NtMapViewOfSection', 'LdrGetDllHandle', 'NtCreateKey', 'GetKeyState', 'CreateRemoteThread', 'NtEnumerateValueKey', 'SetFileAttributesW', 'NtUnmapViewOfSection', 'RegDeleteValueA', 'CreateJobObjectW', 'send', 'NtDeleteKey', 'SetEndOfFile', 'GetUserNameExA', 'GetComputerNameA', 'URLDownloadToFileW', 'NtFreeVirtualMemory', 'recvfrom', 'NtUnloadDriver', 'NtTerminateThread', 'CryptUnprotectData', 'NtCreateThreadEx', 'DeleteService', 'GetFileAttributesW', 'GetFileVersionInfoSizeExW', 'OpenSCManagerA', 'WriteProcessMemory', 'GetSystemInfo', 'SetFilePointer', 'Module32FirstW', 'ioctlsocket', 'RegEnumKeyW', 'RtlCompressBuffer', 'SendNotifyMessageW', 'GetAddrInfoW', 'CryptProtectData', 'Thread32Next', 'NtAllocateVirtualMemory', 'RegEnumKeyExW', 'RegSetValueExA', 'DrawTextExA', 'CreateToolhelp32Snapshot', 'FindWindowW', 'CoUninitialize', 'NtClose', 'WSARecv', 'CertOpenStore', 'InternetGetConnectedState', 'RtlAddVectoredContinueHandler', 'RegDeleteKeyW', 'SHGetSpecialFolderLocation', 'CreateProcessInternalW', 'NtCreateDirectoryObject', 'EnumWindows', 'DrawTextExW', 'RegEnumValueW', 'SendNotifyMessageA', 'NtProtectVirtualMemory', 'NetUserGetLocalGroups', 'GetUserNameW', 'WSASocketW', 'getaddrinfo', 'AssignProcessToJobObject', 'SetFileTime', 'WriteConsoleA', 'CryptDecodeObjectEx', 'EncryptMessage', 'system', 'NtSetContextThread', 'LdrLoadDll', 'InternetGetConnectedStateExA', 'RtlCreateUserThread', 'GetCursorPos', 'Module32NextW', 'RegCreateKeyExA', 'NtLoadDriver', 'NetUserGetInfo', 'SHGetFolderPathW', 'GetBestInterfaceEx', 'CertControlStore', 'StartServiceA', 'NtWriteFile', 'Process32FirstW', 'NtReadVirtualMemory', 'GetDiskFreeSpaceW', 'GetFileVersionInfoW', 'FindFirstFileExW', 'FindWindowExW', 'GetSystemWindowsDirectoryA', 'RegOpenKeyExW', 'CoCreateInstance', 'NtQuerySystemInformation', 'LookupPrivilegeValueW', 'NtReadFile', 'ReadCabinetState', 'GetForegroundWindow', 'InternetCloseHandle', 'FindWindowExA', 'ObtainUserAgentString', 'CryptCreateHash', 'GetTempPathW', 'CryptProtectMemory', 'NetGetJoinInformation', 'NtOpenKey', 'GetSystemDirectoryW', 'DnsQuery_A', 'RegQueryInfoKeyA', 'NtEnumerateKey', 'RegisterHotKey', 'RemoveDirectoryW', 'FindFirstFileExA', 'CertOpenSystemStoreA', 'NtTerminateProcess', 'NtSetValueKey', 'CryptAcquireContextA', 'SetErrorMode', 'UuidCreate', 'RtlRemoveVectoredExceptionHandler', 'RegDeleteKeyA', 'setsockopt', 'FindResourceExA', 'NtSuspendThread', 'GetFileVersionInfoSizeW', 'NtOpenDirectoryObject', 'InternetQueryOptionA', 'InternetReadFile', 'NtCreateFile', 'NtQueryAttributesFile', 'HttpSendRequestW', 'CryptHashMessage', 'CryptHashData', 'NtWriteVirtualMemory', 'SetFilePointerEx', 'CertCreateCertificateContext', 'DeleteUrlCacheEntryW', '__exception__']

# List of system processes that should never be monitored
PROTECTED_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", 
    "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
    "dwm.exe", "spoolsv.exe", "taskhost.exe", "taskmgr.exe",
    "conhost.exe", "rundll32.exe", "LogonUI.exe", "fontdrvhost.exe",
    "WmiPrvSE.exe", "ctfmon.exe", "sihost.exe", "ShellExperienceHost.exe",
    "SearchUI.exe", "RuntimeBroker.exe", "SecurityHealthService.exe",
    "SearchIndexer.exe", "Cortana.exe", "MsMpEng.exe", "NisSrv.exe",
    "msdtc.exe", "wininit.exe", "lsm.exe", "dllhost.exe", "audiodg.exe", 
    "firefox.exe", "SearchHost.exe", "WindowsTerminal.exe", 'smartscreen.exe', "PhoneExperienceHost.exe", 'ShellHost.exe'
]

# Protected process owners
PROTECTED_OWNERS = [
    "NT AUTHORITY\\SYSTEM", 
    "NT AUTHORITY\\LOCAL SERVICE", 
    "NT AUTHORITY\\NETWORK SERVICE", 
    "NT AUTHORITY\\SERVICE"
]

# JavaScript code for Frida hooking - updated for 100 API calls
JS_CODE = """
var apiCalls = %s;
var callSequence = [];
var lastCall = -1;

function hookApi(apiName, index) {
    Interceptor.attach(Module.getExportByName(null, apiName), {
        onEnter: function(args) {
            if (lastCall !== index) {
                callSequence.push(index);
                lastCall = index;
                if (callSequence.length >= 100) {
                    send({type: 'complete', sequence: callSequence.slice(0, 100)});
                    callSequence = [];
                }
            }
        }
    });
}

for (var i = 0; i < apiCalls.length; i++) {
    try {
        hookApi(apiCalls[i], i);
    } catch (e) {
        //console.log("Failed to hook " + apiCalls[i]);
    }
}

setTimeout(function() {
    if (callSequence.length > 0) {
        send({type: 'timeout', sequence: callSequence.slice(0, 100)});
    } else {
        send({type: 'empty'});
    }
}, 20000);
""" % API_CALLS_TO_MONITOR

# CSV file setup
CSV_FILE = "./Log/api_calls_logg_"
def init_csv(file):
    with open(f'{file}', 'a', newline='') as f:
        writer = csv.writer(f)
        header = ['pid'] + [f't_{i}' for i in range(100)]  # Updated for 100 features
        writer.writerow(header)

# Global flag for interruption
KEEP_RUNNING = True



@contextmanager
def frida_session(pid):
    session = None
    try:
        session = frida.attach(pid)
        yield session
    finally:
        if session:
            try:
                session.detach()
            except:
                pass

def classify_behavior(api_sequence, model_path='traditional_ensemble_model.pkl'):
    """
    Classify the behavior using a pre-trained model.
    
    Args:
        api_sequence: List of API call indices (length 100)
        model_path: Path to the .joblib model file
        
    Returns:
        tuple: (prediction, probability) where prediction is the class label
               and probability is the confidence score
    """
    try:
        # Load the model
        model = load(model_path)
        
        # Convert sequence to numpy array and reshape for prediction
        X = np.array(api_sequence).reshape(1, -1)
        
        # Make prediction
        pred = model.predict(X)
        proba = model.predict_proba(X)
        
        # Get the highest probability
        confidence = np.max(proba)
        
        return pred[0], confidence
    except Exception as e:
        print(f"Error during classification: {str(e)}")
        return None, None

def get_proc_info(pid):
    try:
        proc = psutil.Process(pid)
        return {
            'name': proc.name(),
            'username': proc.username(),
            'cpu_percent': proc.cpu_percent(interval=0.1),
            'memory_percent': proc.memory_percent(),
            'memory_info': proc.memory_info()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None  # Process is unsafe (or dead)
    
def monitor_process(pid):
    result_sequence = []
    session = None
    script = None
    
    try:
        # Set timeout
        start_time = time.time()
        timeout = 20  # seconds
        
        with frida_session(pid) as session:
            script = session.create_script(JS_CODE)
            
            def on_message(message, data):
                nonlocal result_sequence
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] in ['complete', 'timeout']:
                        result_sequence = payload['sequence']
                    elif payload['type'] == 'empty':
                        result_sequence = []

            script.on('message', on_message)
            script.load()
            
            # Monitor with timeout
            save = False
            while KEEP_RUNNING:
                if time.time() - start_time >= timeout:
                    break
                if len(result_sequence) >= 60:  # Updated for 100 API calls
                    save = True
                    break
                time.sleep(0.1)
                
        # Process results
        if len(result_sequence) > 0:
            # Pad sequence with -1 if it's shorter than 100
            sequence = result_sequence + [-1] * (100 - len(result_sequence))
            
            # Perform classification
            prediction, confidence = classify_behavior(sequence)
            if prediction is not None:
                print(f"Classification result: {prediction} (confidence: {confidence:.2f})")
                #send_pid_data(pid, get_proc_info(pid)['name'], prediction)
                if prediction == 1:
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True)
                    print("ransomware")
                    print(f"Process {pid} killed successfully.")
            
            # Save to CSV
            if save:
                with open(f'{CSV_FILE}{pid}.csv', 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([pid] + sequence)
            return True
        else:
            print("No API calls captured")
            return False
        
    except Exception as e:
        print(f"Error monitoring PID {pid}: {str(e)}")
        return False
    finally:
        if script:
            try:
                script.unload()
            except:
                pass

def is_not_safe_to_monitor(proc_info):
    try:
        if proc_info['name'] in PROTECTED_PROCESSES or proc_info['name'] !='python.exe':
            return True
        if proc_info['username'] in PROTECTED_OWNERS:
            return True
        if proc_info['cpu_percent'] > 15 or proc_info['memory_percent'] > 15:
            return True
        if proc_info['memory_info'].rss < 1024 * 1024:  # Less than 1 MB
            return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return True

def get_monitorable_processes():
    monitorable_pids = int(input("Enter the PID of the process: "))
    return [monitorable_pids]

def main():
    pid = int(sys.argv[1])
    init_csv(f'{CSV_FILE}{pid}.csv')
    print("Starting process monitoring... Press Ctrl+C to stop")
    if(len(sys.argv) < 2):
        print("Not enough arguments")
        return
    
    processes = []
    processes.append(pid)
    print(f"Found {len(processes)} processes to monitor")
    
    for pid in processes:
        if not KEEP_RUNNING:
            break
            
        try:
            
            process = psutil.Process(pid)

            if is_not_safe_to_monitor(get_proc_info(pid)):
                os._exit(0)

            
            process_name = process.name()
            print(f"Monitoring PID {pid}: {process_name}")
            
            if monitor_process(pid):
                print(f"Finished monitoring PID {pid}: {process_name}")
            else:
                print(f"Skipped PID {pid}: {process_name} due to error")
                
            #time.sleep(0.1)
            
        except psutil.NoSuchProcess:
            print(f"Process {pid} terminated before monitoring")
            continue
            
    print("Monitoring complete")

# Global variables to store metrics
timestamps = []
cpu_percentages = []
memory_usages = []
stop_monitoring = False

def monitor_resources(interval=0.1):
    """Background thread to monitor CPU and Memory usage."""
    global timestamps, cpu_percentages, memory_usages, stop_monitoring
    start_time = time.time()
    
    while not stop_monitoring:
        # Get current CPU and Memory usage
        cpu_percent = psutil.Process().cpu_percent(interval=interval) / psutil.cpu_count()
        memory_info = psutil.Process().memory_info().rss / (1024 ** 2)  # Convert to MB
        
        # Record metrics
        timestamps.append(time.time() - start_time)
        cpu_percentages.append(cpu_percent)
        memory_usages.append(memory_info)
        
        time.sleep(interval)

def plot_metrics():
    """Plot CPU and Memory usage over time with max values highlighted"""
    df = pd.DataFrame({
        'Time (s)': timestamps,
        'CPU (%)': cpu_percentages,
        'Memory (MB)': memory_usages
    })
    
    plt.figure(figsize=(12, 6))
    
    # Find max values and their timestamps
    max_cpu = df['CPU (%)'].max()
    max_cpu_time = df.loc[df['CPU (%)'].idxmax(), 'Time (s)']
    
    max_mem = df['Memory (MB)'].max()
    max_mem_time = df.loc[df['Memory (MB)'].idxmax(), 'Time (s)']
    
    # CPU Plot
    plt.subplot(1, 2, 1)
    plt.plot(df['Time (s)'], df['CPU (%)'], 'r-', label='CPU Usage')
    
    # Highlight max CPU point
    plt.scatter(max_cpu_time, max_cpu, color='red', s=100, 
               label=f'Max: {max_cpu:.1f}%', zorder=5)
    plt.axhline(y=max_cpu, color='red', linestyle=':', alpha=0.3)
    plt.axvline(x=max_cpu_time, color='red', linestyle=':', alpha=0.3)
    
    plt.xlabel('Time (s)')
    plt.ylabel('CPU Utilization (%)')
    plt.title('CPU Usage Over Time')
    plt.grid(True)
    plt.legend()
    
    # Memory Plot
    plt.subplot(1, 2, 2)
    plt.plot(df['Time (s)'], df['Memory (MB)'], 'b-', label='Memory Usage')
    
    # Highlight max Memory point
    plt.scatter(max_mem_time, max_mem, color='blue', s=100, 
               label=f'Max: {max_mem:.1f} MB', zorder=5)
    plt.axhline(y=max_mem, color='blue', linestyle=':', alpha=0.3)
    plt.axvline(x=max_mem_time, color='blue', linestyle=':', alpha=0.3)
    
    plt.xlabel('Time (s)')
    plt.ylabel('Memory Usage (MB)')
    plt.title('Memory Usage Over Time')
    plt.grid(True)
    plt.legend()
    
    plt.tight_layout()
    
    # Save plot with timestamp
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    plot_filename = f'resource_usage_{timestamp}.png'
    plt.savefig(plot_filename)
    print(f"Saved resource usage plot to {plot_filename}")
    plt.show()

if __name__ == "__main__":
    # Start monitoring in a background thread
    # monitor_thread = Thread(target=monitor_resources, daemon=True)
    # monitor_thread.start()
    
    # Your main script logic goes here
    try:
        print("Running your script... Press Ctrl+C to stop.")
        main()
        # stop_monitoring = True
        # monitor_thread.join()
        # plot_metrics()
        os._exit(0)
    except KeyboardInterrupt:
        # stop_monitoring = True
        # monitor_thread.join()
        # plot_metrics()
        print()