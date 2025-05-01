#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <psapi.h>
#include <omp.h>
#include <thread>
#include <atomic>
#include <unordered_set>

// Mutex for thread-safe console output
std::mutex consoleMutex;
// Mutex for protecting the set of monitored PIDs
std::mutex monitoredPidsMutex;
// Set to track which PIDs have already been monitored
std::unordered_set<DWORD> monitoredPids;

// Get the number of logical processors (threads) available
int getSystemThreadCount() {
    return omp_get_num_procs();
}

// Function to check if a process is monitorable (not a system process or driver)
bool isProcessMonitorable(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false; // Can't open the process, so it's not monitorable
    }
    
    // Check if it's a system process - simplified check
    char filename[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, filename, MAX_PATH) == 0) {
        CloseHandle(hProcess);
        return false;
    }
    
    std::string processPath = filename;
    std::transform(processPath.begin(), processPath.end(), processPath.begin(), ::tolower);
    
    CloseHandle(hProcess);
    
    // Exclude system processes and drivers
    if (processPath.find("\\windows\\system32\\") != std::string::npos ||
        processPath.find("\\windows\\syswow64\\") != std::string::npos) {
        // Check for certain system processes that should be excluded
        if (processPath.find("svchost.exe") != std::string::npos ||
            processPath.find("csrss.exe") != std::string::npos ||
            processPath.find("smss.exe") != std::string::npos ||
            processPath.find("winlogon.exe") != std::string::npos ||
            processPath.find("services.exe") != std::string::npos ||
            processPath.find("lsass.exe") != std::string::npos ||
            processPath.find("ntoskrnl.exe") != std::string::npos ||
            processPath.find("terminal.exe") != std::string::npos ||
            processPath.find("firefox.exe") != std::string::npos ||
            processPath.find("explorer.exe") != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

// Function to get Python process PIDs
std::vector<DWORD> getPythonProcessPIDs(DWORD excludePid) {
    std::vector<DWORD> pythonPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot" << std::endl;
        return pythonPids;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::cerr << "Failed to get first process" << std::endl;
        return pythonPids;
    }
    
    do {
        std::string procName = pe32.szExeFile;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
        
        if (procName == "python.exe" || procName == "pythonw.exe") {
            DWORD pid = pe32.th32ProcessID;
            if (pid != excludePid && isProcessMonitorable(pid)) {
                // Check if this PID has already been monitored
                {
                    std::lock_guard<std::mutex> lock(monitoredPidsMutex);
                    if (monitoredPids.find(pid) == monitoredPids.end()) {
                        pythonPids.push_back(pid);
                    }
                }
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return pythonPids;
}

// Get monitorable PIDs that haven't been monitored yet
std::vector<DWORD> getNewMonitorablePIDs(DWORD excludePid) {
    std::vector<DWORD> newPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot" << std::endl;
        return newPids;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::cerr << "Failed to get first process" << std::endl;
        return newPids;
    }
    
    do {
        DWORD pid = pe32.th32ProcessID;
        
        // Skip the system process (PID 0), idle process (PID 4), and excluded PID
        if (pid == 0 || pid == 4 || pid == excludePid) {
            continue;
        }
        
        // Check if we've already monitored this PID
        {
            std::lock_guard<std::mutex> lock(monitoredPidsMutex);
            if (monitoredPids.find(pid) == monitoredPids.end() && isProcessMonitorable(pid)) {
                newPids.push_back(pid);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return newPids;
}

// Mark PIDs as monitored
void markPIDsAsMonitored(const std::vector<DWORD>& pids) {
    std::lock_guard<std::mutex> lock(monitoredPidsMutex);
    for (const auto& pid : pids) {
        monitoredPids.insert(pid);
    }
}

// Kill a Python process for a target PID
void killPythonProcessForPid(DWORD targetPid) {
    std::string targetArg = "main.py " + std::to_string(targetPid);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }
    
    do {
        if (_stricmp(pe32.szExeFile, "python.exe") == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                // Get command line of the process to see if it's our target
                HANDLE hSnapshot2 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                if (hSnapshot2 != INVALID_HANDLE_VALUE) {
                    char cmdline[MAX_PATH * 2];
                    if (GetProcessImageFileNameA(hProcess, cmdline, sizeof(cmdline)) > 0) {
                        // Try to terminate if it's a Python process that might be ours
                        TerminateProcess(hProcess, 1);
                    }
                    CloseHandle(hSnapshot2);
                } else {
                    // If we can't check command line, kill it anyway if it's Python
                    TerminateProcess(hProcess, 1);
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
}

// Run the Python script for a single PID
bool runPythonScript(DWORD pid) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    std::string command = "python -u main.py " + std::to_string(pid);
    
    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "Starting monitoring for PID " << pid << " at " 
                  << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
    }
    
    std::string tempFileName = "output_" + std::to_string(pid) + ".tmp";
    std::string redirectedCommand = command + " > " + tempFileName + " 2>&1";
    
    int exitCode = system(redirectedCommand.c_str());
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::ifstream outputFile(tempFileName);
    std::string result;
    std::string line;
    
    if (outputFile.is_open()) {
        std::stringstream buffer;
        buffer << outputFile.rdbuf();
        result = buffer.str();
        outputFile.close();
    }
    
    // Delete the temporary file
    std::remove(tempFileName.c_str());
    
    // Output the results in a thread-safe manner
    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "== Output from Python script for PID " << pid << " ==" << std::endl;
        std::cout << result;
        std::cout << "== End of output for PID " << pid << " ==" << std::endl;
        std::cout << "PID " << pid << " completed in " << duration << " ms with exit code " << exitCode << std::endl;
        std::cout << "--------------------------------" << std::endl;
    }
    
    return true;
}

// Run the Python script for multiple PIDs
bool runPythonScript2(const std::vector<DWORD>& pids) {
    if (pids.empty()) {
        return true;
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Build the command with the list of PIDs
    std::string command = "python -u test.py";
    
    // Add each PID to the command
    for (const auto& pid : pids) {
        command += " " + std::to_string(pid);
    }
    
    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "Starting monitoring for PIDs: ";
        for (size_t i = 0; i < pids.size(); ++i) {
            std::cout << pids[i];
            if (i < pids.size() - 1) {
                std::cout << ", ";
            }
        }
        std::cout << std::endl;
    }
    
    // Create a unique temp file name (using the first PID for simplicity)
    std::string tempFileName = "output_batch_" + std::to_string(pids[0]) + ".tmp";
    std::string redirectedCommand = command + " > " + tempFileName + " 2>&1";
    
    int exitCode = system(redirectedCommand.c_str());
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::ifstream outputFile(tempFileName);
    std::string result;
    
    if (outputFile.is_open()) {
        std::stringstream buffer;
        buffer << outputFile.rdbuf();
        result = buffer.str();
        outputFile.close();
    }
    
    // Delete the temporary file
    std::remove(tempFileName.c_str());
    
    // Output the results in a thread-safe manner
    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "== Output from Python script for PIDs: ";
        for (size_t i = 0; i < pids.size(); ++i) {
            std::cout << pids[i];
            if (i < pids.size() - 1) {
                std::cout << ", ";
            }
        }
        std::cout << " ==" << std::endl;
        std::cout << result;
        std::cout << "== End of output for batch starting with PID " << pids[0] << " ==" << std::endl;
        std::cout << "Batch completed in " << duration << " ms with exit code " << exitCode << std::endl;
        std::cout << "--------------------------------" << std::endl;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    // Check if a PID was provided as a command-line argument
    DWORD excludePid = 0;
    if (argc > 1) {
        try {
            excludePid = static_cast<DWORD>(std::stoul(argv[1]));
            std::cout << "Excluding PID: " << excludePid << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Invalid PID provided: " << argv[1] << std::endl;
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    std::atomic<bool> shouldContinue{true};
    
    // Create a dedicated high-priority thread for monitoring Python processes
    std::thread pythonMonitorThread([&]() {
        // Set thread priority to above normal for faster detection
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
        
        while (shouldContinue) {
            std::vector<DWORD> pythonPids = getPythonProcessPIDs(excludePid);
            
            if (!pythonPids.empty()) {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << "Found " << pythonPids.size() << " new processes to monitor." << std::endl;
                
                markPIDsAsMonitored(pythonPids);
                
                #pragma omp parallel for schedule(dynamic, 1)
                for (int i = 0; i < static_cast<int>(pythonPids.size()); i++) {
                    runPythonScript(pythonPids[i]);
                }
            }
            
            // Use a very short sleep to prevent CPU overload but keep detection time minimal
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });
    
    std::thread generalMonitorThread([&]() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
        
        while (shouldContinue) {
            std::vector<DWORD> newPids = getNewMonitorablePIDs(excludePid);
            
            if (!newPids.empty()) {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << "Found " << newPids.size() << " new general processes to monitor." << std::endl;
                
                // Mark these PIDs as being monitored
                markPIDsAsMonitored(newPids);
                
                // Monitor general processes
                runPythonScript2(newPids);
            }
            
            // General process monitoring can run at a slower pace
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
    
    // Let the program run for a specified time or until user interruption
    std::cout << "Monitoring started. Press Enter to stop..." << std::endl;
    std::cin.get();
    
    // Signal threads to stop and wait for them
    shouldContinue = false;
    
    if (pythonMonitorThread.joinable()) {
        pythonMonitorThread.join();
    }
    
    if (generalMonitorThread.joinable()) {
        generalMonitorThread.join();
    }
    
    std::cout << "All monitoring tasks completed." << std::endl;
    return 0;
}