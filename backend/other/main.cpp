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

// Mutex for thread-safe console output
std::mutex consoleMutex;

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

std::vector<DWORD> getSpecificProcessPIDs(const std::vector<std::string>& targetProcessNames) {
    std::vector<DWORD> testPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot" << std::endl;
        return testPids;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::cerr << "Failed to get first process" << std::endl;
        return testPids;
    }
    
    do {
        std::string procName = pe32.szExeFile;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
        
        // Check if the process name is in our target list
        for (const auto& targetName : targetProcessNames) {
            std::string targetLower = targetName;
            std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);
            
            if (procName == targetLower) {
                DWORD pid = pe32.th32ProcessID;
                // Optionally, we can still check if it's monitorable
                if (isProcessMonitorable(pid)) {
                    testPids.push_back(pid);
                }
                break; // No need to check other target names
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return testPids;
}

std::vector<DWORD> getMonitorablePIDs() {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot" << std::endl;
        return pids;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        std::cerr << "Failed to get first process" << std::endl;
        return pids;
    }
    
    do {
        DWORD pid = pe32.th32ProcessID;
        
        // Skip the system process (PID 0) and idle process (PID 4)
        if (pid == 0 || pid == 4) {
            continue;
        }
        
        if (isProcessMonitorable(pid)) {
            pids.push_back(pid);
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return pids;
}

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


bool runPythonScript(DWORD pid) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    std::string command = "python -u main.py " + std::to_string(pid);
    
    {
        std::lock_guard<std::mutex> lock(consoleMutex);
        std::cout << "Starting monitoring for PID " << pid << std::endl;
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

int main() {

    std::vector<DWORD> Pids = getMonitorablePIDs();   
    std::cout << "Found " << Pids.size() << " processes to monitor."<< std::endl;
    

    #pragma omp parallel for schedule(dynamic, 4)
    for (int i = 0; i < static_cast<int>(Pids.size()); i++) {
        runPythonScript(Pids[i]);
    }
    
    std::cout << "All monitoring tasks completed." << std::endl;
    return 0;
}