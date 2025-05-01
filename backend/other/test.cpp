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
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <omp.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <algorithm>
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

bool runPythonScript2(const std::vector<DWORD>& pids) {
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




// Function to filter out the excluded PID from a list of PIDs
std::vector<DWORD> filterExcludedPid(const std::vector<DWORD>& pids, DWORD excludePid) {
    std::vector<DWORD> filteredPids = pids;
    if (excludePid > 0) {
        filteredPids.erase(
            std::remove(filteredPids.begin(), filteredPids.end(), excludePid),
            filteredPids.end()
        );
    }
    return filteredPids;
}

// Thread function for monitoring target processes
void monitorTargetProcesses(
    const std::vector<std::string>& targetProcessNames,
    DWORD excludePid,
    const std::atomic<bool>& shouldContinue,
    int delayMs = 0
) {
    if (delayMs > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }

    while (shouldContinue) {
        std::vector<DWORD> targetPids = getSpecificProcessPIDs(targetProcessNames);
        targetPids = filterExcludedPid(targetPids, excludePid);

        std::cout << "Found " << targetPids.size() << " processes to monitor." << std::endl;

        #pragma omp parallel for schedule(dynamic, 1)
        for (int i = 0; i < static_cast<int>(targetPids.size()); i++) {
            runPythonScript(targetPids[i]);
        }

        // Optional: Small delay to prevent CPU overload
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Thread function for monitoring general processes
void monitorGeneralProcesses(
    DWORD excludePid,
    const std::atomic<bool>& shouldContinue
) {
    while (shouldContinue) {
        std::vector<DWORD> generalPids = getMonitorablePIDs();
        generalPids = filterExcludedPid(generalPids, excludePid);

        std::cout << "Found " << generalPids.size() << " processes to monitor." << std::endl;
        runPythonScript2(generalPids);

        // Optional: Small delay to prevent CPU overload
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char* argv[]) {
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

    std::vector<std::string> targetProcessNames = {"python.exe"};
    std::atomic<bool> shouldContinue{true};

    // Start target monitor threads with staggered delays
    std::thread targetMonitorThread1(monitorTargetProcesses, targetProcessNames, excludePid, std::ref(shouldContinue), 0);
    std::thread targetMonitorThread2(monitorTargetProcesses, targetProcessNames, excludePid, std::ref(shouldContinue), 2000);
    std::thread targetMonitorThread3(monitorTargetProcesses, targetProcessNames, excludePid, std::ref(shouldContinue), 4000);
    

    // Start general monitor thread
    std::thread generalMonitorThread(monitorGeneralProcesses, excludePid, std::ref(shouldContinue));

    // Run for 10 minutes (or until interrupted)
    std::this_thread::sleep_for(std::chrono::minutes(10));

    // Signal threads to stop
    shouldContinue = false;

    // Wait for all threads to finish
    targetMonitorThread1.join();
    targetMonitorThread2.join();
    targetMonitorThread3.join();
    
    generalMonitorThread.join();

    std::cout << "All monitoring tasks completed." << std::endl;
    return 0;
}