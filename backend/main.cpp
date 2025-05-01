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

std::mutex consoleMutex;

int getSystemThreadCount() {
    return omp_get_num_procs();
}

// Function to check if a process is monitorable (not a system process or driver)
bool isProcessMonitorable(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false; // Can't open the process, so it's not monitorable
    }
    
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
                HANDLE hSnapshot2 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
                if (hSnapshot2 != INVALID_HANDLE_VALUE) {
                    char cmdline[MAX_PATH * 2];
                    if (GetProcessImageFileNameA(hProcess, cmdline, sizeof(cmdline)) > 0) {
                        TerminateProcess(hProcess, 1);
                    }
                    CloseHandle(hSnapshot2);
                } else {
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
    
    std::remove(tempFileName.c_str());
    
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


// Function to filter out the excluded PID (ie backend server) from a list of PIDs
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
        std::vector<DWORD> targetPids = getMonitorablePIDs();
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


    std::atomic<bool> shouldContinue{true};

    

    std::thread monitorThread1(monitorTargetProcesses, excludePid, std::ref(shouldContinue), 0);
    std::thread monitorThread2(monitorTargetProcesses, excludePid, std::ref(shouldContinue), 1000);
    std::thread monitorThread3(monitorTargetProcesses, excludePid, std::ref(shouldContinue), 3000);
    std::thread monitorThread4(monitorTargetProcesses, excludePid, std::ref(shouldContinue), 5000);
    std::thread monitorThread5(monitorTargetProcesses, excludePid, std::ref(shouldContinue), 7000);


    shouldContinue = false;

 
    
    monitorThread1.join();
    monitorThread2.join();
    monitorThread3.join();
    monitorThread4.join();
    monitorThread5.join();
    
    std::cout << "All monitoring tasks completed." << std::endl;
    return 0;
}