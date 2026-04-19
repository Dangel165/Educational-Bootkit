// BootLoaderEntryPointAnalyzerTest.cpp: Test application for Boot Loader Entry Point Analyzer (Task 4.1)
// Tests the boot loader analysis functionality of the bootkit analysis framework driver

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// IOCTL codes from BootLoaderEntryPointAnalyzer.h
#define IOCTL_BOOTLOADER_ENABLE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_DISABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_GET_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_RESET_STATISTICS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x923, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_GET_REPORT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x924, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_SCAN_MODULES      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x925, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_DETECT_OEP        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x926, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_ANALYZE_DEPS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x927, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_APPLY_PATCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x928, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_RESTORE_PATCH     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x929, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTLOADER_VALIDATE_MODULE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Boot loader analysis statistics structure
typedef struct _BOOT_LOADER_ANALYSIS_STATISTICS {
    BOOLEAN AnalysisActive;
    BOOLEAN OEPDetectionComplete;
    BOOLEAN ModuleTrackingActive;
    BOOLEAN SafePatchingEnabled;
    
    ULONG OEPDetections;
    ULONG ModuleScans;
    ULONG EntryPointDiscoveries;
    ULONG SafePatchesApplied;
    ULONG SafePatchesRestored;
    ULONG DependencyResolutions;
    
    ULONG TotalModules;
    ULONG SignedModules;
    ULONG ModifiedModules;
    ULONG HookedModules;
    
    ULONG TotalDependencies;
    ULONG ResolvedDependencies;
    ULONG CircularDependencies;
    ULONG MissingDependencies;
    
    ULONG SecurityViolations;
    ULONG IntegrityViolations;
    ULONG AuthenticationViolations;
    
    ULONG64 AnalysisStartTime;
    ULONG64 AnalysisDuration;
    ULONG64 LastScanTime;
    
    WCHAR CurrentModule[64];
    WCHAR AnalysisStatus[128];
} BOOT_LOADER_ANALYSIS_STATISTICS, *PBOOT_LOADER_ANALYSIS_STATISTICS;

// OEP detection request structure
typedef struct _OEP_DETECTION_REQUEST {
    ULONG DetectionType;  // 0 = Static, 1 = Dynamic, 2 = Heuristic, 3 = Signature, 4 = Hybrid
    WCHAR ModuleName[64];
    ULONG64 SuspectedBaseAddress;
    BOOLEAN ForceRescan;
    BOOLEAN ValidateSignature;
} OEP_DETECTION_REQUEST, *POEP_DETECTION_REQUEST;

// OEP detection response structure
typedef struct _OEP_DETECTION_RESPONSE {
    ULONG Status;
    ULONG64 DetectedOEP;
    ULONG64 ImageBase;
    BOOLEAN OEPModified;
    BOOLEAN SignatureValid;
    UINT8 OEPHash[32];
    WCHAR DetectionMethod[64];
    WCHAR StatusMessage[128];
} OEP_DETECTION_RESPONSE, *POEP_DETECTION_RESPONSE;

class BootLoaderAnalyzerTester {
private:
    HANDLE m_deviceHandle;
    bool m_connected;
    
public:
    BootLoaderAnalyzerTester() : m_deviceHandle(INVALID_HANDLE_VALUE), m_connected(false) {}
    
    ~BootLoaderAnalyzerTester() {
        Disconnect();
    }
    
    bool Connect() {
        std::wstring devicePath = L"\\\\.\\BootkitDriver";
        
        m_deviceHandle = CreateFileW(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (m_deviceHandle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cout << "Failed to connect to driver. Error: " << error << std::endl;
            std::cout << "Make sure the driver is installed and running." << std::endl;
            return false;
        }
        
        m_connected = true;
        std::cout << "Connected to BootkitDriver successfully." << std::endl;
        return true;
    }
    
    void Disconnect() {
        if (m_connected && m_deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_deviceHandle);
            m_deviceHandle = INVALID_HANDLE_VALUE;
            m_connected = false;
            std::cout << "Disconnected from driver." << std::endl;
        }
    }
    
    bool EnableBootLoaderAnalysis() {
        if (!m_connected) return false;
        
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_ENABLE,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to enable boot loader analysis. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Boot loader analysis enabled successfully." << std::endl;
        return true;
    }
    
    bool DisableBootLoaderAnalysis() {
        if (!m_connected) return false;
        
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_DISABLE,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to disable boot loader analysis. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Boot loader analysis disabled successfully." << std::endl;
        return true;
    }
    
    bool GetStatistics() {
        if (!m_connected) return false;
        
        BOOT_LOADER_ANALYSIS_STATISTICS stats = { 0 };
        DWORD bytesReturned = 0;
        
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_GET_STATISTICS,
            NULL, 0,
            &stats, sizeof(stats),
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to get statistics. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "\n=== Boot Loader Analysis Statistics ===" << std::endl;
        std::cout << "Analysis Active: " << (stats.AnalysisActive ? "Yes" : "No") << std::endl;
        std::cout << "OEP Detection Complete: " << (stats.OEPDetectionComplete ? "Yes" : "No") << std::endl;
        std::cout << "Module Tracking Active: " << (stats.ModuleTrackingActive ? "Yes" : "No") << std::endl;
        std::cout << "Safe Patching Enabled: " << (stats.SafePatchingEnabled ? "Yes" : "No") << std::endl;
        std::cout << "\nCounters:" << std::endl;
        std::cout << "  OEP Detections: " << stats.OEPDetections << std::endl;
        std::cout << "  Module Scans: " << stats.ModuleScans << std::endl;
        std::cout << "  Entry Point Discoveries: " << stats.EntryPointDiscoveries << std::endl;
        std::cout << "  Safe Patches Applied: " << stats.SafePatchesApplied << std::endl;
        std::cout << "  Safe Patches Restored: " << stats.SafePatchesRestored << std::endl;
        std::cout << "  Dependency Resolutions: " << stats.DependencyResolutions << std::endl;
        std::cout << "\nModule Statistics:" << std::endl;
        std::cout << "  Total Modules: " << stats.TotalModules << std::endl;
        std::cout << "  Signed Modules: " << stats.SignedModules << std::endl;
        std::cout << "  Modified Modules: " << stats.ModifiedModules << std::endl;
        std::cout << "  Hooked Modules: " << stats.HookedModules << std::endl;
        std::cout << "\nDependency Statistics:" << std::endl;
        std::cout << "  Total Dependencies: " << stats.TotalDependencies << std::endl;
        std::cout << "  Resolved Dependencies: " << stats.ResolvedDependencies << std::endl;
        std::cout << "  Circular Dependencies: " << stats.CircularDependencies << std::endl;
        std::cout << "  Missing Dependencies: " << stats.MissingDependencies << std::endl;
        std::cout << "\nSecurity Analysis:" << std::endl;
        std::cout << "  Security Violations: " << stats.SecurityViolations << std::endl;
        std::cout << "  Integrity Violations: " << stats.IntegrityViolations << std::endl;
        std::cout << "  Authentication Violations: " << stats.AuthenticationViolations << std::endl;
        std::cout << "\nTiming:" << std::endl;
        std::cout << "  Analysis Duration: " << stats.AnalysisDuration << " ns" << std::endl;
        std::cout << "  Last Scan Time: " << stats.LastScanTime << std::endl;
        std::cout << "  Status: " << stats.AnalysisStatus << std::endl;
        
        return true;
    }
    
    bool DetectOEP() {
        if (!m_connected) return false;
        
        OEP_DETECTION_REQUEST request = { 0 };
        OEP_DETECTION_RESPONSE response = { 0 };
        DWORD bytesReturned = 0;
        
        // Set up request for winload.efi OEP detection using hybrid method
        request.DetectionType = 4;  // Hybrid
        wcscpy_s(request.ModuleName, L"winload.efi");
        request.SuspectedBaseAddress = 0x10000000;
        request.ForceRescan = TRUE;
        request.ValidateSignature = TRUE;
        
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_DETECT_OEP,
            &request, sizeof(request),
            &response, sizeof(response),
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to detect OEP. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "\n=== OEP Detection Results ===" << std::endl;
        std::cout << "Status: " << response.Status << std::endl;
        std::cout << "Detected OEP: 0x" << std::hex << response.DetectedOEP << std::dec << std::endl;
        std::cout << "Image Base: 0x" << std::hex << response.ImageBase << std::dec << std::endl;
        std::cout << "OEP Modified: " << (response.OEPModified ? "Yes" : "No") << std::endl;
        std::cout << "Signature Valid: " << (response.SignatureValid ? "Yes" : "No") << std::endl;
        std::cout << "Detection Method: " << response.DetectionMethod << std::endl;
        std::cout << "Status Message: " << response.StatusMessage << std::endl;
        
        return true;
    }
    
    bool ScanBootModules() {
        if (!m_connected) return false;
        
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_SCAN_MODULES,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to scan boot modules. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Boot modules scanned successfully." << std::endl;
        return true;
    }
    
    bool ResetStatistics() {
        if (!m_connected) return false;
        
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            IOCTL_BOOTLOADER_RESET_STATISTICS,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::cout << "Failed to reset statistics. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "Statistics reset successfully." << std::endl;
        return true;
    }
};

void PrintMenu() {
    std::cout << "\n=== Boot Loader Entry Point Analyzer Test Menu ===" << std::endl;
    std::cout << "1. Connect to driver" << std::endl;
    std::cout << "2. Enable boot loader analysis" << std::endl;
    std::cout << "3. Disable boot loader analysis" << std::endl;
    std::cout << "4. Get statistics" << std::endl;
    std::cout << "5. Detect OEP (winload.efi)" << std::endl;
    std::cout << "6. Scan boot modules" << std::endl;
    std::cout << "7. Reset statistics" << std::endl;
    std::cout << "8. Disconnect from driver" << std::endl;
    std::cout << "9. Exit" << std::endl;
    std::cout << "Enter choice: ";
}

int main() {
    std::cout << "Boot Loader Entry Point Analyzer Test Application" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "This application tests the Boot Loader Entry Point Analyzer" << std::endl;
    std::cout << "functionality implemented in Task 4.1." << std::endl;
    std::cout << std::endl;
    
    BootLoaderAnalyzerTester tester;
    bool running = true;
    
    while (running) {
        PrintMenu();
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                tester.Connect();
                break;
            case 2:
                tester.EnableBootLoaderAnalysis();
                break;
            case 3:
                tester.DisableBootLoaderAnalysis();
                break;
            case 4:
                tester.GetStatistics();
                break;
            case 5:
                tester.DetectOEP();
                break;
            case 6:
                tester.ScanBootModules();
                break;
            case 7:
                tester.ResetStatistics();
                break;
            case 8:
                tester.Disconnect();
                break;
            case 9:
                running = false;
                std::cout << "Exiting..." << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
    }
    
    return 0;
}