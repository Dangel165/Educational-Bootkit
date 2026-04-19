// BootFlowInterceptorTest.cpp: Test application for Boot Flow Interceptor (Task 1.2)
// Tests the boot process execution flow interception functionality of the bootkit analysis framework driver

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// IOCTL codes from BootFlowInterceptor.h
#define IOCTL_BOOTANALYSIS_ENABLE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_DISABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_GET_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_RESET_STATISTICS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_GET_REPORT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x914, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_SCAN_MODULES      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x915, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_TRACE_FLOW        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x916, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Boot analysis statistics structure
typedef struct _BOOT_ANALYSIS_STATISTICS {
    ULONG BootInterceptions;
    ULONG KernelInitTraces;
    ULONG UEFIServiceCalls;
    ULONG BootTimeViolations;
    ULONG HookedEntryPoints;
    ULONG ScannedModules;
    ULONG DetectedModifications;
    BOOLEAN AnalysisActive;
    BOOLEAN UEFIBoot;
    BOOLEAN SecureBootEnabled;
    ULONG64 BootStartTime;
    ULONG64 CurrentBootTime;
    ULONG64 AnalysisStartTime;
    ULONG64 UptimeSeconds;
    WCHAR FirmwareVendor[64];
    WCHAR FirmwareVersion[64];
} BOOT_ANALYSIS_STATISTICS, *PBOOT_ANALYSIS_STATISTICS;

// Boot analysis report structure
typedef struct _BOOT_ANALYSIS_REPORT {
    ULONG ReportVersion;
    ULONG64 ReportTime;
    BOOT_ANALYSIS_STATISTICS Statistics;
    ULONG ModuleCount;
    ULONG ServiceCallCount;
    ULONG HookCount;
    ULONG ViolationCount;
    WCHAR Summary[512];
} BOOT_ANALYSIS_REPORT, *PBOOT_ANALYSIS_REPORT;

class BootFlowInterceptorTester {
private:
    HANDLE m_deviceHandle;
    bool m_connected;
    
public:
    BootFlowInterceptorTester() : m_deviceHandle(INVALID_HANDLE_VALUE), m_connected(false) {}
    
    ~BootFlowInterceptorTester() {
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
            std::cerr << "Failed to connect to driver. Error: " << error << std::endl;
            m_connected = false;
            return false;
        }
        
        std::cout << "Connected to driver successfully" << std::endl;
        m_connected = true;
        return true;
    }
    
    void Disconnect() {
        if (m_deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_deviceHandle);
            m_deviceHandle = INVALID_HANDLE_VALUE;
        }
        m_connected = false;
    }
    
    bool SendIoctl(DWORD ioctlCode, LPVOID inputBuffer, DWORD inputSize,
                   LPVOID outputBuffer, DWORD outputSize, LPDWORD bytesReturned) {
        if (!m_connected) {
            std::cerr << "Not connected to driver" << std::endl;
            return false;
        }
        
        DWORD returned = 0;
        BOOL result = DeviceIoControl(
            m_deviceHandle,
            ioctlCode,
            inputBuffer,
            inputSize,
            outputBuffer,
            outputSize,
            &returned,
            NULL
        );
        
        if (bytesReturned) {
            *bytesReturned = returned;
        }
        
        if (!result) {
            DWORD error = GetLastError();
            std::cerr << "DeviceIoControl failed. Error: " << error << std::endl;
            return false;
        }
        
        return true;
    }
    
    bool EnableBootAnalysis(bool enable) {
        DWORD ioctlCode = enable ? IOCTL_BOOTANALYSIS_ENABLE : 
                                   IOCTL_BOOTANALYSIS_DISABLE;
        
        std::cout << (enable ? "Enabling" : "Disabling") << " boot analysis..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(ioctlCode, NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Boot analysis " << (enable ? "enabled" : "disabled") << " successfully" << std::endl;
        }
        
        return result;
    }
    
    bool GetBootAnalysisStatistics() {
        std::cout << "Getting boot analysis statistics..." << std::endl;
        
        BOOT_ANALYSIS_STATISTICS stats = { 0 };
        DWORD bytesReturned = 0;
        
        bool result = SendIoctl(IOCTL_BOOTANALYSIS_GET_STATISTICS, 
                               NULL, 0, 
                               &stats, sizeof(stats), 
                               &bytesReturned);
        
        if (result && bytesReturned == sizeof(stats)) {
            std::cout << "Boot Analysis Statistics:" << std::endl;
            std::cout << "  Analysis Active: " << (stats.AnalysisActive ? "Yes" : "No") << std::endl;
            std::cout << "  UEFI Boot: " << (stats.UEFIBoot ? "Yes" : "No") << std::endl;
            std::cout << "  Secure Boot Enabled: " << (stats.SecureBootEnabled ? "Yes" : "No") << std::endl;
            std::cout << "  Boot Interceptions: " << stats.BootInterceptions << std::endl;
            std::cout << "  Kernel Init Traces: " << stats.KernelInitTraces << std::endl;
            std::cout << "  UEFI Service Calls: " << stats.UEFIServiceCalls << std::endl;
            std::cout << "  Boot Time Violations: " << stats.BootTimeViolations << std::endl;
            std::cout << "  Hooked Entry Points: " << stats.HookedEntryPoints << std::endl;
            std::cout << "  Scanned Modules: " << stats.ScannedModules << std::endl;
            std::cout << "  Detected Modifications: " << stats.DetectedModifications << std::endl;
            std::cout << "  Uptime (seconds): " << stats.UptimeSeconds << std::endl;
            
            if (wcslen(stats.FirmwareVendor) > 0) {
                std::wcout << L"  Firmware Vendor: " << stats.FirmwareVendor << std::endl;
            }
            if (wcslen(stats.FirmwareVersion) > 0) {
                std::wcout << L"  Firmware Version: " << stats.FirmwareVersion << std::endl;
            }
            
            return true;
        } else {
            std::cerr << "Failed to get statistics. Bytes returned: " << bytesReturned << std::endl;
            return false;
        }
    }
    
    bool ResetBootAnalysisStatistics() {
        std::cout << "Resetting boot analysis statistics..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(IOCTL_BOOTANALYSIS_RESET_STATISTICS, 
                               NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Statistics reset successfully" << std::endl;
        }
        
        return result;
    }
    
    bool GetBootAnalysisReport() {
        std::cout << "Getting boot analysis report..." << std::endl;
        
        // First get required size
        DWORD bytesReturned = 0;
        BOOT_ANALYSIS_REPORT report = { 0 };
        
        // Try with minimum size first
        bool result = SendIoctl(IOCTL_BOOTANALYSIS_GET_REPORT, 
                               NULL, 0, 
                               &report, sizeof(report), 
                               &bytesReturned);
        
        if (!result && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            // Buffer too small, allocate larger buffer
            std::cout << "Report requires larger buffer. Allocating..." << std::endl;
            
            // Estimate required size
            DWORD estimatedSize = sizeof(BOOT_ANALYSIS_REPORT) + (100 * 256); // Estimate
            std::vector<BYTE> buffer(estimatedSize);
            
            result = SendIoctl(IOCTL_BOOTANALYSIS_GET_REPORT, 
                              NULL, 0, 
                              buffer.data(), estimatedSize, 
                              &bytesReturned);
            
            if (result && bytesReturned >= sizeof(BOOT_ANALYSIS_REPORT)) {
                PBOOT_ANALYSIS_REPORT fullReport = (PBOOT_ANALYSIS_REPORT)buffer.data();
                
                std::cout << "Boot Analysis Report:" << std::endl;
                std::cout << "  Report Version: " << fullReport->ReportVersion << std::endl;
                std::cout << "  Module Count: " << fullReport->ModuleCount << std::endl;
                std::cout << "  Service Call Count: " << fullReport->ServiceCallCount << std::endl;
                std::cout << "  Hook Count: " << fullReport->HookCount << std::endl;
                std::cout << "  Violation Count: " << fullReport->ViolationCount << std::endl;
                
                if (wcslen(fullReport->Summary) > 0) {
                    std::wcout << L"  Summary: " << fullReport->Summary << std::endl;
                }
                
                return true;
            }
        } else if (result && bytesReturned >= sizeof(BOOT_ANALYSIS_REPORT)) {
            std::cout << "Boot Analysis Report:" << std::endl;
            std::cout << "  Report Version: " << report.ReportVersion << std::endl;
            std::cout << "  Module Count: " << report.ModuleCount << std::endl;
            std::cout << "  Service Call Count: " << report.ServiceCallCount << std::endl;
            std::cout << "  Hook Count: " << report.HookCount << std::endl;
            std::cout << "  Violation Count: " << report.ViolationCount << std::endl;
            
            if (wcslen(report.Summary) > 0) {
                std::wcout << L"  Summary: " << report.Summary << std::endl;
            }
            
            return true;
        }
        
        std::cerr << "Failed to get report. Bytes returned: " << bytesReturned << std::endl;
        return false;
    }
    
    bool ScanBootModules() {
        std::cout << "Scanning boot modules..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(IOCTL_BOOTANALYSIS_SCAN_MODULES, 
                               NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Boot module scan initiated" << std::endl;
        }
        
        return result;
    }
    
    bool TraceBootFlow() {
        std::cout << "Tracing boot control flow..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(IOCTL_BOOTANALYSIS_TRACE_FLOW, 
                               NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Boot flow tracing initiated" << std::endl;
        }
        
        return result;
    }
    
    void RunComprehensiveTest() {
        std::cout << "\n=== Boot Flow Interceptor Comprehensive Test ===\n" << std::endl;
        
        // Step 1: Connect to driver
        if (!Connect()) {
            std::cerr << "Failed to connect to driver. Make sure driver is loaded." << std::endl;
            return;
        }
        
        // Step 2: Get initial statistics
        std::cout << "\n--- Step 1: Initial Statistics ---" << std::endl;
        GetBootAnalysisStatistics();
        
        // Step 3: Enable analysis
        std::cout << "\n--- Step 2: Enable Analysis ---" << std::endl;
        EnableBootAnalysis(true);
        GetBootAnalysisStatistics();
        
        // Step 4: Scan boot modules
        std::cout << "\n--- Step 3: Scan Boot Modules ---" << std::endl;
        ScanBootModules();
        
        // Step 5: Trace boot flow
        std::cout << "\n--- Step 4: Trace Boot Flow ---" << std::endl;
        TraceBootFlow();
        
        // Step 6: Get updated statistics
        std::cout << "\n--- Step 5: Updated Statistics ---" << std::endl;
        GetBootAnalysisStatistics();
        
        // Step 7: Get detailed report
        std::cout << "\n--- Step 6: Detailed Report ---" << std::endl;
        GetBootAnalysisReport();
        
        // Step 8: Reset statistics
        std::cout << "\n--- Step 7: Reset Statistics ---" << std::endl;
        ResetBootAnalysisStatistics();
        GetBootAnalysisStatistics();
        
        // Step 9: Disable analysis
        std::cout << "\n--- Step 8: Disable Analysis ---" << std::endl;
        EnableBootAnalysis(false);
        GetBootAnalysisStatistics();
        
        // Step 10: Final report
        std::cout << "\n--- Step 9: Final Report ---" << std::endl;
        GetBootAnalysisReport();
        
        std::cout << "\n=== Test Complete ===" << std::endl;
        
        Disconnect();
    }
    
    void RunSimpleTest() {
        std::cout << "\n=== Boot Flow Interceptor Simple Test ===\n" << std::endl;
        
        if (!Connect()) {
            std::cerr << "Failed to connect to driver" << std::endl;
            return;
        }
        
        // Quick test of basic functionality
        EnableBootAnalysis(true);
        GetBootAnalysisStatistics();
        ScanBootModules();
        TraceBootFlow();
        GetBootAnalysisReport();
        EnableBootAnalysis(false);
        
        Disconnect();
        
        std::cout << "\n=== Simple Test Complete ===" << std::endl;
    }
    
    void RunIntegrationTest() {
        std::cout << "\n=== Boot Flow Interceptor Integration Test ===\n" << std::endl;
        std::cout << "Testing integration with IRP Dispatcher Monitor..." << std::endl;
        
        if (!Connect()) {
            std::cerr << "Failed to connect to driver" << std::endl;
            return;
        }
        
        // Test that both components can work together
        std::cout << "\n1. Enabling boot analysis..." << std::endl;
        EnableBootAnalysis(true);
        
        std::cout << "\n2. Getting combined statistics..." << std::endl;
        GetBootAnalysisStatistics();
        
        std::cout << "\n3. Scanning boot modules..." << std::endl;
        ScanBootModules();
        
        std::cout << "\n4. Tracing boot flow..." << std::endl;
        TraceBootFlow();
        
        std::cout << "\n5. Getting comprehensive report..." << std::endl;
        GetBootAnalysisReport();
        
        std::cout << "\n6. Disabling boot analysis..." << std::endl;
        EnableBootAnalysis(false);
        
        Disconnect();
        
        std::cout << "\n=== Integration Test Complete ===" << std::endl;
    }
};

int main() {
    std::cout << "Boot Flow Interceptor Test Application" << std::endl;
    std::cout << "=======================================" << std::endl;
    std::cout << "This application tests the boot flow interception functionality" << std::endl;
    std::cout << "implemented in Task 1.2 of the bootkit analysis framework." << std::endl;
    std::cout << std::endl;
    
    BootFlowInterceptorTester tester;
    
    // Ask user which test to run
    std::cout << "Select test mode:" << std::endl;
    std::cout << "1. Comprehensive Test (all features)" << std::endl;
    std::cout << "2. Simple Test (basic functionality)" << std::endl;
    std::cout << "3. Integration Test (with IRP monitor)" << std::endl;
    std::cout << "4. Exit" << std::endl;
    std::cout << "Choice: ";
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 1:
            tester.RunComprehensiveTest();
            break;
        case 2:
            tester.RunSimpleTest();
            break;
        case 3:
            tester.RunIntegrationTest();
            break;
        case 4:
            std::cout << "Exiting..." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Running simple test." << std::endl;
            tester.RunSimpleTest();
            break;
    }
    
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.ignore();
    std::cin.get();
    
    return 0;
}