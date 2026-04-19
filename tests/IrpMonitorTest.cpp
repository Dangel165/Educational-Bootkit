// IrpMonitorTest.cpp: Test application for IRP Dispatcher Monitor (Task 1.1)
// Tests the IRP monitoring functionality of the bootkit analysis framework driver

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

// IOCTL codes from IrpMonitor.h
#define IOCTL_IRPMONITOR_ENABLE_MONITORING     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_DISABLE_MONITORING    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_STATISTICS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_RESET_STATISTICS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_SCAN_DISPATCH_TABLE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_MODIFICATIONS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IRP monitoring statistics structure
typedef struct _IRP_MONITORING_STATISTICS {
    ULONG TotalIrpsMonitored;
    ULONG ReadIrpsMonitored;
    ULONG DirectoryControlIrpsMonitored;
    ULONG CompletionRoutinesTraced;
    ULONG DispatchTableScansPerformed;
    ULONG ModificationsDetected;
    ULONG HookInstallations;
    ULONG HookFailures;
    ULONG64 MonitoringStartTime;
    ULONG64 UptimeSeconds;
    BOOLEAN MonitoringActive;
    BOOLEAN ReadHookActive;
    BOOLEAN DirectoryControlHookActive;
    BOOLEAN CompletionHookActive;
} IRP_MONITORING_STATISTICS, *PIRP_MONITORING_STATISTICS;

class IrpMonitorTester {
private:
    HANDLE m_deviceHandle;
    bool m_connected;
    
public:
    IrpMonitorTester() : m_deviceHandle(INVALID_HANDLE_VALUE), m_connected(false) {}
    
    ~IrpMonitorTester() {
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
    
    bool EnableIrpMonitoring(bool enable) {
        DWORD ioctlCode = enable ? IOCTL_IRPMONITOR_ENABLE_MONITORING : 
                                   IOCTL_IRPMONITOR_DISABLE_MONITORING;
        
        std::cout << (enable ? "Enabling" : "Disabling") << " IRP monitoring..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(ioctlCode, NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "IRP monitoring " << (enable ? "enabled" : "disabled") << " successfully" << std::endl;
        }
        
        return result;
    }
    
    bool GetIrpMonitoringStatistics() {
        std::cout << "Getting IRP monitoring statistics..." << std::endl;
        
        IRP_MONITORING_STATISTICS stats = { 0 };
        DWORD bytesReturned = 0;
        
        bool result = SendIoctl(IOCTL_IRPMONITOR_GET_STATISTICS, 
                               NULL, 0, 
                               &stats, sizeof(stats), 
                               &bytesReturned);
        
        if (result && bytesReturned == sizeof(stats)) {
            std::cout << "IRP Monitoring Statistics:" << std::endl;
            std::cout << "  Monitoring Active: " << (stats.MonitoringActive ? "Yes" : "No") << std::endl;
            std::cout << "  Read Hook Active: " << (stats.ReadHookActive ? "Yes" : "No") << std::endl;
            std::cout << "  Directory Control Hook Active: " << (stats.DirectoryControlHookActive ? "Yes" : "No") << std::endl;
            std::cout << "  Completion Hook Active: " << (stats.CompletionHookActive ? "Yes" : "No") << std::endl;
            std::cout << "  Hook Installations: " << stats.HookInstallations << std::endl;
            std::cout << "  Modifications Detected: " << stats.ModificationsDetected << std::endl;
            std::cout << "  Dispatch Table Scans: " << stats.DispatchTableScansPerformed << std::endl;
            std::cout << "  Uptime (seconds): " << stats.UptimeSeconds << std::endl;
            return true;
        } else {
            std::cerr << "Failed to get statistics. Bytes returned: " << bytesReturned << std::endl;
            return false;
        }
    }
    
    bool ResetIrpMonitoringStatistics() {
        std::cout << "Resetting IRP monitoring statistics..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(IOCTL_IRPMONITOR_RESET_STATISTICS, 
                               NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Statistics reset successfully" << std::endl;
        }
        
        return result;
    }
    
    bool ScanDispatchTable() {
        std::cout << "Scanning dispatch table for modifications..." << std::endl;
        
        DWORD bytesReturned = 0;
        bool result = SendIoctl(IOCTL_IRPMONITOR_SCAN_DISPATCH_TABLE, 
                               NULL, 0, NULL, 0, &bytesReturned);
        
        if (result) {
            std::cout << "Dispatch table scan initiated" << std::endl;
        }
        
        return result;
    }
    
    bool GetDetectedModifications() {
        std::cout << "Getting detected modifications count..." << std::endl;
        
        DWORD modifications = 0;
        DWORD bytesReturned = 0;
        
        bool result = SendIoctl(IOCTL_IRPMONITOR_GET_MODIFICATIONS, 
                               NULL, 0, 
                               &modifications, sizeof(modifications), 
                               &bytesReturned);
        
        if (result && bytesReturned == sizeof(modifications)) {
            std::cout << "Detected modifications: " << modifications << std::endl;
            return true;
        } else {
            std::cerr << "Failed to get modifications. Bytes returned: " << bytesReturned << std::endl;
            return false;
        }
    }
    
    void RunComprehensiveTest() {
        std::cout << "\n=== IRP Dispatcher Monitor Comprehensive Test ===\n" << std::endl;
        
        // Step 1: Connect to driver
        if (!Connect()) {
            std::cerr << "Failed to connect to driver. Make sure driver is loaded." << std::endl;
            return;
        }
        
        // Step 2: Get initial statistics
        std::cout << "\n--- Step 1: Initial Statistics ---" << std::endl;
        GetIrpMonitoringStatistics();
        
        // Step 3: Enable monitoring
        std::cout << "\n--- Step 2: Enable Monitoring ---" << std::endl;
        EnableIrpMonitoring(true);
        GetIrpMonitoringStatistics();
        
        // Step 4: Scan dispatch table
        std::cout << "\n--- Step 3: Scan Dispatch Table ---" << std::endl;
        ScanDispatchTable();
        GetDetectedModifications();
        
        // Step 5: Get updated statistics
        std::cout << "\n--- Step 4: Updated Statistics ---" << std::endl;
        GetIrpMonitoringStatistics();
        
        // Step 6: Reset statistics
        std::cout << "\n--- Step 5: Reset Statistics ---" << std::endl;
        ResetIrpMonitoringStatistics();
        GetIrpMonitoringStatistics();
        
        // Step 7: Disable monitoring
        std::cout << "\n--- Step 6: Disable Monitoring ---" << std::endl;
        EnableIrpMonitoring(false);
        GetIrpMonitoringStatistics();
        
        // Step 8: Final scan
        std::cout << "\n--- Step 7: Final Scan ---" << std::endl;
        ScanDispatchTable();
        GetDetectedModifications();
        
        std::cout << "\n=== Test Complete ===" << std::endl;
        
        Disconnect();
    }
    
    void RunSimpleTest() {
        std::cout << "\n=== IRP Dispatcher Monitor Simple Test ===\n" << std::endl;
        
        if (!Connect()) {
            std::cerr << "Failed to connect to driver" << std::endl;
            return;
        }
        
        // Quick test of basic functionality
        EnableIrpMonitoring(true);
        GetIrpMonitoringStatistics();
        ScanDispatchTable();
        GetDetectedModifications();
        EnableIrpMonitoring(false);
        
        Disconnect();
        
        std::cout << "\n=== Simple Test Complete ===" << std::endl;
    }
};

int main() {
    std::cout << "IRP Dispatcher Monitor Test Application" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "This application tests the IRP monitoring functionality" << std::endl;
    std::cout << "implemented in Task 1.1 of the bootkit analysis framework." << std::endl;
    std::cout << std::endl;
    
    IrpMonitorTester tester;
    
    // Ask user which test to run
    std::cout << "Select test mode:" << std::endl;
    std::cout << "1. Comprehensive Test (all features)" << std::endl;
    std::cout << "2. Simple Test (basic functionality)" << std::endl;
    std::cout << "3. Exit" << std::endl;
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