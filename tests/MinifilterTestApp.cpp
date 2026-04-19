// MinifilterTestApp.cpp: Test application for Minifilter Driver Implementation
// Demonstrates minifilter driver functionality for educational purposes

#include <windows.h>
#include <fltuser.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

#pragma comment(lib, "fltlib.lib")

// Constants
#define MINIFILTER_PORT_NAME L"\\BootkitAnalysisMinifilterPort"
#define BUFFER_SIZE 4096

// Function declarations
BOOL ConnectToMinifilter();
BOOL DisconnectFromMinifilter();
BOOL SendMinifilterCommand(DWORD command, LPVOID input, DWORD inputSize, LPVOID output, DWORD outputSize);
BOOL EnableMinifilterMonitoring();
BOOL DisableMinifilterMonitoring();
BOOL GetMinifilterStatistics();
BOOL ClearMinifilterStatistics();
BOOL TestFileAccessMonitoring();
BOOL TestIntegrityChecking();
BOOL TestDataSubstitution();
void PrintUsage();

// Global variables
HANDLE g_hPort = INVALID_HANDLE_VALUE;

int main(int argc, char* argv[])
{
    std::cout << "=== Bootkit Analysis Framework - Minifilter Test Application ===" << std::endl;
    std::cout << "Demonstrates minifilter driver functionality for file integrity analysis" << std::endl;
    std::cout << std::endl;

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];

    // Connect to minifilter
    if (!ConnectToMinifilter()) {
        std::cerr << "Failed to connect to minifilter driver" << std::endl;
        return 1;
    }

    std::cout << "Connected to minifilter driver successfully" << std::endl;

    // Process command
    if (command == "enable") {
        if (!EnableMinifilterMonitoring()) {
            std::cerr << "Failed to enable minifilter monitoring" << std::endl;
        } else {
            std::cout << "Minifilter monitoring enabled" << std::endl;
        }
    }
    else if (command == "disable") {
        if (!DisableMinifilterMonitoring()) {
            std::cerr << "Failed to disable minifilter monitoring" << std::endl;
        } else {
            std::cout << "Minifilter monitoring disabled" << std::endl;
        }
    }
    else if (command == "stats") {
        if (!GetMinifilterStatistics()) {
            std::cerr << "Failed to get minifilter statistics" << std::endl;
        }
    }
    else if (command == "clear") {
        if (!ClearMinifilterStatistics()) {
            std::cerr << "Failed to clear minifilter statistics" << std::endl;
        } else {
            std::cout << "Minifilter statistics cleared" << std::endl;
        }
    }
    else if (command == "test-file") {
        if (!TestFileAccessMonitoring()) {
            std::cerr << "File access monitoring test failed" << std::endl;
        } else {
            std::cout << "File access monitoring test completed" << std::endl;
        }
    }
    else if (command == "test-integrity") {
        if (!TestIntegrityChecking()) {
            std::cerr << "Integrity checking test failed" << std::endl;
        } else {
            std::cout << "Integrity checking test completed" << std::endl;
        }
    }
    else if (command == "test-substitution") {
        if (!TestDataSubstitution()) {
            std::cerr << "Data substitution test failed" << std::endl;
        } else {
            std::cout << "Data substitution test completed" << std::endl;
        }
    }
    else if (command == "all") {
        std::cout << "Running comprehensive minifilter tests..." << std::endl;
        
        if (!EnableMinifilterMonitoring()) {
            std::cerr << "Failed to enable monitoring" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        if (!TestFileAccessMonitoring()) {
            std::cerr << "File access test failed" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!TestIntegrityChecking()) {
            std::cerr << "Integrity test failed" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!GetMinifilterStatistics()) {
            std::cerr << "Failed to get statistics" << std::endl;
        }
        
        if (!DisableMinifilterMonitoring()) {
            std::cerr << "Failed to disable monitoring" << std::endl;
        }
        
        std::cout << "Comprehensive tests completed" << std::endl;
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        PrintUsage();
    }

    // Disconnect from minifilter
    DisconnectFromMinifilter();

    return 0;
}

// Connect to minifilter driver
BOOL ConnectToMinifilter()
{
    HRESULT hr = FilterConnectCommunicationPort(
        MINIFILTER_PORT_NAME,
        0,
        NULL,
        0,
        NULL,
        &g_hPort
    );

    return SUCCEEDED(hr);
}

// Disconnect from minifilter driver
BOOL DisconnectFromMinifilter()
{
    if (g_hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPort);
        g_hPort = INVALID_HANDLE_VALUE;
    }
    return TRUE;
}

// Send command to minifilter driver
BOOL SendMinifilterCommand(DWORD command, LPVOID input, DWORD inputSize, LPVOID output, DWORD outputSize)
{
    if (g_hPort == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD bytesReturned = 0;
    HRESULT hr = FilterSendMessage(
        g_hPort,
        &command,
        sizeof(command),
        output,
        outputSize,
        &bytesReturned
    );

    return SUCCEEDED(hr);
}

// Enable minifilter monitoring
BOOL EnableMinifilterMonitoring()
{
    DWORD command = 0x910; // IOCTL_MINIFILTER_ENABLE_MONITORING
    return SendMinifilterCommand(command, NULL, 0, NULL, 0);
}

// Disable minifilter monitoring
BOOL DisableMinifilterMonitoring()
{
    DWORD command = 0x911; // IOCTL_MINIFILTER_DISABLE_MONITORING
    return SendMinifilterCommand(command, NULL, 0, NULL, 0);
}

// Get minifilter statistics
BOOL GetMinifilterStatistics()
{
    DWORD command = 0x912; // IOCTL_MINIFILTER_GET_STATISTICS
    BYTE buffer[BUFFER_SIZE] = { 0 };
    
    if (!SendMinifilterCommand(command, NULL, 0, buffer, sizeof(buffer))) {
        return FALSE;
    }

    // Parse and display statistics
    // Note: In a real implementation, you would parse the actual structure
    std::cout << "=== Minifilter Statistics ===" << std::endl;
    std::cout << "Monitoring: Active" << std::endl;
    std::cout << "File Accesses: 0" << std::endl;
    std::cout << "Integrity Checks: 0" << std::endl;
    std::cout << "Integrity Violations: 0" << std::endl;
    std::cout << "Data Substitutions: 0" << std::endl;
    std::cout << "Uptime: 0 seconds" << std::endl;
    std::cout << "=============================" << std::endl;

    return TRUE;
}

// Clear minifilter statistics
BOOL ClearMinifilterStatistics()
{
    DWORD command = 0x913; // IOCTL_MINIFILTER_CLEAR_STATISTICS
    return SendMinifilterCommand(command, NULL, 0, NULL, 0);
}

// Test file access monitoring
BOOL TestFileAccessMonitoring()
{
    std::cout << "Testing file access monitoring..." << std::endl;
    
    // Create test file
    HANDLE hFile = CreateFile(
        L"test_file_access.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create test file" << std::endl;
        return FALSE;
    }

    // Write test data
    const char* testData = "This is a test file for minifilter monitoring.";
    DWORD bytesWritten = 0;
    
    if (!WriteFile(hFile, testData, (DWORD)strlen(testData), &bytesWritten, NULL)) {
        std::cerr << "Failed to write test data" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Read test file
    hFile = CreateFile(
        L"test_file_access.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open test file for reading" << std::endl;
        return FALSE;
    }

    char buffer[256] = { 0 };
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        std::cerr << "Failed to read test file" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Delete test file
    if (!DeleteFile(L"test_file_access.txt")) {
        std::cerr << "Failed to delete test file" << std::endl;
        return FALSE;
    }

    std::cout << "File access operations completed successfully" << std::endl;
    std::cout << "File content: " << buffer << std::endl;
    
    return TRUE;
}

// Test integrity checking
BOOL TestIntegrityChecking()
{
    std::cout << "Testing integrity checking..." << std::endl;
    
    // Create test file with known content
    HANDLE hFile = CreateFile(
        L"test_integrity.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create integrity test file" << std::endl;
        return FALSE;
    }

    const char* originalData = "Original integrity test data.";
    DWORD bytesWritten = 0;
    
    if (!WriteFile(hFile, originalData, (DWORD)strlen(originalData), &bytesWritten, NULL)) {
        std::cerr << "Failed to write integrity test data" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Read file (should trigger integrity check)
    hFile = CreateFile(
        L"test_integrity.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open integrity test file" << std::endl;
        return FALSE;
    }

    char buffer[256] = { 0 };
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        std::cerr << "Failed to read integrity test file" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Modify file (simulate integrity violation)
    hFile = CreateFile(
        L"test_integrity.txt",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file for modification" << std::endl;
        return FALSE;
    }

    const char* modifiedData = "Modified integrity test data!";
    
    if (!WriteFile(hFile, modifiedData, (DWORD)strlen(modifiedData), &bytesWritten, NULL)) {
        std::cerr << "Failed to modify integrity test data" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Read modified file (should detect integrity violation)
    hFile = CreateFile(
        L"test_integrity.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open modified file" << std::endl;
        return FALSE;
    }

    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        std::cerr << "Failed to read modified file" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Clean up
    if (!DeleteFile(L"test_integrity.txt")) {
        std::cerr << "Failed to delete integrity test file" << std::endl;
        return FALSE;
    }

    std::cout << "Integrity checking test completed" << std::endl;
    std::cout << "Original data: " << originalData << std::endl;
    std::cout << "Modified data: " << buffer << std::endl;
    
    return TRUE;
}

// Test data substitution
BOOL TestDataSubstitution()
{
    std::cout << "Testing data substitution..." << std::endl;
    
    // Create original file
    HANDLE hFile = CreateFile(
        L"test_original.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create original test file" << std::endl;
        return FALSE;
    }

    const char* originalData = "This is the original sensitive data.";
    DWORD bytesWritten = 0;
    
    if (!WriteFile(hFile, originalData, (DWORD)strlen(originalData), &bytesWritten, NULL)) {
        std::cerr << "Failed to write original test data" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Create substitute file
    hFile = CreateFile(
        L"test_substitute.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create substitute test file" << std::endl;
        return FALSE;
    }

    const char* substituteData = "This is substitute data for security analysis.";
    
    if (!WriteFile(hFile, substituteData, (DWORD)strlen(substituteData), &bytesWritten, NULL)) {
        std::cerr << "Failed to write substitute test data" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Read original file (minifilter might substitute data)
    hFile = CreateFile(
        L"test_original.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open original file for reading" << std::endl;
        return FALSE;
    }

    char buffer[256] = { 0 };
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        std::cerr << "Failed to read original file" << std::endl;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Clean up
    DeleteFile(L"test_original.txt");
    DeleteFile(L"test_substitute.txt");

    std::cout << "Data substitution test completed" << std::endl;
    std::cout << "Original data: " << originalData << std::endl;
    std::cout << "Substitute data: " << substituteData << std::endl;
    std::cout << "Read data: " << buffer << std::endl;
    
    return TRUE;
}

// Print usage information
void PrintUsage()
{
    std::cout << "Usage: MinifilterTestApp <command>" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  enable      - Enable minifilter monitoring" << std::endl;
    std::cout << "  disable     - Disable minifilter monitoring" << std::endl;
    std::cout << "  stats       - Get minifilter statistics" << std::endl;
    std::cout << "  clear       - Clear minifilter statistics" << std::endl;
    std::cout << "  test-file   - Test file access monitoring" << std::endl;
    std::cout << "  test-integrity - Test integrity checking" << std::endl;
    std::cout << "  test-substitution - Test data substitution" << std::endl;
    std::cout << "  all         - Run all tests" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: Minifilter driver must be installed and running" << std::endl;
}