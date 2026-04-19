@echo off
echo ============================================
echo Bootkit Analysis Framework - Driver Test Utility
echo ============================================
echo.
echo This script tests communication with the BootkitDriver
echo.
echo WARNING: This requires administrator privileges
echo.

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Set driver name and device path
set DRIVER_NAME=BootkitDriver
set DEVICE_PATH=\\.\%DRIVER_NAME%

echo Step 1: Checking driver service status...
echo.
sc query %DRIVER_NAME%
echo.

echo Step 2: Testing driver communication...
echo.
echo Creating test application...

:: Create a simple C test program
set TEST_PROGRAM=test_driver.c
set TEST_EXE=test_driver.exe

(
echo #include ^<windows.h^>
echo #include ^<stdio.h^>
echo.
echo // IOCTL codes from DeviceControl.h
echo ^#define IOCTL_BOOTKITDRIVER_GET_DRIVER_INFO     0x22000C
echo ^#define IOCTL_BOOTKITDRIVER_GET_STATISTICS      0x220010
echo ^#define IOCTL_BOOTKITDRIVER_PERFORM_TEST        0x220014
echo ^#define IOCTL_BOOTKITDRIVER_GET_VERSION         0x220018
echo ^#define IOCTL_BOOTKITDRIVER_RESET_STATISTICS    0x22001C
echo.
echo int main() {
echo     HANDLE hDevice;
echo     DWORD bytesReturned;
echo     BOOL result;
echo     ULONG version = 0;
echo.
echo     printf("Testing BootkitDriver communication...\n");
echo.
echo     // Open device
echo     hDevice = CreateFile(
echo         "\\\\.\\BootkitDriver",
echo         GENERIC_READ ^| GENERIC_WRITE,
echo         0,
echo         NULL,
echo         OPEN_EXISTING,
echo         FILE_ATTRIBUTE_NORMAL,
echo         NULL
echo     );
echo.
echo     if (hDevice == INVALID_HANDLE_VALUE) {
echo         printf("ERROR: Failed to open device. Error: %%d\n", GetLastError());
echo         printf("\nPossible solutions:\n");
echo         printf("1. Make sure driver is installed (run install_driver.bat)\n");
echo         printf("2. Make sure driver service is running\n");
echo         printf("3. Check device name is correct\n");
echo         return 1;
echo     }
echo.
echo     printf("Successfully opened device handle: 0x%%p\n", hDevice);
echo.
echo     // Test 1: Get driver version
echo     printf("\nTest 1: Getting driver version...\n");
echo     result = DeviceIoControl(
echo         hDevice,
echo         IOCTL_BOOTKITDRIVER_GET_VERSION,
echo         NULL,
echo         0,
echo         ^&version,
echo         sizeof(version),
echo         ^&bytesReturned,
echo         NULL
echo     );
echo.
echo     if (result) {
echo         printf("Success! Driver version: 0x%%08X\n", version);
echo         printf("Bytes returned: %%lu\n", bytesReturned);
echo     } else {
echo         printf("Failed! Error: %%d\n", GetLastError());
echo     }
echo.
echo     // Test 2: Get driver info
echo     printf("\nTest 2: Getting driver information...\n");
echo     // This would require a proper structure - simplified for demo
echo     printf("(Driver info test requires proper buffer setup)\n");
echo.
echo     // Test 3: Get statistics
echo     printf("\nTest 3: Getting driver statistics...\n");
echo     // This would require a proper structure - simplified for demo
echo     printf("(Statistics test requires proper buffer setup)\n");
echo.
echo     // Close device
echo     CloseHandle(hDevice);
echo     printf("\nDevice handle closed.\n");
echo.
echo     printf("\n============================================\n");
echo     printf("Basic driver communication test completed!\n");
echo     printf("============================================\n");
echo.
echo     if (result) {
echo         printf("SUCCESS: Driver is responding to IOCTL requests.\n");
echo         printf("The driver framework is working correctly.\n");
echo     } else {
echo         printf("WARNING: Driver opened but IOCTL failed.\n");
echo         printf("Check driver implementation and IOCTL codes.\n");
echo     }
echo.
echo     return 0;
echo }
) > %TEST_PROGRAM%

echo Test program created: %TEST_PROGRAM%
echo.

echo Step 3: Compiling test program...
echo.
:: Try to compile with available compiler
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    cl /nologo /W4 %TEST_PROGRAM% /Fe:%TEST_EXE%
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    cl /nologo /W4 %TEST_PROGRAM% /Fe:%TEST_EXE%
) else (
    echo WARNING: Visual Studio not found or vcvarsall.bat not in expected location
    echo You need to compile the test program manually:
    echo 1. Open Developer Command Prompt for VS
    echo 2. Navigate to this directory
    echo 3. Run: cl /nologo /W4 test_driver.c
    echo.
    echo Press any key to open the test program source code...
    pause
    notepad %TEST_PROGRAM%
    goto :SKIP_COMPILE
)

:SKIP_COMPILE
if exist %TEST_EXE% (
    echo Step 4: Running test program...
    echo.
    %TEST_EXE%
    echo.
    
    echo Step 5: Cleaning up...
    del %TEST_PROGRAM% 2>nul
    del %TEST_EXE% 2>nul
    del *.obj 2>nul
) else (
    echo ERROR: Failed to compile test program
    echo.
    echo You can manually compile and run the test program:
    echo 1. Open Developer Command Prompt for Visual Studio
    echo 2. Navigate to: %CD%
    echo 3. Run: cl /nologo /W4 test_driver.c
    echo 4. Run: test_driver.exe
    echo.
    echo The test program source is at: %TEST_PROGRAM%
)

echo.
echo ============================================
echo Test completed!
echo ============================================
echo.
echo For more advanced testing:
echo 1. Use WinDbg for kernel debugging
echo 2. Create a proper user-mode test application
echo 3. Implement all IOCTL tests with proper structures
echo.
pause