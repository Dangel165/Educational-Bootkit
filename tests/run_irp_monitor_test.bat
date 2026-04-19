@echo off
echo IRP Dispatcher Monitor Test Runner
echo =================================
echo.
echo This batch file helps test the IRP Dispatcher Monitor implementation.
echo.

REM Check if Visual Studio environment is set up
if "%VCINSTALLDIR%"=="" (
    echo ERROR: Visual Studio environment not detected.
    echo Please run this from a Visual Studio Developer Command Prompt.
    echo.
    pause
    exit /b 1
)

REM Compile the test application
echo Compiling test application...
cl.exe /EHsc /nologo /W4 /O2 /std:c++17 /Fe:IrpMonitorTest.exe IrpMonitorTest.cpp

if errorlevel 1 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo.
echo Test application compiled successfully: IrpMonitorTest.exe
echo.

REM Instructions for testing
echo Testing Instructions:
echo 1. First, load the BootkitDriver driver using the test signing setup
echo 2. Run this test application from an elevated command prompt
echo 3. The test will communicate with the driver using IOCTLs
echo.
echo Note: The driver must be loaded and the device must be accessible.
echo.

REM Ask if user wants to run the test
set /p runtest="Do you want to run the test now? (Y/N): "
if /i "%runtest%"=="Y" (
    echo.
    echo Running test application...
    echo.
    IrpMonitorTest.exe
) else (
    echo.
    echo Test application ready. Run IrpMonitorTest.exe when driver is loaded.
)

echo.
pause