@echo off
REM Evasion Engine Test Execution Script
REM Educational Security Research Purpose Only

echo ==========================================
echo Evasion Engine Test Suite
echo Educational Security Research Purpose Only
echo ==========================================

REM Check if Visual Studio environment is available
if not exist "%VCINSTALLDIR%\vcvarsall.bat" (
    echo Error: Visual Studio environment not found.
    echo Please run from Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

REM Set up build environment
call "%VCINSTALLDIR%\vcvarsall.bat" x64

REM Create build directory
if not exist "build" mkdir build
cd build

REM Configure CMake
echo Configuring CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

if errorlevel 1 (
    echo CMake configuration failed.
    pause
    exit /b 1
)

REM Build the project
echo Building Evasion Engine tests...
cmake --build . --config Release --target EvasionEngineTest

if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

REM Run tests
echo Running Evasion Engine tests...
echo.
echo Note: Some tests may show different results depending on execution environment.
echo This is expected behavior for evasion technique testing.
echo.

if exist "Release\EvasionEngineTest.exe" (
    Release\EvasionEngineTest.exe
) else if exist "EvasionEngineTest.exe" (
    EvasionEngineTest.exe
) else (
    echo Test executable not found.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Test execution completed.
echo ==========================================
pause