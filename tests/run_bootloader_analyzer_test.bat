@echo off
echo ============================================
echo Boot Loader Entry Point Analyzer Test Script
echo ============================================
echo.
echo This script compiles and runs the test application
echo for the Boot Loader Entry Point Analyzer (Task 4.1)
echo.

:: Check for Visual Studio
echo Step 1: Checking for Visual Studio...
echo.

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
    echo Found Visual Studio 2019
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community
    echo Found Visual Studio 2022
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional
    echo Found Visual Studio 2019 Professional
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise
    echo Found Visual Studio 2019 Enterprise
) else (
    echo ERROR: Visual Studio not found!
    echo.
    echo Please install Visual Studio 2019 or later.
    pause
    exit /b 1
)

echo Step 2: Setting up build environment...
echo.
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorLevel% neq 0 (
    echo ERROR: Failed to set up build environment!
    echo.
    echo Make sure you're running from a command prompt that can
    echo execute batch files (not PowerShell with restrictions).
    pause
    exit /b 1
)

echo Step 3: Compiling test application...
echo.

:: Change to tests directory
cd /d "%~dp0"

:: Compile the test application
echo Compiling BootLoaderEntryPointAnalyzerTest.cpp...
cl.exe /EHsc /nologo /W4 /O2 /DUNICODE /D_UNICODE BootLoaderEntryPointAnalyzerTest.cpp /Fe:BootLoaderAnalyzerTest.exe

if %errorLevel% neq 0 (
    echo ERROR: Compilation failed!
    echo.
    echo Check for syntax errors in the test code.
    pause
    exit /b 1
)

echo Step 4: Checking if test executable was created...
echo.

if exist "BootLoaderAnalyzerTest.exe" (
    echo Test application compiled successfully: BootLoaderAnalyzerTest.exe
    echo File size: %%~zBootLoaderAnalyzerTest.exe bytes
    echo.
    
    echo Step 5: Running test application...
    echo.
    echo Note: The driver must be installed and running for the test to work.
    echo If the driver is not installed, the test will fail to connect.
    echo.
    echo Press any key to run the test application...
    pause >nul
    
    echo.
    echo ============================================
    echo Running Boot Loader Entry Point Analyzer Test
    echo ============================================
    echo.
    
    BootLoaderAnalyzerTest.exe
) else (
    echo ERROR: Test executable not found!
    echo.
    echo Check compilation output for errors.
)

echo.
echo ============================================
echo Test completed!
echo ============================================
echo.
echo Next steps:
echo 1. Build and install the driver using build_driver.bat
echo 2. Run this test again to verify functionality
echo 3. Review the implementation in BootLoaderEntryPointAnalyzer.cpp
echo.
pause