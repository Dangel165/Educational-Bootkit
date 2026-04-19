@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Bootkit Analysis Framework Build Script
echo ========================================
echo.

REM Check for Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio Installer not found!
    echo Please install Visual Studio 2019 or later with C++ Desktop Development workload.
    pause
    exit /b 1
)

REM Find MSBuild
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
    set "MSBUILD=%%i"
)

if not defined MSBUILD (
    echo ERROR: MSBuild not found!
    echo Please install Visual Studio with C++ Desktop Development workload.
    pause
    exit /b 1
)

echo Found MSBuild: %MSBUILD%
echo.

REM Check for WDK
set "WDK_PATH=%ProgramFiles(x86)%\Windows Kits\10"
if not exist "%WDK_PATH%" (
    echo WARNING: Windows Driver Kit (WDK) not found at: %WDK_PATH%
    echo Driver project may fail to build.
    echo You can download WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    echo.
    echo Press any key to continue anyway, or Ctrl+C to cancel...
    pause >nul
)

REM Set configuration (default to Release)
set "CONFIG=%1"
if "%CONFIG%"=="" set "CONFIG=Release"

echo Building configuration: %CONFIG%
echo.

REM Clean previous build
if exist "bin" (
    echo Cleaning previous build...
    rmdir /s /q "bin" 2>nul
)
if exist "obj" (
    rmdir /s /q "obj" 2>nul
)
echo.

REM Build the solution
echo Building solution...
echo.
"%MSBUILD%" "BootkitAnalysisFramework.sln" /p:Configuration=%CONFIG% /p:Platform=x64 /m /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo.
    echo Common issues:
    echo 1. Windows Driver Kit (WDK) not installed
    echo    Download from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    echo.
    echo 2. Visual Studio C++ Desktop Development workload not installed
    echo    Install via Visual Studio Installer
    echo.
    echo 3. Platform Toolset mismatch
    echo    Update project files to match your Visual Studio version
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo ========================================
echo.
echo Output directory: bin\x64\%CONFIG%\
echo.

REM List built files
if exist "bin\x64\%CONFIG%" (
    echo Built files:
    dir /b "bin\x64\%CONFIG%\*.exe" 2>nul
    dir /b "bin\x64\%CONFIG%\*.sys" 2>nul
    dir /b "bin\x64\%CONFIG%\*.dll" 2>nul
    echo.
)

echo.
echo To run tests: cd bin\x64\%CONFIG% ^&^& BootkitTests.exe
echo To use tools: cd bin\x64\%CONFIG% ^&^& BootkitTools.exe
echo.
echo NOTE: Driver installation requires administrator privileges and test signing mode.
echo Run scripts\enable_test_signing.bat to enable test signing.
echo.

pause
