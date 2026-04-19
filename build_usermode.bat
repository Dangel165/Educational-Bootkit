@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Bootkit Analysis Framework - User Mode Build
echo ========================================
echo.
echo This script builds only the user-mode components (Tools and Tests).
echo Driver build requires Windows Driver Kit (WDK).
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

REM Set configuration (default to Release)
set "CONFIG=%1"
if "%CONFIG%"=="" set "CONFIG=Release"

echo Building configuration: %CONFIG%
echo.

REM Build BootkitTools
echo Building BootkitTools...
"%MSBUILD%" "tools\BootkitTools\BootkitTools.vcxproj" /p:Configuration=%CONFIG% /p:Platform=x64 /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: BootkitTools build failed!
    pause
    exit /b 1
)

echo BootkitTools build successful!
echo.

REM Build BootkitTests
echo Building BootkitTests...
"%MSBUILD%" "tests\BootkitTests\BootkitTests.vcxproj" /p:Configuration=%CONFIG% /p:Platform=x64 /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: BootkitTests build failed!
    pause
    exit /b 1
)

echo BootkitTests build successful!
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
    echo.
)

echo.
echo To run tests: cd bin\x64\%CONFIG% ^&^& BootkitTests.exe
echo To use tools: cd bin\x64\%CONFIG% ^&^& BootkitTools.exe
echo.
echo To build the driver, install Windows Driver Kit (WDK) and run build.bat
echo.

pause
