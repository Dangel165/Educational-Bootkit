@echo off
echo ============================================
echo Bootkit Analysis Framework - Test Signing Setup
echo ============================================
echo.
echo This script enables test signing mode on Windows
echo Required for loading unsigned drivers during development
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

echo Step 1: Enabling test signing mode...
bcdedit /set testsigning on
if %errorLevel% neq 0 (
    echo ERROR: Failed to enable test signing!
    echo.
    echo Possible solutions:
    echo 1. Make sure you're running as Administrator
    echo 2. Check if Secure Boot is disabled in BIOS
    echo 3. Try running: bcdedit /set testsigning on
    pause
    exit /b 1
)

echo Step 2: Disabling driver signature enforcement...
bcdedit /set nointegritychecks on
if %errorLevel% neq 0 (
    echo WARNING: Failed to disable integrity checks
    echo This may not be necessary on your system
)

echo Step 3: Displaying current boot configuration...
echo.
echo Current boot configuration:
bcdedit /enum | findstr "testsigning"
bcdedit /enum | findstr "nointegritychecks"

echo.
echo ============================================
echo IMPORTANT: You must restart your computer!
echo ============================================
echo.
echo After restart, test signing will be enabled and
echo you can load unsigned drivers for development.
echo.
echo To verify test signing is enabled after restart:
echo 1. Open Command Prompt as Administrator
echo 2. Run: bcdedit /enum | findstr "testsigning"
echo 3. Should show: testsigning Yes
echo.
pause