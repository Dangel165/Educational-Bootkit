@echo off
echo ============================================
echo Bootkit Analysis Framework - Driver Uninstallation
echo ============================================
echo.
echo This script uninstalls the BootkitDriver kernel driver
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

:: Set driver name
set DRIVER_NAME=BootkitDriver

echo Step 1: Stopping driver service...
echo Stopping %DRIVER_NAME% service...

sc stop %DRIVER_NAME% >nul 2>&1
if %errorLevel% neq 0 (
    echo Service was not running or does not exist
)

echo Step 2: Deleting driver service...
sc delete %DRIVER_NAME% >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Failed to delete service (may not exist)
)

echo Step 3: Removing driver package...
echo Removing %DRIVER_NAME% driver package...

:: Find the driver package name
for /f "tokens=2 delims=:" %%i in ('pnputil /enum-drivers ^| findstr /i "BootkitDriver"') do (
    set PACKAGE_NAME=%%i
    goto :FOUND_PACKAGE
)

:FOUND_PACKAGE
if "%PACKAGE_NAME%"=="" (
    echo Driver package not found in pnputil list
    echo It may have been already removed
) else (
    echo Found package: %PACKAGE_NAME%
    pnputil /delete-driver %PACKAGE_NAME% /uninstall /force
    if %errorLevel% neq 0 (
        echo WARNING: Failed to remove driver package
        echo You can try manually: pnputil /delete-driver %PACKAGE_NAME%
    )
)

echo Step 4: Cleaning up files...
echo.
echo Note: Driver files (.sys, .inf, .cat) are typically stored in:
echo C:\Windows\System32\DriverStore\FileRepository\
echo.
echo You may need to manually delete them if they persist.
echo.

echo Step 5: Verifying uninstallation...
echo.
echo Checking if driver service exists...
sc query %DRIVER_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo ERROR: Driver service still exists!
    echo You may need to manually delete it with: sc delete %DRIVER_NAME%
) else (
    echo Driver service successfully removed
)

echo.
echo ============================================
echo Driver uninstallation completed!
echo ============================================
echo.
echo If you want to completely remove test signing mode:
echo 1. Run: bcdedit /set testsigning off
echo 2. Run: bcdedit /set nointegritychecks off
echo 3. Restart your computer
echo.
echo Note: Disabling test signing is recommended for normal use
echo to restore full Windows security features.
echo.
pause