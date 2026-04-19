@echo off
echo ============================================
echo Bootkit Analysis Framework - Driver Installation
echo ============================================
echo.
echo This script installs the BootkitDriver kernel driver
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

:: Set paths
set DRIVER_NAME=BootkitDriver
set DRIVER_PATH=%~dp0..\drivers\%DRIVER_NAME%\%DRIVER_NAME%.sys
set INF_PATH=%~dp0..\drivers\%DRIVER_NAME%\%DRIVER_NAME%.inf

:: Check if driver files exist
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver file not found: %DRIVER_PATH%
    echo Please build the driver first
    pause
    exit /b 1
)

if not exist "%INF_PATH%" (
    echo ERROR: INF file not found: %INF_PATH%
    pause
    exit /b 1
)

echo Step 1: Checking test signing status...
bcdedit /enum | findstr "testsigning" | findstr "Yes" >nul
if %errorLevel% neq 0 (
    echo WARNING: Test signing may not be enabled!
    echo.
    echo To enable test signing, run:
    echo 1. enable_test_signing.bat (as Administrator)
    echo 2. Restart your computer
    echo.
    echo Do you want to continue anyway? (Y/N)
    set /p CONTINUE=
    if /i not "%CONTINUE%"=="Y" (
        echo Installation cancelled.
        pause
        exit /b 1
    )
)

echo Step 2: Installing driver using INF file...
echo Installing driver from: %INF_PATH%
echo.

:: Use pnputil to install the driver
echo Installing driver package...
pnputil /add-driver "%INF_PATH%" /install

if %errorLevel% neq 0 (
    echo ERROR: Failed to install driver package!
    echo.
    echo Possible solutions:
    echo 1. Make sure test signing is enabled (see enable_test_signing.bat)
    echo 2. Check if driver is already installed
    echo 3. Try manual installation: pnputil /add-driver "path\to\driver.inf" /install
    pause
    exit /b 1
)

echo Step 3: Starting driver service...
echo Starting %DRIVER_NAME% service...

:: Create the service if it doesn't exist
sc query %DRIVER_NAME% >nul 2>&1
if %errorLevel% neq 0 (
    echo Creating %DRIVER_NAME% service...
    sc create %DRIVER_NAME% binPath= "%DRIVER_PATH%" type= kernel start= demand displayName= "Bootkit Analysis Framework Driver"
    if %errorLevel% neq 0 (
        echo WARNING: Failed to create service, but driver may still be installed
    )
)

:: Start the service
sc start %DRIVER_NAME%
if %errorLevel% neq 0 (
    echo WARNING: Failed to start service, but driver may still be installed
    echo You can try starting it manually with: sc start %DRIVER_NAME%
)

echo Step 4: Verifying driver installation...
echo.
echo Checking driver status...

sc query %DRIVER_NAME%
echo.

echo Driver installation completed!
echo.
echo ============================================
echo IMPORTANT: Driver Usage Instructions
echo ============================================
echo.
echo 1. To test the driver, use the test_driver.bat script
echo 2. To uninstall, use uninstall_driver.bat
echo 3. For debugging, use WinDbg with kernel debugging enabled
echo.
echo Driver device path: \\DosDevices\%DRIVER_NAME%
echo.
pause