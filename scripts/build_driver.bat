@echo off
echo ============================================
echo Bootkit Analysis Framework - Driver Build Script
echo ============================================
echo.
echo This script builds the BootkitDriver kernel driver
echo using Visual Studio and Windows Driver Kit (WDK)
echo.

:: Check for Visual Studio/WDK
echo Step 1: Checking for Visual Studio and WDK...
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
    echo Please install Visual Studio 2019 or later with:
    echo 1. Desktop development with C++ workload
    echo 2. Windows Driver Kit (WDK) component
    echo.
    pause
    exit /b 1
)

:: Check for WDK
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo ERROR: vcvarsall.bat not found at expected location!
    echo Checked: %VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat
    echo.
    echo Make sure Windows Driver Kit (WDK) is installed.
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

echo Step 3: Building driver...
echo.
echo Building BootkitDriver in Debug configuration...
echo.

:: Change to driver directory
cd /d "%~dp0..\drivers\BootkitDriver"

:: Build using MSBuild
echo Building with MSBuild...
msbuild BootkitDriver.vcxproj /p:Configuration=Debug /p:Platform=x64 /verbosity:minimal

if %errorLevel% neq 0 (
    echo ERROR: MSBuild failed!
    echo.
    echo Trying alternative build method...
    echo.
    
    :: Try building with devenv
    if exist "%VS_PATH%\Common7\IDE\devenv.exe" (
        echo Building with Visual Studio...
        "%VS_PATH%\Common7\IDE\devenv.exe" "%~dp0..\BootkitAnalysisFramework.sln" /Build "Debug|x64"
        
        if %errorLevel% neq 0 (
            echo ERROR: All build methods failed!
            echo.
            echo Possible solutions:
            echo 1. Open Visual Studio manually and build
            echo 2. Check for missing dependencies
            echo 3. Verify WDK is properly installed
            pause
            exit /b 1
        )
    else (
        echo ERROR: devenv.exe not found!
        pause
        exit /b 1
    )
)

echo Step 4: Checking build output...
echo.

:: Check for built driver
if exist "%~dp0..\bin\x64\Debug\BootkitDriver.sys" (
    set DRIVER_PATH=%~dp0..\bin\x64\Debug\BootkitDriver.sys
    echo Driver built successfully: %DRIVER_PATH%
    echo.
    echo File size: %%~zDRIVER_PATH% bytes
) else if exist "BootkitDriver.sys" (
    echo Driver built in current directory: BootkitDriver.sys
    echo File size: %%~zBootkitDriver.sys bytes
) else (
    echo WARNING: Driver .sys file not found in expected locations!
    echo.
    echo Check build output for errors.
    echo The driver may have built to a different location.
)

echo.
echo Step 5: Copying files for installation...
echo.

:: Copy INF file to build directory
if exist "%~dp0..\bin\x64\Debug\" (
    copy BootkitDriver.inf "%~dp0..\bin\x64\Debug\" >nul 2>&1
    echo Copied INF file to build directory
)

:: Create test signing certificate if needed
echo.
echo Step 6: Creating test certificate (if needed)...
echo.
echo Note: For production, you need a proper code signing certificate
echo For development, Windows test signing must be enabled.
echo.

echo.
echo ============================================
echo Build completed!
echo ============================================
echo.
echo Next steps:
echo 1. Enable test signing (if not already): enable_test_signing.bat
echo 2. Install driver: install_driver.bat
echo 3. Test driver: test_driver.bat
echo 4. Debug driver: See debugging_setup.md
echo.
echo Build output directory: %~dp0..\bin\x64\Debug\
echo.
pause