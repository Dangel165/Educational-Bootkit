@echo off
echo ============================================
echo Bootkit Analysis Framework - Minifilter Build
echo ============================================
echo.

REM Check for Visual Studio Developer Command Prompt
if "%VSCMD_VER%"=="" (
    echo ERROR: Please run this script from Visual Studio Developer Command Prompt
    echo.
    echo To open Developer Command Prompt:
    echo 1. Open Start Menu
    echo 2. Search for "Developer Command Prompt for VS"
    echo 3. Run as Administrator
    echo.
    pause
    exit /b 1
)

REM Set paths
set DRIVER_DIR=drivers\BootkitDriver
set TEST_DIR=tests
set OUTPUT_DIR=bin
set DOCS_DIR=docs

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Building Minifilter Driver...
echo.

REM Build driver using MSBuild
echo Building BootkitDriver.sys...
msbuild "%DRIVER_DIR%\BootkitDriver.vcxproj" /p:Configuration=Debug /p:Platform=x64 /p:OutDir="%~dp0%OUTPUT_DIR%\" /verbosity:minimal

if errorlevel 1 (
    echo ERROR: Driver build failed
    pause
    exit /b 1
)

echo Driver built successfully: %OUTPUT_DIR%\BootkitDriver.sys
echo.

echo Building Test Application...
echo.

REM Check for Windows SDK
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: C++ compiler (cl.exe) not found
    echo Please ensure Windows SDK is installed
    pause
    exit /b 1
)

REM Build test application
echo Building MinifilterTestApp.exe...
cl.exe /nologo /EHsc /Fe"%OUTPUT_DIR%\MinifilterTestApp.exe" "%TEST_DIR%\MinifilterTestApp.cpp" /I "%DRIVER_DIR%" /link fltLib.lib

if errorlevel 1 (
    echo ERROR: Test application build failed
    pause
    exit /b 1
)

echo Test application built successfully: %OUTPUT_DIR%\MinifilterTestApp.exe
echo.

echo Creating Documentation...
echo.

REM Copy documentation
if exist "%DOCS_DIR%\Minifilter_Driver_Implementation.md" (
    copy "%DOCS_DIR%\Minifilter_Driver_Implementation.md" "%OUTPUT_DIR%\Minifilter_Driver_Implementation.md" >nul
    echo Documentation copied: %OUTPUT_DIR%\Minifilter_Driver_Implementation.md
)

echo.
echo ============================================
echo Build Summary
echo ============================================
echo.
echo Output Directory: %OUTPUT_DIR%
echo.
echo Files Generated:
echo   - BootkitDriver.sys (Minifilter Driver)
echo   - MinifilterTestApp.exe (Test Application)
echo   - Minifilter_Driver_Implementation.md (Documentation)
echo.
echo Next Steps:
echo   1. Enable test signing: bcdedit /set testsigning on
echo   2. Install driver: sc create BootkitAnalysisMinifilter binPath= "%~dp0%OUTPUT_DIR%\BootkitDriver.sys" type= kernel
echo   3. Start driver: sc start BootkitAnalysisMinifilter
echo   4. Run tests: %OUTPUT_DIR%\MinifilterTestApp.exe all
echo.
echo ============================================
pause