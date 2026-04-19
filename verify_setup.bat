@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Bootkit Analysis Framework - Setup Verification
echo ========================================
echo.

set "ERRORS=0"
set "WARNINGS=0"

REM Check for Visual Studio
echo [1/5] Checking Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    echo   [OK] Visual Studio Installer found
    
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property displayName`) do (
        echo   [OK] %%i installed
    )
    
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        echo   [OK] MSBuild found
    )
) else (
    echo   [ERROR] Visual Studio not found!
    echo   Please install Visual Studio 2019 or later
    set /a ERRORS+=1
)
echo.

REM Check for C++ workload
echo [2/5] Checking C++ Desktop Development workload...
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Workload.NativeDesktop -property displayName 2^>nul`) do (
    echo   [OK] C++ Desktop Development workload installed
    goto :cpp_ok
)
echo   [ERROR] C++ Desktop Development workload not found!
echo   Install via Visual Studio Installer
set /a ERRORS+=1
:cpp_ok
echo.

REM Check for Windows SDK
echo [3/5] Checking Windows SDK...
set "SDK_PATH=%ProgramFiles(x86)%\Windows Kits\10"
if exist "%SDK_PATH%" (
    echo   [OK] Windows SDK found
    
    if exist "%SDK_PATH%\Include" (
        for /f "delims=" %%i in ('dir /b /ad "%SDK_PATH%\Include" 2^>nul') do (
            echo   [OK] SDK Version: %%i
        )
    )
) else (
    echo   [WARNING] Windows SDK not found
    echo   Install via Visual Studio Installer
    set /a WARNINGS+=1
)
echo.

REM Check for WDK
echo [4/5] Checking Windows Driver Kit (WDK)...
set "WDK_CHECK=%ProgramFiles(x86)%\Windows Kits\10\build"
if exist "%WDK_CHECK%" (
    echo   [OK] WDK found
    echo   [OK] Driver development is available
) else (
    echo   [WARNING] WDK not found
    echo   Driver build will not be available
    echo   You can still build user-mode components (Tools, Tests)
    echo   Download WDK: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    set /a WARNINGS+=1
)
echo.

REM Check project files
echo [5/5] Checking project files...
set "PROJECT_OK=1"

if exist "BootkitAnalysisFramework.sln" (
    echo   [OK] Solution file found
) else (
    echo   [ERROR] Solution file not found!
    set "PROJECT_OK=0"
    set /a ERRORS+=1
)

if exist "drivers\BootkitDriver\BootkitDriver.vcxproj" (
    echo   [OK] BootkitDriver project found
) else (
    echo   [ERROR] BootkitDriver project not found!
    set "PROJECT_OK=0"
    set /a ERRORS+=1
)

if exist "tools\BootkitTools\BootkitTools.vcxproj" (
    echo   [OK] BootkitTools project found
) else (
    echo   [ERROR] BootkitTools project not found!
    set "PROJECT_OK=0"
    set /a ERRORS+=1
)

if exist "tests\BootkitTests\BootkitTests.vcxproj" (
    echo   [OK] BootkitTests project found
) else (
    echo   [ERROR] BootkitTests project not found!
    set "PROJECT_OK=0"
    set /a ERRORS+=1
)
echo.

REM Summary
echo ========================================
echo Verification Summary
echo ========================================
echo.

if %ERRORS% EQU 0 (
    if %WARNINGS% EQU 0 (
        echo [SUCCESS] All checks passed!
        echo.
        echo You can build the full solution:
        echo   build.bat
        echo.
    ) else (
        echo [PARTIAL] Setup is partially complete
        echo   Errors: %ERRORS%
        echo   Warnings: %WARNINGS%
        echo.
        echo You can build user-mode components:
        echo   build_usermode.bat
        echo.
        echo To build drivers, install WDK and run:
        echo   build.bat
        echo.
    )
) else (
    echo [FAILED] Setup verification failed
    echo   Errors: %ERRORS%
    echo   Warnings: %WARNINGS%
    echo.
    echo Please fix the errors above before building.
    echo.
)

echo For detailed build instructions, see BUILD_GUIDE.md
echo.

pause
