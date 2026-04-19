@echo off
echo ========================================
echo Bootkit Analysis Framework - Quick Build
echo ========================================
echo.
echo This will build the user-mode components only.
echo No Windows Driver Kit (WDK) required.
echo.
echo Press any key to start build...
pause >nul

call build_usermode.bat Release

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Quick build completed successfully!
    echo ========================================
    echo.
    echo You can now run:
    echo   - bin\x64\Release\BootkitTests.exe
    echo   - bin\x64\Release\BootkitTools.exe
    echo.
)

pause
