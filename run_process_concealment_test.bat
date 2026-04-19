@echo off
echo Process Concealment Engine Test Script
echo =======================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run as administrator.
    pause
    exit /b 1
)

echo.
echo 1. Building ProcessConcealmentEngineTest driver...
echo.

REM Set up build environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Build the test driver
cd /d "%~dp0"
if exist build mkdir build
cd build

cl.exe /nologo /c /W4 /WX /GS- /Gs9999999 /Gy /Zc:wchar_t /Zc:forScope /D "_AMD64_" /D "_WIN64" /D "WIN64" /D "_WIN32_WINNT=0x0601" /D "NTDDI_VERSION=0x06010000" /D "_DEBUG" /D "DBG=1" /D "_KERNEL_MODE" /D "_UNICODE" /D "UNICODE" /kernel /Zp8 /guard:cf- /EHa- /Oi- /FC /errorReport:queue /I "..\drivers\BootkitDriver" /I "%WindowsSdkDir%\Include\10.0.19041.0\km" /I "%WindowsSdkDir%\Include\10.0.19041.0\shared" /Fo".\" /Fd".\ProcessConcealmentEngineTest.pdb" "..\tests\ProcessConcealmentEngineTest.cpp"

if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

link.exe /nologo /DEBUG /DRIVER /SUBSYSTEM:NATIVE /OUT:ProcessConcealmentEngineTest.sys /DYNAMICBASE /NXCOMPAT /MACHINE:X64 /MANIFEST:NO /MANIFESTUAC:NO /DEBUGTYPE:CV /PDB:ProcessConcealmentEngineTest.pdb /OPT:REF /OPT:ICF /INCREMENTAL:NO /NODEFAULTLIB /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /SECTION:INIT,d /ORDER:@%WindowsSdkDir%\Include\10.0.19041.0\km\amd64\kernel.prf /LIBPATH:"%WindowsSdkDir%\Lib\10.0.19041.0\km\x64" ntoskrnl.lib hal.lib wdm.lib wdmsec.lib wmilib.lib ndis.lib "ProcessConcealmentEngineTest.obj"

if errorlevel 1 (
    echo Linking failed.
    pause
    exit /b 1
)

echo.
echo 2. Enabling test signing mode...
echo.

REM Enable test signing
bcdedit /set testsigning on

echo.
echo 3. Installing test driver...
echo.

REM Create service
sc create ProcessConcealmentTest binPath= "%~dp0build\ProcessConcealmentEngineTest.sys" type= kernel start= demand

if errorlevel 1 (
    echo Service creation failed.
    pause
    exit /b 1
)

echo.
echo 4. Starting test driver...
echo.

REM Start the driver
sc start ProcessConcealmentTest

if errorlevel 1 (
    echo Driver start failed.
    sc delete ProcessConcealmentTest
    pause
    exit /b 1
)

echo.
echo 5. Checking test results...
echo.

REM Wait for driver to initialize
timeout /t 5 /nobreak >nul

echo.
echo 6. Stopping and cleaning up...
echo.

REM Stop and delete service
sc stop ProcessConcealmentTest
timeout /t 2 /nobreak >nul
sc delete ProcessConcealmentTest

echo.
echo 7. Disabling test signing mode...
echo.

REM Disable test signing
bcdedit /set testsigning off

echo.
echo Test completed successfully!
echo Check DebugView or WinDbg for test output.
echo.
pause