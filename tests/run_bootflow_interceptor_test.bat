@echo off
echo ========================================
echo Boot Flow Interceptor Test Runner
echo Task 1.2 Implementation Verification
echo ========================================
echo.

echo This batch file compiles and runs the Boot Flow Interceptor test application.
echo Make sure the driver is loaded before running tests.
echo.

REM Check if Visual Studio compiler is available
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Visual Studio compiler (cl.exe) not found in PATH.
    echo Please run from Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

REM Check if driver is loaded (optional)
echo Checking if driver is loaded...
sc query BootkitDriver >nul 2>&1
if %errorlevel% neq 0 (
    echo Warning: BootkitDriver service not found or not running.
    echo Tests may fail if driver is not loaded.
    echo.
)

REM Set compilation flags
set COMPILE_FLAGS=/EHsc /nologo /W4 /O2 /DUNICODE /D_UNICODE /I..\drivers\BootkitDriver

echo Compiling Boot Flow Interceptor test application...
cl %COMPILE_FLAGS% BootFlowInterceptorTest.cpp /link /SUBSYSTEM:CONSOLE /OUT:BootFlowInterceptorTest.exe

if %errorlevel% neq 0 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo.
echo Compilation successful. Running tests...
echo.

REM Run the test application
BootFlowInterceptorTest.exe

echo.
echo Test completed.
echo.

REM Clean up
if exist BootFlowInterceptorTest.exe (
    echo Deleting test executable...
    del BootFlowInterceptorTest.exe
)

if exist BootFlowInterceptorTest.obj (
    echo Deleting object file...
    del BootFlowInterceptorTest.obj
)

echo.
echo ========================================
echo Test runner finished.
echo ========================================
pause