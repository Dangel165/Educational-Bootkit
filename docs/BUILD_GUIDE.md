# Build and Compilation Guide

## Overview

This guide provides comprehensive instructions for building and compiling the Bootkit Analysis Framework. The framework consists of both kernel-mode drivers and user-mode components, all implemented in C++ using modern C++ standards.

## Prerequisites

### Required Software
1. **Windows 10/11** (64-bit)
2. **Visual Studio 2019 or later** with the following workloads:
   - Desktop development with C++
   - Windows Driver Kit (WDK)
3. **Windows SDK** (latest version)
4. **WinDbg Preview** (for kernel debugging)
5. **Git** (for source control)

### System Configuration
1. **Test Signing Enabled** (required for driver development):
   ```cmd
   bcdedit /set testsigning on
   ```
   *Note: Requires system restart*

2. **Administrator Privileges** (required for driver installation and debugging)

3. **Hardware Requirements**:
   - 8GB RAM minimum (16GB recommended)
   - 20GB free disk space
   - Intel VT-x/AMD-V enabled for virtualization (for testing)

## Visual Studio Solution Structure

### BootkitAnalysisFramework.sln
The main solution file contains the following projects:

#### 1. BootkitDriver Project
- **Type**: Windows Driver (KMDF)
- **Target**: Kernel Mode Driver
- **Architecture**: x64
- **Dependencies**: WDK, Windows SDK
- **Output**: BootkitDriver.sys

#### 2. Test Projects
- **IrpMonitorTest**: Tests for IRP Dispatcher Monitor
- **BootFlowInterceptorTest**: Tests for Boot Flow Interceptor
- **EvasionEngineTest**: Tests for Evasion Engine
- **ProcessConcealmentEngineTest**: Tests for Process Concealment Engine
- **SSDTHookTest**: Tests for SSDT Hooking

## Building the Framework

### Step 1: Open Visual Studio
1. Launch Visual Studio as Administrator
2. Open `BootkitAnalysisFramework.sln`
3. Set solution configuration to `Debug` or `Test`

### Step 2: Configure Build Settings
1. **Target Platform**: x64
2. **Platform Toolset**: Latest Windows Driver Kit (WDK)
3. **Windows SDK Version**: Latest installed version
4. **Configuration Type**: 
   - `Debug` for development and testing
   - `Test` for test signing
   - `Release` for production (requires proper signing)

### Step 3: Build the Solution
1. **Build Menu** → **Build Solution** (Ctrl+Shift+B)
2. Monitor Output window for build progress
3. Verify all projects build successfully

### Step 4: Driver Signing
#### Test Signing (Development)
```cmd
# Generate test certificate
makecert -r -pe -ss PrivateCertStore -n "CN=Bootkit Test Certificate" BootkitTest.cer

# Sign the driver
signtool sign /v /s PrivateCertStore /n "Bootkit Test Certificate" /t http://timestamp.digicert.com drivers/BootkitDriver/x64/Debug/BootkitDriver.sys
```

#### Production Signing
Requires EV Code Signing Certificate from trusted Certificate Authority.

## Compilation Instructions

### Command Line Building
```cmd
# Using MSBuild
msbuild BootkitAnalysisFramework.sln /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0

# Using Developer Command Prompt
cd bootkit-analysis-framework
msbuild BootkitAnalysisFramework.sln
```

### Build Scripts
The framework includes several build scripts:

1. **build_driver.bat** - Builds only the kernel driver
2. **build_tests.bat** - Builds all test projects
3. **build_all.bat** - Builds entire solution
4. **clean_build.bat** - Cleans and rebuilds everything

## Driver Installation

### Manual Installation
1. **Copy Driver Files**:
   ```cmd
   copy drivers\BootkitDriver\x64\Debug\BootkitDriver.sys C:\Windows\System32\drivers\
   copy drivers\BootkitDriver\BootkitDriver.inf C:\Windows\INF\
   ```

2. **Install Driver**:
   ```cmd
   sc create BootkitDriver binPath= C:\Windows\System32\drivers\BootkitDriver.sys type= kernel start= demand
   sc start BootkitDriver
   ```

3. **Verify Installation**:
   ```cmd
   sc query BootkitDriver
   ```

### INF-Based Installation
1. **Right-click** on `BootkitDriver.inf`
2. Select **Install**
3. Follow installation wizard
4. Verify in Device Manager under **System devices**

## Kernel Debugging Setup

### WinDbg Configuration
1. **Install WinDbg Preview** from Microsoft Store
2. **Configure Symbol Path**:
   ```
   srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   ```

3. **Configure Source Path**:
   ```
   C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver
   ```

### Debugging Session
1. **Start Debugging**:
   ```cmd
   windbg -k net:port=50000,key=1.1.1.1
   ```

2. **Load Symbols**:
   ```
   .reload
   ld BootkitDriver
   ```

3. **Set Breakpoints**:
   ```
   bp BootkitDriver!DriverEntry
   bp BootkitDriver!IrpMonitorInitialize
   ```

## Testing Framework

### Running Tests
The framework includes comprehensive test suites:

#### 1. IRP Monitor Tests
```cmd
run_irp_monitor_test.bat
```
Tests IRP interception and monitoring functionality.

#### 2. Boot Flow Interceptor Tests
```cmd
run_bootflow_interceptor_test.bat
```
Tests boot process interception and analysis.

#### 3. Evasion Engine Tests
```cmd
run_evasion_engine_test.bat
```
Tests VM detection, sandbox evasion, and debugger detection.

#### 4. Process Concealment Tests
```cmd
run_process_concealment_test.bat
```
Tests process hiding and DKOM techniques.

### Test Results
Tests generate detailed reports in:
- `tests/results/` - Test output and logs
- `tests/coverage/` - Code coverage reports
- `tests/performance/` - Performance metrics

## Troubleshooting

### Common Build Issues

#### Issue: "WDK not found"
**Solution**: Install Windows Driver Kit through Visual Studio Installer.

#### Issue: "Test signing not enabled"
**Solution**: Enable test signing and restart:
```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

#### Issue: "Driver signature verification failed"
**Solution**: Ensure test certificate is installed and driver is properly signed.

#### Issue: "Access denied during installation"
**Solution**: Run Visual Studio and command prompt as Administrator.

### Debugging Tips

1. **Enable Verbose Logging**:
   ```cpp
   #define DEBUG_LEVEL 3
   ```

2. **Check Event Viewer**:
   - Windows Logs → System
   - Applications and Services Logs → BootkitDriver

3. **Use DebugView**:
   Download Sysinternals DebugView to view kernel debug output.

4. **Check Driver Status**:
   ```cmd
   sc query BootkitDriver
   fltmc instances
   ```

## Performance Optimization

### Build Optimization
1. **Use Release Configuration** for production builds
2. **Enable Link-Time Code Generation** (LTCG)
3. **Use Profile-Guided Optimization** (PGO)
4. **Enable Whole Program Optimization**

### Runtime Optimization
1. **Memory Management**: Use pool tags and lookaside lists
2. **Synchronization**: Use fast mutexes and executive resources
3. **IRP Handling**: Use completion routines efficiently
4. **Resource Management**: Properly manage device objects and file objects

## Security Considerations

### Code Signing
1. **Test Certificates**: Use only in development environments
2. **EV Certificates**: Required for production deployment
3. **Timestamping**: Always timestamp signatures
4. **Certificate Validation**: Verify certificate chains

### Driver Security
1. **Input Validation**: Validate all IRP parameters
2. **Buffer Management**: Use probe functions for user buffers
3. **Privilege Checks**: Check caller privileges
4. **Resource Limits**: Implement resource limits and quotas

## Cross-Platform Considerations

### Windows Version Compatibility
The framework supports:
- Windows 10 (Version 1607 and later)
- Windows 11 (All versions)
- Windows Server 2016 and later

### Architecture Support
- **x64**: Primary target architecture
- **ARM64**: Experimental support
- **x86**: Not supported (kernel components require x64)

## Continuous Integration

### GitHub Actions
Example workflow for automated building:
```yaml
name: Build Bootkit Analysis Framework

on: [push, pull_request]

jobs:
  build:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup MSBuild
      uses: microsoft/setup-msbuild@v1
      
    - name: Build Solution
      run: msbuild BootkitAnalysisFramework.sln /p:Configuration=Test /p:Platform=x64
      
    - name: Run Tests
      run: .\run_all_tests.bat
```

### Azure DevOps
Pipeline for automated testing and deployment.

## Advanced Build Configurations

### Custom Build Definitions
Create custom build configurations in Visual Studio:
1. **Configuration Manager** → **New Configuration**
2. Define custom settings for:
   - Debugging symbols
   - Optimization levels
   - Code analysis
   - Security features

### Preprocessor Definitions
Common definitions used in the framework:
```cpp
#define DEBUG_BUILD  // Enable debugging features
#define TEST_SIGNING // Enable test signing features
#define SECURITY_AUDIT // Enable security auditing
#define PERFORMANCE_MONITORING // Enable performance monitoring
```

## Maintenance and Updates

### Regular Maintenance
1. **Update Dependencies**: Regularly update WDK and SDK
2. **Security Updates**: Apply security patches and updates
3. **Code Review**: Regular code reviews for security issues
4. **Documentation Updates**: Keep documentation current

### Version Control
1. **Git Workflow**: Use feature branches and pull requests
2. **Version Tagging**: Tag releases with semantic versioning
3. **Change Log**: Maintain detailed change log
4. **Backup Strategy**: Regular backups of source code

## Conclusion

This build guide provides comprehensive instructions for building, compiling, and deploying the Bootkit Analysis Framework. Follow these instructions carefully to ensure successful compilation and operation of all framework components.

For additional help, refer to:
- [Visual Studio Solution Documentation](VISUAL_STUDIO_SOLUTION.md)
- [Driver Development Guide](driver_development_guide.md)
- [Debugging Setup](debugging_setup.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This framework is for legitimate security research and educational purposes only. Always obtain proper authorization before building or deploying these components.