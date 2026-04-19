# Visual Studio Solution Documentation

## Overview

The `BootkitAnalysisFramework.sln` is the main Visual Studio solution file for the Bootkit Analysis Framework. This document provides comprehensive documentation on the solution structure, project configurations, build settings, and development workflow.

## Solution Structure

### Solution File: `BootkitAnalysisFramework.sln`
- **Visual Studio Version**: 2019 or later
- **Solution Format**: Current (supports multiple projects)
- **Target Platforms**: x64
- **Configuration Types**: Debug, Test, Release

### Projects in Solution

#### 1. BootkitDriver Project
**Location**: `drivers/BootkitDriver/BootkitDriver.vcxproj`
**Type**: Windows Driver (KMDF)
**Purpose**: Main kernel-mode driver implementing framework components

**Key Files**:
- `Driver.cpp` - Driver entry point and initialization
- `IrpMonitor.cpp` - IRP dispatcher monitoring
- `BootFlowInterceptor.cpp` - Boot process interception
- `EvasionEngine.cpp` - Advanced evasion techniques
- `ProcessConcealmentEngine.cpp` - Process hiding techniques
- `DiscordWebhookManager.cpp` - Data exfiltration analysis

#### 2. Test Projects
**Location**: `tests/` directory
**Type**: Console Application (Test Harness)
**Purpose**: Comprehensive testing of framework components

**Test Projects**:
- `IrpMonitorTest` - Tests IRP monitoring functionality
- `BootFlowInterceptorTest` - Tests boot process interception
- `EvasionEngineTest` - Tests evasion techniques
- `ProcessConcealmentEngineTest` - Tests process hiding
- `SSDTHookTest` - Tests SSDT hooking functionality

## Project Configurations

### Configuration Manager
Access via: **Build** → **Configuration Manager**

#### Available Configurations:
1. **Debug**
   - Debug symbols enabled
   - Optimization disabled
   - Additional debug checks
   - Test signing enabled

2. **Test**
   - Partial optimization
   - Test signing enabled
   - Performance profiling
   - Security checks

3. **Release**
   - Full optimization
   - Production signing required
   - Size optimization
   - Security hardening

### Platform Settings
- **Active Platform**: x64
- **Platform Toolset**: Latest Windows Driver Kit (WDK)
- **Windows SDK Version**: Latest installed version

## Build Settings

### Common Properties
**Access**: Right-click project → **Properties**

#### General Settings
- **Target Name**: BootkitDriver
- **Target Extension**: .sys
- **Configuration Type**: Driver
- **Platform Toolset**: WindowsDriverKit

#### Driver Settings
- **Driver Model**: KMDF
- **KMDF Version**: Latest
- **Target OS**: Windows 10
- **Driver Type**: Kernel Mode Driver

### C/C++ Settings

#### General
- **Additional Include Directories**:
  ```
  $(WDKCONTENTROOT)\inc\api
  $(WDKCONTENTROOT)\inc\crt
  $(WDKCONTENTROOT)\inc\km
  $(WDKCONTENTROOT)\inc\ddk
  $(ProjectDir)
  ```

#### Optimization
- **Debug**: /Od (disable optimizations)
- **Test**: /O2 (maximize speed)
- **Release**: /Ox (full optimization)

#### Preprocessor
- **Preprocessor Definitions**:
  ```
  _AMD64_
  _WIN64
  WIN32_LEAN_AND_MEAN
  WINVER=0x0A00
  _WIN32_WINNT=0x0A00
  NTDDI_VERSION=0x0A000002
  DEBUG_LEVEL=1
  ```

#### Code Generation
- **Runtime Library**: /MT (static)
- **Security Check**: /GS (buffer security)
- **Control Flow Guard**: /guard:cf

### Linker Settings

#### General
- **Output File**: $(OutDir)$(TargetName)$(TargetExt)
- **Enable Incremental Linking**: Yes (Debug), No (Release)

#### Input
- **Additional Dependencies**:
  ```
  wdfldr.lib
  wdfkernel.lib
  ntoskrnl.lib
  hal.lib
  wdm.lib
  ```

#### Manifest File
- **Generate Manifest**: No (drivers don't use manifests)

#### Advanced
- **Entry Point**: DriverEntry
- **Base Address**: 0x10000
- **Randomized Base Address**: Yes
- **Data Execution Prevention**: Yes

## Development Workflow

### Setting Up Development Environment

#### Step 1: Open Solution
```cmd
# Open Visual Studio as Administrator
# File → Open → Project/Solution
# Select BootkitAnalysisFramework.sln
```

#### Step 2: Configure Solution
1. **Set Active Configuration**: Debug or Test
2. **Set Active Platform**: x64
3. **Load Driver Project**: BootkitDriver

#### Step 3: Build Solution
1. **Build Menu** → **Build Solution** (Ctrl+Shift+B)
2. Monitor Output window for errors
3. Verify driver builds successfully

### Debugging Workflow

#### Step 1: Configure Debugging
1. **Project Properties** → **Debugging**
2. **Command**: $(TargetPath)
3. **Command Arguments**: (leave empty for drivers)
4. **Working Directory**: $(OutDir)

#### Step 2: Start Debugging
1. **Debug Menu** → **Start Debugging** (F5)
2. Attach WinDbg for kernel debugging
3. Set breakpoints in driver code

#### Step 3: Monitor Output
1. **Output Window**: Build and debug messages
2. **DebugView**: Kernel debug output
3. **Event Viewer**: System and application logs

## Solution Dependencies

### External Dependencies
1. **Windows Driver Kit (WDK)**: Required for driver development
2. **Windows SDK**: Required for Windows API headers
3. **Visual C++ Redistributable**: Runtime libraries
4. **Test Certificates**: For test signing drivers

### Internal Dependencies
```
BootkitDriver
    ├── IrpMonitor (depends on Driver framework)
    ├── BootFlowInterceptor (depends on IrpMonitor)
    ├── EvasionEngine (depends on Driver framework)
    └── ProcessConcealmentEngine (depends on Driver framework)
```

## Build Customization

### Custom Build Steps
Add custom build steps in **Project Properties** → **Build Events**

#### Pre-Build Event
```cmd
echo Building Bootkit Analysis Framework...
echo Configuration: $(ConfigurationName)
echo Platform: $(PlatformName)
```

#### Post-Build Event
```cmd
# Copy driver to system directory
if "$(ConfigurationName)" == "Debug" (
    copy "$(TargetPath)" "C:\Windows\System32\drivers\"
)

# Sign driver with test certificate
if "$(ConfigurationName)" == "Test" (
    signtool sign /v /s PrivateCertStore /n "Bootkit Test Certificate" "$(TargetPath)"
)
```

### Custom Configuration Properties
Create custom property sheets for consistent settings:

#### Common.props
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ImportGroup Label="PropertySheets" />
  <PropertyGroup Label="UserMacros">
    <WDKPath>$(WDKCONTENTROOT)</WDKPath>
  </PropertyGroup>
  <PropertyGroup>
    <IncludePath>$(WDKPath)\inc\api;$(WDKPath)\inc\crt;$(IncludePath)</IncludePath>
    <LibraryPath>$(WDKPath)\lib\$(TargetPlatform)\$(Configuration);$(LibraryPath)</LibraryPath>
  </PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <TreatWarningAsError>true</TreatWarningAsError>
    </ClCompile>
  </ItemDefinitionGroup>
</Project>
```

## Testing Integration

### Test Project Configuration
Test projects are configured as Console Applications with special settings:

#### Test Project Properties
- **Subsystem**: Console (/SUBSYSTEM:CONSOLE)
- **Entry Point**: main or wmain
- **Additional Dependencies**: Test framework libraries

#### Test Execution
Test projects can be executed directly from Visual Studio:
1. **Set as Startup Project** (right-click test project)
2. **Start Debugging** (F5)
3. Monitor test output in console

### Automated Testing
Configure automated test execution in **Test Explorer**:
1. **Test Menu** → **Windows** → **Test Explorer**
2. Discover and run all tests
3. View test results and coverage

## Performance Profiling

### Profiling Configuration
Enable profiling in **Project Properties** → **Advanced**:

#### Performance Tools
- **Profile Guided Optimization**: /LTCG:PGI
- **Instrumentation**: /Gh (hook function entry)
- **Tracing**: Event Tracing for Windows (ETW)

#### Profiling Workflow
1. **Build with Instrumentation**: Enable profiling in build
2. **Run Performance Tests**: Execute test scenarios
3. **Analyze Results**: Use Performance Profiler tool
4. **Optimize Code**: Apply optimizations based on profiling

### Memory Analysis
Use **Diagnostic Tools** window for memory analysis:
1. **Debug Menu** → **Windows** → **Diagnostic Tools**
2. Enable **Memory Usage** tracking
3. Analyze heap allocations and memory leaks

## Security Configuration

### Security Settings
Configure security features in **Project Properties** → **C/C++** → **Security**:

#### Buffer Security
- **Buffer Security Check**: /GS
- **Control Flow Guard**: /guard:cf
- **Spectre Mitigation**: /Qspectre

#### Code Integrity
- **Digital Signatures**: Required for drivers
- **Certificate Validation**: Validate certificate chains
- **Signature Timestamping**: Include timestamps

### Security Analysis
Use **Code Analysis** for security checks:
1. **Analyze Menu** → **Run Code Analysis**
2. Review security warnings
3. Fix identified vulnerabilities

## Cross-Platform Considerations

### Platform-Specific Settings
The solution supports multiple platforms through conditional compilation:

#### x64 Platform
- **Target Architecture**: AMD64
- **Instruction Set**: SSE2
- **Floating Point**: FP:precise

#### ARM64 Platform (Experimental)
- **Target Architecture**: ARM64
- **Instruction Set**: ARMv8
- **Floating Point**: SoftFP

### Conditional Compilation
Use preprocessor directives for platform-specific code:
```cpp
#ifdef _AMD64_
    // x64-specific code
#elif defined(_ARM64_)
    // ARM64-specific code
#endif
```

## Maintenance and Updates

### Solution Maintenance
Regular maintenance tasks:

1. **Update Dependencies**: Keep WDK and SDK updated
2. **Review Configurations**: Update build settings as needed
3. **Clean Solution**: Regular cleaning to remove temporary files
4. **Backup Solution**: Regular backups of solution file

### Version Control Integration
The solution is configured for Git version control:

#### .gitignore Settings
```
# Visual Studio files
*.sln
*.vcxproj
*.vcxproj.filters
*.vcxproj.user

# Build outputs
bin/
obj/
Debug/
Release/
Test/

# Temporary files
*.tmp
*.temp
```

#### Git Workflow
1. **Feature Branches**: Develop features in separate branches
2. **Pull Requests**: Review changes before merging
3. **Version Tags**: Tag releases with semantic versioning

## Troubleshooting

### Common Issues

#### Issue: "WDK not found"
**Solution**: Install Windows Driver Kit through Visual Studio Installer.

#### Issue: "Driver project not loading"
**Solution**: Run Visual Studio as Administrator.

#### Issue: "Build errors with WDK headers"
**Solution**: Verify WDK installation and include paths.

#### Issue: "Test signing errors"
**Solution**: Enable test signing and install test certificate.

### Debugging Tips

1. **Enable Verbose Output**:
   ```cmd
   msbuild BootkitAnalysisFramework.sln /v:d
   ```

2. **Check Build Logs**:
   - Output window in Visual Studio
   - MSBuild log files
   - Event Viewer logs

3. **Verify Dependencies**:
   ```cmd
   dumpbin /dependents BootkitDriver.sys
   ```

## Conclusion

This documentation provides comprehensive guidance for working with the Bootkit Analysis Framework Visual Studio solution. Follow these instructions to configure, build, debug, and maintain the framework effectively.

For additional help, refer to:
- [Build and Compilation Guide](BUILD_GUIDE.md)
- [Driver Development Guide](driver_development_guide.md)
- [Debugging Setup](debugging_setup.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This framework is for legitimate security research and educational purposes only. Always obtain proper authorization before building or deploying these components.