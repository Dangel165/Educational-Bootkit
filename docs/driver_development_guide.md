# Windows Driver Development Environment Setup Guide

## Overview

This guide provides complete instructions for setting up a Windows Driver Development Environment for the Bootkit Analysis Framework. It covers WDK installation, Visual Studio configuration, driver signing, debugging setup, and development workflow.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Windows Driver Kit (WDK) Installation](#windows-driver-kit-wdk-installation)
3. [Visual Studio Configuration](#visual-studio-configuration)
4. [Driver Signing Infrastructure](#driver-signing-infrastructure)
5. [Kernel Debugging Setup](#kernel-debugging-setup)
6. [Driver Installation Utilities](#driver-installation-utilities)
7. [Development Workflow](#development-workflow)
8. [Troubleshooting](#troubleshooting)
9. [Security Considerations](#security-considerations)

## Prerequisites

### Hardware Requirements
- Windows 10/11 x64 system
- 8GB RAM minimum (16GB recommended)
- 50GB free disk space
- Administrator access

### Software Requirements
- Windows 10/11 Pro or Enterprise (Home edition lacks some driver development features)
- Visual Studio 2019 or later
- Windows 10/11 SDK
- Windows Driver Kit (WDK)
- WinDbg Preview (for kernel debugging)

## Windows Driver Kit (WDK) Installation

### Method 1: Visual Studio Installer (Recommended)

1. Open **Visual Studio Installer**
2. Select your Visual Studio edition
3. Click **Modify**
4. Under **Workloads**, select:
   - [x] **Desktop development with C++**
5. Under **Individual components**, search and select:
   - [x] **Windows Driver Kit (WDK)**
   - [x] **Windows Software Development Kit (SDK)** - Latest version
   - [x] **C++ ATL for latest v143 build tools**
   - [x] **C++ MFC for latest v143 build tools**
6. Click **Modify** to install

### Method 2: Standalone WDK Installation

1. Download WDK from [Microsoft Download Center](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
2. Run the installer
3. Follow installation prompts
4. Ensure Visual Studio integration is selected

### Verification

Verify WDK installation:
```batch
:: Check WDK installation
dir "C:\Program Files (x86)\Windows Kits\10\WDK"

:: Check Visual Studio integration
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"
```

## Visual Studio Configuration

### Driver Project Templates

1. Open Visual Studio
2. Create New Project
3. Search for "Driver"
4. Available templates:
   - **Empty WDM Driver**
   - **KMDF Driver**
   - **UMDF Driver**
   - **Filter Driver**

### Solution Configuration

The Bootkit Analysis Framework solution includes:

```
BootkitAnalysisFramework.sln
├── drivers/
│   └── BootkitDriver/
│       ├── BootkitDriver.vcxproj    # Driver project file
│       ├── Driver.cpp               # Main driver implementation
│       ├── Driver.h                  # Driver header
│       ├── IrpHandlers.cpp          # IRP handler implementation
│       ├── IrpHandlers.h            # IRP handler declarations
│       ├── DeviceControl.cpp        # Device control implementation
│       ├── DeviceControl.h          # Device control declarations
│       ├── Debug.cpp                # Debug implementation
│       ├── Debug.h                  # Debug declarations
│       ├── pch.h                    # Precompiled header
│       └── BootkitDriver.inf        # Driver installation INF
├── scripts/                         # Build and installation scripts
├── docs/                            # Documentation
└── tools/                           # Development tools
```

### Build Configurations

Three build configurations are defined:

1. **Debug** - Full debugging symbols, no optimization
2. **Release** - Optimized, minimal debugging
3. **TestSign** - Release build with test signing

### Project Properties

Key driver project settings:

| Setting | Value | Purpose |
|---------|-------|---------|
| Configuration Type | Driver | Specifies kernel driver project |
| Platform Toolset | WindowsKernelModeDriver10.0 | WDK toolchain |
| Driver Type | WDM | Windows Driver Model |
| Target Platform | Desktop | Desktop Windows |
| Warning Level | Level4 (/W4) | Strict warnings |
| Treat Warnings as Errors | Yes | Enforce code quality |

## Driver Signing Infrastructure

### Test Signing vs Production Signing

| Aspect | Test Signing | Production Signing |
|--------|-------------|-------------------|
| Purpose | Development/testing | Production deployment |
| Certificate | Self-signed or test cert | Authenticode certificate |
| Cost | Free | Purchased from CA |
| Windows Requirement | Test signing enabled | No special requirement |
| Security | Lower security | Full Windows security |

### Enabling Test Signing

```batch
:: Run as Administrator
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

### Creating Test Certificate

```batch
:: Create self-signed certificate
makecert -r -pe -ss PrivateCertStore -n "CN=Bootkit Test Certificate" BootkitTest.cer

:: Add to trusted publishers
certmgr.exe -add BootkitTest.cer -s -r localMachine root
```

### Driver Signing Process

1. **Build driver** - Produces .sys file
2. **Create catalog** - From INF file
3. **Sign catalog** - With certificate
4. **Test install** - Verify loading works

### Signing Script

```batch
@echo off
:: Driver signing script
set DRIVER_NAME=BootkitDriver
set CERTIFICATE=BootkitTest.pfx
set PASSWORD=YourPassword

:: Create catalog file
inf2cat /driver:. /os:10_X64

:: Sign catalog
signtool sign /f %CERTIFICATE% /p %PASSWORD% /t http://timestamp.digicert.com %DRIVER_NAME%.cat

:: Sign driver
signtool sign /f %CERTIFICATE% /p %PASSWORD% /t http://timestamp.digicert.com %DRIVER_NAME%.sys
```

## Kernel Debugging Setup

### Debugging Methods

| Method | Speed | Setup Complexity | Best For |
|--------|-------|------------------|----------|
| Network | Fast | Moderate | Single machine |
| Serial | Slow | Complex | Two machines |
| USB 3.0 | Fast | Complex | Performance debugging |
| 1394 | Fast | Complex | Legacy systems |
| Virtual | Fast | Simple | Hyper-V/VirtualBox |

### Network Debugging Setup

**Target Machine (Machine being debugged):**
```batch
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4
```

**Host Machine (Running WinDbg):**
1. Open WinDbg Preview
2. File → Attach to Kernel Debugger
3. Net tab
4. Enter port and key from target

### WinDbg Configuration

#### Symbol Path
```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.sympath+ C:\path\to\driver\build\directory
```

#### Source Path
```windbg
.srcpath+ C:\path\to\driver\source\code
```

#### Common Commands
```windbg
!sym noisy                     # Verbose symbol loading
.reload /f BootkitDriver.sys   # Force reload symbols
x BootkitDriver!*              # List all symbols
bp DriverEntry                 # Set breakpoint
g                              # Continue execution
```

### Debugging Workflow

1. **Set up debugging connection**
2. **Build driver with debug symbols**
3. **Install driver on target**
4. **Attach WinDbg to target**
5. **Set breakpoints**
6. **Trigger driver functionality**
7. **Analyze results**

## Driver Installation Utilities

### Installation Methods

#### 1. INF-Based Installation (Recommended)
```batch
:: Install driver package
pnputil /add-driver BootkitDriver.inf /install

:: Start service
sc create BootkitDriver binPath= "C:\Windows\System32\drivers\BootkitDriver.sys" type= kernel start= demand
sc start BootkitDriver
```

#### 2. Service Control Manager
```batch
:: Create and start service
sc create BootkitDriver binPath= "%SystemRoot%\system32\drivers\BootkitDriver.sys" type= kernel start= demand error= normal
sc start BootkitDriver

:: Stop and delete service
sc stop BootkitDriver
sc delete BootkitDriver
```

#### 3. Manual Loading (Development)
```batch
:: Load driver manually
fltmc load BootkitDriver

:: Unload driver
fltmc unload BootkitDriver
```

### Provided Installation Scripts

The framework includes these scripts:

| Script | Purpose | Usage |
|--------|---------|-------|
| `enable_test_signing.bat` | Enable test signing mode | Run once, then restart |
| `build_driver.bat` | Build driver from source | After code changes |
| `install_driver.bat` | Install and start driver | After building |
| `uninstall_driver.bat` | Remove driver completely | Cleanup |
| `test_driver.bat` | Test driver functionality | Verify installation |

### Installation Verification

```batch
:: Check service status
sc query BootkitDriver

:: Check driver file
dir C:\Windows\System32\drivers\BootkitDriver.sys

:: Check loaded drivers
driverquery /fo list | findstr /i bootkit

:: Check device object
devcon status *BootkitDriver*
```

## Development Workflow

### Step 1: Environment Setup
1. Install Visual Studio with WDK
2. Enable test signing
3. Set up kernel debugging
4. Clone repository

### Step 2: Code Development
1. Open solution in Visual Studio
2. Modify driver code
3. Build solution (F7)
4. Fix compilation errors

### Step 3: Testing Cycle
1. Build driver (`build_driver.bat`)
2. Install driver (`install_driver.bat`)
3. Test functionality (`test_driver.bat`)
4. Debug issues (WinDbg)
5. Uninstall (`uninstall_driver.bat`)
6. Repeat

### Step 4: Debugging Process
1. Reproduce issue
2. Attach WinDbg
3. Set breakpoints
4. Analyze crash dumps
5. Fix code
6. Test fix

### Step 5: Quality Assurance
1. Run Driver Verifier
2. Test on multiple Windows versions
3. Check memory leaks
4. Validate security
5. Document changes

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Driver failed to load" (Error 577)
**Cause**: Driver signature enforcement
**Solution**:
```batch
:: Enable test signing
bcdedit /set testsigning on
shutdown /r /t 0
```

#### Issue: "Access denied" during installation
**Cause**: Insufficient privileges
**Solution**: Run as Administrator

#### Issue: WinDbg cannot connect
**Cause**: Network/firewall issues
**Solution**:
1. Verify IP addresses match
2. Check firewall allows port 50000
3. Ensure target has debugging enabled
4. Try different debugging method

#### Issue: Symbols not loading
**Cause**: Symbol path incorrect
**Solution**:
```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.sympath+ C:\path\to\driver\build
.reload /f
```

#### Issue: Driver causes system crash
**Cause**: Bug in driver code
**Solution**:
1. Analyze crash dump with `!analyze -v`
2. Check Driver Verifier logs
3. Review code for common issues:
   - Buffer overflows
   - Uninitialized memory
   - Incorrect IRP handling
   - Race conditions

### Debugging Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| **WinDbg** | Kernel debugging | `windbg.exe -k net:port=50000,key=1.2.3.4` |
| **Driver Verifier** | Driver validation | `verifier /standard /driver BootkitDriver.sys` |
| **Pool Monitor** | Memory leak detection | `poolmon.exe -p -t` |
| **Process Monitor** | System monitoring | `procmon.exe` |
| **DebugView** | Debug output capture | `dbgview.exe` |
| **ETW** | Event tracing | `wpr.exe -start GeneralProfile` |

### Performance Optimization

1. **Minimize IRP processing time**
2. **Use appropriate pool types** (Paged vs Non-paged)
3. **Implement efficient data structures**
4. **Avoid unnecessary locks**
5. **Batch operations when possible**

## Security Considerations

### Development Security

1. **Use dedicated development machine**
2. **Enable Hyper-V for isolation**
3. **Regular system backups**
4. **Disable test signing when not developing**
5. **Keep Windows and tools updated**

### Driver Security Best Practices

1. **Validate all input parameters**
2. **Use secure string functions** (`RtlStringCbCopyW`)
3. **Implement proper access control**
4. **Sanitize user-mode pointers**
5. **Use memory barriers for multi-processor**
6. **Implement secure cleanup routines**
7. **Audit code for common vulnerabilities**

### Code Signing Security

1. **Protect signing certificates**
2. **Use hardware security modules (HSM) for production**
3. **Implement certificate revocation checking**
4. **Time-stamp signatures**
5. **Regular certificate renewal**

### Deployment Security

1. **Test on multiple Windows versions**
2. **Verify compatibility with security software**
3. **Implement update mechanism**
4. **Provide uninstaller**
5. **Document security features**

## Additional Resources

### Documentation
- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [WDK API Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/)
- [Driver Development Tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/)
- [Kernel-Mode Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)

### Communities
- [OSR Online](https://www.osronline.com/) - Driver development community
- [MSDN Forums](https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/home?forum=wdk) - WDK forums
- [Stack Overflow](https://stackoverflow.com/questions/tagged/wdk) - Tagged questions
- [GitHub](https://github.com/microsoft/Windows-driver-samples) - Sample drivers

### Training
- [Windows Driver Development](https://docs.microsoft.com/en-us/learn/paths/develop-windows-drivers/) - Microsoft Learn path
- [WDK Training](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/getting-started-with-windows-drivers) - Getting started guide
- [Driver Development Videos](https://channel9.msdn.com/Tags/wdk) - Channel 9 videos

### Tools Download
- [Visual Studio](https://visualstudio.microsoft.com/)
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
- [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [WinDbg Preview](https://www.microsoft.com/en-us/p/windbg-preview/9pgjgd53tn86)
- [Driver Development Tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/)

---

*Note: This framework and guide are for legitimate security research and educational purposes only. Always follow applicable laws and regulations when developing kernel drivers.*