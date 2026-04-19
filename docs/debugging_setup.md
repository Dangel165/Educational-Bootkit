# Kernel Debugging Setup Guide

This guide explains how to set up kernel debugging for the Bootkit Analysis Framework driver development.

## Prerequisites

### Required Software
1. **Windows Driver Kit (WDK)** - Install via Visual Studio Installer
2. **Visual Studio 2019 or later** - With C++ workload
3. **WinDbg Preview** - From Microsoft Store
4. **Windows SDK** - Latest version

### System Requirements
- Windows 10/11 x64
- Administrator privileges
- Test signing enabled
- 8GB+ RAM recommended

## Part 1: Enabling Test Signing

Before loading unsigned drivers, enable test signing:

### Method 1: Using Script (Recommended)
```batch
cd bootkit-analysis-framework\scripts
enable_test_signing.bat
```

### Method 2: Manual Commands
```batch
:: Run as Administrator
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
:: Restart computer
```

### Verification
After restart, verify test signing is enabled:
```batch
bcdedit /enum | findstr "testsigning"
```
Should show: `testsigning Yes`

## Part 2: Setting Up Kernel Debugging

### Option A: Network Debugging (Recommended for same machine)

1. **Enable Network Debugging**
   ```batch
   :: Run as Administrator
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4
   ```
   Replace `192.168.1.100` with your IP address.

2. **Note the Connection Settings**
   ```batch
   bcdedit /dbgsettings
   ```
   Save the key and port for WinDbg configuration.

3. **Restart Computer**

### Option B: Serial Debugging (For two machines)

1. **Connect Machines**
   - Connect two computers via null-modem serial cable or USB-to-serial
   - Note COM port numbers

2. **Configure Target Machine**
   ```batch
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

3. **Restart Target Machine**

## Part 3: WinDbg Configuration

### Installing WinDbg Preview
1. Open Microsoft Store
2. Search for "WinDbg Preview"
3. Install and launch

### Configuring Network Debugging in WinDbg

1. **Open WinDbg Preview**
2. **File → Attach to Kernel Debugger**
3. **Net tab**
   - Port: `50000` (or your configured port)
   - Key: `1.2.3.4` (or your generated key)
4. **Click "OK"**

### Configuring Serial Debugging in WinDbg

1. **Open WinDbg Preview**
2. **File → Attach to Kernel Debugger**
3. **COM tab**
   - Baud Rate: `115200`
   - Port: `COM1` (or your COM port)
   - Pipe: (leave unchecked)
4. **Click "OK"**

## Part 4: Driver Debugging Workflow

### Building Driver with Debug Symbols

1. **Open Visual Studio as Administrator**
2. **Load Solution**: `BootkitAnalysisFramework.sln`
3. **Set Configuration**: `Debug | x64`
4. **Build Solution**: Build → Build Solution (Ctrl+Shift+B)

### Installing Driver for Debugging

```batch
cd bootkit-analysis-framework\scripts
install_driver.bat
```

### Setting Breakpoints in WinDbg

Common breakpoints for driver debugging:

```windbg
:: Break on driver load
sxe ld BootkitDriver.sys

:: After driver loads, set breakpoints
bp BootkitDriver!DriverEntry
bp BootkitDriver!DriverUnload
bp BootkitDriver!IrpCreateHandler
bp BootkitDriver!IrpDeviceControlHandler

:: Continue execution
g
```

### Common WinDbg Commands

```windbg
:: List loaded modules
lm

:: Display driver information
!drvobj BootkitDriver 2

:: Display device objects
!devobj \Device\BootkitDriver

:: Dump IRP information
!irp <address>

:: Stack trace
k

:: Display pool usage
!poolused

:: Check for memory leaks
!poolfind BootkitDriver

:: Display process information
!process 0 0
```

## Part 5: Debugging Scenarios

### Scenario 1: Driver Fails to Load

**Symptoms**: Driver installation succeeds but service won't start

**Debugging Steps**:
1. Check Event Viewer → Windows Logs → System
2. Look for driver-related errors
3. Use WinDbg to catch driver load:
   ```windbg
   sxe ld BootkitDriver.sys
   g
   ```
4. When breakpoint hits, examine error:
   ```windbg
   !error <last error code>
   ```

### Scenario 2: Driver Crashes (Bug Check)

**Symptoms**: Blue screen with driver-related error

**Debugging Steps**:
1. Configure Windows to create dump files:
   ```batch
   :: Run as Administrator
   wmic recoveros set DebugInfoType = 7
   ```
2. After crash, analyze dump in WinDbg:
   ```windbg
   .open <dump file>
   !analyze -v
   ```

### Scenario 3: Driver Hangs or Deadlocks

**Symptoms**: System becomes unresponsive

**Debugging Steps**:
1. Break into debugger (Ctrl+Break in WinDbg)
2. Check thread states:
   ```windbg
   !thread
   ```
3. Look for threads waiting on locks
4. Check spin locks and mutexes

## Part 6: Advanced Debugging Techniques

### Symbol Server Configuration

Add Microsoft symbol server to WinDbg:
```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload
```

### Source Code Debugging

1. **Set source path in WinDbg**:
   ```windbg
   .srcpath+ C:\path\to\bootkit-analysis-framework\drivers
   ```

2. **Load symbols**:
   ```windbg
   .reload /f BootkitDriver.sys
   ```

3. **Set breakpoint with source**:
   ```windbg
   bp `BootkitDriver\Driver.cpp:45`
   ```

### Logging and Tracing

The driver includes built-in logging via `DbgPrintEx`:

1. **Enable verbose logging**:
   ```c
   // In Driver.cpp, set DBG=1 for debug builds
   #define DBG 1
   ```

2. **View debug output in WinDbg**:
   ```windbg
   ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF
   g
   ```

3. **Filter debug output**:
   ```windbg
   !dbgprint
   ```

## Part 7: Troubleshooting Common Issues

### Issue: "Driver failed to load" Error 577

**Cause**: Windows requires signed drivers

**Solution**:
1. Ensure test signing is enabled
2. Check Secure Boot is disabled in BIOS
3. Verify driver is built for correct Windows version

### Issue: WinDbg Cannot Connect

**Solution**:
1. Verify network settings match on both machines
2. Check firewall allows port 50000
3. Ensure target machine has debugging enabled
4. Try different connection method (serial vs network)

### Issue: Symbols Not Loading

**Solution**:
1. Verify .pdb file exists in build output
2. Check symbol path includes build directory
3. Use `.sympath` to add local symbol path
4. Try `.reload /f` to force symbol reload

## Part 8: Performance Monitoring

### Driver Verifier

Enable Driver Verifier to catch common driver bugs:

```batch
:: Run as Administrator
verifier /standard /driver BootkitDriver.sys
```

Common checks enabled:
- Memory allocation tracking
- IRP completion verification
- Deadlock detection
- Security checks

### ETW Tracing

Enable Event Tracing for Windows:

```batch
:: Create trace session
logman create trace BootkitTrace -o BootkitTrace.etl -p {BootkitDriver} 0xFFFFFFFF 0xFF -ets

:: Stop trace
logman stop BootkitTrace -ets

:: Convert to text
tracerpt BootkitTrace.etl -o BootkitTrace.txt
```

## Part 9: Security Considerations

### Development Environment Security

1. **Use dedicated development machine** - Don't develop on production systems
2. **Enable Hyper-V/Virtual Machine** - Isolate driver testing
3. **Regular backups** - In case of system corruption
4. **Disable when not in use** - Turn off test signing after development

### Driver Security Best Practices

1. **Validate all input** - Check buffer sizes, pointers
2. **Use secure functions** - `RtlStringCbCopyW` instead of `wcscpy`
3. **Pool tagging** - Track memory allocations
4. **IRP validation** - Verify IRP parameters
5. **Access control** - Check caller privileges

## Additional Resources

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [WinDbg Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [Driver Development Forum](https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/home?forum=wdk)
- [OSR Online](https://www.osronline.com/) - Driver development community

---

*Note: This framework is for legitimate security research and educational purposes only.*