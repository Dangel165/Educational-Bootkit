# Kernel Debugging Guide

## Overview

This guide provides comprehensive instructions for kernel debugging of the Bootkit Analysis Framework using WinDbg. Kernel debugging is essential for developing, testing, and analyzing kernel-mode drivers and system components.

## Prerequisites

### Required Software
1. **WinDbg Preview** (recommended) or **WinDbg** (legacy)
2. **Windows Driver Kit (WDK)** with debugging tools
3. **Symbols** for Windows and framework components
4. **Test Machine** (target system for debugging)

### System Configuration
1. **Test Signing Enabled**:
   ```cmd
   bcdedit /set testsigning on
   ```

2. **Debugging Enabled**:
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.1.1.1
   ```

3. **Symbol Server Configured**:
   ```
   srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   ```

## Debugging Setup

### Network Debugging (Recommended)

#### Host Machine (Debugger)
1. **Configure WinDbg**:
   ```cmd
   windbg -k net:port=50000,key=1.1.1.1
   ```

2. **Set Symbol Path**:
   ```
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .sympath+ C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver
   ```

3. **Set Source Path**:
   ```
   .srcpath C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver
   ```

#### Target Machine (Debuggee)
1. **Configure Network Debugging**:
   ```cmd
   bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.1.1.1
   ```

2. **Enable Debugging**:
   ```cmd
   bcdedit /debug on
   ```

3. **Restart System**:
   ```cmd
   shutdown /r /t 0
   ```

### USB Debugging (Alternative)

#### Host Machine
```cmd
windbg -k usb:targetname=BootkitDebug
```

#### Target Machine
```cmd
bcdedit /dbgsettings usb targetname:BootkitDebug
bcdedit /debug on
```

## WinDbg Commands

### Basic Commands

#### Loading Symbols
```windbg
.reload                     # Reload all symbols
.reload /f BootkitDriver.sys # Force reload specific driver
ld BootkitDriver           # Load driver symbols
```

#### Breakpoints
```windbg
bp BootkitDriver!DriverEntry          # Set breakpoint at DriverEntry
bp /w "nt!PsCreateSystemThread"       # Conditional breakpoint
bl                                    # List breakpoints
bc 0                                  # Clear breakpoint 0
```

#### Stepping and Execution
```windbg
g                                    # Go (continue execution)
p                                    # Step over
t                                    # Step into
gu                                   # Step out
```

#### Memory Examination
```windbg
dd address L length                  # Display DWORDs
db address L length                  # Display bytes
dq address L length                  # Display QWORDs
dt nt!_EPROCESS address              # Display type
```

### Advanced Commands

#### Stack Tracing
```windbg
k                                    # Display stack trace
kb                                   # Display stack with parameters
kn                                   # Display stack with frame numbers
.frame 0                             # Switch to frame 0
```

#### Process and Thread Examination
```windbg
!process 0 0                         # List all processes
!process 0 7                         # Detailed process information
!thread                              # Current thread information
!handle                              # Handle information
```

#### Driver Information
```windbg
lm v m BootkitDriver                # List module information
!drvobj BootkitDriver 2             # Driver object information
!devobj \Device\BootkitDevice       # Device object information
```

## Debugging Framework Components

### Driver Entry Point Debugging

#### Setting Breakpoints
```windbg
# Set breakpoint at DriverEntry
bp BootkitDriver!DriverEntry

# Set breakpoint at initialization functions
bp BootkitDriver!IrpMonitorInitialize
bp BootkitDriver!BootFlowInterceptorInitialize
bp BootkitDriver!EvasionEngineInitialize
```

#### Examining Driver Entry
```windbg
# When breakpoint hits, examine parameters
r                                   # Display registers
dt _DRIVER_OBJECT @rcx              # Display driver object
dt _UNICODE_STRING @rdx             # Display registry path
```

### IRP Monitoring Debugging

#### IRP Breakpoints
```windbg
# Break on IRP_MJ_READ
bp nt!IofCallDriver "j (poi(@rcx+0x70) == 0x3) 'gc'; ''"

# Break on IRP completion
bp BootkitDriver!IrpCompletionRoutine

# Monitor IRP flow
!irp fffffa8001234567               # Examine specific IRP
```

#### IRP Flow Analysis
```windbg
# Trace IRP through stack
!stacks 2                           # Show stack usage
!thread -p                          # Show thread with IRPs
!irql                               # Show current IRQL
```

### Boot Process Debugging

#### Boot Breakpoints
```windbg
# Break on boot initialization
bp nt!IoInitializeBootDrivers
bp nt!IopLoadDriver

# Break on specific boot components
bp winload!OslMain
bp nt!KiSystemStartup
```

#### Boot Sequence Analysis
```windbg
# Monitor boot sequence
!loadorder                         # Show driver load order
!drivers                           # List loaded drivers
!vm 1                              # Show virtual memory information
```

### Evasion Engine Debugging

#### Detection Breakpoints
```windbg
# Break on VM detection
bp BootkitDriver!DetectVirtualization
bp BootkitDriver!CheckCPUID

# Break on sandbox detection
bp BootkitDriver!DetectSandbox
bp BootkitDriver!CheckTiming

# Break on debugger detection
bp BootkitDriver!DetectDebugger
bp BootkitDriver!CheckPEB
```

#### Evasion Analysis
```windbg
# Examine evasion state
dt BootkitDriver!_EVASION_STATE
dt BootkitDriver!_DETECTION_RESULTS

# Monitor evasion techniques
!pooltag Evas                      # Show evasion-related pool usage
!object \Driver\BootkitDriver      # Examine driver object
```

## Common Debugging Scenarios

### Scenario 1: Driver Load Failure

#### Symptoms
- Driver fails to load
- System crash (BSOD) during load
- Error in Event Viewer

#### Debugging Steps
```windbg
# Set breakpoint at DriverEntry
bp BootkitDriver!DriverEntry

# Load driver
sc start BootkitDriver

# When breakpoint hits, examine
k                                   # Stack trace
r                                   # Registers
!error @rax                         # Error code
```

### Scenario 2: IRP Handling Issues

#### Symptoms
- IRP not being processed
- System hang during I/O operations
- Data corruption

#### Debugging Steps
```windbg
# Set breakpoint on IRP handler
bp BootkitDriver!IrpReadHandler

# Trigger IRP (e.g., read file)
# When breakpoint hits
!irp @rcx                           # Examine IRP
dt _IO_STACK_LOCATION @rcx+0xB8     # Examine stack location
```

### Scenario 3: Memory Corruption

#### Symptoms
- Random system crashes
- Pool corruption errors
- Memory leaks

#### Debugging Steps
```windbg
# Enable pool tagging
ed nt!PoolHitTag 'BktP'            # Set pool tag

# Monitor pool usage
!poolused 2                         # Show pool usage by tag
!poolfind BktP                      # Find allocations with tag

# Check for corruption
!poolval                            # Validate pool
!verifier 3                         # Enable driver verifier
```

### Scenario 4: Performance Issues

#### Symptoms
- System slowdown
- High CPU usage
- Resource exhaustion

#### Debugging Steps
```windbg
# Monitor performance
!running -it                        # Show running threads
!cpu 0 1                            # Show CPU usage
!vm                                 # Show memory usage

# Profile driver
!profile                            # Start profiling
!profile -stop                      # Stop profiling
!profile -output file.txt           # Save profile data
```

## Advanced Debugging Techniques

### Time Travel Debugging (TTD)

#### Recording Session
```windbg
# Start recording
.ttd start C:\Traces\BootkitTrace.run

# Execute test scenario
# Stop recording
.ttd stop
```

#### Analyzing Trace
```windbg
# Load trace
windbg -z C:\Traces\BootkitTrace.run

# Time travel commands
.tt                                 # Show time travel status
.g-                                 # Step backward
.g+                                 # Step forward
```

### Script Debugging

#### Creating Debugger Scripts
```windbg
# Create script file debug.wds
$$
$$ Bootkit Analysis Framework Debug Script
$$
ad /q *                             # Clear aliases
.block
{
    .echo "Loading Bootkit Driver symbols..."
    .reload /f BootkitDriver.sys
    .echo "Setting breakpoints..."
    bp BootkitDriver!DriverEntry
    bp BootkitDriver!IrpMonitorInitialize
    g
}
```

#### Executing Scripts
```windbg
$$ Load and execute script
$$>< debug.wds

$$ Execute commands from file
$$>< commands.txt
```

### Extension Debugging

#### Loading Extensions
```windbg
# Load debugger extensions
.load C:\Debuggers\x64\winext\ext.dll

# Use extension commands
!ext.command parameter
```

#### Custom Extensions
Create custom extensions for framework-specific debugging.

## Symbol Management

### Symbol Server Configuration

#### Microsoft Symbol Server
```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

#### Local Symbols
```windbg
.sympath+ C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver
.sympath+ C:\Path\To\BootkitAnalysisFramework\tests
```

#### Cache Management
```windbg
.sympath cache*C:\SymbolCache        # Set symbol cache
.reload /f                           # Force symbol reload
```

### Symbol Issues Troubleshooting

#### Missing Symbols
```windbg
# Check symbol status
lm v m BootkitDriver                # Show module information

# Force symbol load
.reload /f BootkitDriver.sys

# Download symbols
.symfix                             # Fix symbol path
.reload
```

#### Wrong Symbols
```windbg
# Unload wrong symbols
.unload BootkitDriver

# Load correct symbols
.reload /f BootkitDriver.sys
```

## Crash Dump Analysis

### Creating Crash Dumps

#### Manual Dump
```windbg
# Create dump of current state
.dump /ma C:\Dumps\bootkit.dmp

# Create mini dump
.dump /m C:\Dumps\bootkit-mini.dmp
```

#### Automatic Dump
Configure system to create dumps on crash:
```cmd
# Set dump type
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 1

# Set dump path
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v DumpFile /t REG_EXPAND_SZ /d "%SystemRoot%\MEMORY.DMP"
```

### Analyzing Crash Dumps

#### Loading Dump File
```windbg
# Open dump file
windbg -z C:\Dumps\bootkit.dmp

# Analyze crash
!analyze -v                         # Automatic analysis
!thread                             # Current thread
k                                   # Stack trace
```

#### Common Analysis Commands
```windbg
# Determine crash cause
!analyze -v

# Examine exception
.exr -1                             # Last exception
.cxr                                # Context record

# Check drivers
!drivers                            # Loaded drivers
!irp                                # Pending IRPs
```

## Performance Monitoring

### ETW Tracing

#### Starting Trace
```cmd
# Start ETW session
logman start BootkitTrace -p {BootkitProvider} -o bootkit.etl -ets

# Stop trace
logman stop BootkitTrace -ets
```

#### Analyzing Trace
```windbg
# Load ETW trace
windbg -k trace:bootkit.etl

# Analyze events
!wmitrace.logdump                   # Dump trace events
!wmitrace.search "Bootkit"          # Search for events
```

### Performance Counters

#### Monitoring Counters
```windbg
# Monitor performance
!perf                               # Show performance data
!sysinfo cpuinfo                    # CPU information
!sysinfo meminfo                    # Memory information
```

#### Custom Counters
Implement custom performance counters in driver for monitoring.

## Security Considerations

### Secure Debugging

#### Debugging Permissions
```cmd
# Add user to debugger group
net localgroup "Debugger Users" username /add
```

#### Secure Communication
- Use encrypted debugging channels
- Secure network debugging with firewalls
- Limit debugger access to authorized users

### Debugging in Production

#### Production Debugging Guidelines
1. **Minimal Impact**: Use non-invasive debugging techniques
2. **Security Auditing**: Log all debugging activities
3. **Access Control**: Restrict debugging access
4. **Data Protection**: Protect sensitive data during debugging

## Troubleshooting

### Common Debugging Issues

#### Issue: "Breakpoints not hitting"
**Solution**:
```windbg
# Verify symbols are loaded
lm v m BootkitDriver

# Check address
x BootkitDriver!DriverEntry

# Use hardware breakpoints
ba e1 BootkitDriver!DriverEntry
```

#### Issue: "Symbols not loading"
**Solution**:
```windbg
# Check symbol path
.sympath

# Download symbols
.symfix
.reload
```

#### Issue: "Debugger not connecting"
**Solution**:
- Verify network configuration
- Check firewall settings
- Verify debugging is enabled on target
- Check cable connection (USB debugging)

### Debugging Tools

#### Recommended Tools
1. **WinDbg Preview**: Modern debugger with TTD support
2. **DebugView**: Real-time debug output monitoring
3. **Process Monitor**: System activity monitoring
4. **Driver Verifier**: Driver validation and testing
5. **Pool Monitor**: Memory pool monitoring

#### Tool Integration
Integrate debugging tools for comprehensive analysis:
```cmd
# Start multiple tools
start windbg -k net:port=50000,key=1.1.1.1
start dbgview /a
start procmon /quiet
```

## Best Practices

### Debugging Workflow
1. **Preparation**: Set up symbols and breakpoints
2. **Reproduction**: Reproduce the issue
3. **Analysis**: Examine state and data
4. **Resolution**: Identify and fix root cause
5. **Verification**: Test the fix

### Documentation
- Document debugging sessions
- Save relevant dumps and logs
- Create debugging scripts for common scenarios
- Maintain symbol and source code organization

### Performance Optimization
- Use conditional breakpoints to reduce overhead
- Limit symbol loading to necessary modules
- Use logging for non-critical debugging
- Implement telemetry for production debugging

## Conclusion

This kernel debugging guide provides comprehensive instructions for debugging the Bootkit Analysis Framework. Master these techniques to effectively develop, test, and analyze kernel-mode components.

For additional help, refer to:
- [Build and Compilation Guide](BUILD_GUIDE.md)
- [Visual Studio Solution Documentation](VISUAL_STUDIO_SOLUTION.md)
- [Driver Development Guide](driver_development_guide.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This framework is for legitimate security research and educational purposes only. Always obtain proper authorization before debugging these components on any system.