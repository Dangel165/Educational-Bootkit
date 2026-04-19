# Kernel Debugging Tutorial

## Overview

This tutorial provides step-by-step instructions for kernel debugging of the Bootkit Analysis Framework. You'll learn how to set up debugging environments, analyze kernel components, and troubleshoot common issues.

## Prerequisites

### Required Software
1. **Windows 10/11** (64-bit) on both host and target machines
2. **Visual Studio 2019+** with Windows Driver Kit (WDK)
3. **WinDbg Preview** (recommended) from Microsoft Store
4. **Bootkit Analysis Framework** source code
5. **Test signing enabled** on target machine

### Network Configuration
- **Host Machine**: Debugger system (your development machine)
- **Target Machine**: System running the framework (test machine)
- **Network Connection**: Ethernet preferred (Wi-Fi may work but less reliable)

## Part 1: Setting Up Debugging Environment

### Step 1: Enable Test Signing on Target
```cmd
# Open Command Prompt as Administrator on target machine
bcdedit /set testsigning on
bcdedit /set debug on
shutdown /r /t 0
```

### Step 2: Configure Network Debugging

#### On Target Machine:
```cmd
# Set network debugging parameters
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.1.1.1

# Verify settings
bcdedit /enum

# Restart target machine
shutdown /r /t 0
```

*Note: Replace `192.168.1.100` with your host machine's IP address*

#### On Host Machine:
```cmd
# Open WinDbg Preview as Administrator
# Or use command line:
windbg -k net:port=50000,key=1.1.1.1
```

### Step 3: Configure Symbol Path

In WinDbg, configure symbols:
```
# Set symbol path
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.sympath+ C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver

# Set source path
.srcpath C:\Path\To\BootkitAnalysisFramework\drivers\BootkitDriver

# Reload symbols
.reload
```

## Part 2: Basic Debugging Commands

### Essential WinDbg Commands

#### 1. Loading and Examining Modules
```windbg
# List loaded modules
lm

# List modules with details
lm v

# List specific module
lm v m BootkitDriver

# Load module symbols
ld BootkitDriver
```

#### 2. Setting Breakpoints
```windbg
# Set breakpoint at DriverEntry
bp BootkitDriver!DriverEntry

# Set breakpoint with condition
bp BootkitDriver!IrpMonitorInitialize ".if (@rcx != 0) { .echo 'Valid DriverObject' } .else { .echo 'Invalid DriverObject' }"

# List breakpoints
bl

# Clear breakpoint
bc 0
```

#### 3. Stepping Through Code
```windbg
# Continue execution
g

# Step over (execute next instruction)
p

# Step into (enter function call)
t

# Step out (return from function)
gu

# Run to cursor
Ctrl+F10
```

#### 4. Examining Memory
```windbg
# Display memory as DWORDs
dd address L length

# Display memory as bytes
db address L length

# Display memory as QWORDs
dq address L length

# Display type information
dt nt!_EPROCESS
dt BootkitDriver!_IRP_MONITORING_CONTEXT
```

## Part 3: Debugging Framework Components

### Tutorial 1: Debugging IRP Monitor

#### Step 1: Set Initial Breakpoints
```windbg
# Set breakpoints for IRP monitoring
bp BootkitDriver!InitializeIrpMonitoring
bp BootkitDriver!HookIrpMjRead
bp BootkitDriver!HookIrpMjDirectoryControl
bp BootkitDriver!IrpReadHookHandler
```

#### Step 2: Start Debugging Session
```windbg
# Continue execution
g

# When breakpoint hits at InitializeIrpMonitoring
# Examine parameters
r
dt _DRIVER_OBJECT @rcx
dt _DEVICE_OBJECT @rdx
```

#### Step 3: Analyze IRP Hook Installation
```windbg
# When breakpoint hits at HookIrpMjRead
# Examine target device
dt _DEVICE_OBJECT @rcx

# Check device name
!devobj @rcx

# Continue to see hook handler installation
g
```

#### Step 4: Monitor IRP Processing
```windbg
# When IRP_MJ_READ occurs, breakpoint hits at IrpReadHookHandler
# Examine IRP
!irp @rcx

# Examine stack location
dt _IO_STACK_LOCATION @rcx+0xB8

# Continue IRP processing
g
```

#### Step 5: Analyze Completion
```windbg
# Set breakpoint on completion
bp BootkitDriver!CompletionRoutineHook

# When breakpoint hits
# Examine completion status
!irp @rcx
```

### Tutorial 2: Debugging Boot Flow Interceptor

#### Step 1: Set Boot Analysis Breakpoints
```windbg
# Set breakpoints for boot analysis
bp BootkitDriver!InitializeBootFlowInterceptor
bp BootkitDriver!HookWinloadEntryPoints
bp BootkitDriver!MonitorNtoskrnlInit
```

#### Step 2: Analyze Boot Process
```windbg
# When breakpoint hits at HookWinloadEntryPoints
# Examine winload base address
r
dq @rcx

# Check memory protection
!vprot @rcx

# Continue to monitor boot sequence
g
```

#### Step 3: Monitor Kernel Initialization
```windbg
# When breakpoint hits at MonitorNtoskrnlInit
# Examine ntoskrnl base address
dq @rcx

# Check loaded modules
!loadorder

# List kernel modules
lm v m ntoskrnl
```

### Tutorial 3: Debugging Evasion Engine

#### Step 1: Set Evasion Detection Breakpoints
```windbg
# Set breakpoints for evasion detection
bp BootkitDriver!InitializeEvasionEngine
bp BootkitDriver!DetectVirtualization
bp BootkitDriver!DetectDebuggers
bp BootkitDriver!EvadeSandboxes
```

#### Step 2: Analyze VM Detection
```windbg
# When breakpoint hits at DetectVirtualization
# Examine detection state
dt BootkitDriver!_EVASION_DETECTION_STATE @rdx

# Check CPUID results
r
!cpuid

# Continue to see detection results
g
```

#### Step 3: Analyze Debugger Detection
```windbg
# When breakpoint hits at DetectDebuggers
# Examine PEB for debugger flags
dt _PEB @$peb

# Check debug port
!peb

# Examine detection results
dt BootkitDriver!_DEBUGGER_DETECTION_RESULT @rdx
```

## Part 4: Advanced Debugging Techniques

### Time Travel Debugging (TTD)

#### Recording a Session
```windbg
# Start recording
.ttd start C:\Traces\BootkitTrace.run

# Execute test scenario (load driver, trigger IRPs, etc.)

# Stop recording
.ttd stop
```

#### Analyzing the Trace
```windbg
# Load trace file
windbg -z C:\Traces\BootkitTrace.run

# Navigate through time
.g-  # Step backward
.g+  # Step forward

# Find specific events
.tt  # Show time travel status
```

### Script Debugging

#### Create Debug Script
Create file `debug_bootkit.wds`:
```windbg
$$
$$ Bootkit Analysis Framework Debug Script
$$
.ad /q *  // Clear all aliases

.block
{
    .echo "=== Bootkit Analysis Framework Debug Script ==="
    .echo "Loading symbols..."
    
    .reload /f BootkitDriver.sys
    .echo "Symbols loaded."
    
    .echo "Setting breakpoints..."
    bp BootkitDriver!DriverEntry
    bp BootkitDriver!InitializeIrpMonitoring
    bp BootkitDriver!InitializeEvasionEngine
    
    .echo "Breakpoints set. Starting execution..."
    g
}
```

#### Execute Script
```windbg
$$>< debug_bootkit.wds
```

### Extension Debugging

#### Load Debugger Extensions
```windbg
# Load common extensions
.load kdexts
.load exts

# Use extension commands
!process 0 0
!thread
!irp
```

#### Create Custom Extensions
For framework-specific debugging, create custom extensions.

## Part 5: Common Debugging Scenarios

### Scenario 1: Driver Load Failure

#### Symptoms
- Driver fails to load with error
- System crash during driver load
- Event Viewer shows driver errors

#### Debugging Steps
```windbg
# Set breakpoint at DriverEntry
bp BootkitDriver!DriverEntry

# Load driver
sc start BootkitDriver

# When breakpoint hits, examine
k  # Stack trace
r  # Registers
!error @rax  # Error code

# Check driver object
dt _DRIVER_OBJECT @rcx
```

### Scenario 2: IRP Handling Issues

#### Symptoms
- IRP not being processed
- System hang during I/O operations
- Data corruption

#### Debugging Steps
```windbg
# Set breakpoint on IRP handler
bp BootkitDriver!IrpReadHookHandler

# Trigger IRP (read a file)
# When breakpoint hits
!irp @rcx  # Examine IRP
dt _IO_STACK_LOCATION @rcx+0xB8  # Examine stack location

# Check completion
bp BootkitDriver!CompletionRoutineHook
g
```

### Scenario 3: Memory Corruption

#### Symptoms
- Random system crashes
- Pool corruption errors
- Memory leaks

#### Debugging Steps
```windbg
# Enable pool tagging
ed nt!PoolHitTag 'BktP'

# Monitor pool usage
!poolused 2
!poolfind BktP

# Check for corruption
!poolval
!verifier 3  # Enable driver verifier
```

### Scenario 4: Performance Issues

#### Symptoms
- System slowdown
- High CPU usage
- Resource exhaustion

#### Debugging Steps
```windbg
# Monitor performance
!running -it
!cpu 0 1
!vm

# Profile driver
!profile
# Execute operations
!profile -stop
!profile -output profile.txt
```

## Part 6: Debugging Tools Integration

### Using DebugView
DebugView shows kernel debug output in real-time:

```cmd
# Run DebugView as Administrator
# Capture: Capture Kernel, Capture Events
# Filter: BootkitDriver
```

### Using Process Monitor
Process Monitor shows system activity:

```cmd
# Run Process Monitor as Administrator
# Filter: Process Name contains Bootkit
# Monitor: Registry, File System, Network
```

### Using Driver Verifier
Driver Verifier validates driver behavior:

```cmd
# Enable Driver Verifier
verifier /standard /driver BootkitDriver.sys

# Check verifier status
verifier /querysettings
```

## Part 7: Practical Exercises

### Exercise 1: Trace IRP Flow
**Objective**: Trace an IRP_MJ_READ from initiation to completion

**Steps**:
1. Set breakpoints at all IRP handling functions
2. Trigger a file read operation
3. Document the IRP flow through the system
4. Analyze timing and completion status

### Exercise 2: Analyze Boot Sequence
**Objective**: Document boot module loading sequence

**Steps**:
1. Set breakpoints on boot initialization functions
2. Reboot target machine
3. Record module load order and timings
4. Analyze Secure Boot verification

### Exercise 3: Test Evasion Techniques
**Objective**: Verify evasion engine functionality

**Steps**:
1. Set breakpoints on detection functions
2. Run in different environments (VM, sandbox, debugger)
3. Document detection results
4. Test evasion technique effectiveness

### Exercise 4: Debug Memory Issues
**Objective**: Identify and fix memory leaks

**Steps**:
1. Enable pool tagging
2. Run stress tests
3. Monitor pool usage
4. Identify leaks and fix them

## Part 8: Best Practices

### Debugging Workflow
1. **Preparation**: Set up symbols and breakpoints
2. **Reproduction**: Reproduce the issue consistently
3. **Analysis**: Examine state, data, and flow
4. **Hypothesis**: Form hypothesis about root cause
5. **Testing**: Test hypothesis with targeted debugging
6. **Resolution**: Implement and verify fix
7. **Documentation**: Document findings and solution

### Performance Considerations
- Use conditional breakpoints to reduce overhead
- Limit symbol loading to necessary modules
- Use logging for non-critical debugging
- Implement telemetry for production debugging

### Security Considerations
- Secure debugging channels (encrypted networks)
- Limit debugger access to authorized users
- Protect sensitive data during debugging
- Audit debugging activities

## Part 9: Troubleshooting

### Common Issues and Solutions

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

#### Issue: "System crashes during debugging"
**Solution**:
- Use kernel-safe debugging commands
- Avoid breaking in critical sections
- Use non-invasive debugging techniques
- Enable crash dumps for analysis

## Part 10: Resources and References

### Additional Resources
1. **WinDbg Documentation**: Microsoft Docs
2. **WDK Debugging Guide**: Windows Driver Kit documentation
3. **Kernel Debugging Blog**: NTDEV blog and resources
4. **Community Forums**: OSR Online, Stack Overflow

### Recommended Reading
1. "Windows Internals" by Mark Russinovich
2. "Advanced Windows Debugging" by Mario Hewardt
3. "Windows Kernel Programming" by Pavel Yosifovich
4. "Rootkits: Subverting the Windows Kernel" by Greg Hoglund

### Training Resources
1. **Microsoft Learn**: Windows Driver Development
2. **Pluralsight**: Windows Kernel Debugging
3. **OSR Online**: Driver Development Training
4. **Conference Talks**: BlueHat, BlackHat, DEF CON

## Conclusion

This tutorial has provided comprehensive guidance for kernel debugging of the Bootkit Analysis Framework. By mastering these techniques, you can effectively develop, test, and analyze kernel-mode components for legitimate security research.

Remember to always:
1. **Test in controlled environments**
2. **Document debugging sessions**
3. **Follow security best practices**
4. **Maintain ethical research standards**

For additional help, refer to:
- [Kernel Debugging Guide](KERNEL_DEBUGGING_GUIDE.md)
- [API Reference Documentation](API_REFERENCE_KERNEL.md)
- [Build and Compilation Guide](BUILD_GUIDE.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This tutorial is for legitimate security research and educational purposes only. Always obtain proper authorization before debugging any system and follow all applicable laws and regulations.