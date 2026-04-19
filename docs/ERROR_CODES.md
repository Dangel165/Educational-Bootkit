# Error Codes Reference

## Overview

This document provides comprehensive documentation for all error codes used in the Bootkit Analysis Framework. Error codes follow Windows NTSTATUS conventions and provide detailed information about operation success or failure.

## Error Code Format

### NTSTATUS Format
All framework error codes use the NTSTATUS format:
```
3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|S|R|C|N|r|    Facility         |               Code            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

S = Severity (0=Success, 1=Information, 2=Warning, 3=Error)
R = Reserved (0)
C = Customer code flag (1=custom, 0=Microsoft)
N = Reserved (0)
r = Reserved (0)
Facility = Facility code (0x7FF for custom drivers)
Code = Specific error code
```

### Custom Error Code Range
The framework uses custom error codes in the range:
- **Severity**: 3 (Error)
- **Customer Code Flag**: 1 (Custom)
- **Facility**: 0x7FF (Custom driver facility)
- **Code Range**: 0x1000-0x1FFF

## Success Codes

### Common Success Codes

#### STATUS_SUCCESS (0x00000000)
**Description**: Operation completed successfully
**Usage**: General success indicator
**Example**: Driver loaded successfully, IRP processed successfully

#### STATUS_PENDING (0x00000103)
**Description**: Operation is pending completion
**Usage**: Asynchronous operations
**Example**: IRP queued for later processing

#### STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
**Description**: More processing is required
**Usage**: Filter drivers requiring additional processing
**Example**: Minifilter driver needs to process IRP further

## Framework-Specific Error Codes

### IRP Monitoring Errors (0x7FF01000-0x7FF01FFF)

#### STATUS_IRPMONITOR_INIT_FAILED (0xC7FF0101)
**Description**: IRP monitor initialization failed
**Possible Causes**:
- Insufficient system resources
- Invalid driver or device object
- Memory allocation failure
**Resolution**: Check system resources and object validity

#### STATUS_IRPMONITOR_HOOK_FAILED (0xC7FF0102)
**Description**: IRP hook installation failed
**Possible Causes**:
- Invalid target device
- Memory protection issues
- Already hooked function
**Resolution**: Verify target device and memory permissions

#### STATUS_IRPMONITOR_DETACH_FAILED (0xC7FF0103)
**Description**: Device stack detach failed
**Possible Causes**:
- Device not attached
- Invalid device object
- System resource issue
**Resolution**: Check attachment status and device validity

#### STATUS_IRPMONITOR_SCAN_FAILED (0xC7FF0104)
**Description**: Dispatch table scan failed
**Possible Causes**:
- Invalid memory address
- Access violation
- System resource limitation
**Resolution**: Verify memory addresses and permissions

### Boot Analysis Errors (0x7FF02000-0x7FF02FFF)

#### STATUS_BOOTANALYSIS_INIT_FAILED (0xC7FF0201)
**Description**: Boot analysis initialization failed
**Possible Causes**:
- UEFI services unavailable
- Secure Boot restrictions
- System firmware limitations
**Resolution**: Check UEFI/BIOS settings and firmware version

#### STATUS_BOOTANALYSIS_HOOK_FAILED (0xC7FF0202)
**Description**: Boot entry point hook failed
**Possible Causes**:
- Invalid entry point address
- Memory protection violation
- PatchGuard interference
**Resolution**: Verify entry point addresses and memory permissions

#### STATUS_BOOTANALYSIS_SECUREBOOT_FAILED (0xC7FF0203)
**Description**: Secure Boot analysis failed
**Possible Causes**:
- Secure Boot disabled
- Firmware limitations
- Access restrictions
**Resolution**: Check Secure Boot status and firmware capabilities

### Evasion Engine Errors (0x7FF03000-0x7FF03FFF)

#### STATUS_EVASION_INIT_FAILED (0xC7FF0301)
**Description**: Evasion engine initialization failed
**Possible Causes**:
- System compatibility issues
- Resource limitations
- Configuration errors
**Resolution**: Check system compatibility and configuration

#### STATUS_EVASION_DETECTION_FAILED (0xC7FF0302)
**Description**: Detection mechanism failed
**Possible Causes**:
- Hardware limitations
- Environment restrictions
- Timing issues
**Resolution**: Verify hardware capabilities and environment

#### STATUS_EVASION_TECHNIQUE_FAILED (0xC7FF0303)
**Description**: Evasion technique application failed
**Possible Causes**:
- Technique not supported
- System restrictions
- Resource limitations
**Resolution**: Check technique compatibility and system state

### Process Concealment Errors (0x7FF04000-0x7FF04FFF)

#### STATUS_CONCEALMENT_INIT_FAILED (0xC7FF0401)
**Description**: Process concealment initialization failed
**Possible Causes**:
- Invalid process ID
- Access denied
- System resource limitation
**Resolution**: Verify process existence and access permissions

#### STATUS_CONCEALMENT_DKOM_FAILED (0xC7FF0402)
**Description**: DKOM operation failed
**Possible Causes**:
- Invalid kernel object
- Memory access violation
- System protection mechanisms
**Resolution**: Check object validity and memory permissions

#### STATUS_CONCEALMENT_RESTORE_FAILED (0xC7FF0403)
**Description**: Process restoration failed
**Possible Causes**:
- Original data lost
- Memory corruption
- System state changed
**Resolution**: Verify backup data and system state

### Data Exfiltration Errors (0x7FF05000-0x7FF05FFF)

#### STATUS_EXFILTRATION_INIT_FAILED (0xC7FF0501)
**Description**: Data exfiltration initialization failed
**Possible Causes**:
- Network connectivity issues
- Invalid configuration
- Resource limitations
**Resolution**: Check network connectivity and configuration

#### STATUS_EXFILTRATION_SEND_FAILED (0xC7FF0502)
**Description**: Data send operation failed
**Possible Causes**:
- Network failure
- Rate limiting
- Authentication failure
**Resolution**: Verify network status and authentication

#### STATUS_EXFILTRATION_ENCRYPTION_FAILED (0xC7FF0503)
**Description**: Data encryption failed
**Possible Causes**:
- Invalid encryption key
- Cryptographic library failure
- Resource limitations
**Resolution**: Check encryption keys and cryptographic libraries

### Memory Management Errors (0x7FF06000-0x7FF06FFF)

#### STATUS_MEMORY_ALLOCATION_FAILED (0xC7FF0601)
**Description**: Memory allocation failed
**Possible Causes**:
- Insufficient pool memory
- Invalid pool type
- System resource exhaustion
**Resolution**: Check available memory and pool usage

#### STATUS_MEMORY_PROTECTION_FAILED (0xC7FF0602)
**Description**: Memory protection change failed
**Possible Causes**:
- Invalid memory address
- Access denied
- System policy restriction
**Resolution**: Verify memory addresses and permissions

#### STATUS_MEMORY_INTEGRITY_FAILED (0xC7FF0603)
**Description**: Memory integrity check failed
**Possible Causes**:
- Memory corruption
- Tampering detected
- Hash mismatch
**Resolution**: Investigate memory corruption sources

## Windows System Error Codes

### Common System Errors

#### STATUS_INVALID_PARAMETER (0xC000000D)
**Description**: An invalid parameter was passed to a service or function
**Usage**: Parameter validation failures
**Example**: NULL pointer passed where non-NULL required

#### STATUS_BUFFER_TOO_SMALL (0xC0000023)
**Description**: The buffer is too small to contain the entry
**Usage**: Buffer size checking
**Example**: Output buffer too small for data

#### STATUS_ACCESS_DENIED (0xC0000022)
**Description**: Access is denied
**Usage**: Permission checking
**Example**: Insufficient privileges for operation

#### STATUS_NOT_SUPPORTED (0xC00000BB)
**Description**: The request is not supported
**Usage**: Feature availability checking
**Example**: Operation not supported on current system

#### STATUS_INSUFFICIENT_RESOURCES (0xC000009A)
**Description**: Insufficient system resources exist to complete the API
**Usage**: Resource allocation checking
**Example**: Memory, handle, or other resource exhaustion

## Error Handling Guidelines

### Error Checking Pattern
```cpp
NTSTATUS PerformOperation() {
    NTSTATUS status = STATUS_SUCCESS;
    
    // Perform operation
    status = SomeFrameworkFunction();
    if (!NT_SUCCESS(status)) {
        DebugPrint("Operation failed: 0x%X\n", status);
        return status;
    }
    
    // Additional operations...
    return STATUS_SUCCESS;
}
```

### Error Recovery
```cpp
NTSTATUS HandleError(NTSTATUS errorCode) {
    switch (errorCode) {
        case STATUS_IRPMONITOR_HOOK_FAILED:
            // Attempt recovery
            return AttemptRecovery();
            
        case STATUS_MEMORY_ALLOCATION_FAILED:
            // Free resources and retry
            FreeResources();
            return RetryOperation();
            
        default:
            // Log and propagate error
            LogError(errorCode);
            return errorCode;
    }
}
```

### Error Logging
```cpp
VOID LogFrameworkError(NTSTATUS errorCode, PCSTR functionName) {
    CHAR errorText[256];
    
    // Convert error code to text
    GetLastErrorText(errorText, sizeof(errorText), errorCode);
    
    // Log error
    DebugPrint("[ERROR] %s failed: %s (0x%X)\n", 
               functionName, errorText, errorCode);
    
    // Optionally log to system event log
    LogEvent(EVENT_ID_FRAMEWORK_ERROR, EVENTLOG_ERROR_TYPE, errorText);
}
```

## Error Code Utilities

### Error Code to Text Conversion
```cpp
NTSTATUS GetErrorCodeText(
    _Out_writes_z_(BufferSize) PWSTR Buffer,
    _In_ SIZE_T BufferSize,
    _In_ NTSTATUS Status
) {
    if (!Buffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Framework-specific errors
    switch (Status) {
        case STATUS_IRPMONITOR_INIT_FAILED:
            wcscpy_s(Buffer, BufferSize, L"IRP monitor initialization failed");
            break;
            
        case STATUS_BOOTANALYSIS_HOOK_FAILED:
            wcscpy_s(Buffer, BufferSize, L"Boot entry point hook failed");
            break;
            
        // ... other framework errors
            
        default:
            // System errors
            return RtlNtStatusToDosError(Status);
    }
    
    return STATUS_SUCCESS;
}
```

### Error Code Validation
```cpp
BOOLEAN IsFrameworkError(NTSTATUS errorCode) {
    // Check if error is in framework range
    return (errorCode >= 0xC7FF0000 && errorCode <= 0xC7FFFFFF);
}

BOOLEAN IsRecoverableError(NTSTATUS errorCode) {
    // Determine if error is recoverable
    switch (errorCode) {
        case STATUS_MEMORY_ALLOCATION_FAILED:
        case STATUS_BUFFER_TOO_SMALL:
        case STATUS_PENDING:
            return TRUE;
            
        case STATUS_ACCESS_DENIED:
        case STATUS_NOT_SUPPORTED:
        case STATUS_INVALID_PARAMETER:
            return FALSE;
            
        default:
            return FALSE;
    }
}
```

## Debugging Error Codes

### Using WinDbg for Error Analysis
```windbg
# Convert error code to text
!error 0xC7FF0101

# Examine error context
!analyze -v

# Check last error
!gle
```

### Error Tracing
Enable error tracing in framework:
```cpp
#define ERROR_TRACING_ENABLED 1

#if ERROR_TRACING_ENABLED
#define TRACE_ERROR(status, function) \
    DebugPrint("[TRACE] %s returned 0x%X at %s:%d\n", \
               function, status, __FILE__, __LINE__)
#else
#define TRACE_ERROR(status, function)
#endif
```

## Common Error Scenarios

### Scenario 1: Driver Load Failure
**Symptoms**: Driver fails to load, system logs show error
**Common Error Codes**:
- `STATUS_IRPMONITOR_INIT_FAILED`
- `STATUS_INSUFFICIENT_RESOURCES`
- `STATUS_ACCESS_DENIED`

**Debugging Steps**:
1. Check Event Viewer for detailed error
2. Verify driver signing and test signing
3. Check system resource availability
4. Review driver initialization code

### Scenario 2: IRP Processing Failure
**Symptoms**: IRP not processed, system hang
**Common Error Codes**:
- `STATUS_IRPMONITOR_HOOK_FAILED`
- `STATUS_INVALID_PARAMETER`
- `STATUS_NOT_SUPPORTED`

**Debugging Steps**:
1. Set breakpoints on IRP handlers
2. Examine IRP parameters
3. Check device attachment status
4. Verify hook installation

### Scenario 3: Memory Issues
**Symptoms**: System crashes, pool corruption
**Common Error Codes**:
- `STATUS_MEMORY_ALLOCATION_FAILED`
- `STATUS_MEMORY_INTEGRITY_FAILED`
- `STATUS_INSUFFICIENT_RESOURCES`

**Debugging Steps**:
1. Enable pool tagging
2. Monitor pool usage
3. Check for memory leaks
4. Verify memory protection

## Error Code Reference Tables

### Severity Levels
| Severity | Value | Description |
|----------|-------|-------------|
| Success | 0 | Operation completed successfully |
| Information | 1 | Informational message |
| Warning | 2 | Warning condition |
| Error | 3 | Error condition |

### Facility Codes
| Facility | Value | Description |
|----------|-------|-------------|
| System | 0x0 | Windows system errors |
| Framework | 0x7FF | Bootkit Analysis Framework |
| Custom | 0xFFF | Other custom facilities |

### Common Code Ranges
| Component | Range | Description |
|-----------|-------|-------------|
| IRP Monitor | 0x1000-0x1FFF | IRP monitoring errors |
| Boot Analysis | 0x2000-0x2FFF | Boot process errors |
| Evasion Engine | 0x3000-0x3FFF | Evasion technique errors |
| Process Concealment | 0x4000-0x4FFF | Process hiding errors |
| Data Exfiltration | 0x5000-0x5FFF | Data transmission errors |
| Memory Management | 0x6000-0x6FFF | Memory operation errors |

## Conclusion

This error codes reference provides comprehensive documentation for all error conditions in the Bootkit Analysis Framework. Use this reference to understand, handle, and debug framework errors effectively.

For additional information, refer to:
- [API Reference Documentation](API_REFERENCE_KERNEL.md)
- [Kernel Debugging Guide](KERNEL_DEBUGGING_GUIDE.md)
- [Build and Compilation Guide](BUILD_GUIDE.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This error codes reference is for legitimate security research and educational purposes only. Always obtain proper authorization before using this framework and follow all applicable laws and regulations.