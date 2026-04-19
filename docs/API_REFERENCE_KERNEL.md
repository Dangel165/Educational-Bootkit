# Kernel-Mode API Reference

## Overview

This document provides comprehensive API reference documentation for the kernel-mode components of the Bootkit Analysis Framework. All APIs are implemented in C++ and designed for Windows kernel driver development.

## API Organization

### 1. IRP Dispatcher Monitor API
### 2. Boot Flow Interceptor API
### 3. Evasion Engine API
### 4. Process Concealment Engine API
### 5. Discord Webhook Manager API
### 6. Common Utilities API

## 1. IRP Dispatcher Monitor API

### Data Structures

#### IRP_MONITORING_CONTEXT
```cpp
typedef struct _IRP_MONITORING_CONTEXT {
    PDEVICE_OBJECT DeviceObject;           // Associated device object
    PDRIVER_OBJECT DriverObject;           // Associated driver object
    FAST_MUTEX IrpLock;                    // Synchronization lock
    LIST_ENTRY HookedIrpList;              // List of installed hooks
    ULONG HookCount;                       // Number of active hooks
    BOOLEAN MonitoringActive;              // Monitoring status
    PVOID OriginalReadHandler;             // Original IRP_MJ_READ handler
    PVOID OriginalDirectoryHandler;        // Original IRP_MJ_DIRECTORY_CONTROL handler
    PVOID CompletionRoutineHook;           // Completion routine hook
    ULONG64 DispatchTableBase;             // Base address of dispatch table
    ULONG DispatchTableSize;               // Size of dispatch table
    BOOLEAN DispatchTableScanned;          // Scan completion status
    ULONG DetectedModifications;           // Number of detected modifications
} IRP_MONITORING_CONTEXT, *PIRP_MONITORING_CONTEXT;
```

#### IRP_HOOK_ENTRY
```cpp
typedef struct _IRP_HOOK_ENTRY {
    LIST_ENTRY ListEntry;                  // List entry for hook management
    ULONG MajorFunction;                   // IRP major function code
    PVOID OriginalHandler;                 // Original handler address
    PVOID HookHandler;                     // Hook handler address
    ULONG HookFlags;                       // Hook configuration flags
    ULONG64 HookTime;                      // Hook installation timestamp
    BOOLEAN Active;                        // Hook activation status
    WCHAR TargetDeviceName[64];            // Target device name
    PDEVICE_OBJECT TargetDevice;           // Target device object
} IRP_HOOK_ENTRY, *PIRP_HOOK_ENTRY;
```

### Function Reference

#### InitializeIrpMonitoring
```cpp
NTSTATUS InitializeIrpMonitoring(
    _In_ PDRIVER_OBJECT DriverObject,     // Driver object for monitoring
    _In_ PDEVICE_OBJECT DeviceObject      // Device object for monitoring
);
```
**Purpose**: Initializes IRP monitoring infrastructure
**Parameters**:
- `DriverObject`: Pointer to driver object
- `DeviceObject`: Pointer to device object
**Returns**: NTSTATUS success or error code
**Remarks**: Must be called before any monitoring operations

#### HookIrpMjRead
```cpp
NTSTATUS HookIrpMjRead(
    _In_ PDEVICE_OBJECT TargetDevice       // Target device for hooking
);
```
**Purpose**: Installs hook for IRP_MJ_READ operations
**Parameters**:
- `TargetDevice`: Device to monitor for read operations
**Returns**: NTSTATUS success or error code
**Remarks**: Requires test signing for kernel hooking

#### HookIrpMjDirectoryControl
```cpp
NTSTATUS HookIrpMjDirectoryControl(
    _In_ PDEVICE_OBJECT TargetDevice       // Target device for hooking
);
```
**Purpose**: Installs hook for IRP_MJ_DIRECTORY_CONTROL operations
**Parameters**:
- `TargetDevice`: Device to monitor for directory operations
**Returns**: NTSTATUS success or error code
**Remarks**: Used for file hiding analysis

#### ScanKernelMemoryForDispatchTableMods
```cpp
NTSTATUS ScanKernelMemoryForDispatchTableMods();
```
**Purpose**: Scans kernel memory for dispatch table modifications
**Parameters**: None
**Returns**: NTSTATUS success or error code
**Remarks**: Detects rootkit-style hooking techniques

#### EnableIrpMonitoring
```cpp
NTSTATUS EnableIrpMonitoring(
    _In_ BOOLEAN Enable                    // Enable or disable monitoring
);
```
**Purpose**: Enables or disables IRP monitoring
**Parameters**:
- `Enable`: TRUE to enable, FALSE to disable
**Returns**: NTSTATUS success or error code
**Remarks**: Can be called dynamically during operation

### IOCTL Interface

#### IOCTL Codes
```cpp
#define IOCTL_IRPMONITOR_ENABLE_MONITORING     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_DISABLE_MONITORING    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_STATISTICS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_RESET_STATISTICS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_SCAN_DISPATCH_TABLE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_MODIFICATIONS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

#### Usage Example
```cpp
// User-mode control of IRP monitoring
DeviceIoControl(
    hDevice,                            // Device handle
    IOCTL_IRPMONITOR_ENABLE_MONITORING, // Control code
    &enableFlag,                        // Input buffer
    sizeof(enableFlag),                 // Input buffer size
    NULL,                               // Output buffer
    0,                                  // Output buffer size
    &bytesReturned,                     // Bytes returned
    NULL                                // Overlapped structure
);
```

## 2. Boot Flow Interceptor API

### Data Structures

#### BOOT_ANALYSIS_CONTEXT
```cpp
typedef struct _BOOT_ANALYSIS_CONTEXT {
    ULONG64 WinloadBaseAddress;           // winload.efi base address
    ULONG64 NtoskrnlBaseAddress;           // ntoskrnl.exe base address
    ULONG BootPhase;                       // Current boot phase
    LIST_ENTRY LoadedModules;              // List of loaded modules
    FAST_MUTEX ModuleLock;                 // Module list synchronization
    BOOLEAN SecureBootEnabled;             // Secure Boot status
    UINT8 SecureBootHash[32];              // Secure Boot hash
    ULONG HookedEntryPoints;               // Number of hooked entry points
    PVOID OriginalEntryPoints[10];         // Original entry point addresses
} BOOT_ANALYSIS_CONTEXT, *PBOOT_ANALYSIS_CONTEXT;
```

### Function Reference

#### InitializeBootFlowInterceptor
```cpp
NTSTATUS InitializeBootFlowInterceptor(
    _In_ PDRIVER_OBJECT DriverObject      // Driver object for interceptor
);
```
**Purpose**: Initializes boot flow interception system
**Parameters**:
- `DriverObject`: Pointer to driver object
**Returns**: NTSTATUS success or error code
**Remarks**: Must be called during driver initialization

#### HookWinloadEntryPoints
```cpp
NTSTATUS HookWinloadEntryPoints(
    _In_ ULONG64 WinloadBase              // Base address of winload.efi
);
```
**Purpose**: Hooks winload.efi entry points for boot analysis
**Parameters**:
- `WinloadBase`: Base address of winload.efi
**Returns**: NTSTATUS success or error code
**Remarks**: Requires UEFI runtime services access

#### MonitorNtoskrnlInit
```cpp
NTSTATUS MonitorNtoskrnlInit(
    _In_ ULONG64 NtoskrnlBase             // Base address of ntoskrnl.exe
);
```
**Purpose**: Monitors ntoskrnl.exe initialization sequence
**Parameters**:
- `NtoskrnlBase`: Base address of ntoskrnl.exe
**Returns**: NTSTATUS success or error code
**Remarks**: Tracks kernel initialization phases

#### AnalyzeUEFIServices
```cpp
NTSTATUS AnalyzeUEFIServices();
```
**Purpose**: Analyzes UEFI boot and runtime services
**Parameters**: None
**Returns**: NTSTATUS success or error code
**Remarks**: Provides UEFI firmware security analysis

## 3. Evasion Engine API

### Data Structures

#### EVASION_DETECTION_STATE
```cpp
typedef struct _EVASION_DETECTION_STATE {
    BOOLEAN VirtualMachineDetected;        // VM detection status
    BOOLEAN SandboxDetected;               // Sandbox detection status
    BOOLEAN DebuggerDetected;              // Debugger detection status
    ULONG64 DetectionTime;                 // Time of detection
    ULONG EvasionTechniquesUsed;           // Evasion techniques applied
    BOOLEAN PolymorphicCodeActive;         // Polymorphic code status
    ULONG CodeMutationCount;               // Code mutation count
    BOOLEAN PackerActive;                  // Executable packer status
    UINT8 PackerSignature[64];             // Packer signature
} EVASION_DETECTION_STATE, *PEVASION_DETECTION_STATE;
```

### Function Reference

#### InitializeEvasionEngine
```cpp
NTSTATUS InitializeEvasionEngine(
    _In_ PDRIVER_OBJECT DriverObject      // Driver object for engine
);
```
**Purpose**: Initializes evasion engine components
**Parameters**:
- `DriverObject`: Pointer to driver object
**Returns**: NTSTATUS success or error code
**Remarks**: Sets up detection and evasion systems

#### DetectVirtualization
```cpp
NTSTATUS DetectVirtualization(
    _Out_ PEVASION_DETECTION_STATE DetectionState // Detection results
);
```
**Purpose**: Detects virtualization environments
**Parameters**:
- `DetectionState`: Pointer to detection state structure
**Returns**: NTSTATUS success or error code
**Remarks**: Detects VMware, VirtualBox, Hyper-V, QEMU

#### EvadeSandboxes
```cpp
NTSTATUS EvadeSandboxes(
    _In_ ULONG EvasionTechnique           // Evasion technique to apply
);
```
**Purpose**: Applies sandbox evasion techniques
**Parameters**:
- `EvasionTechnique`: Technique identifier
**Returns**: NTSTATUS success or error code
**Remarks**: Includes timing attacks and environment checks

#### DetectDebuggers
```cpp
NTSTATUS DetectDebuggers(
    _Out_ PEVASION_DETECTION_STATE DetectionState // Detection results
);
```
**Purpose**: Detects debugging environments
**Parameters**:
- `DetectionState`: Pointer to detection state structure
**Returns**: NTSTATUS success or error code
**Remarks**: Uses PEB checks and anti-debugging techniques

## 4. Process Concealment Engine API

### Data Structures

#### PROCESS_CONCEALMENT_CONTEXT
```cpp
typedef struct _PROCESS_CONCEALMENT_CONTEXT {
    ULONG ProcessID;                       // Process ID to conceal
    HANDLE ProcessHandle;                  // Process handle
    PEPROCESS ProcessObject;               // Process object pointer
    LIST_ENTRY OriginalProcessLinks;       // Original process list links
    BOOLEAN RemovedFromList;               // Removal status
    ULONG HiddenHandles;                   // Number of hidden handles
    LIST_ENTRY HiddenHandleList;           // List of hidden handles
    BOOLEAN DLLsHidden;                    // DLL hiding status
    LIST_ENTRY HiddenDLLList;              // List of hidden DLLs
    BOOLEAN ThreadsHidden;                 // Thread hiding status
    LIST_ENTRY HiddenThreadList;           // List of hidden threads
} PROCESS_CONCEALMENT_CONTEXT, *PPROCESS_CONCEALMENT_CONTEXT;
```

### Function Reference

#### InitializeProcessConcealment
```cpp
NTSTATUS InitializeProcessConcealment(
    _In_ PDRIVER_OBJECT DriverObject      // Driver object for concealment
);
```
**Purpose**: Initializes process concealment engine
**Parameters**:
- `DriverObject`: Pointer to driver object
**Returns**: NTSTATUS success or error code
**Remarks**: Sets up DKOM and hiding mechanisms

#### ConcealProcess
```cpp
NTSTATUS ConcealProcess(
    _In_ ULONG ProcessID,                 // Process ID to conceal
    _Out_ PPROCESS_CONCEALMENT_CONTEXT Context // Concealment context
);
```
**Purpose**: Conceals a process using DKOM techniques
**Parameters**:
- `ProcessID`: ID of process to conceal
- `Context`: Pointer to concealment context structure
**Returns**: NTSTATUS success or error code
**Remarks**: Uses Direct Kernel Object Manipulation

#### HideProcessDLLs
```cpp
NTSTATUS HideProcessDLLs(
    _In_ PPROCESS_CONCEALMENT_CONTEXT Context, // Concealment context
    _In_ PCWSTR DllName                  // DLL name to hide (optional)
);
```
**Purpose**: Hides DLLs loaded by a process
**Parameters**:
- `Context`: Pointer to concealment context
- `DllName`: Specific DLL to hide (NULL for all)
**Returns**: NTSTATUS success or error code
**Remarks**: Manipulates module lists

#### RestoreProcessVisibility
```cpp
NTSTATUS RestoreProcessVisibility(
    _In_ PPROCESS_CONCEALMENT_CONTEXT Context // Concealment context
);
```
**Purpose**: Restores a concealed process to visibility
**Parameters**:
- `Context`: Pointer to concealment context
**Returns**: NTSTATUS success or error code
**Remarks**: Reverses DKOM modifications

## 5. Discord Webhook Manager API

### Data Structures

#### DISCORD_MESSAGE
```cpp
typedef struct _DISCORD_MESSAGE {
    CHAR Content[2000];                    // Message content
    CHAR Username[64];                     // Sender username
    CHAR AvatarUrl[256];                   // Avatar URL
    BOOLEAN TTS;                           // Text-to-speech flag
    ULONG EmbedCount;                      // Number of embeds
    PDISCORD_EMBED Embeds;                 // Array of embeds
} DISCORD_MESSAGE, *PDISCORD_MESSAGE;
```

#### WEBHOOK_RESPONSE
```cpp
typedef struct _WEBHOOK_RESPONSE {
    ULONG StatusCode;                      // HTTP status code
    CHAR ResponseBody[4096];               // Response body
    BOOLEAN RateLimited;                   // Rate limiting status
    ULONG RetryAfter;                      // Retry after seconds
    ULONG64 ResponseTime;                  // Response timestamp
} WEBHOOK_RESPONSE, *PWEBHOOK_RESPONSE;
```

### Function Reference

#### InitializeDiscordWebhookManager
```cpp
NTSTATUS InitializeDiscordWebhookManager(
    _In_ PCHAR WebhookUrl,                // Discord webhook URL
    _In_ BOOLEAN EnableSSL,               // Enable SSL/TLS
    _In_ BOOLEAN EnableDebug               // Enable debug output
);
```
**Purpose**: Initializes Discord webhook manager
**Parameters**:
- `WebhookUrl`: Discord webhook URL
- `EnableSSL`: Enable SSL/TLS encryption
- `EnableDebug`: Enable debug output
**Returns**: NTSTATUS success or error code
**Remarks**: Validates URL and sets up HTTP client

#### SendDiscordMessage
```cpp
NTSTATUS SendDiscordMessage(
    _In_ PDISCORD_MESSAGE Message,        // Message to send
    _Out_ PWEBHOOK_RESPONSE Response      // Response from webhook
);
```
**Purpose**: Sends message to Discord webhook
**Parameters**:
- `Message`: Pointer to message structure
- `Response`: Pointer to response structure
**Returns**: NTSTATUS success or error code
**Remarks**: Handles rate limiting and retries

#### AnalyzeWebhookUrl
```cpp
NTSTATUS AnalyzeWebhookUrl(
    _In_ PCHAR Url,                       // URL to analyze
    _Out_ PWEBHOOK_VALIDATION Validation  // Validation results
);
```
**Purpose**: Analyzes Discord webhook URL
**Parameters**:
- `Url`: URL to analyze
- `Validation`: Pointer to validation structure
**Returns**: NTSTATUS success or error code
**Remarks**: Validates format and security

## 6. Common Utilities API

### Memory Management

#### SafeAllocatePool
```cpp
PVOID SafeAllocatePool(
    _In_ POOL_TYPE PoolType,              // Pool type
    _In_ SIZE_T NumberOfBytes,            // Number of bytes to allocate
    _In_ ULONG Tag                         // Pool tag for tracking
);
```
**Purpose**: Safely allocates kernel pool memory
**Parameters**:
- `PoolType`: Type of pool (Paged, NonPaged)
- `NumberOfBytes`: Size of allocation
- `Tag`: 4-character pool tag
**Returns**: Pointer to allocated memory or NULL
**Remarks**: Includes overflow checking

#### SafeFreePool
```cpp
VOID SafeFreePool(
    _In_ PVOID Pointer,                   // Pointer to free
    _In_ ULONG Tag                         // Pool tag for verification
);
```
**Purpose**: Safely frees kernel pool memory
**Parameters**:
- `Pointer`: Pointer to free
- `Tag`: Expected pool tag
**Remarks**: Verifies pool tag before freeing

### String Utilities

#### SafeCopyString
```cpp
NTSTATUS SafeCopyString(
    _Out_writes_z_(DestSize) PWCHAR Dest, // Destination buffer
    _In_ PCWSTR Source,                   // Source string
    _In_ SIZE_T DestSize                  // Destination buffer size
);
```
**Purpose**: Safely copies string with bounds checking
**Parameters**:
- `Dest`: Destination buffer
- `Source`: Source string
- `DestSize`: Size of destination buffer
**Returns**: NTSTATUS success or error code
**Remarks**: Ensures null termination

#### ConvertAnsiToUnicode
```cpp
NTSTATUS ConvertAnsiToUnicode(
    _Out_ PUNICODE_STRING UnicodeString,  // Unicode string output
    _In_ PCSTR AnsiString                  // ANSI string input
);
```
**Purpose**: Converts ANSI string to Unicode
**Parameters**:
- `UnicodeString`: Output Unicode string
- `AnsiString`: Input ANSI string
**Returns**: NTSTATUS success or error code
**Remarks**: Allocates memory for Unicode string

### Logging and Debugging

#### DebugPrint
```cpp
VOID DebugPrint(
    _In_ PCSTR Format,                    // Format string
    ...                                   // Variable arguments
);
```
**Purpose**: Outputs debug message
**Parameters**:
- `Format`: printf-style format string
- `...`: Variable arguments
**Remarks**: Only active in debug builds

#### LogEvent
```cpp
NTSTATUS LogEvent(
    _In_ ULONG EventId,                   // Event ID
    _In_ ULONG EventType,                 // Event type
    _In_ PCWSTR Message                   // Event message
);
```
**Purpose**: Logs system event
**Parameters**:
- `EventId`: Unique event identifier
- `EventType`: Type of event (Error, Warning, Information)
- `Message`: Event message
**Returns**: NTSTATUS success or error code
**Remarks**: Uses Windows Event Logging

## Error Handling

### Common Error Codes

#### Success Codes
- `STATUS_SUCCESS` (0x00000000): Operation successful
- `STATUS_PENDING` (0x00000103): Operation pending completion

#### Error Codes
- `STATUS_INVALID_PARAMETER` (0xC000000D): Invalid parameter
- `STATUS_BUFFER_TOO_SMALL` (0xC0000023): Buffer too small
- `STATUS_ACCESS_DENIED` (0xC0000022): Access denied
- `STATUS_NOT_SUPPORTED` (0xC00000BB): Operation not supported
- `STATUS_INSUFFICIENT_RESOURCES` (0xC000009A): Insufficient resources

### Error Handling Functions

#### GetLastErrorText
```cpp
NTSTATUS GetLastErrorText(
    _Out_writes_z_(BufferSize) PWSTR Buffer, // Error text buffer
    _In_ SIZE_T BufferSize,                   // Buffer size
    _In_ NTSTATUS Status                       // Status code
);
```
**Purpose**: Converts NTSTATUS to human-readable text
**Parameters**:
- `Buffer`: Output buffer for error text
- `BufferSize`: Size of output buffer
- `Status`: NTSTATUS code to convert
**Returns**: NTSTATUS success or error code

## Security Considerations

### Input Validation
All API functions validate input parameters to prevent:
- Buffer overflows
- Integer overflows
- Null pointer dereferences
- Invalid memory access

### Access Control
APIs implement proper access control checks:
- Privilege verification
- Security context validation
- Resource ownership checks

### Memory Safety
APIs ensure memory safety through:
- Bounds checking
- Pool tagging
- Reference counting
- Safe memory operations

## Usage Examples

### Example 1: IRP Monitoring
```cpp
// Initialize IRP monitoring
NTSTATUS status = InitializeIrpMonitoring(DriverObject, DeviceObject);
if (!NT_SUCCESS(status)) {
    DebugPrint("Failed to initialize IRP monitoring: 0x%X\n", status);
    return status;
}

// Hook IRP_MJ_READ
status = HookIrpMjRead(TargetDevice);
if (!NT_SUCCESS(status)) {
    DebugPrint("Failed to hook IRP_MJ_READ: 0x%X\n", status);
}

// Enable monitoring
status = EnableIrpMonitoring(TRUE);
```

### Example 2: Evasion Detection
```cpp
// Initialize evasion engine
NTSTATUS status = InitializeEvasionEngine(DriverObject);
if (!NT_SUCCESS(status)) {
    return status;
}

// Detect virtualization
EVASION_DETECTION_STATE detectionState;
status = DetectVirtualization(&detectionState);
if (detectionState.VirtualMachineDetected) {
    DebugPrint("Virtual machine detected\n");
}

// Apply evasion if needed
if (detectionState.SandboxDetected) {
    status = EvadeSandboxes(EVASION_TECHNIQUE_TIMING);
}
```

### Example 3: Process Concealment
```cpp
// Initialize process concealment
NTSTATUS status = InitializeProcessConcealment(DriverObject);
if (!NT_SUCCESS(status)) {
    return status;
}

// Conceal specific process
PROCESS_CONCEALMENT_CONTEXT context;
status = ConcealProcess(1234, &context);
if (NT_SUCCESS(status)) {
    DebugPrint("Process concealed successfully\n");
}

// Hide process DLLs
status = HideProcessDLLs(&context, L"malicious.dll");
```

## API Versioning

### Version Information
- **API Version**: 1.0.0
- **Compatibility**: Windows 10/11, WDK
- **Last Updated**: [Current Date]

### Backward Compatibility
APIs maintain backward compatibility through:
- Versioned interfaces
- Deprecation warnings
- Compatibility layers
- Migration guides

## Conclusion

This API reference provides comprehensive documentation for the kernel-mode components of the Bootkit Analysis Framework. Use these APIs to implement, extend, and integrate framework components for legitimate security research purposes.

For additional information, refer to:
- [Build and Compilation Guide](BUILD_GUIDE.md)
- [Visual Studio Solution Documentation](VISUAL_STUDIO_SOLUTION.md)
- [Kernel Debugging Guide](KERNEL_DEBUGGING_GUIDE.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

These APIs are for legitimate security research and educational purposes only. Always obtain proper authorization before using these APIs and follow all applicable laws and regulations.