// Debug.cpp: Debug and logging implementation file

#include "pch.h"

// Global debug context
typedef struct _DEBUG_CONTEXT {
    FAST_MUTEX DebugLock;
    ULONG TotalLogEntries;
    ULONG ErrorLogEntries;
    ULONG WarningLogEntries;
    ULONG InfoLogEntries;
    ULONG TraceLogEntries;
    BOOLEAN DebugInitialized;
    BOOLEAN LoggingEnabled;
    ULONG DebugLevel;
} DEBUG_CONTEXT, *PDEBUG_CONTEXT;

DEBUG_CONTEXT g_DebugContext = { 0 };

// Initialize debug module
NTSTATUS InitializeDebug()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Initializing debug module");
    
    // Initialize fast mutex
    ExInitializeFastMutex(&g_DebugContext.DebugLock);
    
    // Reset counters
    g_DebugContext.TotalLogEntries = 0;
    g_DebugContext.ErrorLogEntries = 0;
    g_DebugContext.WarningLogEntries = 0;
    g_DebugContext.InfoLogEntries = 0;
    g_DebugContext.TraceLogEntries = 0;
    
    // Set default configuration
    g_DebugContext.LoggingEnabled = TRUE;
    g_DebugContext.DebugLevel = DPFLTR_INFO_LEVEL; // Default to info level
    
    // Mark as initialized
    g_DebugContext.DebugInitialized = TRUE;
    
    LOG_TRACE("Debug module initialized successfully");
    return status;
}

// Clean up debug module
VOID CleanupDebug()
{
    LOG_TRACE("Cleaning up debug module");
    
    // Print final statistics
    PrintDebugStatistics();
    
    // Clear context
    RtlZeroMemory(&g_DebugContext, sizeof(g_DebugContext));
    
    LOG_TRACE("Debug module cleaned up");
}

// Print debug statistics
VOID PrintDebugStatistics()
{
    LOG_INFO("=== Debug Statistics ===");
    LOG_INFO("Total log entries: %lu", g_DebugContext.TotalLogEntries);
    LOG_INFO("Error log entries: %lu", g_DebugContext.ErrorLogEntries);
    LOG_INFO("Warning log entries: %lu", g_DebugContext.WarningLogEntries);
    LOG_INFO("Info log entries: %lu", g_DebugContext.InfoLogEntries);
    LOG_INFO("Trace log entries: %lu", g_DebugContext.TraceLogEntries);
    LOG_INFO("Logging enabled: %s", g_DebugContext.LoggingEnabled ? "Yes" : "No");
    LOG_INFO("Debug level: %lu", g_DebugContext.DebugLevel);
    LOG_INFO("========================");
}

// Enable or disable logging
NTSTATUS SetLoggingEnabled(_In_ BOOLEAN Enabled)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Setting logging enabled: %s", Enabled ? "Yes" : "No");
    
    ExAcquireFastMutex(&g_DebugContext.DebugLock);
    g_DebugContext.LoggingEnabled = Enabled;
    ExReleaseFastMutex(&g_DebugContext.DebugLock);
    
    return status;
}

// Set debug level
NTSTATUS SetDebugLevel(_In_ ULONG Level)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Setting debug level: %lu", Level);
    
    // Validate level
    if (Level > DPFLTR_TRACE_LEVEL) {
        status = STATUS_INVALID_PARAMETER;
        LOG_ERROR("Invalid debug level: %lu", Level);
        return status;
    }
    
    ExAcquireFastMutex(&g_DebugContext.DebugLock);
    g_DebugContext.DebugLevel = Level;
    ExReleaseFastMutex(&g_DebugContext.DebugLock);
    
    return status;
}

// Get debug statistics
NTSTATUS GetDebugStatistics(
    _Out_ PULONG TotalLogEntries,
    _Out_ PULONG ErrorLogEntries,
    _Out_ PULONG WarningLogEntries,
    _Out_ PULONG InfoLogEntries,
    _Out_ PULONG TraceLogEntries
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Getting debug statistics");
    
    ExAcquireFastMutex(&g_DebugContext.DebugLock);
    
    if (TotalLogEntries != NULL) {
        *TotalLogEntries = g_DebugContext.TotalLogEntries;
    }
    
    if (ErrorLogEntries != NULL) {
        *ErrorLogEntries = g_DebugContext.ErrorLogEntries;
    }
    
    if (WarningLogEntries != NULL) {
        *WarningLogEntries = g_DebugContext.WarningLogEntries;
    }
    
    if (InfoLogEntries != NULL) {
        *InfoLogEntries = g_DebugContext.InfoLogEntries;
    }
    
    if (TraceLogEntries != NULL) {
        *TraceLogEntries = g_DebugContext.TraceLogEntries;
    }
    
    ExReleaseFastMutex(&g_DebugContext.DebugLock);
    
    return status;
}

// Internal logging function
VOID InternalLogMessage(
    _In_ ULONG Level,
    _In_ PCSTR Format,
    _In_ ...
)
{
    va_list args;
    CHAR buffer[512] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    
    // Check if logging is enabled
    ExAcquireFastMutex(&g_DebugContext.DebugLock);
    BOOLEAN loggingEnabled = g_DebugContext.LoggingEnabled;
    ULONG debugLevel = g_DebugContext.DebugLevel;
    ExReleaseFastMutex(&g_DebugContext.DebugLock);
    
    if (!loggingEnabled || Level > debugLevel) {
        return;
    }
    
    // Format the message
    va_start(args, Format);
    status = RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);
    
    if (!NT_SUCCESS(status)) {
        // Truncation occurred, but we'll still log what we have
        buffer[sizeof(buffer) - 1] = '\0';
    }
    
    // Log the message
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, "[BootkitDriver] %s", buffer);
    
    // Update statistics
    ExAcquireFastMutex(&g_DebugContext.DebugLock);
    g_DebugContext.TotalLogEntries++;
    
    switch (Level) {
        case DPFLTR_ERROR_LEVEL:
            g_DebugContext.ErrorLogEntries++;
            break;
            
        case DPFLTR_WARNING_LEVEL:
            g_DebugContext.WarningLogEntries++;
            break;
            
        case DPFLTR_INFO_LEVEL:
            g_DebugContext.InfoLogEntries++;
            break;
            
        case DPFLTR_TRACE_LEVEL:
            g_DebugContext.TraceLogEntries++;
            break;
    }
    
    ExReleaseFastMutex(&g_DebugContext.DebugLock);
}

// Log formatted error message
VOID LogError(_In_ PCSTR Format, ...)
{
    va_list args;
    CHAR buffer[512] = { 0 };
    
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);
    
    InternalLogMessage(DPFLTR_ERROR_LEVEL, "ERROR: %s", buffer);
}

// Log formatted warning message
VOID LogWarning(_In_ PCSTR Format, ...)
{
    va_list args;
    CHAR buffer[512] = { 0 };
    
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);
    
    InternalLogMessage(DPFLTR_WARNING_LEVEL, "WARNING: %s", buffer);
}

// Log formatted info message
VOID LogInfo(_In_ PCSTR Format, ...)
{
    va_list args;
    CHAR buffer[512] = { 0 };
    
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);
    
    InternalLogMessage(DPFLTR_INFO_LEVEL, "INFO: %s", buffer);
}

// Log formatted trace message
VOID LogTrace(_In_ PCSTR Format, ...)
{
    va_list args;
    CHAR buffer[512] = { 0 };
    
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);
    
    InternalLogMessage(DPFLTR_TRACE_LEVEL, "TRACE: %s", buffer);
}

// Dump memory contents
VOID DumpMemory(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ PCSTR Description
)
{
    PUCHAR buffer = (PUCHAR)Address;
    CHAR line[80] = { 0 };
    CHAR ascii[17] = { 0 };
    ULONG i, j;
    
    if (Description != NULL) {
        LogInfo("Memory dump: %s", Description);
    }
    
    LogInfo("Address: 0x%p, Length: %lu bytes", Address, Length);
    
    for (i = 0; i < Length; i += 16) {
        // Clear buffers
        RtlZeroMemory(line, sizeof(line));
        RtlZeroMemory(ascii, sizeof(ascii));
        
        // Format hex values
        for (j = 0; j < 16; j++) {
            if (i + j < Length) {
                // Add hex byte
                RtlStringCbPrintfA(line + (j * 3), sizeof(line) - (j * 3), "%02X ", buffer[i + j]);
                
                // Add ASCII character
                if (buffer[i + j] >= 32 && buffer[i + j] <= 126) {
                    ascii[j] = buffer[i + j];
                } else {
                    ascii[j] = '.';
                }
            } else {
                RtlStringCbPrintfA(line + (j * 3), sizeof(line) - (j * 3), "   ");
                ascii[j] = ' ';
            }
        }
        
        ascii[16] = '\0';
        LogInfo("  %04lX: %s %s", i, line, ascii);
    }
}

// Dump IRP information
VOID DumpIrpInfo(
    _In_ PIRP Irp,
    _In_ PCSTR Description
)
{
    PIO_STACK_LOCATION ioStackLocation = NULL;
    
    if (Description != NULL) {
        LogInfo("IRP dump: %s", Description);
    }
    
    if (Irp == NULL) {
        LogWarning("IRP is NULL");
        return;
    }
    
    LogInfo("IRP: 0x%p", Irp);
    LogInfo("  Flags: 0x%08X", Irp->Flags);
    LogInfo("  Status: 0x%08X", Irp->IoStatus.Status);
    LogInfo("  Information: 0x%p", (PVOID)Irp->IoStatus.Information);
    LogInfo("  RequestorMode: %s", 
            Irp->RequestorMode == KernelMode ? "KernelMode" : "UserMode");
    
    // Get current stack location
    ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
    if (ioStackLocation != NULL) {
        LogInfo("  MajorFunction: 0x%02X", ioStackLocation->MajorFunction);
        LogInfo("  MinorFunction: 0x%02X", ioStackLocation->MinorFunction);
        
        // Dump parameters based on major function
        switch (ioStackLocation->MajorFunction) {
            case IRP_MJ_READ:
                LogInfo("  Parameters.Read.Length: %lu", 
                        ioStackLocation->Parameters.Read.Length);
                LogInfo("  Parameters.Read.Key: 0x%08X", 
                        ioStackLocation->Parameters.Read.Key);
                LogInfo("  Parameters.Read.ByteOffset: 0x%016llX", 
                        ioStackLocation->Parameters.Read.ByteOffset.QuadPart);
                break;
                
            case IRP_MJ_WRITE:
                LogInfo("  Parameters.Write.Length: %lu", 
                        ioStackLocation->Parameters.Write.Length);
                LogInfo("  Parameters.Write.Key: 0x%08X", 
                        ioStackLocation->Parameters.Write.Key);
                LogInfo("  Parameters.Write.ByteOffset: 0x%016llX", 
                        ioStackLocation->Parameters.Write.ByteOffset.QuadPart);
                break;
                
            case IRP_MJ_DEVICE_CONTROL:
                LogInfo("  Parameters.DeviceIoControl.IoControlCode: 0x%08X", 
                        ioStackLocation->Parameters.DeviceIoControl.IoControlCode);
                LogInfo("  Parameters.DeviceIoControl.InputBufferLength: %lu", 
                        ioStackLocation->Parameters.DeviceIoControl.InputBufferLength);
                LogInfo("  Parameters.DeviceIoControl.OutputBufferLength: %lu", 
                        ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
                break;
        }
    }
}

// Dump device object information
VOID DumpDeviceObjectInfo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCSTR Description
)
{
    if (Description != NULL) {
        LogInfo("Device object dump: %s", Description);
    }
    
    if (DeviceObject == NULL) {
        LogWarning("Device object is NULL");
        return;
    }
    
    LogInfo("DeviceObject: 0x%p", DeviceObject);
    LogInfo("  DeviceType: 0x%08X", DeviceObject->DeviceType);
    LogInfo("  Size: %lu", DeviceObject->Size);
    LogInfo("  ReferenceCount: %ld", DeviceObject->ReferenceCount);
    LogInfo("  Flags: 0x%08X", DeviceObject->Flags);
    LogInfo("  Characteristics: 0x%08X", DeviceObject->Characteristics);
    LogInfo("  StackSize: %lu", DeviceObject->StackSize);
    LogInfo("  AlignmentRequirement: %lu", DeviceObject->AlignmentRequirement);
    
    if (DeviceObject->DeviceExtension != NULL) {
        LogInfo("  DeviceExtension: 0x%p", DeviceObject->DeviceExtension);
    }
    
    if (DeviceObject->DriverObject != NULL) {
        LogInfo("  DriverObject: 0x%p", DeviceObject->DriverObject);
    }
    
    if (DeviceObject->NextDevice != NULL) {
        LogInfo("  NextDevice: 0x%p", DeviceObject->NextDevice);
    }
}

// Dump driver object information
VOID DumpDriverObjectInfo(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCSTR Description
)
{
    if (Description != NULL) {
        LogInfo("Driver object dump: %s", Description);
    }
    
    if (DriverObject == NULL) {
        LogWarning("Driver object is NULL");
        return;
    }
    
    LogInfo("DriverObject: 0x%p", DriverObject);
    LogInfo("  DriverStart: 0x%p", DriverObject->DriverStart);
    LogInfo("  DriverSize: %lu", DriverObject->DriverSize);
    LogInfo("  DriverName: %wZ", DriverObject->DriverName);
    LogInfo("  HardwareDatabase: %wZ", DriverObject->HardwareDatabase);
    LogInfo("  FastIoDispatch: 0x%p", DriverObject->FastIoDispatch);
    
    // Dump major function pointers
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (DriverObject->MajorFunction[i] != NULL) {
            LogInfo("  MajorFunction[%d]: 0x%p", i, DriverObject->MajorFunction[i]);
        }
    }
}

// Check if debugger is present
BOOLEAN IsDebuggerPresent()
{
    BOOLEAN debuggerPresent = FALSE;
    
    // Check via PEB
    __try {
        PPEB peb = PsGetCurrentProcess()->Peb;
        if (peb != NULL) {
            debuggerPresent = peb->BeingDebugged;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        debuggerPresent = FALSE;
    }
    
    return debuggerPresent;
}

// Break into debugger if present
VOID BreakIfDebuggerPresent()
{
    if (IsDebuggerPresent()) {
        DbgBreakPoint();
    }
}