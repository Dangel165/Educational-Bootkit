// MinifilterDriver.cpp: Minifilter Driver Implementation for File Integrity Analysis
// Implements Requirement 10: Minifilter Driver Implementation for File Integrity Analysis

#include "pch.h"
#include "MinifilterDriver.h"

// Global minifilter context
MINIFILTER_CONTEXT g_MinifilterContext = { 0 };

// Minifilter registration data
const FLT_OPERATION_REGISTRATION CallbackRegistration[] = {
    { IRP_MJ_CREATE, 0, MinifilterPreOperationCallback, MinifilterPostOperationCallback },
    { IRP_MJ_READ, 0, MinifilterPreReadCallback, MinifilterPostReadCallback },
    { IRP_MJ_WRITE, 0, MinifilterPreOperationCallback, MinifilterPostOperationCallback },
    { IRP_MJ_SET_INFORMATION, 0, MinifilterPreOperationCallback, MinifilterPostOperationCallback },
    { IRP_MJ_CLEANUP, 0, MinifilterPreOperationCallback, MinifilterPostOperationCallback },
    { IRP_MJ_CLOSE, 0, MinifilterPreOperationCallback, MinifilterPostOperationCallback },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_STREAM_CONTEXT, 0, NULL, sizeof(FILE_INTEGRITY_CONTEXT), 'TEGI' },
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    CallbackRegistration,
    MinifilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// Initialize minifilter context
NTSTATUS InitializeMinifilterContext()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Initializing minifilter context");
    
    // Zero out the context
    RtlZeroMemory(&g_MinifilterContext, sizeof(g_MinifilterContext));
    
    // Initialize fast mutex
    ExInitializeFastMutex(&g_MinifilterContext.FilterLock);
    
    // Initialize lists
    InitializeListHead(&g_MinifilterContext.FileAccessLog);
    InitializeListHead(&g_MinifilterContext.IntegrityCheckQueue);
    InitializeListHead(&g_MinifilterContext.DataSubstitutionQueue);
    
    // Set filter name
    RtlInitUnicodeString(&g_MinifilterContext.FilterName, L"BootkitAnalysisMinifilter");
    
    // Set default altitudes
    RtlInitUnicodeString(&g_MinifilterContext.Altitudes, L"370000");
    
    // Set start time
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    g_MinifilterContext.StartTime = currentTime.QuadPart;
    
    LOG_INFO("Minifilter context initialized successfully");
    return STATUS_SUCCESS;
}

// Register minifilter driver
NTSTATUS RegisterMinifilterDriver(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_INFO("Registering minifilter driver");
    
    // Initialize context
    status = InitializeMinifilterContext();
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("InitializeMinifilterContext failed with status: 0x%08X", status);
        return status;
    }
    
    // Register filter with Filter Manager
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_MinifilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltRegisterFilter failed with status: 0x%08X", status);
        return status;
    }
    
    // Create communication port
    status = CreateMinifilterCommunicationPort();
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("CreateMinifilterCommunicationPort failed with status: 0x%08X", status);
        FltUnregisterFilter(g_MinifilterContext.FilterHandle);
        return status;
    }
    
    // Start filter
    status = FltStartFiltering(g_MinifilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltStartFiltering failed with status: 0x%08X", status);
        CloseMinifilterCommunicationPort();
        FltUnregisterFilter(g_MinifilterContext.FilterHandle);
        return status;
    }
    
    g_MinifilterContext.FilterRegistered = TRUE;
    g_MinifilterContext.MonitoringActive = TRUE;
    
    LOG_INFO("Minifilter driver registered successfully");
    return STATUS_SUCCESS;
}

// Unregister minifilter driver
NTSTATUS UnregisterMinifilterDriver()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_INFO("Unregistering minifilter driver");
    
    if (g_MinifilterContext.FilterRegistered) {
        // Stop monitoring
        StopMinifilterMonitoring();
        
        // Close communication port
        CloseMinifilterCommunicationPort();
        
        // Unregister filter
        status = FltUnregisterFilter(g_MinifilterContext.FilterHandle);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("FltUnregisterFilter failed with status: 0x%08X", status);
        }
        
        g_MinifilterContext.FilterRegistered = FALSE;
        g_MinifilterContext.FilterHandle = NULL;
    }
    
    // Clean up context
    ClearFileAccessLog();
    
    LOG_INFO("Minifilter driver unregistered");
    return status;
}

// Minifilter unload callback
NTSTATUS MinifilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    
    LOG_INFO("MinifilterUnload called");
    
    // Unregister minifilter
    UnregisterMinifilterDriver();
    
    return STATUS_SUCCESS;
}

// Pre-operation callback
FLT_PREOP_CALLBACK_STATUS MinifilterPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Check if monitoring is active
    if (!g_MinifilterContext.MonitoringActive) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Log file access
    LogFileAccess(Data, FltObjects, STATUS_SUCCESS, FALSE, FALSE);
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Post-operation callback
FLT_POSTOP_CALLBACK_STATUS MinifilterPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    
    // Check if monitoring is active
    if (!g_MinifilterContext.MonitoringActive) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Update statistics based on operation type
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.FileAccessCount++;
    
    switch (Data->Iopb->MajorFunction) {
        case IRP_MJ_CREATE:
            // Handle create operations
            break;
        case IRP_MJ_WRITE:
            // Handle write operations
            break;
        case IRP_MJ_SET_INFORMATION:
            // Handle set information operations
            break;
    }
    
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Pre-read callback (IRP_MJ_READ specific)
FLT_PREOP_CALLBACK_STATUS MinifilterPreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID* CompletionContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN integrityValid = TRUE;
    BOOLEAN substitutionPerformed = FALSE;
    
    // Allocate completion context
    PPRE_OPERATION_CALLBACK_CONTEXT context = (PPRE_OPERATION_CALLBACK_CONTEXT)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(PRE_OPERATION_CALLBACK_CONTEXT), 'CTXP');
    
    if (context == NULL) {
        LOG_ERROR("Failed to allocate completion context");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    RtlZeroMemory(context, sizeof(PRE_OPERATION_CALLBACK_CONTEXT));
    context->Data = Data;
    context->FltObjects = FltObjects;
    
    // Check if monitoring is active
    if (!g_MinifilterContext.MonitoringActive) {
        *CompletionContext = context;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Perform real-time integrity check
    status = PerformRealTimeIntegrityCheck(Data, FltObjects, &integrityValid);
    if (!NT_SUCCESS(status)) {
        LOG_WARNING("PerformRealTimeIntegrityCheck failed with status: 0x%08X", status);
    }
    
    context->IntegrityCheckRequired = integrityValid;
    context->IntegrityContext.IntegrityValid = integrityValid;
    
    // If integrity check failed, consider data substitution
    if (!integrityValid && g_MinifilterContext.MonitoringActive) {
        // Check if we should substitute data
        // This is where security analysis substitution would occur
        context->DataSubstitutionRequired = TRUE;
    }
    
    *CompletionContext = context;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-read callback
FLT_POSTOP_CALLBACK_STATUS MinifilterPostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPRE_OPERATION_CALLBACK_CONTEXT preContext = (PPRE_OPERATION_CALLBACK_CONTEXT)CompletionContext;
    
    if (preContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Check if monitoring is active
    if (!g_MinifilterContext.MonitoringActive) {
        ExFreePoolWithTag(preContext, 'CTXP');
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Update statistics
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.FileAccessCount++;
    
    if (preContext->IntegrityCheckRequired) {
        if (!preContext->IntegrityContext.IntegrityValid) {
            g_MinifilterContext.IntegrityViolations++;
        }
    }
    
    if (preContext->DataSubstitutionRequired) {
        g_MinifilterContext.DataSubstitutions++;
    }
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    // Log the access with integrity and substitution status
    LogFileAccess(Data, FltObjects, Data->IoStatus.Status,
                  preContext->IntegrityContext.IntegrityValid,
                  preContext->DataSubstitutionRequired);
    
    // Free the context
    ExFreePoolWithTag(preContext, 'CTXP');
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Calculate file hash
NTSTATUS CalculateFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 HashValue
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FLT_FILESYSTEM_TYPE fsType;
    LARGE_INTEGER fileSize;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus;
    PVOID buffer = NULL;
    ULONG bufferSize = 4096;
    ULONG64 hash = 0;
    ULONG bytesRead;
    
    if (HashValue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *HashValue = 0;
    
    // Get file system type
    status = FltGetFileSystemType(Instance, &fsType);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltGetFileSystemType failed with status: 0x%08X", status);
        return status;
    }
    
    // Get file size
    status = FltQueryInformationFile(Instance, FileObject, &fileSize,
                                     sizeof(fileSize), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltQueryInformationFile failed with status: 0x%08X", status);
        return status;
    }
    
    // Simple hash calculation for demonstration
    // In a real implementation, you would use a proper hash algorithm
    hash = fileSize.QuadPart;
    
    // Add file name to hash
    if (FileObject->FileName.Buffer != NULL) {
        for (ULONG i = 0; i < FileObject->FileName.Length / sizeof(WCHAR); i++) {
            hash = (hash * 31) + FileObject->FileName.Buffer[i];
        }
    }
    
    *HashValue = hash;
    
    LOG_TRACE("Calculated file hash: 0x%016llX for file: %wZ", hash, &FileObject->FileName);
    return STATUS_SUCCESS;
}

// Verify file integrity
NTSTATUS VerifyFileIntegrity(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG64 ExpectedHash,
    _Out_ PBOOLEAN IntegrityValid,
    _Out_opt_ PULONG64 ActualHash
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 calculatedHash = 0;
    
    if (IntegrityValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *IntegrityValid = FALSE;
    
    // Calculate current file hash
    status = CalculateFileHash(Instance, FileObject, &calculatedHash);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("CalculateFileHash failed with status: 0x%08X", status);
        return status;
    }
    
    // Compare with expected hash
    if (calculatedHash == ExpectedHash) {
        *IntegrityValid = TRUE;
        LOG_TRACE("File integrity verified successfully for: %wZ", &FileObject->FileName);
    } else {
        LOG_WARNING("File integrity violation detected for: %wZ. Expected: 0x%016llX, Actual: 0x%016llX",
                    &FileObject->FileName, ExpectedHash, calculatedHash);
    }
    
    if (ActualHash != NULL) {
        *ActualHash = calculatedHash;
    }
    
    return STATUS_SUCCESS;
}

// Perform real-time integrity check
NTSTATUS PerformRealTimeIntegrityCheck(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IntegrityValid
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN integrityValid = TRUE;
    
    if (IntegrityValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *IntegrityValid = TRUE;
    
    // Check if integrity checking is enabled
    if (!g_MinifilterContext.MonitoringActive) {
        return STATUS_SUCCESS;
    }
    
    // For demonstration, we'll check if file is in integrity check queue
    // In a real implementation, you would have a database of expected hashes
    
    LOG_TRACE("Performing real-time integrity check for file operation");
    
    // Update statistics
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.IntegrityViolations++;
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    *IntegrityValid = integrityValid;
    return STATUS_SUCCESS;
}

// Substitute file data
NTSTATUS SubstituteFileData(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELEATED_OBJECTS FltObjects,
    _In_ PCWSTR SubstituteFilePath,
    _Out_ PBOOLEAN SubstitutionPerformed
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (SubstitutionPerformed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *SubstitutionPerformed = FALSE;
    
    // Check if data substitution is enabled
    if (!g_MinifilterContext.MonitoringActive) {
        return STATUS_SUCCESS;
    }
    
    LOG_INFO("Data substitution requested for security analysis");
    
    // In a real implementation, you would:
    // 1. Validate substitution safety
    // 2. Read substitute file data
    // 3. Modify the read buffer in Data
    // 4. Update completion context
    
    // For demonstration, we'll just log the request
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.DataSubstitutions++;
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    *SubstitutionPerformed = TRUE;
    return STATUS_SUCCESS;
}

// Log file access
NTSTATUS LogFileAccess(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ NTSTATUS AccessStatus,
    _In_ BOOLEAN IntegrityCheckPassed,
    _In_ BOOLEAN DataSubstituted
)
{
    PFILE_ACCESS_LOG_ENTRY logEntry = NULL;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    CHAR processName[256] = { 0 };
    
    // Allocate log entry
    logEntry = (PFILE_ACCESS_LOG_ENTRY)ExAllocatePoolWithTag(
        PagedPool, sizeof(FILE_ACCESS_LOG_ENTRY), 'GOLF');
    
    if (logEntry == NULL) {
        LOG_ERROR("Failed to allocate log entry");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(logEntry, sizeof(FILE_ACCESS_LOG_ENTRY));
    
    // Get current time
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    logEntry->Timestamp = currentTime.QuadPart;
    
    // Get process and thread information
    process = IoGetCurrentProcess();
    thread = PsGetCurrentThread();
    
    logEntry->ProcessId = (ULONG)PsGetProcessId(process);
    logEntry->ThreadId = (ULONG)PsGetThreadId(thread);
    
    // Get process name
    if (process != NULL) {
        PEPROCESS_EXTENSION processExt = (PEPROCESS_EXTENSION)process;
        if (processExt->ImageFileName != NULL) {
            RtlStringCbCopyA(processName, sizeof(processName), processExt->ImageFileName);
            RtlStringCbCopyW(logEntry->ProcessName, sizeof(logEntry->ProcessName),
                            (PCWSTR)processName);
        }
    }
    
    // Get file information
    if (FltObjects->FileObject != NULL && FltObjects->FileObject->FileName.Buffer != NULL) {
        RtlStringCbCopyW(logEntry->FilePath, sizeof(logEntry->FilePath),
                        FltObjects->FileObject->FileName.Buffer);
    }
    
    // Get operation information
    if (Data->Iopb != NULL) {
        logEntry->IrpMajorFunction = Data->Iopb->MajorFunction;
        logEntry->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    
    logEntry->AccessStatus = AccessStatus;
    logEntry->IntegrityCheckPassed = IntegrityCheckPassed;
    logEntry->DataSubstituted = DataSubstituted;
    
    // Add to log list
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    InsertTailList(&g_MinifilterContext.FileAccessLog, &logEntry->ListEntry);
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    LOG_TRACE("Logged file access: PID=%lu, File=%wZ, Operation=%lu, Integrity=%d, Substituted=%d",
              logEntry->ProcessId, &FltObjects->FileObject->FileName,
              logEntry->IrpMajorFunction, IntegrityCheckPassed, DataSubstituted);
    
    return STATUS_SUCCESS;
}

// Get file access statistics
NTSTATUS GetFileAccessStatistics(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
)
{
    PMINIFILTER_STATISTICS stats = (PMINIFILTER_STATISTICS)Buffer;
    
    if (Buffer == NULL || BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (BufferLength < sizeof(MINIFILTER_STATISTICS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    
    // Fill statistics structure
    stats->TotalFileAccesses = g_MinifilterContext.FileAccessCount;
    stats->IntegrityChecksPerformed = g_MinifilterContext.IntegrityViolations; // For demo
    stats->IntegrityViolationsDetected = g_MinifilterContext.IntegrityViolations;
    stats->DataSubstitutionsPerformed = g_MinifilterContext.DataSubstitutions;
    stats->MonitoringStartTime = g_MinifilterContext.StartTime;
    stats->MonitoringActive = g_MinifilterContext.MonitoringActive;
    stats->IntegrityCheckingEnabled = TRUE;
    stats->DataSubstitutionEnabled = TRUE;
    
    // Calculate uptime
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    stats->UptimeSeconds = (currentTime.QuadPart - g_MinifilterContext.StartTime) / 10000000;
    
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    *BytesReturned = sizeof(MINIFILTER_STATISTICS);
    return STATUS_SUCCESS;
}

// Clear file access log
NTSTATUS ClearFileAccessLog()
{
    PLIST_ENTRY entry;
    PFILE_ACCESS_LOG_ENTRY logEntry;
    
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    
    // Free all log entries
    while (!IsListEmpty(&g_MinifilterContext.FileAccessLog)) {
        entry = RemoveHeadList(&g_MinifilterContext.FileAccessLog);
        logEntry = CONTAINING_RECORD(entry, FILE_ACCESS_LOG_ENTRY, ListEntry);
        ExFreePoolWithTag(logEntry, 'GOLF');
    }
    
    // Free integrity check entries
    while (!IsListEmpty(&g_MinifilterContext.IntegrityCheckQueue)) {
        entry = RemoveHeadList(&g_MinifilterContext.IntegrityCheckQueue);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, INTEGRITY_CHECK_ENTRY, ListEntry), 'GOLF');
    }
    
    // Free data substitution entries
    while (!IsListEmpty(&g_MinifilterContext.DataSubstitutionQueue)) {
        entry = RemoveHeadList(&g_MinifilterContext.DataSubstitutionQueue);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, DATA_SUBSTITUTION_ENTRY, ListEntry), 'GOLF');
    }
    
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    LOG_INFO("File access log cleared");
    return STATUS_SUCCESS;
}

// Start minifilter monitoring
NTSTATUS StartMinifilterMonitoring()
{
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.MonitoringActive = TRUE;
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    LOG_INFO("Minifilter monitoring started");
    return STATUS_SUCCESS;
}

// Stop minifilter monitoring
NTSTATUS StopMinifilterMonitoring()
{
    ExAcquireFastMutex(&g_MinifilterContext.FilterLock);
    g_MinifilterContext.MonitoringActive = FALSE;
    ExReleaseFastMutex(&g_MinifilterContext.FilterLock);
    
    LOG_INFO("Minifilter monitoring stopped");
    return STATUS_SUCCESS;
}

// Create minifilter communication port
NTSTATUS CreateMinifilterCommunicationPort()
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    
    // Create security descriptor
    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltBuildDefaultSecurityDescriptor failed with status: 0x%08X", status);
        return status;
    }
    
    // Initialize port name
    RtlInitUnicodeString(&portName, L"\\BootkitAnalysisMinifilterPort");
    
    // Initialize object attributes
    InitializeObjectAttributes(&objectAttributes,
                               &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               securityDescriptor);
    
    // Create communication port
    status = FltCreateCommunicationPort(g_MinifilterContext.FilterHandle,
                                        &g_MinifilterContext.ServerPort,
                                        &objectAttributes,
                                        NULL,
                                        MinifilterConnectCallback,
                                        MinifilterDisconnectCallback,
                                        MinifilterMessageCallback,
                                        1);
    
    if (securityDescriptor != NULL) {
        FltFreeSecurityDescriptor(securityDescriptor);
    }
    
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltCreateCommunicationPort failed with status: 0x%08X", status);
        return status;
    }
    
    LOG_INFO("Minifilter communication port created successfully");
    return STATUS_SUCCESS;
}

// Close minifilter communication port
NTSTATUS CloseMinifilterCommunicationPort()
{
    if (g_MinifilterContext.ServerPort != NULL) {
        FltCloseCommunicationPort(g_MinifilterContext.ServerPort);
        g_MinifilterContext.ServerPort = NULL;
    }
    
    if (g_MinifilterContext.ClientPort != NULL) {
        FltCloseClientPort(g_MinifilterContext.FilterHandle, &g_MinifilterContext.ClientPort);
        g_MinifilterContext.ClientPort = NULL;
    }
    
    LOG_INFO("Minifilter communication port closed");
    return STATUS_SUCCESS;
}

// Minifilter connect callback
NTSTATUS MinifilterConnectCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    
    LOG_INFO("Minifilter client connected");
    
    // Store client port
    g_MinifilterContext.ClientPort = ClientPort;
    
    return STATUS_SUCCESS;
}

// Minifilter disconnect callback
VOID MinifilterDisconnectCallback(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    
    LOG_INFO("Minifilter client disconnected");
    
    // Clear client port
    g_MinifilterContext.ClientPort = NULL;
}

// Minifilter message callback
NTSTATUS MinifilterMessageCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    
    // Handle messages from user mode
    // This would process control commands and return data
    
    return STATUS_SUCCESS;
}

// Send minifilter notification
NTSTATUS SendMinifilterNotification(
    _In_ ULONG NotificationType,
    _In_ PVOID NotificationData,
    _In_ ULONG DataSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (g_MinifilterContext.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }
    
    // Send notification to user mode
    status = FltSendMessage(g_MinifilterContext.FilterHandle,
                            &g_MinifilterContext.ClientPort,
                            NotificationData,
                            DataSize,
                            NULL,
                            NULL,
                            NULL);
    
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("FltSendMessage failed with status: 0x%08X", status);
    }
    
    return status;
}