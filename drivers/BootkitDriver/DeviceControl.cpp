// DeviceControl.cpp: Device control implementation file

#include "pch.h"

// Forward declarations
NTSTATUS HandleDriverInfoRequest(_In_ PVOID InputBuffer, _In_ ULONG InputBufferLength,
                                 _In_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength,
                                 _Out_ PULONG BytesReturned);
NTSTATUS HandleStatisticsRequest(_In_ PVOID InputBuffer, _In_ ULONG InputBufferLength,
                                 _In_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength,
                                 _Out_ PULONG BytesReturned);
NTSTATUS HandleTestRequest(_In_ PVOID InputBuffer, _In_ ULONG InputBufferLength,
                           _In_ PVOID OutputBuffer, _In_ ULONG OutputBufferLength,
                           _Out_ PULONG BytesReturned);

// Global device control context
typedef struct _DEVICE_CONTROL_CONTEXT {
    FAST_MUTEX ControlLock;
    ULONG TotalIoControls;
    ULONG FailedIoControls;
    BOOLEAN ControlInitialized;
} DEVICE_CONTROL_CONTEXT, *PDEVICE_CONTROL_CONTEXT;

DEVICE_CONTROL_CONTEXT g_DeviceControlContext = { 0 };

// IOCTL code definitions
#define IOCTL_BOOTKITDRIVER_GET_DRIVER_INFO     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTKITDRIVER_GET_STATISTICS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTKITDRIVER_PERFORM_TEST        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTKITDRIVER_GET_VERSION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTKITDRIVER_RESET_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Driver information structure
typedef struct _DRIVER_INFO {
    ULONG DriverVersion;
    ULONG BuildNumber;
    WCHAR DriverName[64];
    WCHAR BuildDate[32];
    WCHAR BuildTime[32];
    ULONG FeaturesSupported;
} DRIVER_INFO, *PDRIVER_INFO;

// Driver statistics structure
typedef struct _DRIVER_STATISTICS {
    ULONG TotalIrpsProcessed;
    ULONG FailedIrps;
    ULONG TotalIoControls;
    ULONG FailedIoControls;
    ULONG OpenHandleCount;
    FILETIME DriverStartTime;
    ULONG UptimeSeconds;
} DRIVER_STATISTICS, *PDRIVER_STATISTICS;

// Test request structure
typedef struct _TEST_REQUEST {
    ULONG TestType;
    ULONG TestDataSize;
    UCHAR TestData[256];
} TEST_REQUEST, *PTEST_REQUEST;

// Test response structure
typedef struct _TEST_RESPONSE {
    ULONG TestResult;
    ULONG ProcessedDataSize;
    UCHAR ProcessedData[256];
    ULONG ExecutionTimeMs;
} TEST_RESPONSE, *PTEST_RESPONSE;

// Initialize device control
NTSTATUS InitializeDeviceControl()
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("Initializing device control");
    
    // Initialize fast mutex
    ExInitializeFastMutex(&g_DeviceControlContext.ControlLock);
    
    // Reset counters
    g_DeviceControlContext.TotalIoControls = 0;
    g_DeviceControlContext.FailedIoControls = 0;
    
    // Mark as initialized
    g_DeviceControlContext.ControlInitialized = TRUE;
    
    LOG_TRACE("Device control initialized successfully");
    return status;
}

// Clean up device control
VOID CleanupDeviceControl()
{
    LOG_TRACE("Cleaning up device control");
    
    // Clear context
    RtlZeroMemory(&g_DeviceControlContext, sizeof(g_DeviceControlContext));
    
    LOG_TRACE("Device control cleaned up");
}

// Handle device control requests
NTSTATUS HandleDeviceControl(
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LOG_TRACE("HandleDeviceControl called with IOCTL: 0x%08X", IoControlCode);
    
    // Update statistics
    ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
    g_DeviceControlContext.TotalIoControls++;
    ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
    
    // Handle different IOCTL codes
    switch (IoControlCode) {
        case IOCTL_BOOTKITDRIVER_GET_DRIVER_INFO:
            status = HandleDriverInfoRequest(InputBuffer, InputBufferLength,
                                             OutputBuffer, OutputBufferLength,
                                             BytesReturned);
            break;
            
        case IOCTL_BOOTKITDRIVER_GET_STATISTICS:
            status = HandleStatisticsRequest(InputBuffer, InputBufferLength,
                                             OutputBuffer, OutputBufferLength,
                                             BytesReturned);
            break;
            
        case IOCTL_BOOTKITDRIVER_PERFORM_TEST:
            status = HandleTestRequest(InputBuffer, InputBufferLength,
                                       OutputBuffer, OutputBufferLength,
                                       BytesReturned);
            break;
            
        case IOCTL_BOOTKITDRIVER_GET_VERSION:
            // Simple version request
            if (OutputBuffer != NULL && OutputBufferLength >= sizeof(ULONG)) {
                *(PULONG)OutputBuffer = 0x00010000; // Version 1.0.0.0
                *BytesReturned = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
                *BytesReturned = 0;
            }
            break;
            
        case IOCTL_BOOTKITDRIVER_RESET_STATISTICS:
            // Reset statistics
            ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
            g_DeviceControlContext.TotalIoControls = 0;
            g_DeviceControlContext.FailedIoControls = 0;
            ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
            
            // Also reset IRP handler statistics
            ExAcquireFastMutex(&g_IrpHandlerContext.HandlerLock);
            g_IrpHandlerContext.TotalIrpsProcessed = 0;
            g_IrpHandlerContext.FailedIrps = 0;
            ExReleaseFastMutex(&g_IrpHandlerContext.HandlerLock);
            
            *BytesReturned = 0;
            status = STATUS_SUCCESS;
            break;
            
        // IRP Monitor IOCTLs (Task 1.1)
        case IOCTL_IRPMONITOR_ENABLE_MONITORING:
            status = EnableIrpMonitoring(TRUE);
            *BytesReturned = 0;
            break;
            
        case IOCTL_IRPMONITOR_DISABLE_MONITORING:
            status = EnableIrpMonitoring(FALSE);
            *BytesReturned = 0;
            break;
            
        case IOCTL_IRPMONITOR_GET_STATISTICS:
            status = GetIrpMonitoringStatistics(OutputBuffer, OutputBufferLength, BytesReturned);
            break;
            
        case IOCTL_IRPMONITOR_RESET_STATISTICS:
            status = ResetIrpMonitoringStatistics();
            *BytesReturned = 0;
            break;
            
        case IOCTL_IRPMONITOR_SCAN_DISPATCH_TABLE:
            status = ScanKernelMemoryForDispatchTableMods();
            *BytesReturned = 0;
            break;
            
        case IOCTL_IRPMONITOR_GET_MODIFICATIONS:
            // Return detected modifications count
            if (OutputBuffer != NULL && OutputBufferLength >= sizeof(ULONG)) {
                *(PULONG)OutputBuffer = g_IrpMonitoringContext.DetectedModifications;
                *BytesReturned = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
                *BytesReturned = 0;
            }
            break;
            
        // Boot Flow Interceptor IOCTLs (Task 1.2)
        case IOCTL_BOOTANALYSIS_ENABLE:
            status = EnableBootAnalysis(TRUE);
            *BytesReturned = 0;
            break;
            
        case IOCTL_BOOTANALYSIS_DISABLE:
            status = EnableBootAnalysis(FALSE);
            *BytesReturned = 0;
            break;
            
        case IOCTL_BOOTANALYSIS_GET_STATISTICS:
            status = GetBootAnalysisStatistics(OutputBuffer, OutputBufferLength, BytesReturned);
            break;
            
        case IOCTL_BOOTANALYSIS_RESET_STATISTICS:
            status = ResetBootAnalysisStatistics();
            *BytesReturned = 0;
            break;
            
        case IOCTL_BOOTANALYSIS_GET_REPORT:
            status = GenerateBootAnalysisReport(OutputBuffer, OutputBufferLength, BytesReturned);
            break;
            
        case IOCTL_BOOTANALYSIS_SCAN_MODULES:
            status = ScanBootModules();
            *BytesReturned = 0;
            break;
            
        case IOCTL_BOOTANALYSIS_TRACE_FLOW:
            status = TraceBootControlFlow();
            *BytesReturned = 0;
            break;
            
        default:
            LOG_WARNING("Unknown IOCTL code: 0x%08X", IoControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            *BytesReturned = 0;
            
            // Update failed count
            ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
            g_DeviceControlContext.FailedIoControls++;
            ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
            break;
    }
    
    LOG_TRACE("HandleDeviceControl completed with status: 0x%08X, bytes returned: %lu",
              status, *BytesReturned);
    return status;
}

// Handle driver info request
NTSTATUS HandleDriverInfoRequest(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_INFO driverInfo = NULL;
    
    LOG_TRACE("Handling driver info request");
    
    // Check output buffer size
    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DRIVER_INFO)) {
        status = STATUS_BUFFER_TOO_SMALL;
        *BytesReturned = sizeof(DRIVER_INFO);
        goto Exit;
    }
    
    // Fill driver info structure
    driverInfo = (PDRIVER_INFO)OutputBuffer;
    RtlZeroMemory(driverInfo, sizeof(DRIVER_INFO));
    
    driverInfo->DriverVersion = 0x00010000; // Version 1.0.0.0
    driverInfo->BuildNumber = 1;
    
    // Copy driver name
    status = RtlStringCbCopyW(driverInfo->DriverName, sizeof(driverInfo->DriverName),
                              L"Bootkit Analysis Framework Driver");
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to copy driver name: 0x%08X", status);
        goto Exit;
    }
    
    // Copy build date and time
    status = RtlStringCbCopyW(driverInfo->BuildDate, sizeof(driverInfo->BuildDate),
                              L"2024-01-01");
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to copy build date: 0x%08X", status);
        goto Exit;
    }
    
    status = RtlStringCbCopyW(driverInfo->BuildTime, sizeof(driverInfo->BuildTime),
                              L"12:00:00");
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to copy build time: 0x%08X", status);
        goto Exit;
    }
    
    // Set supported features
    driverInfo->FeaturesSupported = 0x00000001; // Basic driver functionality
    
    *BytesReturned = sizeof(DRIVER_INFO);
    
Exit:
    if (!NT_SUCCESS(status)) {
        *BytesReturned = 0;
        
        // Update failed count
        ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
        g_DeviceControlContext.FailedIoControls++;
        ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
    }
    
    LOG_TRACE("Driver info request handled with status: 0x%08X", status);
    return status;
}

// Handle statistics request
NTSTATUS HandleStatisticsRequest(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_STATISTICS statistics = NULL;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER driverStartTime;
    PDEVICE_EXTENSION deviceExtension = NULL;
    
    LOG_TRACE("Handling statistics request");
    
    // Check output buffer size
    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DRIVER_STATISTICS)) {
        status = STATUS_BUFFER_TOO_SMALL;
        *BytesReturned = sizeof(DRIVER_STATISTICS);
        goto Exit;
    }
    
    // Fill statistics structure
    statistics = (PDRIVER_STATISTICS)OutputBuffer;
    RtlZeroMemory(statistics, sizeof(DRIVER_STATISTICS));
    
    // Get current time
    KeQuerySystemTime(&currentTime);
    
    // Set driver start time (simulated - would be actual start time in real implementation)
    driverStartTime.QuadPart = currentTime.QuadPart - (10 * 10000000); // 10 seconds ago
    
    // Convert to FILETIME
    statistics->DriverStartTime.dwLowDateTime = driverStartTime.LowPart;
    statistics->DriverStartTime.dwHighDateTime = driverStartTime.HighPart;
    
    // Calculate uptime in seconds
    LARGE_INTEGER uptime;
    uptime.QuadPart = currentTime.QuadPart - driverStartTime.QuadPart;
    statistics->UptimeSeconds = (ULONG)(uptime.QuadPart / 10000000); // Convert to seconds
    
    // Get IRP handler statistics
    ExAcquireFastMutex(&g_IrpHandlerContext.HandlerLock);
    statistics->TotalIrpsProcessed = g_IrpHandlerContext.TotalIrpsProcessed;
    statistics->FailedIrps = g_IrpHandlerContext.FailedIrps;
    ExReleaseFastMutex(&g_IrpHandlerContext.HandlerLock);
    
    // Get device control statistics
    ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
    statistics->TotalIoControls = g_DeviceControlContext.TotalIoControls;
    statistics->FailedIoControls = g_DeviceControlContext.FailedIoControls;
    ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
    
    // Get open handle count from device extension
    if (g_DriverContext.DeviceObject != NULL) {
        deviceExtension = (PDEVICE_EXTENSION)g_DriverContext.DeviceObject->DeviceExtension;
        ExAcquireFastMutex(&deviceExtension->DeviceLock);
        statistics->OpenHandleCount = deviceExtension->OpenHandleCount;
        ExReleaseFastMutex(&deviceExtension->DeviceLock);
    }
    
    *BytesReturned = sizeof(DRIVER_STATISTICS);
    
Exit:
    if (!NT_SUCCESS(status)) {
        *BytesReturned = 0;
        
        // Update failed count
        ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
        g_DeviceControlContext.FailedIoControls++;
        ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
    }
    
    LOG_TRACE("Statistics request handled with status: 0x%08X", status);
    return status;
}

// Handle test request
NTSTATUS HandleTestRequest(
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTEST_REQUEST testRequest = NULL;
    PTEST_RESPONSE testResponse = NULL;
    LARGE_INTEGER startTime, endTime, elapsedTime;
    
    LOG_TRACE("Handling test request");
    
    // Check input buffer
    if (InputBuffer == NULL || InputBufferLength < sizeof(TEST_REQUEST)) {
        status = STATUS_INVALID_PARAMETER;
        *BytesReturned = 0;
        goto Exit;
    }
    
    // Check output buffer
    if (OutputBuffer == NULL || OutputBufferLength < sizeof(TEST_RESPONSE)) {
        status = STATUS_BUFFER_TOO_SMALL;
        *BytesReturned = sizeof(TEST_RESPONSE);
        goto Exit;
    }
    
    // Get test request
    testRequest = (PTEST_REQUEST)InputBuffer;
    
    // Validate test data size
    if (testRequest->TestDataSize > sizeof(testRequest->TestData)) {
        status = STATUS_INVALID_PARAMETER;
        *BytesReturned = 0;
        goto Exit;
    }
    
    // Start timing
    KeQueryPerformanceCounter(&startTime);
    
    // Process test based on type
    testResponse = (PTEST_RESPONSE)OutputBuffer;
    RtlZeroMemory(testResponse, sizeof(TEST_RESPONSE));
    
    switch (testRequest->TestType) {
        case 0: // Echo test
            testResponse->TestResult = 0x00000001; // Success
            testResponse->ProcessedDataSize = testRequest->TestDataSize;
            
            // Echo data back
            if (testRequest->TestDataSize > 0) {
                RtlCopyMemory(testResponse->ProcessedData, testRequest->TestData,
                             MIN(testRequest->TestDataSize, sizeof(testResponse->ProcessedData)));
            }
            break;
            
        case 1: // Checksum test
            testResponse->TestResult = 0x00000001; // Success
            testResponse->ProcessedDataSize = sizeof(ULONG);
            
            // Calculate simple checksum
            ULONG checksum = 0;
            for (ULONG i = 0; i < testRequest->TestDataSize; i++) {
                checksum += testRequest->TestData[i];
            }
            
            // Store checksum in response
            *(PULONG)testResponse->ProcessedData = checksum;
            break;
            
        case 2: // Reverse test
            testResponse->TestResult = 0x00000001; // Success
            testResponse->ProcessedDataSize = testRequest->TestDataSize;
            
            // Reverse the data
            for (ULONG i = 0; i < testRequest->TestDataSize; i++) {
                testResponse->ProcessedData[i] = testRequest->TestData[testRequest->TestDataSize - i - 1];
            }
            break;
            
        default:
            testResponse->TestResult = 0x00000000; // Failure
            testResponse->ProcessedDataSize = 0;
            status = STATUS_INVALID_PARAMETER;
            break;
    }
    
    // End timing
    KeQueryPerformanceCounter(&endTime);
    
    // Calculate elapsed time in milliseconds
    elapsedTime.QuadPart = endTime.QuadPart - startTime.QuadPart;
    
    // Convert to milliseconds (assuming performance frequency is in counts per second)
    LARGE_INTEGER frequency;
    KeQueryPerformanceCounter(&frequency); // Actually gets frequency
    // Note: In real code, we would use KeQueryPerformanceFrequency, but for simplicity:
    testResponse->ExecutionTimeMs = (ULONG)(elapsedTime.QuadPart / 10000); // Approximation
    
    *BytesReturned = sizeof(TEST_RESPONSE);
    
Exit:
    if (!NT_SUCCESS(status)) {
        *BytesReturned = 0;
        
        // Update failed count
        ExAcquireFastMutex(&g_DeviceControlContext.ControlLock);
        g_DeviceControlContext.FailedIoControls++;
        ExReleaseFastMutex(&g_DeviceControlContext.ControlLock);
    }
    
    LOG_TRACE("Test request handled with status: 0x%08X, test type: %lu", 
              status, testRequest ? testRequest->TestType : 0);
    return status;
}