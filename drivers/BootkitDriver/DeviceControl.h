// DeviceControl.h: Device control IOCTL definitions

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Device control initialization and cleanup
NTSTATUS InitializeDeviceControl();
VOID CleanupDeviceControl();

// Main device control handler
NTSTATUS HandleDeviceControl(
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesReturned
);

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

#ifdef __cplusplus
}
#endif