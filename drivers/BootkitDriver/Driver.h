// Driver.h: Main driver header file

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

// Driver unload routine
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

// Device extension structure
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDeviceObject;
    FAST_MUTEX DeviceLock;
    ULONG OpenHandleCount;
    BOOLEAN DeviceRemoved;
    PVOID DeviceContext;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// Global driver context
typedef struct _DRIVER_CONTEXT {
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLinkName;
    DEVICE_EXTENSION DeviceExtension;
    BOOLEAN Initialized;
    FAST_MUTEX GlobalLock;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

// Function declarations
NTSTATUS CreateDevice(
    _In_ PDRIVER_OBJECT DriverObject
);

VOID DeleteDevice(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS RegisterForPowerEvents(
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID UnregisterFromPowerEvents(
    _In_ PDEVICE_OBJECT DeviceObject
);

// Global context access
extern DRIVER_CONTEXT g_DriverContext;

#ifdef __cplusplus
}
#endif