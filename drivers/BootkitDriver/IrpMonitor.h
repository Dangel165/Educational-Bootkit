// IrpMonitor.h: IRP Dispatcher Monitor component for Task 1.1
// Implements real IRP hooking and monitoring for bootkit analysis framework

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// IRP monitoring context structure
typedef struct _IRP_MONITORING_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    FAST_MUTEX IrpLock;
    LIST_ENTRY HookedIrpList;
    ULONG HookCount;
    BOOLEAN MonitoringActive;
    PVOID OriginalReadHandler;
    PVOID OriginalDirectoryHandler;
    PVOID CompletionRoutineHook;
    ULONG64 DispatchTableBase;
    ULONG DispatchTableSize;
    BOOLEAN DispatchTableScanned;
    ULONG DetectedModifications;
} IRP_MONITORING_CONTEXT, *PIRP_MONITORING_CONTEXT;

// IRP hook entry structure
typedef struct _IRP_HOOK_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG MajorFunction;
    PVOID OriginalHandler;
    PVOID HookHandler;
    ULONG HookFlags;
    ULONG64 HookTime;
    BOOLEAN Active;
    WCHAR TargetDeviceName[64];
    PDEVICE_OBJECT TargetDevice;
} IRP_HOOK_ENTRY, *PIRP_HOOK_ENTRY;

// IRP completion tracking structure
typedef struct _IRP_COMPLETION_TRACK {
    PIRP Irp;
    ULONG MajorFunction;
    PVOID CompletionRoutine;
    PVOID CompletionContext;
    ULONG64 StartTime;
    ULONG64 EndTime;
    NTSTATUS CompletionStatus;
    ULONG Information;
    BOOLEAN Completed;
    LIST_ENTRY ListEntry;
} IRP_COMPLETION_TRACK, *PIRP_COMPLETION_TRACK;

// Dispatch table modification detection structure
typedef struct _DISPATCH_TABLE_MOD {
    ULONG64 Address;
    PVOID OriginalValue;
    PVOID CurrentValue;
    ULONG64 DetectionTime;
    BOOLEAN Suspicious;
    WCHAR ModuleName[64];
    ULONG FunctionIndex;
    LIST_ENTRY ListEntry;
} DISPATCH_TABLE_MOD, *PDISPATCH_TABLE_MOD;

// Function declarations for IRP monitoring
NTSTATUS InitializeIrpMonitoring(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID CleanupIrpMonitoring();

NTSTATUS HookIrpMjRead(
    _In_ PDEVICE_OBJECT TargetDevice
);

NTSTATUS HookIrpMjDirectoryControl(
    _In_ PDEVICE_OBJECT TargetDevice
);

NTSTATUS InstallCompletionRoutineHook(
    _In_ PDEVICE_OBJECT TargetDevice
);

NTSTATUS ScanKernelMemoryForDispatchTableMods();

NTSTATUS AttachToDeviceStack(
    _In_ PDEVICE_OBJECT SourceDevice,
    _In_ PUNICODE_STRING TargetDeviceName
);

NTSTATUS DetachFromDeviceStack(
    _In_ PDEVICE_OBJECT SourceDevice
);

// IRP hook handlers
NTSTATUS IrpReadHookHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS IrpDirectoryControlHookHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// Completion routine hook
NTSTATUS CompletionRoutineHook(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
);

// Utility functions
BOOLEAN IsIrpHookActive(
    _In_ ULONG MajorFunction
);

NTSTATUS EnableIrpMonitoring(
    _In_ BOOLEAN Enable
);

NTSTATUS GetIrpMonitoringStatistics(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS ResetIrpMonitoringStatistics();

// IOCTL codes for IRP monitoring control
#define IOCTL_IRPMONITOR_ENABLE_MONITORING     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_DISABLE_MONITORING    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_STATISTICS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_RESET_STATISTICS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_SCAN_DISPATCH_TABLE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IRPMONITOR_GET_MODIFICATIONS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IRP monitoring statistics structure
typedef struct _IRP_MONITORING_STATISTICS {
    ULONG TotalIrpsMonitored;
    ULONG ReadIrpsMonitored;
    ULONG DirectoryControlIrpsMonitored;
    ULONG CompletionRoutinesTraced;
    ULONG DispatchTableScansPerformed;
    ULONG ModificationsDetected;
    ULONG HookInstallations;
    ULONG HookFailures;
    ULONG64 MonitoringStartTime;
    ULONG64 UptimeSeconds;
    BOOLEAN MonitoringActive;
    BOOLEAN ReadHookActive;
    BOOLEAN DirectoryControlHookActive;
    BOOLEAN CompletionHookActive;
} IRP_MONITORING_STATISTICS, *PIRP_MONITORING_STATISTICS;

// Dispatch table modification report structure
typedef struct _DISPATCH_TABLE_REPORT {
    ULONG TotalModifications;
    ULONG SuspiciousModifications;
    ULONG64 ScanTime;
    WCHAR ScannedModule[64];
    ULONG ScannedFunctions;
} DISPATCH_TABLE_REPORT, *PDISPATCH_TABLE_REPORT;

// Global context
extern IRP_MONITORING_CONTEXT g_IrpMonitoringContext;

#ifdef __cplusplus
}
#endif