// Debug.h: Debug and logging header file

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Debug module initialization and cleanup
NTSTATUS InitializeDebug();
VOID CleanupDebug();

// Logging control functions
NTSTATUS SetLoggingEnabled(_In_ BOOLEAN Enabled);
NTSTATUS SetDebugLevel(_In_ ULONG Level);
NTSTATUS GetDebugStatistics(
    _Out_ PULONG TotalLogEntries,
    _Out_ PULONG ErrorLogEntries,
    _Out_ PULONG WarningLogEntries,
    _Out_ PULONG InfoLogEntries,
    _Out_ PULONG TraceLogEntries
);

// Formatted logging functions
VOID LogError(_In_ PCSTR Format, ...);
VOID LogWarning(_In_ PCSTR Format, ...);
VOID LogInfo(_In_ PCSTR Format, ...);
VOID LogTrace(_In_ PCSTR Format, ...);

// Debug dump functions
VOID DumpMemory(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ PCSTR Description
);

VOID DumpIrpInfo(
    _In_ PIRP Irp,
    _In_ PCSTR Description
);

VOID DumpDeviceObjectInfo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCSTR Description
);

VOID DumpDriverObjectInfo(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCSTR Description
);

// Debugger functions
BOOLEAN IsDebuggerPresent();
VOID BreakIfDebuggerPresent();

// Print debug statistics
VOID PrintDebugStatistics();

#ifdef __cplusplus
}
#endif