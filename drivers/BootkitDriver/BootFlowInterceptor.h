// BootFlowInterceptor.h: Boot Flow Interceptor implementation for Task 1.2
// Implements boot process execution flow interception and analysis for bootkit analysis framework

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "pch.h"
#include "ModernCpp.h"

// Boot analysis context structure
typedef struct _BOOT_ANALYSIS_CONTEXT {
    // Core boot components
    ULONG64 WinloadBaseAddress;
    ULONG64 NtoskrnlBaseAddress;
    ULONG64 HalBaseAddress;
    
    // Boot phase tracking
    ULONG BootPhase;
    ULONG64 BootStartTime;
    ULONG64 BootEndTime;
    
    // Module tracking
    LIST_ENTRY LoadedModules;
    FAST_MUTEX ModuleLock;
    ULONG ModuleCount;
    
    // UEFI/BIOS information
    BOOLEAN UEFIBoot;
    BOOLEAN SecureBootEnabled;
    UINT8 SecureBootHash[32];
    WCHAR FirmwareVendor[64];
    WCHAR FirmwareVersion[64];
    
    // Hook tracking
    ULONG HookedEntryPoints;
    PVOID OriginalEntryPoints[20];
    ULONG64 HookInstallationTimes[20];
    
    // Synchronization
    FAST_MUTEX BootLock;
    BOOLEAN AnalysisActive;
    BOOLEAN Initialized;
    
    // Statistics
    ULONG BootInterceptions;
    ULONG KernelInitTraces;
    ULONG UEFIServiceCalls;
    ULONG BootTimeViolations;
    
    // Memory for analysis data
    PVOID AnalysisBuffer;
    ULONG AnalysisBufferSize;
    
} BOOT_ANALYSIS_CONTEXT, *PBOOT_ANALYSIS_CONTEXT;

// Boot module information structure
typedef struct _BOOT_MODULE_INFO {
    LIST_ENTRY ListEntry;
    WCHAR ModuleName[64];
    ULONG64 BaseAddress;
    ULONG ModuleSize;
    ULONG LoadOrder;
    ULONG64 LoadTime;
    BOOLEAN Signed;
    UINT8 ModuleHash[32];
    WCHAR Publisher[128];
    WCHAR Description[256];
} BOOT_MODULE_INFO, *PBOOT_MODULE_INFO;

// UEFI service call tracking structure
typedef struct _UEFI_SERVICE_CALL {
    LIST_ENTRY ListEntry;
    ULONG ServiceType;
    ULONG ServiceFunction;
    ULONG64 CallTime;
    ULONG64 ReturnTime;
    NTSTATUS Status;
    ULONG Parameters[8];
    ULONG64 ReturnValue;
    WCHAR ServiceName[64];
} UEFI_SERVICE_CALL, *PUEFI_SERVICE_CALL;

// Boot phase definitions
typedef enum _BOOT_PHASE {
    BOOT_PHASE_PRE_BOOT = 0,
    BOOT_PHASE_BOOT_LOADER,
    BOOT_PHASE_KERNEL_INIT,
    BOOT_PHASE_DRIVER_LOAD,
    BOOT_PHASE_SYSTEM_START,
    BOOT_PHASE_USER_LOGON,
    BOOT_PHASE_COMPLETE
} BOOT_PHASE;

// UEFI service type definitions
typedef enum _UEFI_SERVICE_TYPE {
    UEFI_SERVICE_BOOT = 0,
    UEFI_SERVICE_RUNTIME,
    UEFI_SERVICE_SECURE_BOOT,
    UEFI_SERVICE_VARIABLE,
    UEFI_SERVICE_PROTOCOL,
    UEFI_SERVICE_IMAGE,
    UEFI_SERVICE_MEMORY,
    UEFI_SERVICE_EVENT
} UEFI_SERVICE_TYPE;

// Boot interception hook types
typedef enum _BOOT_HOOK_TYPE {
    HOOK_WINLOAD_ENTRY = 0,
    HOOK_NTOSKRNL_INIT,
    HOOK_HAL_INIT,
    HOOK_SMSS_INIT,
    HOOK_CSRSS_INIT,
    HOOK_WINLOGON_INIT,
    HOOK_SERVICES_INIT,
    HOOK_LSASS_INIT
} BOOT_HOOK_TYPE;

// Function declarations for boot flow interception
NTSTATUS InitializeBootFlowInterceptor(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID CleanupBootFlowInterceptor();

NTSTATUS HookWinloadEntryPoints();

NTSTATUS MonitorNtoskrnlInitialization();

NTSTATUS AnalyzeUEFIServices();

NTSTATUS DetectEntryPointModifications();

NTSTATUS TraceBootControlFlow();

NTSTATUS InstallBootHook(
    _In_ BOOT_HOOK_TYPE HookType,
    _In_ ULONG64 TargetAddress,
    _In_ PVOID HookHandler
);

NTSTATUS RemoveBootHook(
    _In_ BOOT_HOOK_TYPE HookType
);

NTSTATUS ScanBootModules();

NTSTATUS LogBootSequence(
    _In_ BOOT_PHASE Phase,
    _In_ PCWSTR PhaseName,
    _In_ ULONG64 StartTime,
    _In_ ULONG64 EndTime
);

NTSTATUS GenerateBootAnalysisReport(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS EnableBootAnalysis(
    _In_ BOOLEAN Enable
);

// Hook handler declarations
NTSTATUS WinloadEntryHookHandler(
    _In_ ULONG64 EntryPoint,
    _In_ PVOID Context
);

NTSTATUS NtoskrnlInitHookHandler(
    _In_ ULONG64 InitRoutine,
    _In_ PVOID Context
);

NTSTATUS UEFIServiceHookHandler(
    _In_ UEFI_SERVICE_TYPE ServiceType,
    _In_ ULONG ServiceFunction,
    _In_ PVOID Parameters,
    _In_ PVOID Context
);

// Utility functions
BOOLEAN IsBootAnalysisActive();

NTSTATUS GetBootAnalysisStatistics(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS ResetBootAnalysisStatistics();

// IOCTL codes for boot flow interception control
#define IOCTL_BOOTANALYSIS_ENABLE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_DISABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_GET_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_RESET_STATISTICS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_GET_REPORT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x914, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_SCAN_MODULES      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x915, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BOOTANALYSIS_TRACE_FLOW        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x916, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Boot analysis statistics structure
typedef struct _BOOT_ANALYSIS_STATISTICS {
    ULONG BootInterceptions;
    ULONG KernelInitTraces;
    ULONG UEFIServiceCalls;
    ULONG BootTimeViolations;
    ULONG HookedEntryPoints;
    ULONG ScannedModules;
    ULONG DetectedModifications;
    BOOLEAN AnalysisActive;
    BOOLEAN UEFIBoot;
    BOOLEAN SecureBootEnabled;
    ULONG64 BootStartTime;
    ULONG64 CurrentBootTime;
    ULONG64 AnalysisStartTime;
    ULONG64 UptimeSeconds;
    WCHAR FirmwareVendor[64];
    WCHAR FirmwareVersion[64];
} BOOT_ANALYSIS_STATISTICS, *PBOOT_ANALYSIS_STATISTICS;

// Boot analysis report structure
typedef struct _BOOT_ANALYSIS_REPORT {
    ULONG ReportVersion;
    ULONG64 ReportTime;
    BOOT_ANALYSIS_STATISTICS Statistics;
    ULONG ModuleCount;
    ULONG ServiceCallCount;
    ULONG HookCount;
    ULONG ViolationCount;
    WCHAR Summary[512];
} BOOT_ANALYSIS_REPORT, *PBOOT_ANALYSIS_REPORT;

// Boot module report structure
typedef struct _BOOT_MODULE_REPORT {
    WCHAR ModuleName[64];
    ULONG64 BaseAddress;
    ULONG ModuleSize;
    ULONG LoadOrder;
    BOOLEAN Signed;
    WCHAR Publisher[128];
    WCHAR Description[256];
    UINT8 ModuleHash[32];
} BOOT_MODULE_REPORT, *PBOOT_MODULE_REPORT;

// Global context
extern BOOT_ANALYSIS_CONTEXT g_BootAnalysisContext;

#ifdef __cplusplus
}
#endif