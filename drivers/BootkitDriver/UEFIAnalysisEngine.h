// UEFIAnalysisEngine.h: UEFI Analysis Engine implementation for Task 2.1
// Implements comprehensive UEFI firmware security analysis for bootkit analysis framework

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "pch.h"
#include "ModernCpp.h"

// UEFI analysis context structure
typedef struct _UEFI_ANALYSIS_CONTEXT {
    // Secure Boot analysis
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootEnforced;
    UINT8 PlatformKeyHash[32];
    UINT8 KeyExchangeKeyHash[32];
    UINT8 SignatureDatabaseHash[32];
    UINT8 ForbiddenDatabaseHash[32];
    ULONG CertificateCount;
    ULONG RevokedCertificateCount;
    
    // UEFI driver tracking
    LIST_ENTRY UEFIDriverList;
    FAST_MUTEX DriverLock;
    ULONG DriverCount;
    ULONG DriverLoadFailures;
    
    // UEFI variable monitoring
    LIST_ENTRY UEFIVariableList;
    FAST_MUTEX VariableLock;
    ULONG VariableAccessCount;
    ULONG VariableModificationCount;
    
    // UEFI protocol monitoring
    LIST_ENTRY UEFIProtocolList;
    FAST_MUTEX ProtocolLock;
    ULONG ProtocolInstallCount;
    ULONG ProtocolUsageCount;
    
    // Runtime services hooks
    LIST_ENTRY RuntimeHooks;
    FAST_MUTEX HookLock;
    ULONG HookCount;
    BOOLEAN RuntimeHookingEnabled;
    
    // Synchronization
    FAST_MUTEX AnalysisLock;
    BOOLEAN AnalysisActive;
    BOOLEAN Initialized;
    
    // Statistics
    ULONG SecureBootValidations;
    ULONG DriverLoadTraces;
    ULONG VariableAccessTraces;
    ULONG ProtocolUsageTraces;
    ULONG RuntimeServiceCalls;
    ULONG SecurityViolations;
    
    // Memory for analysis data
    PVOID AnalysisBuffer;
    ULONG AnalysisBufferSize;
    
    // Firmware information
    WCHAR FirmwareVendor[64];
    WCHAR FirmwareVersion[64];
    WCHAR FirmwareDate[32];
    ULONG64 FirmwareSize;
    BOOLEAN UEFICompliant;
    ULONG UEFIVersionMajor;
    ULONG UEFIVersionMinor;
    
} UEFI_ANALYSIS_CONTEXT, *PUEFI_ANALYSIS_CONTEXT;

// UEFI driver information structure
typedef struct _UEFI_DRIVER_INFO {
    LIST_ENTRY ListEntry;
    WCHAR DriverName[64];
    WCHAR DriverPath[256];
    ULONG64 DriverBase;
    ULONG DriverSize;
    ULONG LoadOrder;
    ULONG64 LoadTime;
    BOOLEAN Signed;
    BOOLEAN Authenticated;
    UINT8 DriverHash[32];
    WCHAR Publisher[128];
    WCHAR Description[256];
    ULONG DependencyCount;
    WCHAR Dependencies[10][64];
} UEFI_DRIVER_INFO, *PUEFI_DRIVER_INFO;

// UEFI variable information structure
typedef struct _UEFI_VARIABLE_INFO {
    LIST_ENTRY ListEntry;
    WCHAR VariableName[64];
    GUID VariableGuid;
    ULONG VariableSize;
    ULONG VariableAttributes;
    ULONG64 LastAccessTime;
    ULONG64 LastModificationTime;
    ULONG AccessCount;
    ULONG ModificationCount;
    BOOLEAN SecureBootVariable;
    BOOLEAN AuthenticatedVariable;
    WCHAR VariableType[32];
    UINT8 VariableHash[32];
} UEFI_VARIABLE_INFO, *PUEFI_VARIABLE_INFO;

// UEFI protocol information structure
typedef struct _UEFI_PROTOCOL_INFO {
    LIST_ENTRY ListEntry;
    GUID ProtocolGuid;
    WCHAR ProtocolName[64];
    ULONG64 ProtocolInterface;
    ULONG ProtocolVersion;
    ULONG64 InstallationTime;
    ULONG UsageCount;
    ULONG64 LastUsageTime;
    WCHAR ProducerGuid[64];
    WCHAR ConsumerGuid[64];
    BOOLEAN StandardProtocol;
    WCHAR Description[256];
} UEFI_PROTOCOL_INFO, *PUEFI_PROTOCOL_INFO;

// Runtime service hook structure
typedef struct _RUNTIME_SERVICE_HOOK {
    LIST_ENTRY ListEntry;
    ULONG ServiceIndex;
    ULONG64 OriginalService;
    ULONG64 HookedService;
    ULONG64 HookTime;
    ULONG CallCount;
    BOOLEAN HookActive;
    WCHAR ServiceName[64];
    WCHAR HookPurpose[128];
} RUNTIME_SERVICE_HOOK, *PRUNTIME_SERVICE_HOOK;

// Secure Boot validation result structure
typedef struct _SECURE_BOOT_VALIDATION {
    ULONG64 ValidationTime;
    BOOLEAN ValidationPassed;
    NTSTATUS ValidationStatus;
    WCHAR ValidatedObject[64];
    UINT8 ObjectHash[32];
    WCHAR SignerName[128];
    UINT8 CertificateHash[32];
    ULONG CertificateChainLength;
    BOOLEAN ChainValid;
    WCHAR ValidationDetails[256];
} SECURE_BOOT_VALIDATION, *PSECURE_BOOT_VALIDATION;

// UEFI service type definitions
typedef enum _UEFI_SERVICE_CATEGORY {
    UEFI_SERVICE_BOOT = 0,
    UEFI_SERVICE_RUNTIME,
    UEFI_SERVICE_SECURE_BOOT,
    UEFI_SERVICE_VARIABLE,
    UEFI_SERVICE_PROTOCOL,
    UEFI_SERVICE_IMAGE,
    UEFI_SERVICE_MEMORY,
    UEFI_SERVICE_EVENT,
    UEFI_SERVICE_DXE,
    UEFI_SERVICE_SMM
} UEFI_SERVICE_CATEGORY;

// Secure Boot component types
typedef enum _SECURE_BOOT_COMPONENT {
    SECURE_BOOT_PLATFORM_KEY = 0,
    SECURE_BOOT_KEY_EXCHANGE_KEY,
    SECURE_BOOT_SIGNATURE_DATABASE,
    SECURE_BOOT_FORBIDDEN_DATABASE,
    SECURE_BOOT_TIMESTAMP_DATABASE,
    SECURE_BOOT_OS_LOADER,
    SECURE_BOOT_DRIVER,
    SECURE_BOOT_APPLICATION
} SECURE_BOOT_COMPONENT;

// UEFI variable operation types
typedef enum _UEFI_VARIABLE_OPERATION {
    VARIABLE_GET = 0,
    VARIABLE_SET,
    VARIABLE_QUERY,
    VARIABLE_DELETE,
    VARIABLE_ENUMERATE
} UEFI_VARIABLE_OPERATION;

// UEFI protocol operation types
typedef enum _UEFI_PROTOCOL_OPERATION {
    PROTOCOL_INSTALL = 0,
    PROTOCOL_UNINSTALL,
    PROTOCOL_LOCATE,
    PROTOCOL_OPEN,
    PROTOCOL_CLOSE,
    PROTOCOL_HANDLE_PROTOCOL
} UEFI_PROTOCOL_OPERATION;

// Function declarations for UEFI analysis engine
NTSTATUS InitializeUEFIAnalysisEngine(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID CleanupUEFIAnalysisEngine();

NTSTATUS AnalyzeSecureBoot();

NTSTATUS MonitorUEFIDrivers();

NTSTATUS DetectUEFIVariableManipulation();

NTSTATUS AnalyzeBootServices();

NTSTATUS StudyRuntimeServices();

NTSTATUS InstallRuntimeServiceHook(
    _In_ ULONG ServiceIndex,
    _In_ ULONG64 HookHandler,
    _In_ PCWSTR HookPurpose
);

NTSTATUS RemoveRuntimeServiceHook(
    _In_ ULONG ServiceIndex
);

NTSTATUS ScanUEFIFirmware();

NTSTATUS ValidateSecureBootCertificate(
    _In_ SECURE_BOOT_COMPONENT ComponentType,
    _In_ PVOID CertificateData,
    _In_ ULONG CertificateSize
);

NTSTATUS TraceDriverLoadingSequence(
    _In_ PCWSTR DriverName,
    _In_ ULONG64 DriverBase
);

NTSTATUS MonitorVariableAccess(
    _In_ UEFI_VARIABLE_OPERATION Operation,
    _In_ PCWSTR VariableName,
    _In_ GUID VariableGuid
);

NTSTATUS MonitorProtocolUsage(
    _In_ UEFI_PROTOCOL_OPERATION Operation,
    _In_ GUID ProtocolGuid,
    _In_ ULONG64 ProtocolInterface
);

NTSTATUS GenerateUEFISecurityReport(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS EnableUEFIAnalysis(
    _In_ BOOLEAN Enable
);

// Hook handler declarations
NTSTATUS RuntimeServiceHookHandler(
    _In_ ULONG ServiceIndex,
    _In_ PVOID Parameters,
    _In_ PVOID Context
);

NTSTATUS SecureBootValidationHandler(
    _In_ SECURE_BOOT_COMPONENT ComponentType,
    _In_ PVOID ValidationData,
    _In_ PVOID Context
);

NTSTATUS DriverLoadEventHandler(
    _In_ PCWSTR DriverName,
    _In_ ULONG64 DriverBase,
    _In_ PVOID Context
);

NTSTATUS VariableAccessEventHandler(
    _In_ UEFI_VARIABLE_OPERATION Operation,
    _In_ PCWSTR VariableName,
    _In_ GUID VariableGuid,
    _In_ PVOID Context
);

// Utility functions
BOOLEAN IsUEFIAnalysisActive();

NTSTATUS GetUEFIAnalysisStatistics(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS ResetUEFIAnalysisStatistics();

// IOCTL codes for UEFI analysis engine control
#define IOCTL_UEFIANALYSIS_ENABLE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_DISABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_GET_STATISTICS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_RESET_STATISTICS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x923, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_GET_REPORT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x924, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_SCAN_FIRMWARE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x925, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_VALIDATE_CERT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x926, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_TRACE_DRIVERS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x927, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_MONITOR_VARS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x928, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UEFIANALYSIS_MONITOR_PROTOCOLS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x929, METHOD_BUFFERED, FILE_ANY_ACCESS)

// UEFI analysis statistics structure
typedef struct _UEFI_ANALYSIS_STATISTICS {
    ULONG SecureBootValidations;
    ULONG DriverLoadTraces;
    ULONG VariableAccessTraces;
    ULONG ProtocolUsageTraces;
    ULONG RuntimeServiceCalls;
    ULONG SecurityViolations;
    ULONG HookedServices;
    ULONG ScannedDrivers;
    ULONG MonitoredVariables;
    ULONG TrackedProtocols;
    BOOLEAN AnalysisActive;
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootEnforced;
    BOOLEAN RuntimeHookingEnabled;
    ULONG64 AnalysisStartTime;
    ULONG64 UptimeSeconds;
    WCHAR FirmwareVendor[64];
    WCHAR FirmwareVersion[64];
    ULONG UEFIVersionMajor;
    ULONG UEFIVersionMinor;
} UEFI_ANALYSIS_STATISTICS, *PUEFI_ANALYSIS_STATISTICS;

// UEFI security report structure
typedef struct _UEFI_SECURITY_REPORT {
    ULONG ReportVersion;
    ULONG64 ReportTime;
    UEFI_ANALYSIS_STATISTICS Statistics;
    ULONG DriverCount;
    ULONG VariableCount;
    ULONG ProtocolCount;
    ULONG HookCount;
    ULONG ViolationCount;
    WCHAR SecurityAssessment[512];
    WCHAR Recommendations[1024];
    WCHAR Vulnerabilities[1024];
} UEFI_SECURITY_REPORT, *PUEFI_SECURITY_REPORT;

// Secure Boot validation report structure
typedef struct _SECURE_BOOT_VALIDATION_REPORT {
    ULONG ValidationCount;
    ULONG FailedValidations;
    ULONG RevokedCertificates;
    BOOLEAN PlatformKeyValid;
    BOOLEAN KeyExchangeKeyValid;
    BOOLEAN SignatureDatabaseValid;
    BOOLEAN ForbiddenDatabaseValid;
    WCHAR PlatformKeySigner[128];
    WCHAR KeyExchangeKeySigner[128];
    UINT8 PlatformKeyHash[32];
    UINT8 KeyExchangeKeyHash[32];
    UINT8 SignatureDatabaseHash[32];
    UINT8 ForbiddenDatabaseHash[32];
} SECURE_BOOT_VALIDATION_REPORT, *PSECURE_BOOT_VALIDATION_REPORT;

// Global context
extern UEFI_ANALYSIS_CONTEXT g_UEFIAnalysisContext;

#ifdef __cplusplus
}
#endif