// MinifilterDriver.h: Minifilter Driver Implementation for File Integrity Analysis
// Implements Requirement 10: Minifilter Driver Implementation for File Integrity Analysis

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Minifilter context structure
typedef struct _MINIFILTER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    FAST_MUTEX FilterLock;
    BOOLEAN FilterRegistered;
    BOOLEAN MonitoringActive;
    ULONG FileAccessCount;
    ULONG IntegrityViolations;
    ULONG DataSubstitutions;
    ULONG64 StartTime;
    LIST_ENTRY FileAccessLog;
    LIST_ENTRY IntegrityCheckQueue;
    LIST_ENTRY DataSubstitutionQueue;
    UNICODE_STRING FilterName;
    UNICODE_STRING Altitudes;
    ULONG InstanceCount;
    PFLT_INSTANCE* Instances;
} MINIFILTER_CONTEXT, *PMINIFILTER_CONTEXT;

// File access log entry
typedef struct _FILE_ACCESS_LOG_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG64 Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
    WCHAR FilePath[512];
    WCHAR ProcessName[256];
    ACCESS_MASK DesiredAccess;
    ULONG IrpMajorFunction;
    ULONG64 FileSize;
    BOOLEAN IntegrityCheckPassed;
    BOOLEAN DataSubstituted;
    NTSTATUS AccessStatus;
    ULONG IntegrityCheckFlags;
    ULONG DataSubstitutionFlags;
} FILE_ACCESS_LOG_ENTRY, *PFILE_ACCESS_LOG_ENTRY;

// Integrity check entry
typedef struct _INTEGRITY_CHECK_ENTRY {
    LIST_ENTRY ListEntry;
    WCHAR FilePath[512];
    ULONG64 ExpectedHash;
    ULONG64 ActualHash;
    ULONG64 CheckTime;
    BOOLEAN IntegrityValid;
    ULONG ViolationCount;
    WCHAR ViolationReason[256];
} INTEGRITY_CHECK_ENTRY, *PINTEGRITY_CHECK_ENTRY;

// Data substitution entry
typedef struct _DATA_SUBSTITUTION_ENTRY {
    LIST_ENTRY ListEntry;
    WCHAR OriginalFilePath[512];
    WCHAR SubstituteFilePath[512];
    ULONG64 OriginalSize;
    ULONG64 SubstituteSize;
    ULONG64 SubstitutionTime;
    BOOLEAN Active;
    ULONG SubstitutionCount;
    WCHAR SubstitutionReason[256];
} DATA_SUBSTITUTION_ENTRY, *PDATA_SUBSTITUTION_ENTRY;

// File integrity validation context
typedef struct _FILE_INTEGRITY_CONTEXT {
    ULONG64 FileSize;
    ULONG64 FileHash;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER LastAccessTime;
    ULONG IntegrityFlags;
    BOOLEAN HashCalculated;
    BOOLEAN IntegrityValid;
    WCHAR IntegrityAlgorithm[32];
    ULONG64 ExpectedHash;
    ULONG64 ActualHash;
} FILE_INTEGRITY_CONTEXT, *PFILE_INTEGRITY_CONTEXT;

// Minifilter callback structures
typedef struct _PRE_OPERATION_CALLBACK_CONTEXT {
    PFLT_CALLBACK_DATA Data;
    PCFLT_RELATED_OBJECTS FltObjects;
    PVOID CompletionContext;
    BOOLEAN IntegrityCheckRequired;
    BOOLEAN DataSubstitutionRequired;
    FILE_INTEGRITY_CONTEXT IntegrityContext;
} PRE_OPERATION_CALLBACK_CONTEXT, *PPRE_OPERATION_CALLBACK_CONTEXT;

typedef struct _POST_OPERATION_CALLBACK_CONTEXT {
    PFLT_CALLBACK_DATA Data;
    PCFLT_RELATED_OBJECTS FltObjects;
    PVOID CompletionContext;
    NTSTATUS OperationStatus;
    BOOLEAN IntegrityChecked;
    BOOLEAN DataSubstituted;
    FILE_INTEGRITY_CONTEXT IntegrityContext;
} POST_OPERATION_CALLBACK_CONTEXT, *PPOST_OPERATION_CALLBACK_CONTEXT;

// Minifilter callback function declarations
FLT_PREOP_CALLBACK_STATUS MinifilterPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS MinifilterPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// IRP_MJ_READ specific callback
FLT_PREOP_CALLBACK_STATUS MinifilterPreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS MinifilterPostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// File integrity checking functions
NTSTATUS CalculateFileHash(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG64 HashValue
);

NTSTATUS VerifyFileIntegrity(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG64 ExpectedHash,
    _Out_ PBOOLEAN IntegrityValid,
    _Out_opt_ PULONG64 ActualHash
);

NTSTATUS PerformRealTimeIntegrityCheck(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOLEAN IntegrityValid
);

// Data substitution functions
NTSTATUS SubstituteFileData(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCWSTR SubstituteFilePath,
    _Out_ PBOOLEAN SubstitutionPerformed
);

NTSTATUS CreateAlternativeData(
    _In_ PCWSTR OriginalFilePath,
    _In_ PCWSTR SubstituteFilePath,
    _In_ ULONG SubstitutionFlags
);

NTSTATUS ValidateSubstitutionSafety(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PCWSTR SubstituteFilePath
);

// Forensic logging functions
NTSTATUS LogFileAccess(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ NTSTATUS AccessStatus,
    _In_ BOOLEAN IntegrityCheckPassed,
    _In_ BOOLEAN DataSubstituted
);

NTSTATUS GetFileAccessStatistics(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

NTSTATUS ClearFileAccessLog();

// Minifilter registration and management
NTSTATUS RegisterMinifilterDriver(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS UnregisterMinifilterDriver();

NTSTATUS StartMinifilterMonitoring();

NTSTATUS StopMinifilterMonitoring();

NTSTATUS AttachMinifilterToVolume(
    _In_ PCWSTR VolumeName
);

NTSTATUS DetachMinifilterFromVolume(
    _In_ PCWSTR VolumeName
);

// Port communication for user-mode interaction
NTSTATUS CreateMinifilterCommunicationPort();

NTSTATUS CloseMinifilterCommunicationPort();

NTSTATUS SendMinifilterNotification(
    _In_ ULONG NotificationType,
    _In_ PVOID NotificationData,
    _In_ ULONG DataSize
);

// Configuration and control
NTSTATUS SetMinifilterConfiguration(
    _In_ PVOID ConfigurationData,
    _In_ ULONG DataSize
);

NTSTATUS GetMinifilterConfiguration(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG BytesReturned
);

// Integrity checking algorithms
#define INTEGRITY_ALGORITHM_SHA256   0x00000001
#define INTEGRITY_ALGORITHM_SHA1     0x00000002
#define INTEGRITY_ALGORITHM_MD5      0x00000004
#define INTEGRITY_ALGORITHM_CRC32    0x00000008
#define INTEGRITY_ALGORITHM_CUSTOM   0x00000010

// Data substitution flags
#define SUBSTITUTION_FLAG_SECURE     0x00000001
#define SUBSTITUTION_FLAG_EDUCATIONAL 0x00000002
#define SUBSTITUTION_FLAG_TESTING    0x00000004
#define SUBSTITUTION_FLAG_TEMPORARY  0x00000008
#define SUBSTITUTION_FLAG_PERMANENT  0x00000010

// Integrity check flags
#define INTEGRITY_CHECK_REALTIME     0x00000001
#define INTEGRITY_CHECK_ONACCESS     0x00000002
#define INTEGRITY_CHECK_SCHEDULED    0x00000004
#define INTEGRITY_CHECK_HASHONLY     0x00000008
#define INTEGRITY_CHECK_FULL         0x00000010

// IOCTL codes for minifilter control
#define IOCTL_MINIFILTER_ENABLE_MONITORING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_DISABLE_MONITORING     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_GET_STATISTICS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_CLEAR_STATISTICS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_SET_CONFIGURATION      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x914, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_GET_CONFIGURATION      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x915, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_ADD_INTEGRITY_CHECK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x916, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_REMOVE_INTEGRITY_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x917, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_ADD_DATA_SUBSTITUTION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x918, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_REMOVE_DATA_SUBSTITUTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x919, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_GET_ACCESS_LOG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIFILTER_CLEAR_ACCESS_LOG       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91B, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Minifilter statistics structure
typedef struct _MINIFILTER_STATISTICS {
    ULONG TotalFileAccesses;
    ULONG ReadOperations;
    ULONG WriteOperations;
    ULONG CreateOperations;
    ULONG DeleteOperations;
    ULONG IntegrityChecksPerformed;
    ULONG IntegrityViolationsDetected;
    ULONG DataSubstitutionsPerformed;
    ULONG64 MonitoringStartTime;
    ULONG64 UptimeSeconds;
    BOOLEAN MonitoringActive;
    BOOLEAN IntegrityCheckingEnabled;
    BOOLEAN DataSubstitutionEnabled;
    ULONG AttachedVolumes;
    ULONG ActiveInstances;
} MINIFILTER_STATISTICS, *PMINIFILTER_STATISTICS;

// Minifilter configuration structure
typedef struct _MINIFILTER_CONFIGURATION {
    BOOLEAN EnableIntegrityChecking;
    BOOLEAN EnableDataSubstitution;
    BOOLEAN EnableForensicLogging;
    ULONG IntegrityAlgorithm;
    ULONG SubstitutionFlags;
    ULONG LogLevel;
    ULONG MaxLogEntries;
    ULONG64 IntegrityCheckInterval;
    WCHAR DefaultSubstitutePath[512];
    WCHAR LogFilePath[512];
} MINIFILTER_CONFIGURATION, *PMINIFILTER_CONFIGURATION;

// Global minifilter context
extern MINIFILTER_CONTEXT g_MinifilterContext;

#ifdef __cplusplus
}
#endif