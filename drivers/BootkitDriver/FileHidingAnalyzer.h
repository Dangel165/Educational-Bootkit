// FileHidingAnalyzer.h: File Hiding Analysis System for Task 3.3
// Implements comprehensive file hiding analysis and IRP_MJ_DIRECTORY_CONTROL simulation
// for educational security research purposes only

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// File hiding analysis context structure
typedef struct _FILE_HIDING_CONTEXT {
    FAST_MUTEX AnalysisLock;
    LIST_ENTRY HiddenFileList;
    LIST_ENTRY DirectoryHookList;
    ULONG TotalFilesHidden;
    ULONG TotalDirectoriesAnalyzed;
    ULONG64 AnalysisStartTime;
    BOOLEAN AnalysisActive;
    BOOLEAN BufferManipulationEnabled;
    BOOLEAN RootkitBehaviorLogging;
    ULONG BufferManipulationCount;
    ULONG RootkitBehaviorCount;
} FILE_HIDING_CONTEXT, *PFILE_HIDING_CONTEXT;

// Hidden file entry structure
typedef struct _HIDDEN_FILE_ENTRY {
    LIST_ENTRY ListEntry;
    WCHAR FilePath[260];
    WCHAR FileName[256];
    ULONG64 FileSize;
    FILETIME CreationTime;
    FILETIME LastAccessTime;
    FILETIME LastWriteTime;
    ULONG FileAttributes;
    BOOLEAN HiddenByRootkit;
    ULONG HidingTechnique;
    ULONG64 HideTime;
    WCHAR HidingProcess[64];
} HIDDEN_FILE_ENTRY, *PHIDDEN_FILE_ENTRY;

// Directory hook entry structure
typedef struct _DIRECTORY_HOOK_ENTRY {
    LIST_ENTRY ListEntry;
    WCHAR DeviceName[64];
    WCHAR VolumeName[32];
    ULONG VolumeSerialNumber;
    PVOID OriginalDirectoryHandler;
    PVOID HookedDirectoryHandler;
    ULONG HookFlags;
    ULONG64 HookTime;
    BOOLEAN HookActive;
    ULONG FilesFiltered;
    ULONG DirectoriesFiltered;
} DIRECTORY_HOOK_ENTRY, *PDIRECTORY_HOOK_ENTRY;

// Result buffer manipulation context
typedef struct _RESULT_BUFFER_CONTEXT {
    PVOID OriginalBuffer;
    PVOID ModifiedBuffer;
    ULONG OriginalBufferSize;
    ULONG ModifiedBufferSize;
    ULONG EntriesRemoved;
    ULONG EntriesModified;
    BOOLEAN BufferModified;
    ULONG64 ModificationTime;
    WCHAR TargetPattern[64];
    ULONG FilteringTechnique;
} RESULT_BUFFER_CONTEXT, *PRESULT_BUFFER_CONTEXT;

// Rootkit behavior log entry
typedef struct _ROOTKIT_BEHAVIOR_LOG {
    LIST_ENTRY ListEntry;
    ULONG BehaviorType;
    WCHAR BehaviorDescription[256];
    WCHAR TargetPath[260];
    ULONG64 Timestamp;
    ULONG ProcessId;
    WCHAR ProcessName[64];
    BOOLEAN DetectedBySecurity;
    ULONG DetectionMethod;
    WCHAR DetectionTool[64];
} ROOTKIT_BEHAVIOR_LOG, *PROOTKIT_BEHAVIOR_LOG;

// File system filter driver techniques
typedef struct _FILTER_DRIVER_TECHNIQUE {
    LIST_ENTRY ListEntry;
    ULONG TechniqueId;
    WCHAR TechniqueName[64];
    WCHAR Description[512];
    BOOLEAN Implemented;
    ULONG ImplementationComplexity;
    WCHAR ExampleCodePath[260];
    ULONG SecurityImpact;
} FILTER_DRIVER_TECHNIQUE, *PFILTER_DRIVER_TECHNIQUE;

// File hiding analysis statistics
typedef struct _FILE_HIDING_STATISTICS {
    ULONG TotalDirectoriesMonitored;
    ULONG TotalFilesAnalyzed;
    ULONG HiddenFilesDetected;
    ULONG RootkitFilesDetected;
    ULONG BufferManipulationsPerformed;
    ULONG RootkitBehaviorsLogged;
    ULONG FilterDriverTechniquesAnalyzed;
    ULONG64 AnalysisDuration;
    BOOLEAN AnalysisComplete;
    ULONG DetectionAccuracy;
    ULONG FalsePositives;
    ULONG FalseNegatives;
} FILE_HIDING_STATISTICS, *PFILE_HIDING_STATISTICS;

// Directory enumeration result structure
typedef struct _DIRECTORY_ENUM_RESULT {
    PVOID DirectoryBuffer;
    ULONG BufferSize;
    ULONG EntriesReturned;
    ULONG EntriesTotal;
    ULONG FileInformationClass;
    BOOLEAN ResultModified;
    ULONG ModifiedEntries;
    ULONG RemovedEntries;
    ULONG64 QueryTime;
    WCHAR QueryPath[260];
} DIRECTORY_ENUM_RESULT, *PDIRECTORY_ENUM_RESULT;

// File hiding technique enumeration
typedef enum _FILE_HIDING_TECHNIQUE {
    HIDING_TECHNIQUE_NONE = 0,
    HIDING_TECHNIQUE_DIRECTORY_FILTERING,
    HIDING_TECHNIQUE_RESULT_BUFFER_MANIPULATION,
    HIDING_TECHNIQUE_FILE_SYSTEM_FILTER,
    HIDING_TECHNIQUE_KERNEL_HOOK,
    HIDING_TECHNIQUE_ALTERNATE_DATA_STREAM,
    HIDING_TECHNIQUE_FILE_ATTRIBUTE_MANIPULATION,
    HIDING_TECHNIQUE_DKOM_PROCESS_HIDING,
    HIDING_TECHNIQUE_MEMORY_ONLY_FILES,
    HIDING_TECHNIQUE_MAX
} FILE_HIDING_TECHNIQUE;

// Rootkit behavior types
typedef enum _ROOTKIT_BEHAVIOR_TYPE {
    BEHAVIOR_FILE_HIDING = 0,
    BEHAVIOR_PROCESS_HIDING,
    BEHAVIOR_REGISTRY_HIDING,
    BEHAVIOR_NETWORK_HIDING,
    BEHAVIOR_PORT_HIDING,
    BEHAVIOR_SERVICE_HIDING,
    BEHAVIOR_DRIVER_HIDING,
    BEHAVIOR_MEMORY_HIDING,
    BEHAVIOR_API_HOOKING,
    BEHAVIOR_SSDT_HOOKING,
    BEHAVIOR_IDT_HOOKING,
    BEHAVIOR_MAX
} ROOTKIT_BEHAVIOR_TYPE;

// Function declarations for file hiding analysis

// Initialization and cleanup
NTSTATUS InitializeFileHidingAnalysis();
VOID CleanupFileHidingAnalysis();

// Directory hook management
NTSTATUS InstallDirectoryHook(
    _In_ PDEVICE_OBJECT TargetDevice,
    _In_ ULONG HookFlags
);

NTSTATUS RemoveDirectoryHook(
    _In_ PDEVICE_OBJECT TargetDevice
);

// Result buffer manipulation
NTSTATUS ManipulateDirectoryResultBuffer(
    _In_ PVOID OriginalBuffer,
    _In_ ULONG BufferSize,
    _In_ ULONG FileInformationClass,
    _Out_ PVOID* ModifiedBuffer,
    _Out_ PULONG ModifiedBufferSize,
    _In_ PCWSTR FilterPattern
);

NTSTATUS RestoreDirectoryResultBuffer(
    _In_ PVOID ModifiedBuffer
);

// Rootkit behavior logging
NTSTATUS LogRootkitBehavior(
    _In_ ULONG BehaviorType,
    _In_ PCWSTR BehaviorDescription,
    _In_ PCWSTR TargetPath,
    _In_ ULONG ProcessId,
    _In_ PCWSTR ProcessName
);

NTSTATUS GetRootkitBehaviorLog(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReturned
);

// File hiding detection
NTSTATUS AnalyzeDirectoryForHiddenFiles(
    _In_ PCWSTR DirectoryPath,
    _Out_ PHIDDEN_FILE_ENTRY* HiddenFiles,
    _Out_ PULONG HiddenFileCount
);

BOOLEAN IsFileHiddenByRootkit(
    _In_ PCWSTR FilePath,
    _Out_ PULONG HidingTechnique
);

// Filter driver technique analysis
NTSTATUS AnalyzeFilterDriverTechniques(
    _Out_ PFILTER_DRIVER_TECHNIQUE* Techniques,
    _Out_ PULONG TechniqueCount
);

NTSTATUS ImplementFilterDriverTechnique(
    _In_ ULONG TechniqueId,
    _Out_ PULONG ImplementationStatus
);

// Statistics and reporting
NTSTATUS GetFileHidingStatistics(
    _Out_ PFILE_HIDING_STATISTICS Statistics
);

NTSTATUS ResetFileHidingStatistics();

// Educational examples
NTSTATUS GenerateFileHidingExample(
    _In_ ULONG ExampleType,
    _Out_ PVOID* ExampleCode,
    _Out_ PULONG ExampleSize
);

NTSTATUS GenerateRootkitAnalysisReport(
    _Out_ PVOID* ReportBuffer,
    _Out_ PULONG ReportSize
);

// Utility functions
BOOLEAN IsFileHidingAnalysisActive();
NTSTATUS EnableFileHidingAnalysis(_In_ BOOLEAN Enable);
NTSTATUS SetBufferManipulationMode(_In_ BOOLEAN Enable);
NTSTATUS SetRootkitLoggingMode(_In_ BOOLEAN Enable);

// Advanced analysis functions
NTSTATUS PerformDeepFileSystemAnalysis(
    _In_ PCWSTR RootPath,
    _Out_ PDIRECTORY_ENUM_RESULT* AnalysisResults,
    _Out_ PULONG ResultCount
);

NTSTATUS DetectAdvancedHidingTechniques(
    _In_ PCWSTR TargetPath,
    _Out_ PROOTKIT_BEHAVIOR_LOG* DetectedBehaviors,
    _Out_ PULONG BehaviorCount
);

// IOCTL codes for file hiding analysis control
#define IOCTL_FILEHIDING_ENABLE_ANALYSIS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_DISABLE_ANALYSIS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_GET_STATISTICS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_RESET_STATISTICS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_ANALYZE_DIRECTORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x914, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_LOG_BEHAVIOR         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x915, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_GET_BEHAVIOR_LOG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x916, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_MANIPULATE_BUFFER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x917, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_GENERATE_EXAMPLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x918, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILEHIDING_DETECT_TECHNIQUES   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x919, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Global context
extern FILE_HIDING_CONTEXT g_FileHidingContext;

#ifdef __cplusplus
}
#endif