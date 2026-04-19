// AntiDetectionAnalyzer.h: Anti-Detection Analyzer component implementation
// Implements Requirement 3: Anti-Detection Mechanism Analysis
// 
// Purpose: Analysis of anti-detection mechanisms and evasion techniques
// Implementation: Behavioral analysis engine with pattern recognition
//
// Interfaces:
// - AnalyzeDataSubstitution(): Detects clean data substitution patterns
// - DetectSSDTHooks(): Identifies System Service Descriptor Table hooks
// - AnalyzeFileHiding(): Studies rootkit file hiding techniques
// - MonitorKernelObjects(): Tracks kernel object manipulation
// - GenerateBehavioralReports(): Creates comprehensive analysis reports

#pragma once

#include "pch.h"
#include "ModernCpp.h"

namespace BootkitFramework {

// Forward declarations
class AntiDetectionAnalyzer;
class DataSubstitutionDetector;
class SSDT_HookDetector;
class FileHidingAnalyzer;
class KernelObjectMonitor;
class BehavioralAnalysisEngine;

// Data substitution detection structures
typedef struct _DATA_SUBSTITUTION_PATTERN {
    ULONG PatternId;
    WCHAR PatternName[64];
    ULONG PatternType;  // 0 = IRP_MJ_READ, 1 = IRP_MJ_WRITE, 2 = IRP_MJ_DEVICE_CONTROL
    ULONG PatternFlags;
    ULONG DetectionThreshold;
    ULONG ConfidenceLevel;
} DATA_SUBSTITUTION_PATTERN, *PDATA_SUBSTITUTION_PATTERN;

typedef struct _DATA_SUBSTITUTION_DETECTION {
    ULONG DetectionId;
    ULONG PatternId;
    ULONG ProcessId;
    ULONG ThreadId;
    WCHAR ProcessName[256];
    WCHAR FilePath[512];
    LARGE_INTEGER DetectionTime;
    ULONG DetectionFlags;
    ULONG ConfidenceScore;
    ULONG DataSize;
    UCHAR SampleData[256];
} DATA_SUBSTITUTION_DETECTION, *PDATA_SUBSTITUTION_DETECTION;

// SSDT hook detection structures
typedef struct _SSDT_ENTRY_INFO {
    ULONG ServiceNumber;
    PVOID OriginalAddress;
    PVOID CurrentAddress;
    PVOID ModuleBase;
    WCHAR ModuleName[64];
    WCHAR FunctionName[64];
    ULONG HookType;  // 0 = Inline, 1 = IAT, 2 = EAT, 3 = SSDT
    ULONG HookFlags;
    BOOLEAN IsHooked;
    ULONG HookConfidence;
} SSDT_ENTRY_INFO, *PSSDT_ENTRY_INFO;

typedef struct _SSDT_HOOK_DETECTION {
    ULONG DetectionId;
    ULONG ServiceNumber;
    PVOID OriginalAddress;
    PVOID HookedAddress;
    PVOID HookModuleBase;
    WCHAR HookModuleName[64];
    WCHAR HookFunctionName[64];
    ULONG HookType;
    ULONG HookFlags;
    LARGE_INTEGER DetectionTime;
    ULONG DetectionConfidence;
    ULONG ProcessId;
    WCHAR ProcessName[256];
} SSDT_HOOK_DETECTION, *PSSDT_HOOK_DETECTION;

// File hiding analysis structures
typedef struct _FILE_HIDING_TECHNIQUE {
    ULONG TechniqueId;
    WCHAR TechniqueName[64];
    ULONG TechniqueType;  // 0 = Direct Kernel Object Manipulation, 1 = Filter Driver, 2 = Hook-based
    ULONG TechniqueFlags;
    ULONG DetectionComplexity;
    WCHAR Description[256];
} FILE_HIDING_TECHNIQUE, *PFILE_HIDING_TECHNIQUE;

typedef struct _FILE_HIDING_DETECTION {
    ULONG DetectionId;
    ULONG TechniqueId;
    WCHAR FilePath[512];
    WCHAR HiddenPath[512];
    ULONG FileSize;
    LARGE_INTEGER FileCreationTime;
    LARGE_INTEGER FileModificationTime;
    LARGE_INTEGER DetectionTime;
    ULONG DetectionFlags;
    ULONG ConfidenceScore;
    ULONG ProcessId;
    WCHAR ProcessName[256];
    WCHAR DriverName[64];
} FILE_HIDING_DETECTION, *PFILE_HIDING_DETECTION;

// Kernel object manipulation structures
typedef struct _KERNEL_OBJECT_INFO {
    ULONG ObjectType;  // 0 = Process, 1 = Thread, 2 = File, 3 = Driver, 4 = Registry
    PVOID ObjectAddress;
    ULONG ObjectSize;
    ULONG ReferenceCount;
    ULONG HandleCount;
    WCHAR ObjectName[256];
    ULONG ObjectFlags;
    LARGE_INTEGER CreationTime;
} KERNEL_OBJECT_INFO, *PKERNEL_OBJECT_INFO;

typedef struct _KERNEL_OBJECT_MANIPULATION {
    ULONG ManipulationId;
    ULONG ObjectType;
    PVOID ObjectAddress;
    WCHAR ObjectName[256];
    ULONG ManipulationType;  // 0 = Reference Count, 1 = Handle Count, 2 = Object Attributes, 3 = Security Descriptor
    ULONG OriginalValue;
    ULONG ModifiedValue;
    LARGE_INTEGER ManipulationTime;
    ULONG ProcessId;
    WCHAR ProcessName[256];
    ULONG ConfidenceScore;
} KERNEL_OBJECT_MANIPULATION, *PKERNEL_OBJECT_MANIPULATION;

// Behavioral analysis structures
typedef struct _BEHAVIORAL_PATTERN {
    ULONG PatternId;
    WCHAR PatternName[64];
    ULONG PatternType;  // 0 = Anti-Detection, 1 = Evasion, 2 = Stealth, 3 = Persistence
    ULONG PatternFlags;
    ULONG PatternWeight;
    WCHAR PatternDescription[512];
    ULONG DetectionRules[16];
    ULONG RuleCount;
} BEHAVIORAL_PATTERN, *PBEHAVIORAL_PATTERN;

typedef struct _BEHAVIORAL_ANALYSIS_RESULT {
    ULONG AnalysisId;
    ULONG PatternId;
    ULONG DetectionScore;
    ULONG ConfidenceLevel;
    LARGE_INTEGER AnalysisTime;
    ULONG ProcessId;
    WCHAR ProcessName[256];
    WCHAR PatternName[64];
    ULONG RelatedDetections[32];
    ULONG RelatedDetectionCount;
    WCHAR AnalysisSummary[1024];
} BEHAVIORAL_ANALYSIS_RESULT, *PBEHAVIORAL_ANALYSIS_RESULT;

// Anti-Detection Analyzer context
typedef struct _ANTI_DETECTION_CONTEXT {
    FAST_MUTEX ContextLock;
    BOOLEAN Initialized;
    BOOLEAN MonitoringEnabled;
    
    // Data substitution detection
    ULONG DataSubstitutionPatternCount;
    PDATA_SUBSTITUTION_PATTERN DataSubstitutionPatterns;
    ULONG DataSubstitutionDetectionCount;
    PDATA_SUBSTITUTION_DETECTION DataSubstitutionDetections;
    
    // SSDT hook detection
    ULONG SSDTEntryCount;
    PSSDT_ENTRY_INFO SSDTEntries;
    ULONG SSDTDetectionCount;
    PSSDT_HOOK_DETECTION SSDTDetections;
    
    // File hiding analysis
    ULONG FileHidingTechniqueCount;
    PFILE_HIDING_TECHNIQUE FileHidingTechniques;
    ULONG FileHidingDetectionCount;
    PFILE_HIDING_DETECTION FileHidingDetections;
    
    // Kernel object monitoring
    ULONG KernelObjectCount;
    PKERNEL_OBJECT_INFO KernelObjects;
    ULONG KernelManipulationCount;
    PKERNEL_OBJECT_MANIPULATION KernelManipulations;
    
    // Behavioral analysis
    ULONG BehavioralPatternCount;
    PBEHAVIORAL_PATTERN BehavioralPatterns;
    ULONG BehavioralAnalysisCount;
    PBEHAVIORAL_ANALYSIS_RESULT BehavioralAnalyses;
    
    // Statistics
    ULONG TotalAnalysesPerformed;
    ULONG TotalDetectionsFound;
    ULONG HighConfidenceDetections;
    ULONG MediumConfidenceDetections;
    ULONG LowConfidenceDetections;
    
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastAnalysisTime;
} ANTI_DETECTION_CONTEXT, *PANTI_DETECTION_CONTEXT;

// Anti-Detection Analyzer class
class AntiDetectionAnalyzer {
private:
    PANTI_DETECTION_CONTEXT m_context;
    BOOLEAN m_initialized;
    
    // Sub-components
    std::unique_ptr<DataSubstitutionDetector> m_dataSubstitutionDetector;
    std::unique_ptr<SSDT_HookDetector> m_ssdtHookDetector;
    std::unique_ptr<FileHidingAnalyzer> m_fileHidingAnalyzer;
    std::unique_ptr<KernelObjectMonitor> m_kernelObjectMonitor;
    std::unique_ptr<BehavioralAnalysisEngine> m_behavioralAnalysisEngine;
    
public:
    AntiDetectionAnalyzer();
    ~AntiDetectionAnalyzer();
    
    // Initialization and cleanup
    NTSTATUS Initialize(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject);
    NTSTATUS Cleanup();
    
    // Core analysis functions
    NTSTATUS AnalyzeDataSubstitution(PIRP Irp, PIO_STACK_LOCATION IrpStack);
    NTSTATUS DetectSSDTHooks();
    NTSTATUS AnalyzeFileHiding(PIRP Irp, PIO_STACK_LOCATION IrpStack);
    NTSTATUS MonitorKernelObjects();
    NTSTATUS GenerateBehavioralReports(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    
    // Configuration functions
    NTSTATUS EnableMonitoring(BOOLEAN Enable);
    NTSTATUS ResetStatistics();
    NTSTATUS GetStatistics(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetDetections(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    
    // Pattern management
    NTSTATUS AddDataSubstitutionPattern(PDATA_SUBSTITUTION_PATTERN Pattern);
    NTSTATUS AddFileHidingTechnique(PFILE_HIDING_TECHNIQUE Technique);
    NTSTATUS AddBehavioralPattern(PBEHAVIORAL_PATTERN Pattern);
    
    // Utility functions
    BOOLEAN IsInitialized() const { return m_initialized; }
    BOOLEAN IsMonitoringEnabled() const { return m_context && m_context->MonitoringEnabled; }
    
private:
    NTSTATUS InitializeContext();
    NTSTATUS CleanupContext();
    NTSTATUS InitializeDefaultPatterns();
    NTSTATUS InitializeDefaultTechniques();
    NTSTATUS InitializeDefaultBehavioralPatterns();
    
    // Helper functions
    NTSTATUS AddDetectionToContext(PDATA_SUBSTITUTION_DETECTION Detection);
    NTSTATUS AddSSDTDetectionToContext(PSSDT_HOOK_DETECTION Detection);
    NTSTATUS AddFileHidingDetectionToContext(PFILE_HIDING_DETECTION Detection);
    NTSTATUS AddKernelManipulationToContext(PKERNEL_OBJECT_MANIPULATION Manipulation);
    NTSTATUS AddBehavioralAnalysisToContext(PBEHAVIORAL_ANALYSIS_RESULT Analysis);
    
    // Memory management
    PVOID AllocateDetectionMemory(ULONG Size);
    VOID FreeDetectionMemory(PVOID Memory);
};

// Data Substitution Detector sub-component
class DataSubstitutionDetector {
private:
    PANTI_DETECTION_CONTEXT m_context;
    
public:
    DataSubstitutionDetector(PANTI_DETECTION_CONTEXT Context);
    ~DataSubstitutionDetector();
    
    NTSTATUS Initialize();
    NTSTATUS Cleanup();
    
    NTSTATUS AnalyzeIrp(PIRP Irp, PIO_STACK_LOCATION IrpStack);
    NTSTATUS CheckForDataSubstitution(PUCHAR Data, ULONG DataSize, WCHAR* FilePath);
    NTSTATUS GetPatterns(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetDetections(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    
private:
    NTSTATUS InitializeDefaultPatterns();
    NTSTATUS PatternMatch(PUCHAR Data, ULONG DataSize, PDATA_SUBSTITUTION_PATTERN Pattern);
    NTSTATUS CalculateConfidence(PDATA_SUBSTITUTION_DETECTION Detection);
};

// SSDT Hook Detector sub-component
class SSDT_HookDetector {
private:
    PANTI_DETECTION_CONTEXT m_context;
    PVOID m_ssdtBase;
    ULONG m_ssdtEntryCount;
    
public:
    SSDT_HookDetector(PANTI_DETECTION_CONTEXT Context);
    ~SSDT_HookDetector();
    
    NTSTATUS Initialize();
    NTSTATUS Cleanup();
    
    NTSTATUS DetectHooks();
    NTSTATUS GetSSDTEntries(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetDetections(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS ScanForInlineHooks();
    NTSTATUS ScanForIATHooks();
    NTSTATUS ScanForEATHooks();
    
private:
    NTSTATUS LocateSSDT();
    NTSTATUS EnumerateSSDTEntries();
    NTSTATUS CheckEntryForHook(PSSDT_ENTRY_INFO Entry);
    NTSTATUS ResolveSymbol(PVOID Address, WCHAR* ModuleName, WCHAR* FunctionName);
    NTSTATUS CalculateHookConfidence(PSSDT_HOOK_DETECTION Detection);
};

// File Hiding Analyzer sub-component
class FileHidingAnalyzer {
private:
    PANTI_DETECTION_CONTEXT m_context;
    
public:
    FileHidingAnalyzer(PANTI_DETECTION_CONTEXT Context);
    ~FileHidingAnalyzer();
    
    NTSTATUS Initialize();
    NTSTATUS Cleanup();
    
    NTSTATUS AnalyzeFileSystem(PIRP Irp, PIO_STACK_LOCATION IrpStack);
    NTSTATUS CheckForFileHiding(WCHAR* FilePath);
    NTSTATUS GetTechniques(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetDetections(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS ScanFileSystemForHiddenFiles();
    
private:
    NTSTATUS InitializeDefaultTechniques();
    NTSTATUS TechniqueMatch(WCHAR* FilePath, PFILE_HIDING_TECHNIQUE Technique);
    NTSTATUS CalculateDetectionConfidence(PFILE_HIDING_DETECTION Detection);
    NTSTATUS CheckForDKOM(WCHAR* FilePath);
    NTSTATUS CheckForFilterDriver(WCHAR* FilePath);
    NTSTATUS CheckForHookBasedHiding(WCHAR* FilePath);
};

// Kernel Object Monitor sub-component
class KernelObjectMonitor {
private:
    PANTI_DETECTION_CONTEXT m_context;
    
public:
    KernelObjectMonitor(PANTI_DETECTION_CONTEXT Context);
    ~KernelObjectMonitor();
    
    NTSTATUS Initialize();
    NTSTATUS Cleanup();
    
    NTSTATUS MonitorObjects();
    NTSTATUS CheckForManipulations();
    NTSTATUS GetObjects(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetManipulations(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS ScanForObjectManipulation();
    
private:
    NTSTATUS EnumerateKernelObjects();
    NTSTATUS CheckObjectForManipulation(PKERNEL_OBJECT_INFO Object);
    NTSTATUS CalculateManipulationConfidence(PKERNEL_OBJECT_MANIPULATION Manipulation);
    NTSTATUS CheckReferenceCountManipulation(PKERNEL_OBJECT_INFO Object);
    NTSTATUS CheckHandleCountManipulation(PKERNEL_OBJECT_INFO Object);
    NTSTATUS CheckSecurityDescriptorManipulation(PKERNEL_OBJECT_INFO Object);
};

// Behavioral Analysis Engine sub-component
class BehavioralAnalysisEngine {
private:
    PANTI_DETECTION_CONTEXT m_context;
    
public:
    BehavioralAnalysisEngine(PANTI_DETECTION_CONTEXT Context);
    ~BehavioralAnalysisEngine();
    
    NTSTATUS Initialize();
    NTSTATUS Cleanup();
    
    NTSTATUS AnalyzeBehavior();
    NTSTATUS GetPatterns(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS GetAnalyses(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    NTSTATUS PerformCorrelationAnalysis();
    NTSTATUS GenerateReport(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
    
private:
    NTSTATUS InitializeDefaultPatterns();
    NTSTATUS PatternMatch(ULONG DetectionType, ULONG DetectionId, PBEHAVIORAL_PATTERN Pattern);
    NTSTATUS CalculateAnalysisScore(PBEHAVIORAL_ANALYSIS_RESULT Analysis);
    NTSTATUS CorrelateDetections(PBEHAVIORAL_ANALYSIS_RESULT Analysis);
    NTSTATUS GenerateAnalysisSummary(PBEHAVIORAL_ANALYSIS_RESULT Analysis);
};

// Global context
extern ANTI_DETECTION_CONTEXT g_AntiDetectionContext;

// Global instance
extern std::unique_ptr<AntiDetectionAnalyzer> g_AntiDetectionAnalyzer;

// Public interface functions
NTSTATUS InitializeAntiDetectionAnalyzer(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject);
NTSTATUS CleanupAntiDetectionAnalyzer();
NTSTATUS AntiDetectionAnalyzeIrp(PIRP Irp, PIO_STACK_LOCATION IrpStack);
NTSTATUS AntiDetectionGetStatistics(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
NTSTATUS AntiDetectionGetDetections(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG BytesReturned);
NTSTATUS AntiDetectionEnableMonitoring(BOOLEAN Enable);
NTSTATUS AntiDetectionResetStatistics();

// IOCTL definitions for Anti-Detection Analyzer
#define IOCTL_ANTIDETECTION_ENABLE_MONITORING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_DISABLE_MONITORING     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_GET_STATISTICS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_GET_DETECTIONS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_RESET_STATISTICS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_ANALYZE_IRP            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_DETECT_SSDT_HOOKS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_ANALYZE_FILE_HIDING   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_MONITOR_KERNEL_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIDETECTION_GENERATE_REPORT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)

} // namespace BootkitFramework