#pragma once

// Self-Protection System
// Purpose: Advanced self-protection mechanisms to detect and respond to security analysis
// Implementation: Code integrity checks, anti-tampering mechanisms, automatic termination, behavioral analysis
//
// This component implements Requirement 18: Advanced Evasion and Anti-Analysis
// Framework uses real self-protection techniques to detect and respond to security tools
//
// Educational Security Research Purpose Only

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <winioctl.h>
#include <winternl.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <winnt.h>
#include <ntifs.h>
#include <ntdddisk.h>
#include <intrin.h>
#include <wmiutils.h>
#include <winuser.h>
#include <wingdi.h>
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "ModernCpp.h"

// Forward declarations
typedef struct _SELF_PROTECTION_STATE SELF_PROTECTION_STATE;
typedef struct _CODE_INTEGRITY_CONFIG CODE_INTEGRITY_CONFIG;
typedef struct _ANTI_TAMPERING_CONFIG ANTI_TAMPERING_CONFIG;
typedef struct _AUTOMATIC_TERMINATION_CONFIG AUTOMATIC_TERMINATION_CONFIG;
typedef struct _BEHAVIORAL_ANALYSIS_CONFIG BEHAVIORAL_ANALYSIS_CONFIG;
typedef struct _MONITORING_RESPONSE_CONFIG MONITORING_RESPONSE_CONFIG;

// Code Integrity Configuration Structure
struct _CODE_INTEGRITY_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN CRC32Enabled;
    BOOLEAN SHA256Enabled;
    BOOLEAN RealTimeVerification;
    ULONG CheckInterval;
    ULONG MaxIntegrityViolations;
    FAST_MUTEX IntegrityLock;
    ULONG IntegrityViolations;
    ULONGLONG LastCheckTime;
    WCHAR CurrentHash[65]; // SHA-256 hash string
    DWORD CurrentCRC32;
};

// Anti-Tampering Configuration Structure
struct _ANTI_TAMPERING_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN CodeSigningVerification;
    BOOLEAN MemoryIntegrityCheck;
    BOOLEAN FileIntegrityCheck;
    BOOLEAN RegistryIntegrityCheck;
    BOOLEAN DriverIntegrityCheck;
    FAST_MUTEX TamperingLock;
    ULONG TamperingAttempts;
    ULONG MaxTamperingAttempts;
    WCHAR LastTamperingSource[256];
};

// Automatic Termination Configuration Structure
struct _AUTOMATIC_TERMINATION_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN SecureTermination;
    BOOLEAN EvidenceRemoval;
    BOOLEAN PersistenceRemoval;
    ULONG TerminationDelay;
    ULONG MaxTerminationAttempts;
    FAST_MUTEX TerminationLock;
    BOOLEAN TerminationTriggered;
    ULONG TerminationCount;
    WCHAR TerminationReason[256];
};

// Behavioral Analysis Configuration Structure
struct _BEHAVIORAL_ANALYSIS_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN MouseMovementAnalysis;
    BOOLEAN KeyboardTimingAnalysis;
    BOOLEAN ProcessBehaviorAnalysis;
    BOOLEAN NetworkBehaviorAnalysis;
    BOOLEAN UserInteractionAnalysis;
    FAST_MUTEX BehavioralLock;
    ULONG SuspiciousBehaviorCount;
    ULONG MaxSuspiciousBehaviors;
    WCHAR CurrentBehaviorProfile[64];
    ULONGLONG AnalysisStartTime;
};

// Monitoring and Response Configuration Structure
struct _MONITORING_RESPONSE_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN RealTimeMonitoring;
    BOOLEAN ThreatResponseActive;
    BOOLEAN ForensicCountermeasures;
    BOOLEAN EvasionTechniques;
    FAST_MUTEX MonitoringLock;
    ULONG ThreatEvents;
    ULONG ResponseActions;
    WCHAR CurrentThreatLevel[32];
    ULONGLONG LastResponseTime;
};

// Self-Protection State Structure
struct _SELF_PROTECTION_STATE {
    // Configuration structures
    CODE_INTEGRITY_CONFIG CodeIntegrityConfig;
    ANTI_TAMPERING_CONFIG AntiTamperingConfig;
    AUTOMATIC_TERMINATION_CONFIG AutomaticTerminationConfig;
    BEHAVIORAL_ANALYSIS_CONFIG BehavioralAnalysisConfig;
    MONITORING_RESPONSE_CONFIG MonitoringResponseConfig;
    
    // System state
    BOOLEAN SystemActive;
    BOOLEAN ProtectionActive;
    BOOLEAN EmergencyMode;
    FAST_MUTEX SystemLock;
    ULONG SystemState;
    WCHAR SystemStatus[64];
    
    // Statistics
    ULONG TotalIntegrityChecks;
    ULONG TotalTamperingAttempts;
    ULONG TotalTerminations;
    ULONG TotalBehavioralEvents;
    ULONG TotalThreatResponses;
    ULONGLONG TotalRuntime;
    
    // Resource handles
    HANDLE ProtectionThread;
    HANDLE MonitoringThread;
    HANDLE BehavioralThread;
    KEVENT ShutdownEvent;
    KEVENT ResponseEvent;
};

// Function declarations
NTSTATUS 
InitializeSelfProtectionSystem(
    _Out_ SELF_PROTECTION_STATE** State
);

NTSTATUS 
StartSelfProtectionSystem(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
StopSelfProtectionSystem(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
CleanupSelfProtectionSystem(
    _In_ SELF_PROTECTION_STATE* State
);

// Code Integrity Functions
NTSTATUS 
VerifyCodeIntegrity(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PVOID CodeAddress,
    _In_ SIZE_T CodeSize
);

NTSTATUS 
CalculateCRC32Hash(
    _In_ PVOID Data,
    _In_ SIZE_T Size,
    _Out_ PDWORD CRC32Hash
);

NTSTATUS 
CalculateSHA256Hash(
    _In_ PVOID Data,
    _In_ SIZE_T Size,
    _Out_ PUCHAR HashBuffer,
    _In_ SIZE_T BufferSize
);

NTSTATUS 
VerifyMemoryIntegrity(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PVOID MemoryRegion,
    _In_ SIZE_T RegionSize
);

// Anti-Tampering Functions
NTSTATUS 
VerifyCodeSigning(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR FilePath
);

NTSTATUS 
CheckFileIntegrity(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR FilePath
);

NTSTATUS 
CheckRegistryIntegrity(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR RegistryPath
);

NTSTATUS 
CheckDriverIntegrity(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR DriverName
);

// Automatic Termination Functions
NTSTATUS 
InitiateSecureTermination(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR Reason
);

NTSTATUS 
RemoveForensicEvidence(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
RemovePersistenceMechanisms(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
ExecuteEmergencyShutdown(
    _In_ SELF_PROTECTION_STATE* State
);

// Behavioral Analysis Functions
NTSTATUS 
AnalyzeMouseMovement(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
AnalyzeKeyboardTiming(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
AnalyzeProcessBehavior(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ DWORD ProcessId
);

NTSTATUS 
AnalyzeNetworkBehavior(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
AnalyzeUserInteraction(
    _In_ SELF_PROTECTION_STATE* State
);

// Monitoring and Response Functions
NTSTATUS 
StartRealTimeMonitoring(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
ExecuteThreatResponse(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR ThreatType,
    _In_ ULONG ThreatSeverity
);

NTSTATUS 
ActivateForensicCountermeasures(
    _In_ SELF_PROTECTION_STATE* State
);

NTSTATUS 
ActivateEvasionTechniques(
    _In_ SELF_PROTECTION_STATE* State
);

// Utility Functions
NTSTATUS 
GetSystemProtectionStatus(
    _In_ SELF_PROTECTION_STATE* State,
    _Out_ PWCHAR StatusBuffer,
    _In_ SIZE_T BufferSize
);

NTSTATUS 
GetProtectionStatistics(
    _In_ SELF_PROTECTION_STATE* State,
    _Out_ PULONG IntegrityChecks,
    _Out_ PULONG TamperingAttempts,
    _Out_ PULONG Terminations,
    _Out_ PULONG BehavioralEvents,
    _Out_ PULONG ThreatResponses
);

NTSTATUS 
SetProtectionLevel(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ ULONG ProtectionLevel
);

NTSTATUS 
ConfigureProtectionParameters(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ ULONG CheckInterval,
    _In_ ULONG MaxViolations,
    _In_ ULONG TerminationDelay,
    _In_ ULONG MaxSuspiciousBehaviors
);

// Thread Functions
VOID 
ProtectionMonitoringThread(
    _In_ PVOID Context
);

VOID 
BehavioralAnalysisThread(
    _In_ PVOID Context
);

VOID 
ThreatResponseThread(
    _In_ PVOID Context
);

// Callback Functions
NTSTATUS 
IntegrityViolationCallback(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR ViolationType,
    _In_ PWCHAR ViolationDetails
);

NTSTATUS 
TamperingDetectionCallback(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR TamperingSource,
    _In_ PWCHAR TamperingMethod
);

NTSTATUS 
BehavioralAnomalyCallback(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR AnomalyType,
    _In_ PWCHAR AnomalyDetails
);

NTSTATUS 
ThreatResponseCallback(
    _In_ SELF_PROTECTION_STATE* State,
    _In_ PWCHAR ResponseType,
    _In_ PWCHAR ResponseDetails
);

// Constants
#define SELF_PROTECTION_TAG 'SPRT'
#define MAX_INTEGRITY_VIOLATIONS 5
#define MAX_TAMPERING_ATTEMPTS 3
#define MAX_SUSPICIOUS_BEHAVIORS 10
#define DEFAULT_CHECK_INTERVAL 60000 // 60 seconds
#define DEFAULT_TERMINATION_DELAY 5000 // 5 seconds
#define BEHAVIORAL_ANALYSIS_INTERVAL 30000 // 30 seconds

// Protection Levels
#define PROTECTION_LEVEL_DISABLED 0
#define PROTECTION_LEVEL_BASIC 1
#define PROTECTION_LEVEL_STANDARD 2
#define PROTECTION_LEVEL_ADVANCED 3
#define PROTECTION_LEVEL_MAXIMUM 4

// Threat Levels
#define THREAT_LEVEL_NONE 0
#define THREAT_LEVEL_LOW 1
#define THREAT_LEVEL_MEDIUM 2
#define THREAT_LEVEL_HIGH 3
#define THREAT_LEVEL_CRITICAL 4

// Response Actions
#define RESPONSE_ACTION_NONE 0
#define RESPONSE_ACTION_LOG 1
#define RESPONSE_ACTION_ALERT 2
#define RESPONSE_ACTION_EVASION 3
#define RESPONSE_ACTION_TERMINATION 4
#define RESPONSE_ACTION_DESTRUCTION 5