// KernelHookFramework.h: Kernel Hook Implementation Framework for Task 2.2
// Implements inline hooking, SSDT hooking, and comprehensive hook management system

#pragma once

#include "pch.h"
#include "ModernCpp.h"
#include "MemoryManagement.h"
#include "Concurrency.h"

namespace BootkitFramework {

// Hook types enumeration
enum class HookType {
    InlineHook,
    SSDT_Hook,
    IAT_Hook,
    EAT_Hook,
    IDT_Hook,
    IRP_Hook,
    Unknown
};

// Hook status enumeration
enum class HookStatus {
    NotInstalled,
    Installed,
    Active,
    Suspended,
    Removed,
    Error
};

// Memory protection flags for VirtualProtect operations
enum class MemoryProtection {
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400
};

// Hook descriptor structure
struct HookDescriptor {
    HookType Type;
    HookStatus Status;
    PVOID OriginalFunction;
    PVOID HookFunction;
    PVOID Trampoline;
    SIZE_T HookSize;
    ULONG_PTR OriginalBytes[16];  // Store original bytes for restoration
    SIZE_T OriginalBytesCount;
    ULONG_PTR HookedModuleBase;
    ULONG_PTR HookedFunctionRVA;
    CHAR FunctionName[64];
    CHAR ModuleName[32];
    ULONG Flags;
    LARGE_INTEGER InstallationTime;
    LARGE_INTEGER LastAccessTime;
    ULONG ReferenceCount;
    BOOLEAN IsPermanent;
    BOOLEAN IsHidden;
};

// SSDT entry structure
struct SSDTEntry {
    ULONG_PTR ServiceNumber;
    PVOID ServiceAddress;
    CHAR ServiceName[32];
    BOOLEAN IsHooked;
    HookDescriptor* HookDesc;
};

// Inline hook trampoline structure
struct InlineHookTrampoline {
    BYTE Prologue[32];           // Original function prologue
    BYTE JumpToOriginal[6];      // JMP to original function + prologue size
    BYTE JumpToHook[6];          // JMP to hook function
    SIZE_T PrologueSize;
    BOOLEAN IsValid;
};

// Hook manager context
class KernelHookManager {
private:
    KernelMutex m_Mutex;
    KernelList<HookDescriptor*> m_Hooks;
    KernelList<SSDTEntry*> m_SSDTEntries;
    ULONG m_MaxHooks;
    ULONG m_ActiveHooks;
    BOOLEAN m_IsInitialized;
    
    // Internal methods
    NTSTATUS InternalInstallInlineHook(
        _In_ PVOID TargetFunction,
        _In_ PVOID HookFunction,
        _Out_ HookDescriptor** HookDesc
    );
    
    NTSTATUS InternalInstallSSDTHook(
        _In_ ULONG ServiceNumber,
        _In_ PVOID HookFunction,
        _Out_ HookDescriptor** HookDesc
    );
    
    NTSTATUS InternalCreateTrampoline(
        _In_ PVOID TargetFunction,
        _Out_ InlineHookTrampoline* Trampoline
    );
    
    NTSTATUS InternalPatchMemory(
        _In_ PVOID TargetAddress,
        _In_ const BYTE* PatchBytes,
        _In_ SIZE_T PatchSize,
        _Out_ BYTE* OriginalBytes,
        _In_ SIZE_T OriginalBytesSize
    );
    
    NTSTATUS InternalChangeMemoryProtection(
        _In_ PVOID Address,
        _In_ SIZE_T Size,
        _In_ MemoryProtection NewProtection,
        _Out_ MemoryProtection* OldProtection
    );
    
    NTSTATUS InternalScanForHooks(
        _In_ PVOID ModuleBase,
        _In_ ULONG ModuleSize,
        _Out_ KernelList<HookDescriptor*>* DetectedHooks
    );
    
    NTSTATUS InternalAnalyzeSSDT(
        _Out_ KernelList<SSDTEntry*>* SSDTEntries
    );
    
public:
    KernelHookManager();
    ~KernelHookManager();
    
    // Initialization and cleanup
    NTSTATUS Initialize(ULONG MaxHooks = 256);
    NTSTATUS Cleanup();
    
    // Hook installation methods
    NTSTATUS InstallInlineHook(
        _In_ PCSTR ModuleName,
        _In_ PCSTR FunctionName,
        _In_ PVOID HookFunction,
        _Out_ HookDescriptor** HookDesc = nullptr
    );
    
    NTSTATUS InstallSSDTHook(
        _In_ ULONG ServiceNumber,
        _In_ PCSTR ServiceName,
        _In_ PVOID HookFunction,
        _Out_ HookDescriptor** HookDesc = nullptr
    );
    
    NTSTATUS InstallIRPHook(
        _In_ PDEVICE_OBJECT DeviceObject,
        _In_ ULONG MajorFunction,
        _In_ PVOID HookFunction,
        _Out_ HookDescriptor** HookDesc = nullptr
    );
    
    // Hook management methods
    NTSTATUS RemoveHook(_In_ HookDescriptor* HookDesc);
    NTSTATUS SuspendHook(_In_ HookDescriptor* HookDesc);
    NTSTATUS ResumeHook(_In_ HookDescriptor* HookDesc);
    NTSTATUS HideHook(_In_ HookDescriptor* HookDesc);
    NTSTATUS UnhideHook(_In_ HookDescriptor* HookDesc);
    
    // Hook detection and analysis
    NTSTATUS DetectInlineHooks(
        _In_ PCSTR ModuleName,
        _Out_ KernelList<HookDescriptor*>* DetectedHooks
    );
    
    NTSTATUS DetectSSDTHooks(
        _Out_ KernelList<HookDescriptor*>* DetectedHooks
    );
    
    NTSTATUS AnalyzeHookPatterns(
        _Out_ KernelList<HookDescriptor*>* SuspiciousHooks
    );
    
    // Memory protection manipulation
    NTSTATUS ProtectMemory(
        _In_ PVOID Address,
        _In_ SIZE_T Size,
        _In_ MemoryProtection Protection
    );
    
    NTSTATUS UnprotectMemory(
        _In_ PVOID Address,
        _In_ SIZE_T Size
    );
    
    // Utility methods
    NTSTATUS GetHookDescriptor(
        _In_ PVOID HookedFunction,
        _Out_ HookDescriptor** HookDesc
    );
    
    NTSTATUS EnumerateHooks(
        _Out_ KernelList<HookDescriptor*>* Hooks
    );
    
    NTSTATUS GetHookStatistics(
        _Out_ ULONG* TotalHooks,
        _Out_ ULONG* ActiveHooks,
        _Out_ ULONG* SuspendedHooks
    );
    
    // Safety and validation
    NTSTATUS ValidateHook(_In_ HookDescriptor* HookDesc);
    NTSTATUS BackupHookState(_In_ HookDescriptor* HookDesc);
    NTSTATUS RestoreHookState(_In_ HookDescriptor* HookDesc);
    
    // SSDT analysis
    NTSTATUS GetSSDTEntries(
        _Out_ KernelList<SSDTEntry*>* Entries
    );
    
    NTSTATUS FindSSDTEntryByNumber(
        _In_ ULONG ServiceNumber,
        _Out_ SSDTEntry** Entry
    );
    
    NTSTATUS FindSSDTEntryByName(
        _In_ PCSTR ServiceName,
        _Out_ SSDTEntry** Entry
    );
};

// Global hook manager instance
extern KernelUniquePtr<KernelHookManager> g_HookManager;

// Hook safety validator
class HookSafetyValidator {
private:
    KernelMutex m_Mutex;
    
public:
    NTSTATUS ValidateMemoryRegion(
        _In_ PVOID Address,
        _In_ SIZE_T Size,
        _In_ BOOLEAN IsExecutable
    );
    
    NTSTATUS ValidateFunctionProbe(
        _In_ PVOID FunctionAddress,
        _In_ SIZE_T ProbeSize
    );
    
    NTSTATUS CheckForAntiHookMechanisms(
        _In_ PVOID TargetAddress
    );
    
    NTSTATUS DetectDebuggerPresence();
    NTSTATUS DetectVMPresence();
    NTSTATUS DetectSandboxPresence();
};

// Hook installation utilities
NTSTATUS InstallKernelHook(
    _In_ HookType Type,
    _In_ PVOID Target,
    _In_ PVOID Hook,
    _Out_ HookDescriptor** HookDesc = nullptr
);

NTSTATUS RemoveKernelHook(_In_ HookDescriptor* HookDesc);
NTSTATUS EnumerateSystemHooks(_Out_ KernelList<HookDescriptor*>* Hooks);

// Memory protection utilities
NTSTATUS KernelVirtualProtect(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MemoryProtection NewProtection,
    _Out_ MemoryProtection* OldProtection
);

NTSTATUS KernelVirtualQuery(
    _In_ PVOID Address,
    _Out_ PMEMORY_BASIC_INFORMATION MemoryInfo
);

// Hook detection and analysis utilities
NTSTATUS ScanMemoryForHooks(
    _In_ PVOID StartAddress,
    _In_ SIZE_T RegionSize,
    _Out_ KernelList<HookDescriptor*>* DetectedHooks
);

NTSTATUS AnalyzeHookPattern(
    _In_ HookDescriptor* Hook,
    _Out_ PCHAR PatternType,
    _Out_ PCHAR HookTechnique
);

// SSDT manipulation utilities
NTSTATUS GetSSDTBase(_Out_ PVOID* SSDTBase);
NTSTATUS GetSSDTEntryCount(_Out_ ULONG* EntryCount);
NTSTATUS HookSSDTEntry(
    _In_ ULONG ServiceNumber,
    _In_ PVOID HookFunction,
    _Out_ PVOID* OriginalFunction
);

// Inline hooking utilities
NTSTATUS CreateInlineTrampoline(
    _In_ PVOID TargetFunction,
    _In_ SIZE_T MinPrologueSize,
    _Out_ InlineHookTrampoline* Trampoline
);

NTSTATUS InstallInlineHookWithTrampoline(
    _In_ PVOID TargetFunction,
    _In_ PVOID HookFunction,
    _In_ InlineHookTrampoline* Trampoline,
    _Out_ HookDescriptor** HookDesc
);

} // namespace BootkitFramework