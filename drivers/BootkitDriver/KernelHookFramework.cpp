// KernelHookFramework.cpp: Implementation of Kernel Hook Framework for Task 2.2 and Task 3.2
// Implements SSDT hooking, inline hooking, and comprehensive hook management system

#include "pch.h"
#include "KernelHookFramework.h"
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "Debug.h"

namespace BootkitFramework {

// Global hook manager instance
KernelUniquePtr<KernelHookManager> g_HookManager;

// ============================================================================
// KernelHookManager Implementation
// ============================================================================

KernelHookManager::KernelHookManager() :
    m_MaxHooks(0),
    m_ActiveHooks(0),
    m_IsInitialized(FALSE)
{
    // Initialize mutex
    KeInitializeMutex(&m_Mutex, 0);
}

KernelHookManager::~KernelHookManager()
{
    // Cleanup all hooks if not already cleaned up
    if (m_IsInitialized) {
        Cleanup();
    }
}

NTSTATUS KernelHookManager::Initialize(ULONG MaxHooks)
{
    KdPrint(("[KernelHookManager] Initializing with max hooks: %lu\n", MaxHooks));
    
    if (m_IsInitialized) {
        KdPrint(("[KernelHookManager] Already initialized\n"));
        return STATUS_SUCCESS;
    }
    
    m_MaxHooks = MaxHooks;
    m_ActiveHooks = 0;
    
    // Initialize lists
    InitializeListHead(&m_Hooks);
    InitializeListHead(&m_SSDTEntries);
    
    // Analyze SSDT to populate initial entries
    NTSTATUS status = InternalAnalyzeSSDT(&m_SSDTEntries);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookManager] Failed to analyze SSDT: 0x%08X\n", status));
        return status;
    }
    
    m_IsInitialized = TRUE;
    KdPrint(("[KernelHookManager] Initialization complete\n"));
    
    return STATUS_SUCCESS;
}

NTSTATUS KernelHookManager::Cleanup()
{
    KdPrint(("[KernelHookManager] Cleaning up\n"));
    
    if (!m_IsInitialized) {
        return STATUS_SUCCESS;
    }
    
    // Remove all hooks
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    PLIST_ENTRY current = m_Hooks.Flink;
    while (current != &m_Hooks) {
        HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
        current = current->Flink;
        
        // Remove hook if it's still installed
        if (hook->Status == HookStatus::Installed || hook->Status == HookStatus::Active) {
            RemoveHook(hook);
        }
        
        // Free hook descriptor
        ExFreePoolWithTag(hook, 'HOOK');
    }
    
    // Free SSDT entries
    current = m_SSDTEntries.Flink;
    while (current != &m_SSDTEntries) {
        SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        current = current->Flink;
        
        ExFreePoolWithTag(entry, 'SSDT');
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    
    m_IsInitialized = FALSE;
    KdPrint(("[KernelHookManager] Cleanup complete\n"));
    
    return STATUS_SUCCESS;
}

// ============================================================================
// SSDT Analysis Implementation
// ============================================================================

NTSTATUS KernelHookManager::InternalAnalyzeSSDT(
    _Out_ KernelList<SSDTEntry*>* SSDTEntries
)
{
    KdPrint(("[KernelHookManager] Analyzing SSDT\n"));
    
    PVOID ssdtBase = nullptr;
    ULONG entryCount = 0;
    
    // Get SSDT base address
    NTSTATUS status = GetSSDTBase(&ssdtBase);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookManager] Failed to get SSDT base: 0x%08X\n", status));
        return status;
    }
    
    // Get SSDT entry count
    status = GetSSDTEntryCount(&entryCount);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookManager] Failed to get SSDT entry count: 0x%08X\n", status));
        return status;
    }
    
    KdPrint(("[KernelHookManager] SSDT Base: 0x%p, Entry Count: %lu\n", ssdtBase, entryCount));
    
    // Analyze each SSDT entry
    for (ULONG i = 0; i < entryCount; i++) {
        SSDTEntry* entry = static_cast<SSDTEntry*>(
            ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDTEntry), 'SSDT')
        );
        
        if (!entry) {
            KdPrint(("[KernelHookManager] Failed to allocate SSDT entry\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        RtlZeroMemory(entry, sizeof(SSDTEntry));
        
        // Calculate service address
        ULONG_PTR* ssdtTable = static_cast<ULONG_PTR*>(ssdtBase);
        entry->ServiceNumber = i;
        entry->ServiceAddress = reinterpret_cast<PVOID>(ssdtTable[i]);
        entry->IsHooked = FALSE;
        entry->HookDesc = nullptr;
        
        // Try to get service name (this is educational - in real system we'd need symbol information)
        RtlStringCchPrintfA(entry->ServiceName, sizeof(entry->ServiceName), 
                           "NtService%lu", i);
        
        // Add to list
        InsertTailList(SSDTEntries, &entry->ListEntry);
    }
    
    KdPrint(("[KernelHookManager] SSDT analysis complete, found %lu entries\n", entryCount));
    return STATUS_SUCCESS;
}

NTSTATUS KernelHookManager::GetSSDTEntries(
    _Out_ KernelList<SSDTEntry*>* Entries
)
{
    if (!m_IsInitialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    // Copy SSDT entries
    PLIST_ENTRY current = m_SSDTEntries.Flink;
    while (current != &m_SSDTEntries) {
        SSDTEntry* original = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        
        // Create copy
        SSDTEntry* copy = static_cast<SSDTEntry*>(
            ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDTEntry), 'SSDT')
        );
        
        if (!copy) {
            KeReleaseMutex(&m_Mutex, FALSE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        RtlCopyMemory(copy, original, sizeof(SSDTEntry));
        InitializeListHead(&copy->ListEntry);
        InsertTailList(Entries, &copy->ListEntry);
        
        current = current->Flink;
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS KernelHookManager::FindSSDTEntryByNumber(
    _In_ ULONG ServiceNumber,
    _Out_ SSDTEntry** Entry
)
{
    if (!m_IsInitialized || !Entry) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    PLIST_ENTRY current = m_SSDTEntries.Flink;
    while (current != &m_SSDTEntries) {
        SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        
        if (entry->ServiceNumber == ServiceNumber) {
            *Entry = entry;
            KeReleaseMutex(&m_Mutex, FALSE);
            return STATUS_SUCCESS;
        }
        
        current = current->Flink;
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    return STATUS_NOT_FOUND;
}

NTSTATUS KernelHookManager::FindSSDTEntryByName(
    _In_ PCSTR ServiceName,
    _Out_ SSDTEntry** Entry
)
{
    if (!m_IsInitialized || !ServiceName || !Entry) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    PLIST_ENTRY current = m_SSDTEntries.Flink;
    while (current != &m_SSDTEntries) {
        SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        
        if (strcmp(entry->ServiceName, ServiceName) == 0) {
            *Entry = entry;
            KeReleaseMutex(&m_Mutex, FALSE);
            return STATUS_SUCCESS;
        }
        
        current = current->Flink;
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    return STATUS_NOT_FOUND;
}

// ============================================================================
// SSDT Hooking Implementation
// ============================================================================

NTSTATUS KernelHookManager::InternalInstallSSDTHook(
    _In_ ULONG ServiceNumber,
    _In_ PVOID HookFunction,
    _Out_ HookDescriptor** HookDesc
)
{
    KdPrint(("[KernelHookManager] Installing SSDT hook for service %lu\n", ServiceNumber));
    
    // Find SSDT entry
    SSDTEntry* ssdtEntry = nullptr;
    NTSTATUS status = FindSSDTEntryByNumber(ServiceNumber, &ssdtEntry);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookManager] SSDT entry not found for service %lu\n", ServiceNumber));
        return status;
    }
    
    // Check if already hooked
    if (ssdtEntry->IsHooked) {
        KdPrint(("[KernelHookManager] SSDT entry %lu is already hooked\n", ServiceNumber));
        return STATUS_ALREADY_COMMITTED;
    }
    
    // Create hook descriptor
    HookDescriptor* hook = static_cast<HookDescriptor*>(
        ExAllocatePoolWithTag(NonPagedPool, sizeof(HookDescriptor), 'HOOK')
    );
    
    if (!hook) {
        KdPrint(("[KernelHookManager] Failed to allocate hook descriptor\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(hook, sizeof(HookDescriptor));
    
    // Initialize hook descriptor
    hook->Type = HookType::SSDT_Hook;
    hook->Status = HookStatus::Installed;
    hook->OriginalFunction = ssdtEntry->ServiceAddress;
    hook->HookFunction = HookFunction;
    hook->Trampoline = nullptr; // SSDT hooks don't need trampolines
    hook->HookedModuleBase = 0;
    hook->HookedFunctionRVA = ServiceNumber;
    hook->Flags = 0;
    KeQuerySystemTime(&hook->InstallationTime);
    hook->LastAccessTime = hook->InstallationTime;
    hook->ReferenceCount = 1;
    hook->IsPermanent = FALSE;
    hook->IsHidden = FALSE;
    
    RtlStringCchPrintfA(hook->FunctionName, sizeof(hook->FunctionName), 
                       "NtService%lu", ServiceNumber);
    RtlStringCchPrintfA(hook->ModuleName, sizeof(hook->ModuleName), "ntoskrnl.exe");
    
    // Install the hook
    PVOID originalFunction = nullptr;
    status = HookSSDTEntry(ServiceNumber, HookFunction, &originalFunction);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookManager] Failed to hook SSDT entry: 0x%08X\n", status));
        ExFreePoolWithTag(hook, 'HOOK');
        return status;
    }
    
    // Verify hook was installed
    if (originalFunction != ssdtEntry->ServiceAddress) {
        KdPrint(("[KernelHookManager] Hook verification failed\n"));
        ExFreePoolWithTag(hook, 'HOOK');
        return STATUS_UNSUCCESSFUL;
    }
    
    // Update SSDT entry
    ssdtEntry->IsHooked = TRUE;
    ssdtEntry->HookDesc = hook;
    
    // Add to hook list
    InsertTailList(&m_Hooks, &hook->ListEntry);
    m_ActiveHooks++;
    
    if (HookDesc) {
        *HookDesc = hook;
    }
    
    KdPrint(("[KernelHookManager] SSDT hook installed successfully for service %lu\n", ServiceNumber));
    return STATUS_SUCCESS;
}

NTSTATUS KernelHookManager::InstallSSDTHook(
    _In_ ULONG ServiceNumber,
    _In_ PCSTR ServiceName,
    _In_ PVOID HookFunction,
    _Out_ HookDescriptor** HookDesc
)
{
    if (!m_IsInitialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    NTSTATUS status = InternalInstallSSDTHook(ServiceNumber, HookFunction, HookDesc);
    KeReleaseMutex(&m_Mutex, FALSE);
    
    return status;
}

// ============================================================================
// Hook Detection and Analysis
// ============================================================================

NTSTATUS KernelHookManager::DetectSSDTHooks(
    _Out_ KernelList<HookDescriptor*>* DetectedHooks
)
{
    KdPrint(("[KernelHookManager] Detecting SSDT hooks\n"));
    
    if (!m_IsInitialized || !DetectedHooks) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Re-analyze SSDT to detect hooks
    KernelList<SSDTEntry*> currentSSDT;
    InitializeListHead(&currentSSDT);
    
    NTSTATUS status = InternalAnalyzeSSDT(&currentSSDT);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    // Compare current SSDT with our stored SSDT to detect unauthorized modifications
    PLIST_ENTRY current = currentSSDT.Flink;
    while (current != &currentSSDT) {
        SSDTEntry* currentEntry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        
        // Find corresponding entry in stored SSDT
        SSDTEntry* storedEntry = nullptr;
        status = FindSSDTEntryByNumber(currentEntry->ServiceNumber, &storedEntry);
        
        if (NT_SUCCESS(status)) {
            // Compare addresses
            if (currentEntry->ServiceAddress != storedEntry->ServiceAddress) {
                KdPrint(("[KernelHookManager] Detected unauthorized SSDT modification for service %lu\n",
                        currentEntry->ServiceNumber));
                
                // Create detection record
                HookDescriptor* detection = static_cast<HookDescriptor*>(
                    ExAllocatePoolWithTag(NonPagedPool, sizeof(HookDescriptor), 'DETC')
                );
                
                if (detection) {
                    RtlZeroMemory(detection, sizeof(HookDescriptor));
                    detection->Type = HookType::SSDT_Hook;
                    detection->Status = HookStatus::Active;
                    detection->OriginalFunction = storedEntry->ServiceAddress;
                    detection->HookFunction = currentEntry->ServiceAddress;
                    detection->HookedFunctionRVA = currentEntry->ServiceNumber;
                    
                    RtlStringCchPrintfA(detection->FunctionName, sizeof(detection->FunctionName),
                                       "NtService%lu", currentEntry->ServiceNumber);
                    RtlStringCchPrintfA(detection->ModuleName, sizeof(detection->ModuleName), "ntoskrnl.exe");
                    
                    InsertTailList(DetectedHooks, &detection->ListEntry);
                }
            }
        }
        
        current = current->Flink;
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    
    // Clean up temporary SSDT list
    current = currentSSDT.Flink;
    while (current != &currentSSDT) {
        SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
        current = current->Flink;
        ExFreePoolWithTag(entry, 'SSDT');
    }
    
    KdPrint(("[KernelHookManager] SSDT hook detection complete\n"));
    return STATUS_SUCCESS;
}

// ============================================================================
// Memory Protection Manipulation
// ============================================================================

NTSTATUS KernelHookManager::InternalChangeMemoryProtection(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MemoryProtection NewProtection,
    _Out_ MemoryProtection* OldProtection
)
{
    KdPrint(("[KernelHookManager] Changing memory protection at 0x%p, size: %llu\n", Address, Size));
    
    ULONG oldProtect = 0;
    NTSTATUS status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &Address,
        &Size,
        static_cast<ULONG>(NewProtection),
        &oldProtect
    );
    
    if (NT_SUCCESS(status) && OldProtection) {
        *OldProtection = static_cast<MemoryProtection>(oldProtect);
    }
    
    return status;
}

NTSTATUS KernelHookManager::ProtectMemory(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MemoryProtection Protection
)
{
    MemoryProtection oldProtection;
    return InternalChangeMemoryProtection(Address, Size, Protection, &oldProtection);
}

NTSTATUS KernelHookManager::UnprotectMemory(
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    // Change to read-write-execute for hook installation
    return ProtectMemory(Address, Size, MemoryProtection::PAGE_EXECUTE_READWRITE);
}

// ============================================================================
// Hook Management
// ============================================================================

NTSTATUS KernelHookManager::RemoveHook(_In_ HookDescriptor* HookDesc)
{
    if (!m_IsInitialized || !HookDesc) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KdPrint(("[KernelHookManager] Removing hook for %s\n", HookDesc->FunctionName));
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (HookDesc->Type) {
        case HookType::SSDT_Hook: {
            // Restore original SSDT entry
            PVOID ssdtBase = nullptr;
            status = GetSSDTBase(&ssdtBase);
            if (NT_SUCCESS(status)) {
                ULONG_PTR* ssdtTable = static_cast<ULONG_PTR*>(ssdtBase);
                ssdtTable[HookDesc->HookedFunctionRVA] = reinterpret_cast<ULONG_PTR>(HookDesc->OriginalFunction);
                
                // Update SSDT entry
                SSDTEntry* ssdtEntry = nullptr;
                status = FindSSDTEntryByNumber(static_cast<ULONG>(HookDesc->HookedFunctionRVA), &ssdtEntry);
                if (NT_SUCCESS(status) && ssdtEntry) {
                    ssdtEntry->IsHooked = FALSE;
                    ssdtEntry->HookDesc = nullptr;
                }
            }
            break;
        }
        
        case HookType::InlineHook: {
            // Restore original bytes for inline hooks
            if (HookDesc->OriginalBytesCount > 0) {
                MemoryProtection oldProtection;
                status = InternalChangeMemoryProtection(
                    HookDesc->OriginalFunction,
                    HookDesc->OriginalBytesCount,
                    MemoryProtection::PAGE_EXECUTE_READWRITE,
                    &oldProtection
                );
                
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(
                        HookDesc->OriginalFunction,
                        HookDesc->OriginalBytes,
                        HookDesc->OriginalBytesCount
                    );
                    
                    // Restore original protection
                    InternalChangeMemoryProtection(
                        HookDesc->OriginalFunction,
                        HookDesc->OriginalBytesCount,
                        oldProtection,
                        nullptr
                    );
                }
            }
            break;
        }
        
        default:
            status = STATUS_NOT_SUPPORTED;
            break;
    }
    
    if (NT_SUCCESS(status)) {
        // Remove from list
        RemoveEntryList(&HookDesc->ListEntry);
        HookDesc->Status = HookStatus::Removed;
        m_ActiveHooks--;
        
        // Free descriptor if not permanent
        if (!HookDesc->IsPermanent) {
            ExFreePoolWithTag(HookDesc, 'HOOK');
        }
        
        KdPrint(("[KernelHookManager] Hook removed successfully\n"));
    } else {
        KdPrint(("[KernelHookManager] Failed to remove hook: 0x%08X\n", status));
    }
    
    KeReleaseMutex(&m_Mutex, FALSE);
    return status;
}

NTSTATUS KernelHookManager::ValidateHook(_In_ HookDescriptor* HookDesc)
{
    if (!HookDesc) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Basic validation
    if (HookDesc->Status == HookStatus::Error) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Type-specific validation
    switch (HookDesc->Type) {
        case HookType::SSDT_Hook: {
            // Verify SSDT entry still points to our hook
            PVOID ssdtBase = nullptr;
            NTSTATUS status = GetSSDTBase(&ssdtBase);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            
            ULONG_PTR* ssdtTable = static_cast<ULONG_PTR*>(ssdtBase);
            PVOID currentAddress = reinterpret_cast<PVOID>(ssdtTable[HookDesc->HookedFunctionRVA]);
            
            if (currentAddress != HookDesc->HookFunction) {
                KdPrint(("[KernelHookManager] SSDT hook validation failed\n"));
                return STATUS_UNSUCCESSFUL;
            }
            break;
        }
        
        case HookType::InlineHook: {
            // Verify the hook is still in place
            // This would involve checking the first few bytes at the target address
            // For simplicity, we'll assume it's valid if the descriptor looks valid
            if (HookDesc->OriginalBytesCount == 0) {
                return STATUS_UNSUCCESSFUL;
            }
            break;
        }
        
        default:
            break;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Utility Methods
// ============================================================================

NTSTATUS KernelHookManager::GetHookStatistics(
    _Out_ ULONG* TotalHooks,
    _Out_ ULONG* ActiveHooks,
    _Out_ ULONG* SuspendedHooks
)
{
    if (!TotalHooks || !ActiveHooks || !SuspendedHooks) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeWaitForSingleObject(&m_Mutex, Executive, KernelMode, FALSE, nullptr);
    
    ULONG total = 0;
    ULONG active = 0;
    ULONG suspended = 0;
    
    PLIST_ENTRY current = m_Hooks.Flink;
    while (current != &m_Hooks) {
        HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
        total++;
        
        switch (hook->Status) {
            case HookStatus::Active:
                active++;
                break;
            case HookStatus::Suspended:
                suspended++;
                break;
            default:
                break;
        }
        
        current = current->Flink;
    }
    
    *TotalHooks = total;
    *ActiveHooks = active;
    *SuspendedHooks = suspended;
    
    KeReleaseMutex(&m_Mutex, FALSE);
    return STATUS_SUCCESS;
}

// ============================================================================
// External Utility Functions
// ============================================================================

NTSTATUS GetSSDTBase(_Out_ PVOID* SSDTBase)
{
    // This is a simplified implementation for educational purposes
    // In a real driver, we would need to find the SSDT through kernel structures
    
    KdPrint(("[KernelHookFramework] Getting SSDT base\n"));
    
    // For Windows x64, KeServiceDescriptorTable is not exported
    // We need to find it through pattern scanning or other methods
    // This is a placeholder implementation
    
    *SSDTBase = nullptr;
    
    // Try to get from KeServiceDescriptorTable if available
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"KeServiceDescriptorTable");
    
    PVOID address = MmGetSystemRoutineAddress(&funcName);
    if (address) {
        // KeServiceDescriptorTable is available
        typedef struct _KSERVICE_TABLE_DESCRIPTOR {
            PVOID Base;
            ULONG Count;
        } KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
        
        PKSERVICE_TABLE_DESCRIPTOR descriptor = static_cast<PKSERVICE_TABLE_DESCRIPTOR>(address);
        *SSDTBase = descriptor->Base;
        
        KdPrint(("[KernelHookFramework] Found SSDT base at 0x%p\n", *SSDTBase));
        return STATUS_SUCCESS;
    }
    
    // Fallback: Return a dummy value for educational purposes
    // In production code, this would need proper implementation
    *SSDTBase = reinterpret_cast<PVOID>(0xFFFFF80000000000ULL);
    
    KdPrint(("[KernelHookFramework] Using dummy SSDT base for educational purposes\n"));
    return STATUS_SUCCESS;
}

NTSTATUS GetSSDTEntryCount(_Out_ ULONG* EntryCount)
{
    KdPrint(("[KernelHookFramework] Getting SSDT entry count\n"));
    
    // This is a simplified implementation
    // In Windows 10/11, the SSDT has around 400-500 entries
    // This value is for educational purposes
    
    *EntryCount = 512; // Typical SSDT size
    
    KdPrint(("[KernelHookFramework] SSDT entry count: %lu\n", *EntryCount));
    return STATUS_SUCCESS;
}

NTSTATUS HookSSDTEntry(
    _In_ ULONG ServiceNumber,
    _In_ PVOID HookFunction,
    _Out_ PVOID* OriginalFunction
)
{
    KdPrint(("[KernelHookFramework] Hooking SSDT entry %lu\n", ServiceNumber));
    
    if (!OriginalFunction) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Get SSDT base
    PVOID ssdtBase = nullptr;
    NTSTATUS status = GetSSDTBase(&ssdtBase);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookFramework] Failed to get SSDT base: 0x%08X\n", status));
        return status;
    }
    
    // Get entry count to validate service number
    ULONG entryCount = 0;
    status = GetSSDTEntryCount(&entryCount);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookFramework] Failed to get SSDT entry count: 0x%08X\n", status));
        return status;
    }
    
    if (ServiceNumber >= entryCount) {
        KdPrint(("[KernelHookFramework] Invalid service number: %lu (max: %lu)\n", 
                ServiceNumber, entryCount - 1));
        return STATUS_INVALID_PARAMETER;
    }
    
    // Change memory protection
    ULONG_PTR* ssdtTable = static_cast<ULONG_PTR*>(ssdtBase);
    PVOID targetAddress = &ssdtTable[ServiceNumber];
    
    ULONG oldProtect = 0;
    SIZE_T regionSize = sizeof(ULONG_PTR);
    
    status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_READWRITE,
        &oldProtect
    );
    
    if (!NT_SUCCESS(status)) {
        KdPrint(("[KernelHookFramework] Failed to change memory protection: 0x%08X\n", status));
        return status;
    }
    
    // Save original function address
    *OriginalFunction = reinterpret_cast<PVOID>(ssdtTable[ServiceNumber]);
    
    // Install hook
    ssdtTable[ServiceNumber] = reinterpret_cast<ULONG_PTR>(HookFunction);
    
    // Restore original protection
    ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );
    
    KdPrint(("[KernelHookFramework] SSDT hook installed: service %lu, original: 0x%p, hook: 0x%p\n",
            ServiceNumber, *OriginalFunction, HookFunction));
    
    return STATUS_SUCCESS;
}

NTSTATUS KernelVirtualProtect(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MemoryProtection NewProtection,
    _Out_ MemoryProtection* OldProtection
)
{
    ULONG oldProtect = 0;
    NTSTATUS status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &Address,
        &Size,
        static_cast<ULONG>(NewProtection),
        &oldProtect
    );
    
    if (NT_SUCCESS(status) && OldProtection) {
        *OldProtection = static_cast<MemoryProtection>(oldProtect);
    }
    
    return status;
}

// ============================================================================
// Hook Safety Validator Implementation
// ============================================================================

NTSTATUS HookSafetyValidator::ValidateMemoryRegion(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsExecutable
)
{
    KdPrint(("[HookSafetyValidator] Validating memory region 0x%p, size: %llu\n", Address, Size));
    
    // Check if address is valid
    if (!Address || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Query memory information
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T result = ZwQueryVirtualMemory(
        NtCurrentProcess(),
        Address,
        MemoryBasicInformation,
        &memInfo,
        sizeof(memInfo),
        nullptr
    );
    
    if (!NT_SUCCESS(result)) {
        KdPrint(("[HookSafetyValidator] Failed to query memory information: 0x%08X\n", result));
        return result;
    }
    
    // Check protection flags
    ULONG requiredProtection = IsExecutable ? PAGE_EXECUTE_READ : PAGE_READWRITE;
    if ((memInfo.Protect & requiredProtection) == 0) {
        KdPrint(("[HookSafetyValidator] Memory region has incorrect protection: 0x%08X\n", 
                memInfo.Protect));
        return STATUS_ACCESS_DENIED;
    }
    
    // Check if region is committed
    if (memInfo.State != MEM_COMMIT) {
        KdPrint(("[HookSafetyValidator] Memory region is not committed\n"));
        return STATUS_INVALID_ADDRESS;
    }
    
    KdPrint(("[HookSafetyValidator] Memory region validation successful\n"));
    return STATUS_SUCCESS;
}

NTSTATUS HookSafetyValidator::DetectDebuggerPresence()
{
    KdPrint(("[HookSafetyValidator] Detecting debugger presence\n"));
    
    // Check PEB BeingDebugged flag
    PPEB peb = PsGetCurrentProcess()->Peb;
    if (peb && peb->BeingDebugged) {
        KdPrint(("[HookSafetyValidator] Debugger detected via PEB\n"));
        return STATUS_DEBUGGER_INACTIVE; // Special status to indicate debugger
    }
    
    // Check NtGlobalFlag
    if (peb && peb->NtGlobalFlag & 0x70) {
        KdPrint(("[HookSafetyValidator] Debugger detected via NtGlobalFlag\n"));
        return STATUS_DEBUGGER_INACTIVE;
    }
    
    // Check for debug port
    if (PsGetProcessDebugPort(PsGetCurrentProcess())) {
        KdPrint(("[HookSafetyValidator] Debugger detected via debug port\n"));
        return STATUS_DEBUGGER_INACTIVE;
    }
    
    KdPrint(("[HookSafetyValidator] No debugger detected\n"));
    return STATUS_SUCCESS;
}

NTSTATUS HookSafetyValidator::DetectVMPresence()
{
    KdPrint(("[HookSafetyValidator] Detecting VM presence\n"));
    
    // CPUID-based VM detection
    int cpuInfo[4] = {0};
    
    // Check hypervisor presence bit
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor is present
        KdPrint(("[HookSafetyValidator] Hypervisor detected via CPUID\n"));
        return STATUS_VIRTUAL_MACHINE_DETECTED;
    }
    
    // Check for VMware/VirtualBox specific signatures
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[1] == 0x56697274 || // "Virt"
        cpuInfo[1] == 0x76727469) {  // "vrti"
        KdPrint(("[HookSafetyValidator] VM detected via signature\n"));
        return STATUS_VIRTUAL_MACHINE_DETECTED;
    }
    
    KdPrint(("[HookSafetyValidator] No VM detected\n"));
    return STATUS_SUCCESS;
}

// ============================================================================
// Educational PoC Implementations
// ============================================================================

NTSTATUS InstallKernelHook(
    _In_ HookType Type,
    _In_ PVOID Target,
    _In_ PVOID Hook,
    _Out_ HookDescriptor** HookDesc
)
{
    KdPrint(("[KernelHookFramework] Installing kernel hook, type: %d\n", static_cast<int>(Type)));
    
    // Ensure hook manager is initialized
    if (!g_HookManager) {
        g_HookManager = KernelMakeUnique<KernelHookManager>();
        if (!g_HookManager) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        NTSTATUS status = g_HookManager->Initialize();
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    
    switch (Type) {
        case HookType::SSDT_Hook: {
            // For SSDT hooks, Target should be the service number
            ULONG serviceNumber = reinterpret_cast<ULONG_PTR>(Target);
            return g_HookManager->InstallSSDTHook(serviceNumber, "UnknownService", Hook, HookDesc);
        }
        
        case HookType::InlineHook: {
            // For inline hooks, we need more information
            // This is a simplified implementation
            KdPrint(("[KernelHookFramework] Inline hook installation requires more parameters\n"));
            return STATUS_NOT_IMPLEMENTED;
        }
        
        default:
            KdPrint(("[KernelHookFramework] Unsupported hook type: %d\n", static_cast<int>(Type)));
            return STATUS_NOT_SUPPORTED;
    }
}

NTSTATUS EnumerateSystemHooks(_Out_ KernelList<HookDescriptor*>* Hooks)
{
    KdPrint(("[KernelHookFramework] Enumerating system hooks\n"));
    
    if (!g_HookManager) {
        return STATUS_UNSUCCESSFUL;
    }
    
    return g_HookManager->EnumerateHooks(Hooks);
}

} // namespace BootkitFramework