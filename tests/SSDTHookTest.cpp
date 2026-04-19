// SSDTHookTest.cpp: Test file for SSDT Hooking Implementation (Task 3.2)
// Demonstrates SSDT hooking, analysis, and educational PoC implementations

#include "pch.h"
#include "KernelHookFramework.h"
#include "Debug.h"

using namespace BootkitFramework;

// Test function prototypes
NTSTATUS TestSSDTHookInstallation();
NTSTATUS TestSSDTAnalysis();
NTSTATUS TestMemoryProtection();
NTSTATUS TestHookDetection();
NTSTATUS TestEducationalExamples();

// Test hook function for NtCreateFile
NTSTATUS TestHook_NtCreateFile(
    _In_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ PVOID EaBuffer,
    _In_ ULONG EaLength
)
{
    KdPrint(("[SSDTHookTest] NtCreateFile hook intercepted\n"));
    
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        KdPrint(("[SSDTHookTest] File path: %wZ\n", ObjectAttributes->ObjectName));
        
        // Example: Block access to specific files
        UNICODE_STRING blockedFile;
        RtlInitUnicodeString(&blockedFile, L"\\??\\C:\\blocked.txt");
        
        if (RtlCompareUnicodeString(ObjectAttributes->ObjectName, &blockedFile, TRUE) == 0) {
            KdPrint(("[SSDTHookTest] Blocking access to blocked.txt\n"));
            return STATUS_ACCESS_DENIED;
        }
    }
    
    // In a real implementation, we would call the original function
    // For this test, we'll simulate successful operation
    if (FileHandle) {
        *FileHandle = reinterpret_cast<HANDLE>(0x12345678);
    }
    
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }
    
    return STATUS_SUCCESS;
}

// Test hook function for NtReadFile
NTSTATUS TestHook_NtReadFile(
    _In_ HANDLE FileHandle,
    _In_ HANDLE Event,
    _In_ PIO_APC_ROUTINE ApcRoutine,
    _In_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PULONG Key
)
{
    KdPrint(("[SSDTHookTest] NtReadFile hook intercepted\n"));
    
    // Log read operation
    KdPrint(("[SSDTHookTest] Reading %lu bytes from handle 0x%p\n", Length, FileHandle));
    
    // In a real implementation, we would call the original function
    // For this test, we'll simulate successful operation
    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = Length; // Pretend we read all bytes
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS TestSSDTHookInstallation()
{
    KdPrint(("[SSDTHookTest] ========================================\n"));
    KdPrint(("[SSDTHookTest] Testing SSDT Hook Installation\n"));
    KdPrint(("[SSDTHookTest] ========================================\n"));
    
    // Initialize hook manager
    if (!g_HookManager) {
        g_HookManager = KernelMakeUnique<KernelHookManager>();
        if (!g_HookManager) {
            KdPrint(("[SSDTHookTest] Failed to create hook manager\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        NTSTATUS status = g_HookManager->Initialize(100);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[SSDTHookTest] Failed to initialize hook manager: 0x%08X\n", status));
            return status;
        }
    }
    
    KdPrint(("[SSDTHookTest] Hook manager initialized\n"));
    
    // Test 1: Install SSDT hook for NtCreateFile (using example service number)
    HookDescriptor* createFileHook = nullptr;
    NTSTATUS status = g_HookManager->InstallSSDTHook(
        0x55,  // Example service number for NtCreateFile
        "NtCreateFile",
        reinterpret_cast<PVOID>(TestHook_NtCreateFile),
        &createFileHook
    );
    
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] NtCreateFile SSDT hook installed successfully\n"));
        
        // Test hook validation
        status = g_HookManager->ValidateHook(createFileHook);
        if (NT_SUCCESS(status)) {
            KdPrint(("[SSDTHookTest] Hook validation passed\n"));
        } else {
            KdPrint(("[SSDTHookTest] Hook validation failed: 0x%08X\n", status));
        }
    } else {
        KdPrint(("[SSDTHookTest] Failed to install NtCreateFile hook: 0x%08X\n", status));
    }
    
    // Test 2: Install SSDT hook for NtReadFile
    HookDescriptor* readFileHook = nullptr;
    status = g_HookManager->InstallSSDTHook(
        0x56,  // Example service number for NtReadFile
        "NtReadFile",
        reinterpret_cast<PVOID>(TestHook_NtReadFile),
        &readFileHook
    );
    
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] NtReadFile SSDT hook installed successfully\n"));
    } else {
        KdPrint(("[SSDTHookTest] Failed to install NtReadFile hook: 0x%08X\n", status));
    }
    
    // Test 3: Get hook statistics
    ULONG totalHooks, activeHooks, suspendedHooks;
    status = g_HookManager->GetHookStatistics(&totalHooks, &activeHooks, &suspendedHooks);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] Hook statistics: Total=%lu, Active=%lu, Suspended=%lu\n",
                totalHooks, activeHooks, suspendedHooks));
    }
    
    // Test 4: Enumerate hooks
    KernelList<HookDescriptor*> hooks;
    InitializeListHead(&hooks);
    
    status = g_HookManager->EnumerateHooks(&hooks);
    if (NT_SUCCESS(status)) {
        ULONG count = 0;
        PLIST_ENTRY current = hooks.Flink;
        while (current != &hooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            KdPrint(("[SSDTHookTest] Hook %lu: %s!%s (Type: %d, Status: %d)\n",
                    count, hook->ModuleName, hook->FunctionName,
                    static_cast<int>(hook->Type), static_cast<int>(hook->Status)));
            count++;
            current = current->Flink;
        }
        
        KdPrint(("[SSDTHookTest] Enumerated %lu hooks\n", count));
        
        // Clean up enumeration list
        current = hooks.Flink;
        while (current != &hooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            current = current->Flink;
            ExFreePoolWithTag(hook, 'HOOK');
        }
    }
    
    // Test 5: Remove hooks
    if (createFileHook) {
        status = g_HookManager->RemoveHook(createFileHook);
        if (NT_SUCCESS(status)) {
            KdPrint(("[SSDTHookTest] NtCreateFile hook removed successfully\n"));
        }
    }
    
    if (readFileHook) {
        status = g_HookManager->RemoveHook(readFileHook);
        if (NT_SUCCESS(status)) {
            KdPrint(("[SSDTHookTest] NtReadFile hook removed successfully\n"));
        }
    }
    
    // Final statistics
    status = g_HookManager->GetHookStatistics(&totalHooks, &activeHooks, &suspendedHooks);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] Final statistics: Total=%lu, Active=%lu, Suspended=%lu\n",
                totalHooks, activeHooks, suspendedHooks));
    }
    
    KdPrint(("[SSDTHookTest] SSDT Hook Installation Test Complete\n"));
    return STATUS_SUCCESS;
}

NTSTATUS TestSSDTAnalysis()
{
    KdPrint(("[SSDTHookTest] ========================================\n"));
    KdPrint(("[SSDTHookTest] Testing SSDT Analysis\n"));
    KdPrint(("[SSDTHookTest] ========================================\n"));
    
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
    
    // Test 1: Get SSDT entries
    KernelList<SSDTEntry*> entries;
    InitializeListHead(&entries);
    
    NTSTATUS status = g_HookManager->GetSSDTEntries(&entries);
    if (NT_SUCCESS(status)) {
        ULONG count = 0;
        PLIST_ENTRY current = entries.Flink;
        
        KdPrint(("[SSDTHookTest] SSDT Entries (first 10):\n"));
        while (current != &entries && count < 10) {
            SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
            KdPrint(("[SSDTHookTest]   [%03lu] Service %lu: 0x%p (%s)\n",
                    count, entry->ServiceNumber, entry->ServiceAddress, entry->ServiceName));
            count++;
            current = current->Flink;
        }
        
        KdPrint(("[SSDTHookTest] Retrieved %lu SSDT entries\n", count));
        
        // Clean up
        current = entries.Flink;
        while (current != &entries) {
            SSDTEntry* entry = CONTAINING_RECORD(current, SSDTEntry, ListEntry);
            current = current->Flink;
            ExFreePoolWithTag(entry, 'SSDT');
        }
    } else {
        KdPrint(("[SSDTHookTest] Failed to get SSDT entries: 0x%08X\n", status));
    }
    
    // Test 2: Find SSDT entry by number
    SSDTEntry* foundEntry = nullptr;
    status = g_HookManager->FindSSDTEntryByNumber(0x55, &foundEntry);
    if (NT_SUCCESS(status) && foundEntry) {
        KdPrint(("[SSDTHookTest] Found SSDT entry for service 0x55: 0x%p (%s)\n",
                foundEntry->ServiceAddress, foundEntry->ServiceName));
    } else {
        KdPrint(("[SSDTHookTest] SSDT entry for service 0x55 not found\n"));
    }
    
    // Test 3: Detect SSDT hooks
    KernelList<HookDescriptor*> detectedHooks;
    InitializeListHead(&detectedHooks);
    
    status = g_HookManager->DetectSSDTHooks(&detectedHooks);
    if (NT_SUCCESS(status)) {
        ULONG hookCount = 0;
        PLIST_ENTRY current = detectedHooks.Flink;
        
        while (current != &detectedHooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            KdPrint(("[SSDTHookTest] Detected unauthorized SSDT modification:\n"));
            KdPrint(("[SSDTHookTest]   Service: %lu\n", hook->HookedFunctionRVA));
            KdPrint(("[SSDTHookTest]   Original: 0x%p\n", hook->OriginalFunction));
            KdPrint(("[SSDTHookTest]   Current: 0x%p\n", hook->HookFunction));
            hookCount++;
            current = current->Flink;
        }
        
        KdPrint(("[SSDTHookTest] Detected %lu unauthorized SSDT modifications\n", hookCount));
        
        // Clean up
        current = detectedHooks.Flink;
        while (current != &detectedHooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            current = current->Flink;
            ExFreePoolWithTag(hook, 'DETC');
        }
    } else {
        KdPrint(("[SSDTHookTest] SSDT hook detection failed: 0x%08X\n", status));
    }
    
    // Test 4: Analyze hook patterns
    KernelList<HookDescriptor*> suspiciousHooks;
    InitializeListHead(&suspiciousHooks);
    
    status = g_HookManager->AnalyzeHookPatterns(&suspiciousHooks);
    if (NT_SUCCESS(status)) {
        ULONG suspiciousCount = 0;
        PLIST_ENTRY current = suspiciousHooks.Flink;
        
        while (current != &suspiciousHooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            KdPrint(("[SSDTHookTest] Suspicious hook pattern detected: %s!%s\n",
                    hook->ModuleName, hook->FunctionName));
            suspiciousCount++;
            current = current->Flink;
        }
        
        KdPrint(("[SSDTHookTest] Found %lu suspicious hook patterns\n", suspiciousCount));
        
        // Clean up
        current = suspiciousHooks.Flink;
        while (current != &suspiciousHooks) {
            HookDescriptor* hook = CONTAINING_RECORD(current, HookDescriptor, ListEntry);
            current = current->Flink;
            ExFreePoolWithTag(hook, 'SUSP');
        }
    }
    
    KdPrint(("[SSDTHookTest] SSDT Analysis Test Complete\n"));
    return STATUS_SUCCESS;
}

NTSTATUS TestMemoryProtection()
{
    KdPrint(("[SSDTHookTest] ========================================\n"));
    KdPrint(("[SSDTHookTest] Testing Memory Protection Manipulation\n"));
    KdPrint(("[SSDTHookTest] ========================================\n"));
    
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
    
    // Allocate test memory
    PVOID testMemory = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'TEST');
    if (!testMemory) {
        KdPrint(("[SSDTHookTest] Failed to allocate test memory\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KdPrint(("[SSDTHookTest] Allocated test memory at 0x%p\n", testMemory));
    
    // Test 1: Unprotect memory (change to read-write-execute)
    NTSTATUS status = g_HookManager->UnprotectMemory(testMemory, PAGE_SIZE);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] Memory unprotected successfully\n"));
        
        // Write test pattern
        PUCHAR bytes = static_cast<PUCHAR>(testMemory);
        for (ULONG i = 0; i < 16; i++) {
            bytes[i] = static_cast<UCHAR>(i);
        }
        
        KdPrint(("[SSDTHookTest] Wrote test pattern to memory\n"));
        
        // Verify pattern
        BOOLEAN patternCorrect = TRUE;
        for (ULONG i = 0; i < 16; i++) {
            if (bytes[i] != static_cast<UCHAR>(i)) {
                patternCorrect = FALSE;
                break;
            }
        }
        
        if (patternCorrect) {
            KdPrint(("[SSDTHookTest] Memory write verification successful\n"));
        } else {
            KdPrint(("[SSDTHookTest] Memory write verification failed\n"));
        }
    } else {
        KdPrint(("[SSDTHookTest] Failed to unprotect memory: 0x%08X\n", status));
    }
    
    // Test 2: Protect memory (change to execute-only)
    status = g_HookManager->ProtectMemory(testMemory, PAGE_SIZE, 
                                         MemoryProtection::PAGE_EXECUTE);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] Memory protected to execute-only\n"));
    } else {
        KdPrint(("[SSDTHookTest] Failed to protect memory: 0x%08X\n", status));
    }
    
    // Test 3: Test VirtualProtect utility function
    MemoryProtection oldProtection;
    status = KernelVirtualProtect(testMemory, PAGE_SIZE,
                                 MemoryProtection::PAGE_READWRITE,
                                 &oldProtection);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] KernelVirtualProtect successful, old protection: %d\n",
                static_cast<int>(oldProtection)));
    }
    
    // Clean up
    ExFreePoolWithTag(testMemory, 'TEST');
    
    KdPrint(("[SSDTHookTest] Memory Protection Test Complete\n"));
    return STATUS_SUCCESS;
}

NTSTATUS TestHookDetection()
{
    KdPrint(("[SSDTHookTest] ========================================\n"));
    KdPrint(("[SSDTHookTest] Testing Hook Detection\n"));
    KdPrint(("[SSDTHookTest] ========================================\n"));
    
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
    
    // Create safety validator
    HookSafetyValidator validator;
    
    // Test 1: Validate memory region
    PVOID testAddr = reinterpret_cast<PVOID>(0x0000000140000000ULL); // Example address
    NTSTATUS status = validator.ValidateMemoryRegion(testAddr, 4096, TRUE);
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] Memory region validation successful\n"));
    } else {
        KdPrint(("[SSDTHookTest] Memory region validation failed: 0x%08X\n", status));
    }
    
    // Test 2: Detect debugger
    status = validator.DetectDebuggerPresence();
    if (status == STATUS_DEBUGGER_INACTIVE) {
        KdPrint(("[SSDTHookTest] Debugger detected\n"));
    } else if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] No debugger detected\n"));
    } else {
        KdPrint(("[SSDTHookTest] Debugger detection failed: 0x%08X\n", status));
    }
    
    // Test 3: Detect VM
    status = validator.DetectVMPresence();
    if (status == STATUS_VIRTUAL_MACHINE_DETECTED) {
        KdPrint(("[SSDTHookTest] Virtual machine detected\n"));
    } else if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] No virtual machine detected\n"));
    } else {
        KdPrint(("[SSDTHookTest] VM detection failed: 0x%08X\n", status));
    }
    
    KdPrint(("[SSDTHookTest] Hook Detection Test Complete\n"));
    return STATUS_SUCCESS;
}

NTSTATUS TestEducationalExamples()
{
    KdPrint(("[SSDTHookTest] ========================================\n"));
    KdPrint(("[SSDTHookTest] Testing Educational Examples\n"));
    KdPrint(("[SSDTHookTest] ========================================\n"));
    
    KdPrint(("[SSDTHookTest] Running ExampleSafeHookInstallation...\n"));
    NTSTATUS status = ExampleSafeHookInstallation();
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] ExampleSafeHookInstallation completed successfully\n"));
    } else {
        KdPrint(("[SSDTHookTest] ExampleSafeHookInstallation failed: 0x%08X\n", status));
    }
    
    KdPrint(("[SSDTHookTest] Running ExampleSSDTAnalysis...\n"));
    status = ExampleSSDTAnalysis();
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] ExampleSSDTAnalysis completed successfully\n"));
    } else {
        KdPrint(("[SSDTHookTest] ExampleSSDTAnalysis failed: 0x%08X\n", status));
    }
    
    KdPrint(("[SSDTHookTest] Running ExampleMemoryProtectionManipulation...\n"));
    status = ExampleMemoryProtectionManipulation();
    if (NT_SUCCESS(status)) {
        KdPrint(("[SSDTHookTest] ExampleMemoryProtectionManipulation completed successfully\n"));
    } else {
        KdPrint(("[SSDTHookTest] ExampleMemoryProtectionManipulation failed: 0x%08X\n", status));
    }
    
    KdPrint(("[SSDTHookTest] Educational Examples Test Complete\n"));
    return STATUS_SUCCESS;
}

// Main test function
extern "C" NTSTATUS TestSSDTHookingImplementation()
{
    KdPrint(("[SSDTHookTest] **************************************************\n"));
    KdPrint(("[SSDTHookTest] STARTING SSDT HOOKING IMPLEMENTATION TESTS\n"));
    KdPrint(("[SSDTHookTest] Task 3.2: SSDT Hooking Implementation\n"));
    KdPrint(("[SSDTHookTest] **************************************************\n"));
    
    NTSTATUS finalStatus = STATUS_SUCCESS;
    
    // Run all tests
    NTSTATUS status = TestSSDTHookInstallation();
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        KdPrint(("[SSDTHookTest] TestSSDTHookInstallation failed: 0x%08X\n", status));
    }
    
    status = TestSSDTAnalysis();
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        KdPrint(("[SSDTHookTest] TestSSDTAnalysis failed: 0x%08X\n", status));
    }
    
    status = TestMemoryProtection();
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        KdPrint(("[SSDTHookTest] TestMemoryProtection failed: 0x%08X\n", status));
    }
    
    status = TestHookDetection();
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        KdPrint(("[SSDTHookTest] TestHookDetection failed: 0x%08X\n", status));
    }
    
    status = TestEducationalExamples();
    if (!NT_SUCCESS(status)) {
        finalStatus = status;
        KdPrint(("[SSDTHookTest] TestEducationalExamples failed: 0x%08X\n", status));
    }
    
    KdPrint(("[SSDTHookTest] **************************************************\n"));
    KdPrint(("[SSDTHookTest] SSDT HOOKING IMPLEMENTATION TESTS COMPLETE\n"));
    KdPrint(("[SSDTHookTest] Final status: 0x%08X\n", finalStatus));
    KdPrint(("[SSDTHookTest] **************************************************\n"));
    
    return finalStatus;
}