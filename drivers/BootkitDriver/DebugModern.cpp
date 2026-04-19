// DebugModern.cpp: Modern C++ debug and logging implementation
// Uses enhanced logging infrastructure with compile-time configuration

#include "pch.h"

using namespace BootkitFramework;

// Modern debug context using RAII patterns
class ModernDebugContext {
private:
    KernelUniquePtr<DEBUG_CONTEXT> m_context;
    KernelMutex m_mutex;
    std::unique_ptr<PerformanceLogger> m_perfLogger;
    std::unique_ptr<AuditLogger> m_auditLogger;
    
public:
    ModernDebugContext() : m_context(nullptr) {}
    
    ~ModernDebugContext() {
        Cleanup();
    }
    
    NTSTATUS Initialize() {
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Allocate context using modern memory management
            m_context.reset(static_cast<DEBUG_CONTEXT*>(
                g_MemoryManager->Allocate(sizeof(DEBUG_CONTEXT))));
            
            if (!m_context) {
                KERNEL_THROW_IF_FAILED(STATUS_INSUFFICIENT_RESOURCES,
                                      "Failed to allocate debug context");
            }
            
            // Initialize context
            RtlZeroMemory(m_context.get(), sizeof(DEBUG_CONTEXT));
            ExInitializeFastMutex(&m_context->DebugLock);
            
            // Set default configuration
            m_context->LoggingEnabled = TRUE;
            m_context->DebugLevel = DPFLTR_INFO_LEVEL;
            
            // Initialize performance and audit loggers
            m_perfLogger = std::make_unique<PerformanceLogger>();
            m_auditLogger = std::make_unique<AuditLogger>();
            
            LOG_INFO("Modern debug context initialized");
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    void Cleanup() noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            LOG_INFO("Cleaning up modern debug context");
            
            // Print final statistics
            PrintModernStatistics();
            
            // Clean up loggers
            m_auditLogger.reset();
            m_perfLogger.reset();
            
            // Free context
            g_MemoryManager->Free(m_context.get(), sizeof(DEBUG_CONTEXT));
            m_context.reset();
        }
    }
    
    DEBUG_CONTEXT* Get() const noexcept {
        return m_context.get();
    }
    
    PerformanceLogger* GetPerformanceLogger() const noexcept {
        return m_perfLogger.get();
    }
    
    AuditLogger* GetAuditLogger() const noexcept {
        return m_auditLogger.get();
    }
    
    // Modern logging functions
    template<typename... Args>
    void LogError(const char* format, Args&&... args) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled) {
            m_context->ErrorLogEntries++;
            m_context->TotalLogEntries++;
            LOG_ERROR(format, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    void LogWarning(const char* format, Args&&... args) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && 
            m_context->DebugLevel <= DPFLTR_WARNING_LEVEL) {
            m_context->WarningLogEntries++;
            m_context->TotalLogEntries++;
            LOG_WARNING(format, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    void LogInfo(const char* format, Args&&... args) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && 
            m_context->DebugLevel <= DPFLTR_INFO_LEVEL) {
            m_context->InfoLogEntries++;
            m_context->TotalLogEntries++;
            LOG_INFO(format, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    void LogTrace(const char* format, Args&&... args) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && 
            m_context->DebugLevel <= DPFLTR_TRACE_LEVEL) {
            m_context->TraceLogEntries++;
            m_context->TotalLogEntries++;
            LOG_TRACE(format, std::forward<Args>(args)...);
        }
    }
    
    // Modern debug dump functions
    void DumpMemory(
        _In_ PVOID address,
        _In_ ULONG length,
        _In_ const char* description
    ) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled) {
            LOG_INFO("Memory dump: %s (address: 0x%p, length: %lu)", 
                     description, address, length);
            
            // Hex dump implementation
            PUCHAR data = static_cast<PUCHAR>(address);
            for (ULONG i = 0; i < length; i += 16) {
                char line[128];
                char ascii[17];
                
                // Format hex bytes
                for (ULONG j = 0; j < 16; j++) {
                    if (i + j < length) {
                        sprintf_s(&line[j * 3], 4, "%02X ", data[i + j]);
                        ascii[j] = isprint(data[i + j]) ? data[i + j] : '.';
                    } else {
                        sprintf_s(&line[j * 3], 4, "   ");
                        ascii[j] = ' ';
                    }
                }
                ascii[16] = '\0';
                
                LOG_INFO("  0x%p: %s %s", data + i, line, ascii);
            }
        }
    }
    
    void DumpIrpInfo(
        _In_ PIRP irp,
        _In_ const char* description
    ) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && irp) {
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            
            LOG_INFO("IRP dump: %s", description);
            LOG_INFO("  IRP: 0x%p", irp);
            LOG_INFO("  Status: 0x%08X", irp->IoStatus.Status);
            LOG_INFO("  Information: %Iu", irp->IoStatus.Information);
            
            if (irpStack) {
                LOG_INFO("  MajorFunction: 0x%02X", irpStack->MajorFunction);
                LOG_INFO("  MinorFunction: 0x%02X", irpStack->MinorFunction);
                LOG_INFO("  Flags: 0x%08X", irpStack->Flags);
            }
        }
    }
    
    void DumpDeviceObjectInfo(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ const char* description
    ) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && deviceObject) {
            LOG_INFO("Device object dump: %s", description);
            LOG_INFO("  DeviceObject: 0x%p", deviceObject);
            LOG_INFO("  DeviceType: 0x%08X", deviceObject->DeviceType);
            LOG_INFO("  Flags: 0x%08X", deviceObject->Flags);
            LOG_INFO("  Characteristics: 0x%08X", deviceObject->Characteristics);
            LOG_INFO("  StackSize: %lu", deviceObject->StackSize);
        }
    }
    
    void DumpDriverObjectInfo(
        _In_ PDRIVER_OBJECT driverObject,
        _In_ const char* description
    ) {
        ScopedLock lock(m_mutex);
        if (m_context && m_context->LoggingEnabled && driverObject) {
            LOG_INFO("Driver object dump: %s", description);
            LOG_INFO("  DriverObject: 0x%p", driverObject);
            LOG_INFO("  DriverStart: 0x%p", driverObject->DriverStart);
            LOG_INFO("  DriverSize: %Iu", driverObject->DriverSize);
            LOG_INFO("  DriverName: %wZ", driverObject->DriverName);
        }
    }
    
    // Modern debugger functions
    BOOLEAN IsDebuggerPresent() const noexcept {
        return ::IsDebuggerPresent() != FALSE;
    }
    
    void BreakIfDebuggerPresent() noexcept {
        if (IsDebuggerPresent()) {
            DbgBreakPoint();
        }
    }
    
    // Modern statistics
    void PrintModernStatistics() const {
        ScopedLock lock(m_mutex);
        if (m_context) {
            LOG_INFO("=== Modern Debug Statistics ===");
            LOG_INFO("Total log entries: %lu", m_context->TotalLogEntries);
            LOG_INFO("Error log entries: %lu", m_context->ErrorLogEntries);
            LOG_INFO("Warning log entries: %lu", m_context->WarningLogEntries);
            LOG_INFO("Info log entries: %lu", m_context->InfoLogEntries);
            LOG_INFO("Trace log entries: %lu", m_context->TraceLogEntries);
            LOG_INFO("Logging enabled: %s", m_context->LoggingEnabled ? "Yes" : "No");
            LOG_INFO("Debug level: %lu", m_context->DebugLevel);
            LOG_INFO("==============================");
        }
    }
    
    // Modern configuration
    NTSTATUS SetLoggingEnabled(BOOLEAN enabled) noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            m_context->LoggingEnabled = enabled;
            LOG_INFO("Logging %s", enabled ? "enabled" : "disabled");
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS SetDebugLevel(ULONG level) noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            if (level > DPFLTR_TRACE_LEVEL) {
                return STATUS_INVALID_PARAMETER;
            }
            m_context->DebugLevel = level;
            LOG_INFO("Debug level set to: %lu", level);
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS GetDebugStatistics(
        _Out_ PULONG totalLogEntries,
        _Out_ PULONG errorLogEntries,
        _Out_ PULONG warningLogEntries,
        _Out_ PULONG infoLogEntries,
        _Out_ PULONG traceLogEntries
    ) const noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            *totalLogEntries = m_context->TotalLogEntries;
            *errorLogEntries = m_context->ErrorLogEntries;
            *warningLogEntries = m_context->WarningLogEntries;
            *infoLogEntries = m_context->InfoLogEntries;
            *traceLogEntries = m_context->TraceLogEntries;
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }
};

// Global modern debug context
static ModernDebugContext g_ModernDebugContext;

// Modern debug module initialization
NTSTATUS InitializeDebug() {
    return g_ModernDebugContext.Initialize();
}

// Modern debug module cleanup
VOID CleanupDebug() {
    g_ModernDebugContext.Cleanup();
}

// Modern logging control functions
NTSTATUS SetLoggingEnabled(_In_ BOOLEAN enabled) {
    return g_ModernDebugContext.SetLoggingEnabled(enabled);
}

NTSTATUS SetDebugLevel(_In_ ULONG level) {
    return g_ModernDebugContext.SetDebugLevel(level);
}

NTSTATUS GetDebugStatistics(
    _Out_ PULONG totalLogEntries,
    _Out_ PULONG errorLogEntries,
    _Out_ PULONG warningLogEntries,
    _Out_ PULONG infoLogEntries,
    _Out_ PULONG traceLogEntries
) {
    return g_ModernDebugContext.GetDebugStatistics(
        totalLogEntries, errorLogEntries, warningLogEntries,
        infoLogEntries, traceLogEntries);
}

// Modern formatted logging functions
VOID LogError(_In_ PCSTR format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[512];
    vsprintf_s(buffer, format, args);
    g_ModernDebugContext.LogError("%s", buffer);
    va_end(args);
}

VOID LogWarning(_In_ PCSTR format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[512];
    vsprintf_s(buffer, format, args);
    g_ModernDebugContext.LogWarning("%s", buffer);
    va_end(args);
}

VOID LogInfo(_In_ PCSTR format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[512];
    vsprintf_s(buffer, format, args);
    g_ModernDebugContext.LogInfo("%s", buffer);
    va_end(args);
}

VOID LogTrace(_In_ PCSTR format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[512];
    vsprintf_s(buffer, format, args);
    g_ModernDebugContext.LogTrace("%s", buffer);
    va_end(args);
}

// Modern debug dump functions
VOID DumpMemory(
    _In_ PVOID address,
    _In_ ULONG length,
    _In_ PCSTR description
) {
    g_ModernDebugContext.DumpMemory(address, length, description);
}

VOID DumpIrpInfo(
    _In_ PIRP irp,
    _In_ PCSTR description
) {
    g_ModernDebugContext.DumpIrpInfo(irp, description);
}

VOID DumpDeviceObjectInfo(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PCSTR description
) {
    g_ModernDebugContext.DumpDeviceObjectInfo(deviceObject, description);
}

VOID DumpDriverObjectInfo(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PCSTR description
) {
    g_ModernDebugContext.DumpDriverObjectInfo(driverObject, description);
}

// Modern debugger functions
BOOLEAN IsDebuggerPresent() {
    return g_ModernDebugContext.IsDebuggerPresent();
}

VOID BreakIfDebuggerPresent() {
    g_ModernDebugContext.BreakIfDebuggerPresent();
}

// Modern statistics printing
VOID PrintDebugStatistics() {
    g_ModernDebugContext.PrintModernStatistics();
}

// Performance logging access
PerformanceLogger* GetPerformanceLogger() {
    return g_ModernDebugContext.GetPerformanceLogger();
}

// Audit logging access
AuditLogger* GetAuditLogger() {
    return g_ModernDebugContext.GetAuditLogger();
}