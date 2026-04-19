// DeviceControlModern.cpp: Modern C++ device control implementation
// Uses template metaprogramming and exception-safe patterns

#include "pch.h"

using namespace BootkitFramework;

// Modern device control context using RAII patterns
class ModernDeviceControlContext {
private:
    KernelUniquePtr<DEVICE_CONTROL_CONTEXT> m_context;
    KernelMutex m_mutex;
    ThreadSafeMap<ULONG, TypeSafeCallback<PVOID, ULONG, PVOID, ULONG, PULONG>> m_ioctlHandlers;
    ThreadSafeQueue<IOCTL_REQUEST> m_pendingRequests;
    
    struct IOCTL_REQUEST {
        ULONG IoControlCode;
        PVOID InputBuffer;
        ULONG InputBufferLength;
        PVOID OutputBuffer;
        ULONG OutputBufferLength;
        PULONG BytesReturned;
        std::promise<NTSTATUS> Promise;
        
        IOCTL_REQUEST(ULONG code, PVOID inBuf, ULONG inLen,
                     PVOID outBuf, ULONG outLen, PULONG bytesRet)
            : IoControlCode(code), InputBuffer(inBuf), InputBufferLength(inLen),
              OutputBuffer(outBuf), OutputBufferLength(outLen), BytesReturned(bytesRet) {}
    };
    
public:
    ModernDeviceControlContext() : m_context(nullptr) {}
    
    ~ModernDeviceControlContext() {
        Cleanup();
    }
    
    NTSTATUS Initialize() {
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Allocate context using modern memory management
            m_context.reset(static_cast<DEVICE_CONTROL_CONTEXT*>(
                g_MemoryManager->Allocate(sizeof(DEVICE_CONTROL_CONTEXT))));
            
            if (!m_context) {
                KERNEL_THROW_IF_FAILED(STATUS_INSUFFICIENT_RESOURCES,
                                      "Failed to allocate device control context");
            }
            
            // Initialize context
            RtlZeroMemory(m_context.get(), sizeof(DEVICE_CONTROL_CONTEXT));
            ExInitializeFastMutex(&m_context->ControlLock);
            
            // Register default IOCTL handlers
            RegisterDefaultHandlers();
            
            LOG_INFO("Modern device control context initialized");
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    void Cleanup() noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            LOG_INFO("Cleaning up modern device control context");
            
            // Clear all handlers
            m_ioctlHandlers.Clear();
            
            // Process pending requests
            ProcessPendingRequests();
            
            // Free context
            g_MemoryManager->Free(m_context.get(), sizeof(DEVICE_CONTROL_CONTEXT));
            m_context.reset();
        }
    }
    
    DEVICE_CONTROL_CONTEXT* Get() const noexcept {
        return m_context.get();
    }
    
    // Modern IOCTL handler registration
    template<typename Handler>
    NTSTATUS RegisterHandler(ULONG ioControlCode, Handler&& handler) {
        ScopedLock lock(m_mutex);
        
        if (m_ioctlHandlers.Contains(ioControlCode)) {
            LOG_WARNING("IOCTL handler already registered: 0x%08X", ioControlCode);
            return STATUS_OBJECT_NAME_COLLISION;
        }
        
        m_ioctlHandlers.Insert(ioControlCode, 
            [handler = std::forward<Handler>(handler)](
                PVOID inputBuffer, ULONG inputBufferLength,
                PVOID outputBuffer, ULONG outputBufferLength,
                PULONG bytesReturned) -> NTSTATUS {
                
                KERNEL_TRY {
                    return handler(inputBuffer, inputBufferLength,
                                 outputBuffer, outputBufferLength,
                                 bytesReturned);
                }
                KERNEL_CATCH
            });
        
        LOG_INFO("Registered handler for IOCTL: 0x%08X", ioControlCode);
        return STATUS_SUCCESS;
    }
    
    // Modern IOCTL handling
    NTSTATUS HandleDeviceControl(
        _In_ ULONG ioControlCode,
        _In_ PVOID inputBuffer,
        _In_ ULONG inputBufferLength,
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        PERF_SCOPE("HandleDeviceControl");
        
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Update statistics
            m_context->TotalIoControls++;
            
            // Find handler
            auto handler = m_ioctlHandlers.Find(ioControlCode);
            if (handler != m_ioctlHandlers.end()) {
                NTSTATUS status = handler->second(
                    inputBuffer, inputBufferLength,
                    outputBuffer, outputBufferLength,
                    bytesReturned);
                
                if (!NT_SUCCESS(status)) {
                    m_context->FailedIoControls++;
                }
                
                AUDIT_LOG("USER", "DEVICE_CONTROL", "Driver",
                         fmt::format("IOCTL: 0x{:08X} - Status: 0x{:08X}", 
                                    ioControlCode, status),
                         NT_SUCCESS(status));
                
                return status;
            }
            
            // No handler found
            m_context->FailedIoControls++;
            LOG_WARNING("No handler for IOCTL: 0x%08X", ioControlCode);
            
            AUDIT_LOG("USER", "DEVICE_CONTROL", "Driver",
                     fmt::format("Unknown IOCTL: 0x{:08X}", ioControlCode),
                     false);
            
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        KERNEL_CATCH
    }
    
    // Async IOCTL handling
    std::future<NTSTATUS> HandleDeviceControlAsync(
        _In_ ULONG ioControlCode,
        _In_ PVOID inputBuffer,
        _In_ ULONG inputBufferLength,
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            auto request = std::make_shared<IOCTL_REQUEST>(
                ioControlCode, inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength, bytesReturned);
            
            std::future<NTSTATUS> future = request->Promise.get_future();
            m_pendingRequests.Push(std::move(request));
            
            return future;
        }
        KERNEL_CATCH
    }
    
private:
    void RegisterDefaultHandlers() {
        // Driver info handler
        RegisterHandler(IOCTL_BOOTKITDRIVER_GET_DRIVER_INFO,
            [this](PVOID inputBuffer, ULONG inputBufferLength,
                   PVOID outputBuffer, ULONG outputBufferLength,
                   PULONG bytesReturned) -> NTSTATUS {
                return HandleDriverInfoRequest(
                    outputBuffer, outputBufferLength, bytesReturned);
            });
        
        // Statistics handler
        RegisterHandler(IOCTL_BOOTKITDRIVER_GET_STATISTICS,
            [this](PVOID inputBuffer, ULONG inputBufferLength,
                   PVOID outputBuffer, ULONG outputBufferLength,
                   PULONG bytesReturned) -> NTSTATUS {
                return HandleStatisticsRequest(
                    outputBuffer, outputBufferLength, bytesReturned);
            });
        
        // Test handler
        RegisterHandler(IOCTL_BOOTKITDRIVER_PERFORM_TEST,
            [this](PVOID inputBuffer, ULONG inputBufferLength,
                   PVOID outputBuffer, ULONG outputBufferLength,
                   PULONG bytesReturned) -> NTSTATUS {
                return HandleTestRequest(
                    inputBuffer, inputBufferLength,
                    outputBuffer, outputBufferLength, bytesReturned);
            });
        
        // Version handler
        RegisterHandler(IOCTL_BOOTKITDRIVER_GET_VERSION,
            [this](PVOID inputBuffer, ULONG inputBufferLength,
                   PVOID outputBuffer, ULONG outputBufferLength,
                   PULONG bytesReturned) -> NTSTATUS {
                return HandleVersionRequest(
                    outputBuffer, outputBufferLength, bytesReturned);
            });
        
        // Reset statistics handler
        RegisterHandler(IOCTL_BOOTKITDRIVER_RESET_STATISTICS,
            [this](PVOID inputBuffer, ULONG inputBufferLength,
                   PVOID outputBuffer, ULONG outputBufferLength,
                   PULONG bytesReturned) -> NTSTATUS {
                return HandleResetStatisticsRequest(bytesReturned);
            });
    }
    
    NTSTATUS HandleDriverInfoRequest(
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            if (outputBufferLength < sizeof(DRIVER_INFO)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            PDRIVER_INFO driverInfo = static_cast<PDRIVER_INFO>(outputBuffer);
            
            // Fill driver info with modern details
            driverInfo->DriverVersion = 0x00020000; // Version 2.0 (modern)
            driverInfo->BuildNumber = 20240101; // Build date
            wcscpy_s(driverInfo->DriverName, L"BootkitDriver Modern C++ Edition");
            wcscpy_s(driverInfo->BuildDate, L"2024-01-01");
            wcscpy_s(driverInfo->BuildTime, L"12:00:00");
            
            // Modern features
            driverInfo->FeaturesSupported = 
                (1 << 0) |  // Exception handling
                (1 << 1) |  // RAII patterns
                (1 << 2) |  // Smart pointers
                (1 << 3) |  // Template metaprogramming
                (1 << 4) |  // Enhanced logging
                (1 << 5) |  // Memory pooling
                (1 << 6);   // Thread-safe containers
            
            *bytesReturned = sizeof(DRIVER_INFO);
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleStatisticsRequest(
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            if (outputBufferLength < sizeof(DRIVER_STATISTICS)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            PDRIVER_STATISTICS stats = static_cast<PDRIVER_STATISTICS>(outputBuffer);
            
            ScopedLock lock(m_mutex);
            
            // Fill statistics
            stats->TotalIrpsProcessed = 0; // Would track from IRP handlers
            stats->FailedIrps = 0;
            stats->TotalIoControls = m_context->TotalIoControls;
            stats->FailedIoControls = m_context->FailedIoControls;
            stats->OpenHandleCount = 0; // Would track from device extension
            
            // Get current time
            FILETIME currentTime;
            GetSystemTimeAsFileTime(&currentTime);
            stats->DriverStartTime = currentTime;
            stats->UptimeSeconds = 0; // Would calculate actual uptime
            
            *bytesReturned = sizeof(DRIVER_STATISTICS);
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleTestRequest(
        _In_ PVOID inputBuffer,
        _In_ ULONG inputBufferLength,
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            if (inputBufferLength < sizeof(TEST_REQUEST) ||
                outputBufferLength < sizeof(TEST_RESPONSE)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            PTEST_REQUEST request = static_cast<PTEST_REQUEST>(inputBuffer);
            PTEST_RESPONSE response = static_cast<PTEST_RESPONSE>(outputBuffer);
            
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Process test based on type
            switch (request->TestType) {
                case 1: // Echo test
                    response->TestResult = HandleEchoTest(request, response);
                    break;
                    
                case 2: // Performance test
                    response->TestResult = HandlePerformanceTest(request, response);
                    break;
                    
                case 3: // Memory test
                    response->TestResult = HandleMemoryTest(request, response);
                    break;
                    
                default:
                    response->TestResult = STATUS_INVALID_PARAMETER;
                    break;
            }
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - startTime);
            
            response->ExecutionTimeMs = static_cast<ULONG>(duration.count());
            
            *bytesReturned = sizeof(TEST_RESPONSE);
            return response->TestResult;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleVersionRequest(
        _In_ PVOID outputBuffer,
        _In_ ULONG outputBufferLength,
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            if (outputBufferLength < sizeof(ULONG)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            
            PULONG version = static_cast<PULONG>(outputBuffer);
            *version = 0x00020000; // Version 2.0 (modern)
            *bytesReturned = sizeof(ULONG);
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleResetStatisticsRequest(
        _Out_ PULONG bytesReturned
    ) {
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Reset statistics
            m_context->TotalIoControls = 0;
            m_context->FailedIoControls = 0;
            
            *bytesReturned = 0;
            LOG_INFO("Device control statistics reset");
            
            AUDIT_LOG("ADMIN", "RESET_STATISTICS", "DeviceControl",
                     "Device control statistics reset", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleEchoTest(
        _In_ PTEST_REQUEST request,
        _Out_ PTEST_RESPONSE response
    ) {
        KERNEL_TRY {
            response->ProcessedDataSize = min(request->TestDataSize, 256);
            
            // Echo back processed data
            memcpy(response->ProcessedData, request->TestData, 
                   response->ProcessedDataSize);
            
            LOG_INFO("Echo test completed: %lu bytes", 
                     response->ProcessedDataSize);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePerformanceTest(
        _In_ PTEST_REQUEST request,
        _Out_ PTEST_RESPONSE response
    ) {
        KERNEL_TRY {
            // Simple performance test: allocate and free memory
            const size_t testSize = 1024 * 1024; // 1MB
            
            auto startAlloc = std::chrono::high_resolution_clock::now();
            
            void* testMemory = g_MemoryManager->Allocate(testSize);
            if (!testMemory) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            auto endAlloc = std::chrono::high_resolution_clock::now();
            
            // Fill with pattern
            memset(testMemory, 0xAA, testSize);
            
            auto startFree = std::chrono::high_resolution_clock::now();
            g_MemoryManager->Free(testMemory, testSize);
            auto endFree = std::chrono::high_resolution_clock::now();
            
            auto allocTime = std::chrono::duration_cast<std::chrono::microseconds>(
                endAlloc - startAlloc);
            auto freeTime = std::chrono::duration_cast<std::chrono::microseconds>(
                endFree - startFree);
            
            // Store results
            response->ProcessedDataSize = sizeof(ULONG) * 2;
            PULONG results = reinterpret_cast<PULONG>(response->ProcessedData);
            results[0] = static_cast<ULONG>(allocTime.count());
            results[1] = static_cast<ULONG>(freeTime.count());
            
            LOG_INFO("Performance test: alloc=%lu us, free=%lu us",
                     results[0], results[1]);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleMemoryTest(
        _In_ PTEST_REQUEST request,
        _Out_ PTEST_RESPONSE response
    ) {
        KERNEL_TRY {
            // Test memory pool allocation
            const size_t numAllocations = 100;
            const size_t allocationSize = 1024; // 1KB
            
            std::vector<void*> allocations;
            allocations.reserve(numAllocations);
            
            // Allocate
            for (size_t i = 0; i < numAllocations; ++i) {
                void* ptr = g_MemoryManager->Allocate(allocationSize);
                if (!ptr) {
                    // Clean up on failure
                    for (void* alloc : allocations) {
                        g_MemoryManager->Free(alloc, allocationSize);
                    }
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                allocations.push_back(ptr);
            }
            
            // Fill with pattern
            for (void* ptr : allocations) {
                memset(ptr, static_cast<int>(reinterpret_cast<uintptr_t>(ptr) & 0xFF), 
                       allocationSize);
            }
            
            // Free
            for (void* ptr : allocations) {
                g_MemoryManager->Free(ptr, allocationSize);
            }
            
            response->ProcessedDataSize = sizeof(ULONG);
            PULONG result = reinterpret_cast<PULONG>(response->ProcessedData);
            *result = static_cast<ULONG>(numAllocations);
            
            LOG_INFO("Memory test completed: %lu allocations", numAllocations);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    void ProcessPendingRequests() {
        std::shared_ptr<IOCTL_REQUEST> request;
        while (m_pendingRequests.TryPop(request)) {
            if (request) {
                NTSTATUS status = HandleDeviceControl(
                    request->IoControlCode,
                    request->InputBuffer,
                    request->InputBufferLength,
                    request->OutputBuffer,
                    request->OutputBufferLength,
                    request->BytesReturned);
                
                request->Promise.set_value(status);
            }
        }
    }
};

// Global modern device control context
static ModernDeviceControlContext g_ModernDeviceControlContext;

// Modern device control initialization
NTSTATUS InitializeDeviceControl() {
    return g_ModernDeviceControlContext.Initialize();
}

// Modern device control cleanup
VOID CleanupDeviceControl() {
    g_ModernDeviceControlContext.Cleanup();
}

// Modern device control handler
NTSTATUS HandleDeviceControl(
    _In_ ULONG ioControlCode,
    _In_ PVOID inputBuffer,
    _In_ ULONG inputBufferLength,
    _In_ PVOID outputBuffer,
    _In_ ULONG outputBufferLength,
    _Out_ PULONG bytesReturned
) {
    return g_ModernDeviceControlContext.HandleDeviceControl(
        ioControlCode, inputBuffer, inputBufferLength,
        outputBuffer, outputBufferLength, bytesReturned);
}

// Additional modern IOCTL registration
NTSTATUS RegisterCustomIoctlHandler(
    _In_ ULONG ioControlCode,
    _In_ std::function<NTSTATUS(PVOID, ULONG, PVOID, ULONG, PULONG)> handler
) {
    return g_ModernDeviceControlContext.RegisterHandler(ioControlCode, handler);
}