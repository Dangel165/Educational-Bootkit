// IrpHandlersModern.cpp: Modern C++ IRP handler implementation
// Uses thread-safe patterns and exception safety

#include "pch.h"

using namespace BootkitFramework;

// Modern IRP handler context using RAII patterns
class ModernIrpHandlerContext {
private:
    KernelUniquePtr<IRP_HANDLER_CONTEXT> m_context;
    KernelMutex m_mutex;
    ThreadSafeMap<UCHAR, TypeSafeCallback<PDEVICE_OBJECT, PIRP>> m_irpHandlers;
    ThreadSafeQueue<PIRP> m_pendingIrps;
    KernelThreadPool m_irpThreadPool;
    
public:
    ModernIrpHandlerContext() 
        : m_context(nullptr), m_irpThreadPool(2) {} // 2 threads for IRP processing
    
    ~ModernIrpHandlerContext() {
        Cleanup();
    }
    
    NTSTATUS Initialize() {
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Allocate context using modern memory management
            m_context.reset(static_cast<IRP_HANDLER_CONTEXT*>(
                g_MemoryManager->Allocate(sizeof(IRP_HANDLER_CONTEXT))));
            
            if (!m_context) {
                KERNEL_THROW_IF_FAILED(STATUS_INSUFFICIENT_RESOURCES,
                                      "Failed to allocate IRP handler context");
            }
            
            // Initialize context
            RtlZeroMemory(m_context.get(), sizeof(IRP_HANDLER_CONTEXT));
            ExInitializeFastMutex(&m_context->HandlerLock);
            
            // Register default IRP handlers
            RegisterDefaultHandlers();
            
            LOG_INFO("Modern IRP handler context initialized");
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    void Cleanup() noexcept {
        ScopedLock lock(m_mutex);
        if (m_context) {
            LOG_INFO("Cleaning up modern IRP handler context");
            
            // Stop thread pool
            m_irpThreadPool.Stop();
            
            // Clear all handlers
            m_irpHandlers.Clear();
            
            // Complete pending IRPs
            CompletePendingIrps();
            
            // Free context
            g_MemoryManager->Free(m_context.get(), sizeof(IRP_HANDLER_CONTEXT));
            m_context.reset();
        }
    }
    
    IRP_HANDLER_CONTEXT* Get() const noexcept {
        return m_context.get();
    }
    
    // Modern IRP handler registration
    template<typename Handler>
    NTSTATUS RegisterHandler(UCHAR majorFunction, Handler&& handler) {
        ScopedLock lock(m_mutex);
        
        if (m_irpHandlers.Contains(majorFunction)) {
            LOG_WARNING("IRP handler already registered: 0x%02X", majorFunction);
            return STATUS_OBJECT_NAME_COLLISION;
        }
        
        m_irpHandlers.Insert(majorFunction,
            [handler = std::forward<Handler>(handler)](
                PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                
                PERF_SCOPE(fmt::format("IrpHandler_0x{:02X}", majorFunction).c_str());
                
                KERNEL_TRY {
                    return handler(deviceObject, irp);
                }
                KERNEL_CATCH
            });
        
        LOG_INFO("Registered handler for IRP_MJ: 0x%02X", majorFunction);
        return STATUS_SUCCESS;
    }
    
    // Modern IRP dispatch
    NTSTATUS DispatchIrp(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp,
        _In_ UCHAR majorFunction
    ) {
        KERNEL_TRY {
            ScopedLock lock(m_mutex);
            
            // Update statistics
            m_context->TotalIrpsProcessed++;
            
            // Find handler
            auto handler = m_irpHandlers.Find(majorFunction);
            if (handler != m_irpHandlers.end()) {
                NTSTATUS status = handler->second(deviceObject, irp);
                
                if (!NT_SUCCESS(status)) {
                    m_context->FailedIrps++;
                }
                
                AUDIT_LOG("SYSTEM", "IRP_DISPATCH", "Driver",
                         fmt::format("IRP_MJ: 0x{:02X} - Status: 0x{:08X}", 
                                    majorFunction, status),
                         NT_SUCCESS(status));
                
                return status;
            }
            
            // No handler found - forward to next device
            m_context->FailedIrps++;
            LOG_WARNING("No handler for IRP_MJ: 0x%02X", majorFunction);
            
            return ForwardIrpToNextDevice(deviceObject, irp);
        }
        KERNEL_CATCH
    }
    
    // Async IRP processing
    std::future<NTSTATUS> DispatchIrpAsync(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp,
        _In_ UCHAR majorFunction
    ) {
        KERNEL_TRY {
            auto promise = std::make_shared<std::promise<NTSTATUS>>();
            std::future<NTSTATUS> future = promise->get_future();
            
            // Submit to thread pool
            m_irpThreadPool.Submit([this, deviceObject, irp, majorFunction, promise]() {
                NTSTATUS status = DispatchIrp(deviceObject, irp, majorFunction);
                promise->set_value(status);
            });
            
            // Store pending IRP
            m_pendingIrps.Push(irp);
            
            return future;
        }
        KERNEL_CATCH
    }
    
private:
    void RegisterDefaultHandlers() {
        // IRP_MJ_CREATE handler
        RegisterHandler(IRP_MJ_CREATE,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleCreate(deviceObject, irp);
            });
        
        // IRP_MJ_CLOSE handler
        RegisterHandler(IRP_MJ_CLOSE,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleClose(deviceObject, irp);
            });
        
        // IRP_MJ_READ handler
        RegisterHandler(IRP_MJ_READ,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleRead(deviceObject, irp);
            });
        
        // IRP_MJ_WRITE handler
        RegisterHandler(IRP_MJ_WRITE,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleWrite(deviceObject, irp);
            });
        
        // IRP_MJ_DEVICE_CONTROL handler
        RegisterHandler(IRP_MJ_DEVICE_CONTROL,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleDeviceControl(deviceObject, irp);
            });
        
        // IRP_MJ_CLEANUP handler
        RegisterHandler(IRP_MJ_CLEANUP,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleCleanup(deviceObject, irp);
            });
        
        // IRP_MJ_SHUTDOWN handler
        RegisterHandler(IRP_MJ_SHUTDOWN,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandleShutdown(deviceObject, irp);
            });
        
        // IRP_MJ_PNP handler
        RegisterHandler(IRP_MJ_PNP,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandlePnp(deviceObject, irp);
            });
        
        // IRP_MJ_POWER handler
        RegisterHandler(IRP_MJ_POWER,
            [this](PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS {
                return HandlePower(deviceObject, irp);
            });
    }
    
    NTSTATUS HandleCreate(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_CREATE handler");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("USER", "FILE_CREATE", "Device",
                     "File handle created", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleClose(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_CLOSE handler");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("USER", "FILE_CLOSE", "Device",
                     "File handle closed", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleRead(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_READ handler");
            
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            PMDL mdl = irp->MdlAddress;
            
            // Validate parameters
            if (!irpStack->Parameters.Read.Length) {
                return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            
            if (!mdl) {
                return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            
            // Get user buffer
            PVOID userBuffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (!userBuffer) {
                return CompleteIrp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            }
            
            // Process read request
            ULONG bytesRead = ProcessReadRequest(
                userBuffer,
                irpStack->Parameters.Read.Length,
                irpStack->Parameters.Read.ByteOffset);
            
            return CompleteIrp(irp, STATUS_SUCCESS, bytesRead);
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleWrite(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_WRITE handler");
            
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            PMDL mdl = irp->MdlAddress;
            
            // Validate parameters
            if (!irpStack->Parameters.Write.Length) {
                return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            
            if (!mdl) {
                return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            
            // Get user buffer
            PVOID userBuffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (!userBuffer) {
                return CompleteIrp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            }
            
            // Process write request
            ULONG bytesWritten = ProcessWriteRequest(
                userBuffer,
                irpStack->Parameters.Write.Length,
                irpStack->Parameters.Write.ByteOffset);
            
            return CompleteIrp(irp, STATUS_SUCCESS, bytesWritten);
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleDeviceControl(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_DEVICE_CONTROL handler");
            
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
            PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
            ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
            PVOID outputBuffer = irp->AssociatedIrp.SystemBuffer;
            ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
            ULONG bytesReturned = 0;
            
            // Handle IOCTL
            NTSTATUS status = ::HandleDeviceControl(
                ioControlCode,
                inputBuffer,
                inputBufferLength,
                outputBuffer,
                outputBufferLength,
                &bytesReturned);
            
            return CompleteIrp(irp, status, bytesReturned);
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleCleanup(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_CLEANUP handler");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("SYSTEM", "FILE_CLEANUP", "Device",
                     "File cleanup completed", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandleShutdown(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_SHUTDOWN handler");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("SYSTEM", "SYSTEM_SHUTDOWN", "Device",
                     "System shutdown notification", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePnp(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_PNP handler");
            
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            UCHAR minorFunction = irpStack->MinorFunction;
            
            switch (minorFunction) {
                case IRP_MN_START_DEVICE:
                    return HandlePnpStartDevice(deviceObject, irp);
                    
                case IRP_MN_STOP_DEVICE:
                    return HandlePnpStopDevice(deviceObject, irp);
                    
                case IRP_MN_REMOVE_DEVICE:
                    return HandlePnpRemoveDevice(deviceObject, irp);
                    
                default:
                    // Forward to next device
                    return ForwardIrpToNextDevice(deviceObject, irp);
            }
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePower(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_TRACE("Modern IRP_MJ_POWER handler");
            
            // For power IRPs, we typically just forward them
            PoStartNextPowerIrp(irp);
            return ForwardIrpToNextDevice(deviceObject, irp);
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePnpStartDevice(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_INFO("Modern PNP Start Device");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("SYSTEM", "PNP_START_DEVICE", "Device",
                     "Device started successfully", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePnpStopDevice(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_INFO("Modern PNP Stop Device");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("SYSTEM", "PNP_STOP_DEVICE", "Device",
                     "Device stopped", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    NTSTATUS HandlePnpRemoveDevice(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            LOG_INFO("Modern PNP Remove Device");
            
            // Complete IRP successfully
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            AUDIT_LOG("SYSTEM", "PNP_REMOVE_DEVICE", "Device",
                     "Device removed", true);
            
            return STATUS_SUCCESS;
        }
        KERNEL_CATCH
    }
    
    ULONG ProcessReadRequest(
        _In_ PVOID buffer,
        _In_ ULONG length,
        _In_ LARGE_INTEGER byteOffset
    ) {
        KERNEL_TRY {
            // Simulate read operation
            // In real implementation, this would read from device memory or file
            
            // Fill buffer with pattern
            PUCHAR data = static_cast<PUCHAR>(buffer);
            for (ULONG i = 0; i < length; ++i) {
                data[i] = static_cast<UCHAR>((byteOffset.QuadPart + i) & 0xFF);
            }
            
            LOG_TRACE("Read processed: offset=%I64d, length=%lu", 
                     byteOffset.QuadPart, length);
            
            return length;
        }
        KERNEL_CATCH
        
        return 0;
    }
    
    ULONG ProcessWriteRequest(
        _In_ PVOID buffer,
        _In_ ULONG length,
        _In_ LARGE_INTEGER byteOffset
    ) {
        KERNEL_TRY {
            // Simulate write operation
            // In real implementation, this would write to device memory or file
            
            LOG_TRACE("Write processed: offset=%I64d, length=%lu", 
                     byteOffset.QuadPart, length);
            
            // Validate data (simple checksum)
            PUCHAR data = static_cast<PUCHAR>(buffer);
            ULONG checksum = 0;
            for (ULONG i = 0; i < length; ++i) {
                checksum += data[i];
            }
            
            LOG_TRACE("Write checksum: 0x%08X", checksum);
            
            return length;
        }
        KERNEL_CATCH
        
        return 0;
    }
    
    NTSTATUS CompleteIrp(
        _In_ PIRP irp,
        _In_ NTSTATUS status,
        _In_ ULONG_PTR information
    ) {
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = information;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
    
    NTSTATUS ForwardIrpToNextDevice(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp
    ) {
        KERNEL_TRY {
            PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
            
            // Skip current stack location
            IoSkipCurrentIrpStackLocation(irp);
            
            // Call next driver
            return IoCallDriver(deviceObject->AttachedDevice, irp);
        }
        KERNEL_CATCH
    }
    
    void CompletePendingIrps() {
        PIRP irp = nullptr;
        while (m_pendingIrps.TryPop(irp)) {
            if (irp) {
                CompleteIrp(irp, STATUS_CANCELLED, 0);
            }
        }
    }
};

// Global modern IRP handler context
static ModernIrpHandlerContext g_ModernIrpHandlerContext;

// Modern IRP handler initialization
NTSTATUS InitializeIrpHandlers() {
    return g_ModernIrpHandlerContext.Initialize();
}

// Modern IRP handler cleanup
VOID CleanupIrpHandlers() {
    g_ModernIrpHandlerContext.Cleanup();
}

// Modern IRP handlers (compatibility wrappers)
NTSTATUS IrpCreateHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_CREATE);
}

NTSTATUS IrpCloseHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_CLOSE);
}

NTSTATUS IrpReadHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_READ);
}

NTSTATUS IrpWriteHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_WRITE);
}

NTSTATUS IrpDeviceControlHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_DEVICE_CONTROL);
}

NTSTATUS IrpCleanupHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_CLEANUP);
}

NTSTATUS IrpShutdownHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_SHUTDOWN);
}

NTSTATUS IrpPnpHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_PNP);
}

NTSTATUS IrpPowerHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    return g_ModernIrpHandlerContext.DispatchIrp(deviceObject, irp, IRP_MJ_POWER);
}

// Modern IRP completion routine
NTSTATUS CompleteIrp(
    _In_ PIRP irp,
    _In_ NTSTATUS status,
    _In_ ULONG_PTR information
) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

// Modern IRP forwarding
NTSTATUS ForwardIrpToNextDevice(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp
) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(deviceObject->AttachedDevice, irp);
}

// Additional modern IRP registration
NTSTATUS RegisterCustomIrpHandler(
    _In_ UCHAR majorFunction,
    _In_ std::function<NTSTATUS(PDEVICE_OBJECT, PIRP)> handler
) {
    return g_ModernIrpHandlerContext.RegisterHandler(majorFunction, handler);
}