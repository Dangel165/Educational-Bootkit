# C++ Implementation Guide

## Overview

This guide provides comprehensive best practices and implementation guidelines for C++ development in the Bootkit Analysis Framework. The framework uses modern C++ standards (C++17 and later) with Windows Driver Kit (WDK) integration for kernel-mode development.

## C++ Standards and Compatibility

### Supported Standards
- **C++17**: Primary standard for framework development
- **C++20**: Experimental features where supported
- **Windows Extensions**: Microsoft-specific extensions for kernel development

### Compiler Requirements
- **Visual Studio 2019+** with C++ workload
- **Windows Driver Kit (WDK)** integration
- **Platform Toolset**: Latest Windows Driver Kit
- **Language Standard**: /std:c++17 or /std:c++latest

## Memory Management

### Smart Pointers
Use C++ smart pointers for automatic memory management:

#### Unique Pointer (std::unique_ptr)
```cpp
// Kernel-mode unique pointer with custom deleter
auto driverObject = std::unique_ptr<DRIVER_OBJECT, 
    decltype(&ObfDereferenceObject)>(
        IoGetDriverObjectByName(L"\\Driver\\BootkitDriver"),
        &ObfDereferenceObject
    );

// Custom allocator for kernel pool
template<typename T>
struct KernelAllocator {
    using value_type = T;
    
    KernelAllocator() = default;
    
    template<typename U>
    KernelAllocator(const KernelAllocator<U>&) {}
    
    T* allocate(size_t n) {
        return static_cast<T*>(ExAllocatePool2(
            POOL_FLAG_NON_PAGED, 
            n * sizeof(T), 
            'BktP'
        ));
    }
    
    void deallocate(T* p, size_t n) {
        ExFreePool(p);
    }
};

// Usage with vector
std::vector<IRP_HOOK_ENTRY, KernelAllocator<IRP_HOOK_ENTRY>> hooks;
```

#### Shared Pointer (std::shared_ptr)
```cpp
// Shared ownership in user-mode components
auto context = std::make_shared<IrpMonitoringContext>();

// Pass to other components
auto monitor = std::make_shared<IrpMonitor>(context);
```

### RAII (Resource Acquisition Is Initialization)
Implement RAII for all resources:

```cpp
class FastMutexLock {
public:
    explicit FastMutexLock(PFAST_MUTEX mutex) 
        : mutex_(mutex) {
        ExAcquireFastMutex(mutex_);
    }
    
    ~FastMutexLock() {
        ExReleaseFastMutex(mutex_);
    }
    
    // Non-copyable
    FastMutexLock(const FastMutexLock&) = delete;
    FastMutexLock& operator=(const FastMutexLock&) = delete;
    
private:
    PFAST_MUTEX mutex_;
};

// Usage
void ProcessIrp(PIRP irp) {
    FastMutexLock lock(&g_IrpContext.IrpLock);
    // Process IRP with lock held
    // Lock automatically released when function exits
}
```

### Pool Allocation Best Practices
```cpp
// Use type-safe pool allocation
template<typename T>
T* AllocateFromPool(POOL_TYPE poolType, ULONG tag = 'BktP') {
    return static_cast<T*>(ExAllocatePool2(
        poolType, 
        sizeof(T), 
        tag
    ));
}

// Use placement new for construction
auto entry = AllocateFromPool<IRP_HOOK_ENTRY>(NonPagedPoolNx);
if (entry) {
    new (entry) IRP_HOOK_ENTRY();  // Construct in-place
    // Use entry...
    entry->~IRP_HOOK_ENTRY();      // Destruct explicitly
    ExFreePool(entry);
}
```

## Error Handling

### Exception Safety
Implement exception-safe code with proper cleanup:

```cpp
class IrpMonitor {
public:
    IrpMonitor() 
        : deviceObject_(nullptr)
        , hooks_() {
        
        // Constructor should not throw for kernel code
        // Use NTSTATUS return pattern instead
    }
    
    NTSTATUS Initialize(PDRIVER_OBJECT driverObject) {
        NTSTATUS status = STATUS_SUCCESS;
        
        try {
            // Allocate resources that might fail
            deviceObject_ = CreateDeviceObject(driverObject);
            if (!deviceObject_) {
                throw std::bad_alloc();
            }
            
            // Initialize components
            status = InitializeHooks();
            if (!NT_SUCCESS(status)) {
                throw status;  // Throw NTSTATUS as exception
            }
            
        } catch (const std::bad_alloc&) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            Cleanup();
        } catch (NTSTATUS errorStatus) {
            status = errorStatus;
            Cleanup();
        } catch (...) {
            status = STATUS_UNSUCCESSFUL;
            Cleanup();
        }
        
        return status;
    }
    
private:
    void Cleanup() {
        if (deviceObject_) {
            IoDeleteDevice(deviceObject_);
            deviceObject_ = nullptr;
        }
        hooks_.clear();
    }
    
    PDEVICE_OBJECT deviceObject_;
    std::vector<IRP_HOOK_ENTRY> hooks_;
};
```

### NTSTATUS Pattern
Use consistent NTSTATUS return pattern:

```cpp
NTSTATUS PerformOperation(PVOID parameter) {
    NTSTATUS status = STATUS_SUCCESS;
    
    // Validate parameters
    if (!parameter) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    
    // Perform operation
    status = InternalOperation(parameter);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    
    // Additional operations...
    
Exit:
    // Cleanup if needed
    if (!NT_SUCCESS(status)) {
        CleanupResources();
    }
    
    return status;
}
```

## Concurrency and Thread Safety

### Synchronization Primitives
Use appropriate synchronization for kernel-mode:

```cpp
class ThreadSafeContext {
public:
    ThreadSafeContext() {
        ExInitializeFastMutex(&mutex_);
        ExInitializeResourceLite(&resource_);
        KeInitializeSpinLock(&spinLock_);
    }
    
    ~ThreadSafeContext() {
        ExDeleteResourceLite(&resource_);
    }
    
    // For frequent, short operations
    void UpdateWithSpinLock() {
        KIRQL oldIrql;
        KeAcquireSpinLock(&spinLock_, &oldIrql);
        
        // Update shared data
        sharedData_++;
        
        KeReleaseSpinLock(&spinLock_, oldIrql);
    }
    
    // For longer operations
    void UpdateWithMutex() {
        ExAcquireFastMutex(&mutex_);
        
        // Longer operation
        ProcessData();
        
        ExReleaseFastMutex(&mutex_);
    }
    
    // For reader/writer scenarios
    void ReadWithResource() {
        ExAcquireResourceSharedLite(&resource_, TRUE);
        
        // Read operation
        auto value = sharedData_;
        
        ExReleaseResourceLite(&resource_);
    }
    
    void WriteWithResource() {
        ExAcquireResourceExclusiveLite(&resource_, TRUE);
        
        // Write operation
        sharedData_ = newValue;
        
        ExReleaseResourceLite(&resource_);
    }
    
private:
    FAST_MUTEX mutex_;
    ERESOURCE resource_;
    KSPIN_LOCK spinLock_;
    ULONG sharedData_ = 0;
};
```

### Atomic Operations
Use atomic operations for simple shared data:

```cpp
#include <atomic>

class AtomicCounter {
public:
    void Increment() {
        counter_.fetch_add(1, std::memory_order_relaxed);
    }
    
    ULONG GetValue() const {
        return counter_.load(std::memory_order_acquire);
    }
    
    bool CompareAndSwap(ULONG expected, ULONG desired) {
        return counter_.compare_exchange_strong(
            expected, 
            desired,
            std::memory_order_acq_rel,
            std::memory_order_acquire
        );
    }
    
private:
    std::atomic<ULONG> counter_{0};
};
```

## Template Metaprogramming

### Type Traits
Use type traits for compile-time checks:

```cpp
// Check if type is pointer
template<typename T>
struct IsPointer {
    static constexpr bool value = false;
};

template<typename T>
struct IsPointer<T*> {
    static constexpr bool value = true;
};

// Usage
static_assert(IsPointer<PVOID>::value, "PVOID should be a pointer type");
static_assert(!IsPointer<ULONG>::value, "ULONG should not be a pointer type");

// Safe dereference with type checking
template<typename T>
typename std::enable_if<IsPointer<T>::value, 
    typename std::remove_pointer<T>::type>::type
SafeDereference(T ptr) {
    if (!ptr) {
        throw std::invalid_argument("Null pointer dereference");
    }
    return *ptr;
}
```

### SFINAE (Substitution Failure Is Not An Error)
Use SFINAE for template specialization:

```cpp
// Function for integral types
template<typename T>
typename std::enable_if<std::is_integral<T>::value, T>::type
ProcessValue(T value) {
    return value * 2;
}

// Function for pointer types  
template<typename T>
typename std::enable_if<std::is_pointer<T>::value, 
    typename std::remove_pointer<T>::type>::type
ProcessValue(T value) {
    if (!value) return 0;
    return *value;
}

// Compile-time selection
auto result1 = ProcessValue(42);      // Calls integral version
auto result2 = ProcessValue(&value);  // Calls pointer version
```

## Modern C++ Features

### Lambda Expressions
Use lambdas for concise callback implementations:

```cpp
// IRP completion routine as lambda
auto completionRoutine = [](PDEVICE_OBJECT deviceObject, 
                            PIRP irp, 
                            PVOID context) -> NTSTATUS {
    
    auto monitor = static_cast<IrpMonitor*>(context);
    if (monitor) {
        monitor->LogCompletion(irp);
    }
    
    // Continue completion
    return STATUS_SUCCESS;
};

// Install completion routine
IoSetCompletionRoutine(
    irp,
    completionRoutine,
    this,  // Context
    TRUE,  // InvokeOnSuccess
    TRUE,  // InvokeOnError
    TRUE   // InvokeOnCancel
);
```

### Range-based For Loops
Use modern iteration patterns:

```cpp
// Iterate through hook list
for (auto& hook : hooks_) {
    if (hook.Active) {
        ProcessHook(hook);
    }
}

// Iterate with index (C++20)
for (size_t i = 0; auto& hook : hooks_) {
    DebugPrint("Hook %zu: %ws\n", i, hook.TargetDeviceName);
    i++;
}
```

### Structured Bindings (C++17)
Use structured bindings for tuple-like types:

```cpp
// Return multiple values
std::tuple<NTSTATUS, PVOID, SIZE_T> AllocateMemory(SIZE_T size) {
    auto memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'BktP');
    if (!memory) {
        return { STATUS_INSUFFICIENT_RESOURCES, nullptr, 0 };
    }
    return { STATUS_SUCCESS, memory, size };
}

// Usage with structured binding
auto [status, memory, allocatedSize] = AllocateMemory(4096);
if (NT_SUCCESS(status)) {
    // Use memory and allocatedSize
}
```

## Kernel-Mode Specific Considerations

### Inline Assembly
Use inline assembly for low-level operations:

```cpp
// Read CPUID
ULONG cpuid[4];
__cpuid(cpuid, 1);

// Read MSR
ULONG64 msrValue;
msrValue = __readmsr(0x3A);  // IA32_FEATURE_CONTROL

// Memory barriers
_mm_lfence();   // Load fence
_mm_sfence();   // Store fence
_mm_mfence();   // Memory fence
```

### Memory-Mapped I/O
Access hardware registers safely:

```cpp
class MmioRegister {
public:
    explicit MmioRegister(PVOID address) 
        : address_(static_cast<volatile ULONG*>(address)) {}
    
    ULONG Read() const {
        return *address_;
    }
    
    void Write(ULONG value) {
        *address_ = value;
    }
    
    ULONG ReadModifyWrite(ULONG mask, ULONG value) {
        ULONG oldValue = Read();
        Write((oldValue & ~mask) | (value & mask));
        return oldValue;
    }
    
private:
    volatile ULONG* address_;
};
```

### Interrupt Handling
Implement interrupt service routines:

```cpp
// ISR prototype
BOOLEAN InterruptServiceRoutine(
    _In_ PKINTERRUPT interrupt,
    _In_ PVOID serviceContext
) {
    auto device = static_cast<PDEVICE_OBJECT>(serviceContext);
    
    // Read interrupt status
    ULONG status = ReadInterruptStatus(device);
    
    // Handle interrupt
    if (status & INTERRUPT_PENDING) {
        // Acknowledge interrupt
        AcknowledgeInterrupt(device);
        return TRUE;  // Interrupt handled
    }
    
    return FALSE;  // Interrupt not for this device
}
```

## Performance Optimization

### Cache Optimization
Optimize for CPU cache:

```cpp
// Align structures for cache lines
struct alignas(64) CacheAlignedData {
    ULONG data[16];  // 64 bytes = typical cache line size
};

// Use prefetching
void PrefetchData(PVOID data) {
    _mm_prefetch(static_cast<const char*>(data), _MM_HINT_T0);
}

// Avoid false sharing
struct ThreadLocalData {
    alignas(64) ULONG counter;  // Separate cache line per thread
    // ... other thread-local data
};
```

### Branch Prediction
Help CPU with branch prediction:

```cpp
// Use likely/unlikely hints
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

NTSTATUS ProcessRequest(PREQUEST request) {
    if (UNLIKELY(!request)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (LIKELY(request->Type == REQUEST_NORMAL)) {
        return ProcessNormalRequest(request);
    } else {
        return ProcessSpecialRequest(request);
    }
}
```

### Vectorization
Use SIMD instructions where appropriate:

```cpp
#include <immintrin.h>

void ProcessBuffer(float* buffer, size_t size) {
    // Process 8 floats at a time with AVX
    for (size_t i = 0; i < size; i += 8) {
        __m256 data = _mm256_load_ps(&buffer[i]);
        __m256 result = _mm256_mul_ps(data, _mm256_set1_ps(2.0f));
        _mm256_store_ps(&buffer[i], result);
    }
}
```

## Security Best Practices

### Input Validation
Validate all inputs thoroughly:

```cpp
NTSTATUS ValidateIrpParameters(PIRP irp) {
    if (!irp) {
        return STATUS_INVALID_PARAMETER;
    }
    
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (!stack) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    // Validate buffer access
    if (stack->Parameters.DeviceIoControl.InputBufferLength > MAX_INPUT_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    // Probe buffers for user-mode access
    __try {
        ProbeForRead(
            irp->AssociatedIrp.SystemBuffer,
            stack->Parameters.DeviceIoControl.InputBufferLength,
            sizeof(UCHAR)
        );
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    
    return STATUS_SUCCESS;
}
```

### Secure Memory Operations
Use secure memory functions:

```cpp
// Secure zeroing
void SecureZeroMemory(PVOID buffer, SIZE_T size) {
    RtlSecureZeroMemory(buffer, size);
}

// Secure copying
NTSTATUS SecureCopyMemory(PVOID dest, PVOID src, SIZE_T size) {
    __try {
        RtlCopyMemory(dest, src, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// Bounds checking
template<typename T, size_t N>
class BoundedArray {
public:
    T& operator[](size_t index) {
        if (index >= N) {
            throw std::out_of_range("Index out of bounds");
        }
        return data_[index];
    }
    
private:
    T data_[N];
};
```

## Testing and Debugging

### Unit Testing
Implement comprehensive unit tests:

```cpp
// Google Test example for kernel code
TEST(IrpMonitorTest, InitializeSuccess) {
    IrpMonitor monitor;
    DRIVER_OBJECT driverObject = {0};
    DEVICE_OBJECT deviceObject = {0};
    
    driverObject.DeviceObject = &deviceObject;
    
    NTSTATUS status = monitor.Initialize(&driverObject);
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_TRUE(monitor.IsInitialized());
}

TEST(IrpMonitorTest, InitializeNullDriver) {
    IrpMonitor monitor;
    
    NTSTATUS status = monitor.Initialize(nullptr);
    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    EXPECT_FALSE(monitor.IsInitialized());
}
```

### Debugging Support
Add comprehensive debugging support:

```cpp
class DebugLogger {
public:
    enum class Level {
        Error,
        Warning,
        Info,
        Verbose
    };
    
    static void Log(Level level, const char* format, ...) {
        if (static_cast<int>(level) > currentLevel_) {
            return;
        }
        
        va_list args;
        va_start(args, format);
        
        char buffer[512];
        vsnprintf(buffer, sizeof(buffer), format, args);
        
        DbgPrint("[Bootkit] %s: %s\n", 
                 LevelToString(level), 
                 buffer);
        
        va_end(args);
    }
    
private:
    static constexpr Level currentLevel_ = 
#ifdef DEBUG
        Level::Verbose;
#else
        Level::Warning;
#endif
    
    static const char* LevelToString(Level level) {
        switch (level) {
            case Level::Error: return "ERROR";
            case Level::Warning: return "WARNING";
            case Level::Info: return "INFO";
            case Level::Verbose: return "VERBOSE";
            default: return "UNKNOWN";
        }
    }
};

// Usage
DebugLogger::Log(DebugLogger::Level::Info, 
                 "IRP monitor initialized with %u hooks", 
                 hookCount);
```

## Code Organization

### Header Files
Organize headers properly:

```cpp
// BootkitDriver.h - Main driver header
#pragma once

#include <ntddk.h>
#include <wdf.h>

// Forward declarations
class IrpMonitor;
class BootFlowInterceptor;

// Global context
extern "C" {
    DRIVER_INITIALIZE DriverEntry;
    DRIVER_UNLOAD DriverUnload;
}

// Framework version
#define BOOTKIT_FRAMEWORK_VERSION_MAJOR 1
#define BOOTKIT_FRAMEWORK_VERSION_MINOR 0
#define BOOTKIT_FRAMEWORK_VERSION_PATCH 0
```

### Source Files
Organize source files by component:

```
drivers/BootkitDriver/
├── Driver.cpp          # Driver entry and main logic
├── IrpMonitor.cpp      # IRP monitoring implementation
├── BootFlowInterceptor.cpp # Boot analysis implementation
├── EvasionEngine.cpp   # Evasion techniques
├── ProcessConcealmentEngine.cpp # Process hiding
└── Common/            # Shared utilities
    ├── Memory.cpp     # Memory management
    ├── String.cpp     # String utilities
    └── Debug.cpp      # Debugging support
```

### Namespace Usage
Use namespaces to prevent collisions:

```cpp
namespace Bootkit {
    namespace Kernel {
        
        class IrpMonitor {
        public:
            NTSTATUS Initialize(PDRIVER_OBJECT driverObject);
            // ...
        };
        
        namespace Utilities {
            
            template<typename T>
            class SafePointer {
                // ...
            };
            
        } // namespace Utilities
        
    } // namespace Kernel
    
    namespace Analysis {
        
        class BehavioralAnalyzer {
            // ...
        };
        
    } // namespace Analysis
    
} // namespace Bootkit
```

## Build Configuration

### CMake Configuration
Use CMake for cross-platform builds:

```cmake
cmake_minimum_required(VERSION 3.15)
project(BootkitAnalysisFramework LANGUAGES CXX)

# Windows driver specific settings
if(WIN32)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    
    # Driver specific flags
    add_compile_options(
        /kernel
        /GS
        /guard:cf
        /W4
        /WX
    )
    
    add_link_options(
        /DRIVER
        /DYNAMICBASE
        /NXCOMPAT
        /MANIFEST:NO
    )
endif()

# Add driver target
add_library(BootkitDriver SHARED
    drivers/BootkitDriver/Driver.cpp
    drivers/BootkitDriver/IrpMonitor.cpp
    # ... other source files
)

# Test targets
add_executable(IrpMonitorTest
    tests/IrpMonitorTest.cpp
)

target_link_libraries(IrpMonitorTest
    BootkitDriver
    gtest
    gtest_main
)
```

## Conclusion

This C++ implementation guide provides comprehensive best practices for developing the Bootkit Analysis Framework. Follow these guidelines to ensure code quality, performance, security, and maintainability.

For additional information, refer to:
- [API Reference Documentation](API_REFERENCE_KERNEL.md)
- [Data Structures Reference](DATA_STRUCTURES.md)
- [Build and Compilation Guide](BUILD_GUIDE.md)

---

**⚠️ IMPORTANT: EDUCATIONAL USE ONLY ⚠️**

This implementation guide is for legitimate security research and educational purposes only. Always obtain proper authorization before implementing these techniques and follow all applicable laws and regulations.