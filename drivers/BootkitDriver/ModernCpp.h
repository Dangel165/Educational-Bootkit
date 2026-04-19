// ModernCpp.h: Modern C++ utilities and RAII wrappers for kernel-mode development
// This file implements C++17/20 best practices for Windows Driver Kit (WDK) development

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <memory>
#include <type_traits>
#include <utility>
#include <exception>
#include <stdexcept>
#include <string_view>
#include <atomic>
#include <mutex>
#include <chrono>

// Forward declarations
namespace BootkitFramework {
    class KernelException;
    class ScopedFastMutex;
    class UniqueKernelPtr;
    class KernelAllocator;
    template<typename T> class KernelUniquePtr;
    template<typename T> class KernelSharedPtr;
    class KernelResource;
    class KernelMemoryPool;
}

// Compile-time configuration
#ifdef _DEBUG
#define KERNEL_DEBUG 1
#else
#define KERNEL_DEBUG 0
#endif

// Compile-time logging configuration
template<bool Enable = KERNEL_DEBUG>
struct KernelLoggingConfig {
    static constexpr bool Enabled = Enable;
    static constexpr ULONG DefaultLevel = DPFLTR_INFO_LEVEL;
};

// Type-safe logging macros using variadic templates
template<typename... Args>
constexpr void KernelLogTrace(const char* format, Args&&... args) noexcept {
    if constexpr (KernelLoggingConfig<>::Enabled) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, 
                   "[BootkitDriver] TRACE: " format, std::forward<Args>(args)...);
    }
}

template<typename... Args>
constexpr void KernelLogInfo(const char* format, Args&&... args) noexcept {
    if constexpr (KernelLoggingConfig<>::Enabled) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
                   "[BootkitDriver] INFO: " format, std::forward<Args>(args)...);
    }
}

template<typename... Args>
constexpr void KernelLogWarning(const char* format, Args&&... args) noexcept {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, 
               "[BootkitDriver] WARNING: " format, std::forward<Args>(args)...);
}

template<typename... Args>
constexpr void KernelLogError(const char* format, Args&&... args) noexcept {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
               "[BootkitDriver] ERROR: " format, std::forward<Args>(args)...);
}

// Kernel exception class with NTSTATUS integration
namespace BootkitFramework {

class KernelException : public std::runtime_error {
private:
    NTSTATUS m_status;
    std::string m_function;
    ULONG m_line;

public:
    KernelException(NTSTATUS status, const char* message, const char* function, ULONG line)
        : std::runtime_error(message), m_status(status), m_function(function), m_line(line) {}

    NTSTATUS GetStatus() const noexcept { return m_status; }
    const std::string& GetFunction() const noexcept { return m_function; }
    ULONG GetLine() const noexcept { return m_line; }

    static void ThrowIfFailed(NTSTATUS status, const char* message, const char* function, ULONG line) {
        if (!NT_SUCCESS(status)) {
            throw KernelException(status, message, function, line);
        }
    }
};

// Exception-safe NTSTATUS wrapper
class NtStatus {
private:
    NTSTATUS m_status;

public:
    explicit NtStatus(NTSTATUS status = STATUS_SUCCESS) noexcept : m_status(status) {}
    
    operator NTSTATUS() const noexcept { return m_status; }
    
    bool Success() const noexcept { return NT_SUCCESS(m_status); }
    bool Failed() const noexcept { return !NT_SUCCESS(m_status); }
    
    void ThrowIfFailed(const char* message, const char* function, ULONG line) const {
        if (Failed()) {
            throw KernelException(m_status, message, function, line);
        }
    }
    
    template<typename Func>
    static NtStatus Try(Func&& func) noexcept {
        try {
            return NtStatus(func());
        } catch (const KernelException& e) {
            return NtStatus(e.GetStatus());
        } catch (...) {
            return NtStatus(STATUS_UNSUCCESSFUL);
        }
    }
};

// RAII wrapper for FAST_MUTEX
class ScopedFastMutex {
private:
    PFAST_MUTEX m_mutex;
    bool m_acquired;

public:
    explicit ScopedFastMutex(PFAST_MUTEX mutex) noexcept 
        : m_mutex(mutex), m_acquired(false) {
        if (m_mutex) {
            ExAcquireFastMutex(m_mutex);
            m_acquired = true;
        }
    }
    
    ~ScopedFastMutex() noexcept {
        if (m_acquired && m_mutex) {
            ExReleaseFastMutex(m_mutex);
        }
    }
    
    // Non-copyable
    ScopedFastMutex(const ScopedFastMutex&) = delete;
    ScopedFastMutex& operator=(const ScopedFastMutex&) = delete;
    
    // Movable
    ScopedFastMutex(ScopedFastMutex&& other) noexcept 
        : m_mutex(other.m_mutex), m_acquired(other.m_acquired) {
        other.m_mutex = nullptr;
        other.m_acquired = false;
    }
    
    ScopedFastMutex& operator=(ScopedFastMutex&& other) noexcept {
        if (this != &other) {
            if (m_acquired && m_mutex) {
                ExReleaseFastMutex(m_mutex);
            }
            m_mutex = other.m_mutex;
            m_acquired = other.m_acquired;
            other.m_mutex = nullptr;
            other.m_acquired = false;
        }
        return *this;
    }
};

// Custom kernel allocator with type safety
template<typename T>
class KernelAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using size_type = size_t;
    
    KernelAllocator() noexcept = default;
    
    template<typename U>
    KernelAllocator(const KernelAllocator<U>&) noexcept {}
    
    pointer allocate(size_type n) {
        if (n > (std::numeric_limits<size_type>::max() / sizeof(T))) {
            throw std::bad_alloc();
        }
        
        void* p = ExAllocatePool2(POOL_FLAG_NON_PAGED, n * sizeof(T), 'BDKT');
        if (!p) {
            throw std::bad_alloc();
        }
        
        return static_cast<pointer>(p);
    }
    
    void deallocate(pointer p, size_type) noexcept {
        ExFreePoolWithTag(p, 'BDKT');
    }
    
    template<typename U>
    struct rebind {
        using other = KernelAllocator<U>;
    };
};

// Kernel unique pointer with custom deleter
template<typename T>
class KernelUniquePtr {
private:
    T* m_ptr;
    
public:
    using element_type = T;
    
    explicit KernelUniquePtr(T* ptr = nullptr) noexcept : m_ptr(ptr) {}
    
    ~KernelUniquePtr() noexcept {
        reset();
    }
    
    // Non-copyable
    KernelUniquePtr(const KernelUniquePtr&) = delete;
    KernelUniquePtr& operator=(const KernelUniquePtr&) = delete;
    
    // Movable
    KernelUniquePtr(KernelUniquePtr&& other) noexcept : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }
    
    KernelUniquePtr& operator=(KernelUniquePtr&& other) noexcept {
        if (this != &other) {
            reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }
    
    T* get() const noexcept { return m_ptr; }
    T* operator->() const noexcept { return m_ptr; }
    T& operator*() const noexcept { return *m_ptr; }
    explicit operator bool() const noexcept { return m_ptr != nullptr; }
    
    void reset(T* ptr = nullptr) noexcept {
        if (m_ptr) {
            ExFreePoolWithTag(m_ptr, 'BDKT');
        }
        m_ptr = ptr;
    }
    
    T* release() noexcept {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }
};

// Kernel shared pointer with reference counting
template<typename T>
class KernelSharedPtr {
private:
    T* m_ptr;
    std::atomic<size_t>* m_refCount;
    
    void add_ref() noexcept {
        if (m_refCount) {
            m_refCount->fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    void release() noexcept {
        if (m_refCount && m_refCount->fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete m_refCount;
            if (m_ptr) {
                ExFreePoolWithTag(m_ptr, 'BDKT');
            }
        }
    }
    
public:
    explicit KernelSharedPtr(T* ptr = nullptr) 
        : m_ptr(ptr), m_refCount(ptr ? new std::atomic<size_t>(1) : nullptr) {}
    
    ~KernelSharedPtr() noexcept {
        release();
    }
    
    // Copyable
    KernelSharedPtr(const KernelSharedPtr& other) noexcept 
        : m_ptr(other.m_ptr), m_refCount(other.m_refCount) {
        add_ref();
    }
    
    KernelSharedPtr& operator=(const KernelSharedPtr& other) noexcept {
        if (this != &other) {
            release();
            m_ptr = other.m_ptr;
            m_refCount = other.m_refCount;
            add_ref();
        }
        return *this;
    }
    
    // Movable
    KernelSharedPtr(KernelSharedPtr&& other) noexcept 
        : m_ptr(other.m_ptr), m_refCount(other.m_refCount) {
        other.m_ptr = nullptr;
        other.m_refCount = nullptr;
    }
    
    KernelSharedPtr& operator=(KernelSharedPtr&& other) noexcept {
        if (this != &other) {
            release();
            m_ptr = other.m_ptr;
            m_refCount = other.m_refCount;
            other.m_ptr = nullptr;
            other.m_refCount = nullptr;
        }
        return *this;
    }
    
    T* get() const noexcept { return m_ptr; }
    T* operator->() const noexcept { return m_ptr; }
    T& operator*() const noexcept { return *m_ptr; }
    explicit operator bool() const noexcept { return m_ptr != nullptr; }
    
    size_t use_count() const noexcept {
        return m_refCount ? m_refCount->load(std::memory_order_relaxed) : 0;
    }
};

// Template metaprogramming utilities
namespace TypeTraits {
    
    // Check if type is a pointer
    template<typename T>
    struct IsPointer : std::false_type {};
    
    template<typename T>
    struct IsPointer<T*> : std::true_type {};
    
    template<typename T>
    struct IsPointer<T* const> : std::true_type {};
    
    template<typename T>
    struct IsPointer<T* volatile> : std::true_type {};
    
    template<typename T>
    struct IsPointer<T* const volatile> : std::true_type {};
    
    // Remove pointer
    template<typename T>
    struct RemovePointer {
        using Type = T;
    };
    
    template<typename T>
    struct RemovePointer<T*> {
        using Type = T;
    };
    
    template<typename T>
    struct RemovePointer<T* const> {
        using Type = T;
    };
    
    template<typename T>
    struct RemovePointer<T* volatile> {
        using Type = T;
    };
    
    template<typename T>
    struct RemovePointer<T* const volatile> {
        using Type = T;
    };
    
    // Compile-time string view for logging
    template<size_t N>
    struct FixedString {
        char data[N];
        
        constexpr FixedString(const char (&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i];
            }
        }
        
        constexpr operator std::string_view() const {
            return std::string_view(data, N - 1);
        }
    };
}

// Compile-time configuration utilities
template<auto Value>
struct ConfigValue {
    static constexpr auto value = Value;
};

template<bool EnableFeature>
struct FeatureFlag {
    static constexpr bool Enabled = EnableFeature;
    
    template<typename Func>
    static void ExecuteIfEnabled(Func&& func) {
        if constexpr (EnableFeature) {
            func();
        }
    }
};

// Thread-safe container base
template<typename T, typename Allocator = KernelAllocator<T>>
class ThreadSafeContainer {
protected:
    FAST_MUTEX m_mutex;
    Allocator m_allocator;
    
public:
    ThreadSafeContainer() {
        ExInitializeFastMutex(&m_mutex);
    }
    
    virtual ~ThreadSafeContainer() = default;
    
    // Non-copyable, non-movable
    ThreadSafeContainer(const ThreadSafeContainer&) = delete;
    ThreadSafeContainer& operator=(const ThreadSafeContainer&) = delete;
    ThreadSafeContainer(ThreadSafeContainer&&) = delete;
    ThreadSafeContainer& operator=(ThreadSafeContainer&&) = delete;
    
protected:
    void Lock() noexcept {
        ExAcquireFastMutex(&m_mutex);
    }
    
    void Unlock() noexcept {
        ExReleaseFastMutex(&m_mutex);
    }
    
    class ScopedLock {
    private:
        ThreadSafeContainer& m_container;
        
    public:
        explicit ScopedLock(ThreadSafeContainer& container) noexcept 
            : m_container(container) {
            m_container.Lock();
        }
        
        ~ScopedLock() noexcept {
            m_container.Unlock();
        }
        
        ScopedLock(const ScopedLock&) = delete;
        ScopedLock& operator=(const ScopedLock&) = delete;
    };
};

// Exception-safe resource wrapper
class KernelResource {
private:
    using CleanupFunc = void(*)(void*);
    
    void* m_resource;
    CleanupFunc m_cleanup;
    
public:
    KernelResource() noexcept : m_resource(nullptr), m_cleanup(nullptr) {}
    
    template<typename T>
    KernelResource(T* resource, CleanupFunc cleanup) noexcept 
        : m_resource(static_cast<void*>(resource)), m_cleanup(cleanup) {}
    
    ~KernelResource() noexcept {
        Release();
    }
    
    // Non-copyable
    KernelResource(const KernelResource&) = delete;
    KernelResource& operator=(const KernelResource&) = delete;
    
    // Movable
    KernelResource(KernelResource&& other) noexcept 
        : m_resource(other.m_resource), m_cleanup(other.m_cleanup) {
        other.m_resource = nullptr;
        other.m_cleanup = nullptr;
    }
    
    KernelResource& operator=(KernelResource&& other) noexcept {
        if (this != &other) {
            Release();
            m_resource = other.m_resource;
            m_cleanup = other.m_cleanup;
            other.m_resource = nullptr;
            other.m_cleanup = nullptr;
        }
        return *this;
    }
    
    template<typename T>
    T* Get() const noexcept {
        return static_cast<T*>(m_resource);
    }
    
    void Release() noexcept {
        if (m_resource && m_cleanup) {
            m_cleanup(m_resource);
            m_resource = nullptr;
            m_cleanup = nullptr;
        }
    }
    
    explicit operator bool() const noexcept {
        return m_resource != nullptr;
    }
};

} // namespace BootkitFramework

// Convenience macros for exception handling
#define KERNEL_TRY try
#define KERNEL_CATCH catch (const BootkitFramework::KernelException& e) { \
    KernelLogError("KernelException at %s:%lu - Status: 0x%08X - %s", \
                   e.GetFunction().c_str(), e.GetLine(), e.GetStatus(), e.what()); \
    return e.GetStatus(); \
} catch (const std::exception& e) { \
    KernelLogError("std::exception: %s", e.what()); \
    return STATUS_UNSUCCESSFUL; \
} catch (...) { \
    KernelLogError("Unknown exception"); \
    return STATUS_UNSUCCESSFUL; \
}

#define KERNEL_THROW_IF_FAILED(status, message) \
    BootkitFramework::KernelException::ThrowIfFailed(status, message, __FUNCTION__, __LINE__)

#define KERNEL_NTSTATUS(status) BootkitFramework::NtStatus(status)

// Compile-time feature flags
using KernelDebugLogging = BootkitFramework::FeatureFlag<KERNEL_DEBUG>;
using KernelExceptionHandling = BootkitFramework::FeatureFlag<true>;
using KernelMemoryPooling = BootkitFramework::FeatureFlag<true>;