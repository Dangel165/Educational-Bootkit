// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// Windows headers
#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>

// Standard C/C++ headers
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// Modern C++ headers
#include <memory>
#include <type_traits>
#include <utility>
#include <exception>
#include <stdexcept>
#include <string_view>
#include <atomic>
#include <mutex>
#include <chrono>
#include <vector>
#include <list>
#include <map>
#include <queue>
#include <functional>
#include <future>
#include <tuple>
#include <variant>
#include <optional>
#include <sstream>
#include <iomanip>
#include <format>

// Framework headers
#include "Driver.h"
#include "IrpHandlers.h"
#include "DeviceControl.h"
#include "Debug.h"
#include "BootLoaderEntryPointAnalyzer.h"
#include "IrpMonitor.h"
#include "BootFlowInterceptor.h"

// Modern C++ utilities
#include "ModernCpp.h"
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "TemplateUtils.h"
#include "EnhancedLogging.h"

// Debug macros (legacy - use modern logging instead)
#if DBG
#define DEBUG_PRINT(level, fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, level, "[BootkitDriver] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(level, fmt, ...)
#endif

#define LOG_ERROR(fmt, ...) DEBUG_PRINT(DPFLTR_ERROR_LEVEL, "ERROR: " fmt, ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) DEBUG_PRINT(DPFLTR_WARNING_LEVEL, "WARNING: " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) DEBUG_PRINT(DPFLTR_INFO_LEVEL, "INFO: " fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) DEBUG_PRINT(DPFLTR_TRACE_LEVEL, "TRACE: " fmt, ##__VA_ARGS__)

// Memory allocation macros (legacy - use modern allocators instead)
#define ALLOCATE_NONPAGED(size) ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'BDKT')
#define ALLOCATE_PAGED(size) ExAllocatePool2(POOL_FLAG_PAGED, size, 'BDKT')
#define FREE_MEMORY(ptr) ExFreePoolWithTag(ptr, 'BDKT')

// Utility macros
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Modern C++ convenience macros
#define KERNEL_TRY try
#define KERNEL_CATCH catch (const BootkitFramework::KernelException& e) { \
    LOG_ERROR("KernelException at %s:%lu - Status: 0x%08X - %s", \
              e.GetFunction().c_str(), e.GetLine(), e.GetStatus(), e.what()); \
    return e.GetStatus(); \
} catch (const std::exception& e) { \
    LOG_ERROR("std::exception: %s", e.what()); \
    return STATUS_UNSUCCESSFUL; \
} catch (...) { \
    LOG_ERROR("Unknown exception"); \
    return STATUS_UNSUCCESSFUL; \
}

#define KERNEL_THROW_IF_FAILED(status, message) \
    BootkitFramework::KernelException::ThrowIfFailed(status, message, __FUNCTION__, __LINE__)

#define KERNEL_NTSTATUS(status) BootkitFramework::NtStatus(status)

// Modern logging macros (preferred)
#define MODERN_LOG_TRACE(...) LOG_TRACE(__VA_ARGS__)
#define MODERN_LOG_INFO(...) LOG_INFO(__VA_ARGS__)
#define MODERN_LOG_WARNING(...) LOG_WARNING(__VA_ARGS__)
#define MODERN_LOG_ERROR(...) LOG_ERROR(__VA_ARGS__)

// Compile-time configuration
#ifdef _DEBUG
#define KERNEL_DEBUG 1
#else
#define KERNEL_DEBUG 0
#endif

// Feature flags
#define ENABLE_EXCEPTION_HANDLING 1
#define ENABLE_MEMORY_POOLING 1
#define ENABLE_ADVANCED_LOGGING 1
#define ENABLE_THREAD_SAFE_CONTAINERS 1

// Safe string operations
#define COPY_STRING(dest, src, dest_size) \
    RtlStringCbCopyW((dest), (dest_size), (src))

#define APPEND_STRING(dest, src, dest_size, dest_used) \
    RtlStringCbCatExW((dest), (dest_size), (src), NULL, NULL, 0)

#endif // PCH_H