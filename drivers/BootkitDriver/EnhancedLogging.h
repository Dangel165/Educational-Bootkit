// EnhancedLogging.h: Enhanced logging infrastructure with compile-time configuration
// Implements type-safe logging, variadic templates, and compile-time filtering

#pragma once

#include "ModernCpp.h"
#include "TemplateUtils.h"
#include <string_view>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <format>

namespace BootkitFramework {

// Log level enumeration
TYPE_SAFE_ENUM(LogLevel,
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    FATAL
);

// Compile-time log level configuration
template<LogLevel Level>
struct LogLevelConfig {
    static constexpr LogLevel Value = Level;
    
    static constexpr bool ShouldLog(LogLevel messageLevel) noexcept {
        return static_cast<int>(messageLevel) >= static_cast<int>(Value);
    }
};

// Default log level configuration
using DefaultLogLevel = LogLevelConfig<LogLevel::INFO>;

// Log entry structure
struct LogEntry {
    std::chrono::system_clock::time_point Timestamp;
    LogLevel Level;
    std::string_view Function;
    std::string_view File;
    int Line;
    std::string Message;
    
    LogEntry(LogLevel level, std::string_view function, 
             std::string_view file, int line, std::string message)
        : Timestamp(std::chrono::system_clock::now()),
          Level(level), Function(function), File(file), Line(line),
          Message(std::move(message)) {}
    
    std::string ToString() const {
        auto time = std::chrono::system_clock::to_time_t(Timestamp);
        std::tm tm;
        localtime_s(&tm, &time);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " ";
        
        switch (Level) {
            case LogLevel::TRACE:   oss << "[TRACE] "; break;
            case LogLevel::DEBUG:   oss << "[DEBUG] "; break;
            case LogLevel::INFO:    oss << "[INFO]  "; break;
            case LogLevel::WARNING: oss << "[WARN]  "; break;
            case LogLevel::ERROR:   oss << "[ERROR] "; break;
            case LogLevel::FATAL:   oss << "[FATAL] "; break;
        }
        
        oss << Function << " (" << File << ":" << Line << ") - " << Message;
        return oss.str();
    }
};

// Log sink interface
class ILogSink {
public:
    virtual ~ILogSink() = default;
    virtual void Write(const LogEntry& entry) = 0;
    virtual void Flush() = 0;
};

// Console log sink (kernel debugger)
class ConsoleLogSink : public ILogSink {
public:
    void Write(const LogEntry& entry) override {
        if constexpr (DefaultLogLevel::ShouldLog(entry.Level)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
                       ConvertLogLevel(entry.Level),
                       "%s\n", entry.ToString().c_str());
        }
    }
    
    void Flush() override {
        // Debugger output doesn't need flushing
    }
    
private:
    static ULONG ConvertLogLevel(LogLevel level) noexcept {
        switch (level) {
            case LogLevel::TRACE:   return DPFLTR_TRACE_LEVEL;
            case LogLevel::DEBUG:   return DPFLTR_TRACE_LEVEL;
            case LogLevel::INFO:    return DPFLTR_INFO_LEVEL;
            case LogLevel::WARNING: return DPFLTR_WARNING_LEVEL;
            case LogLevel::ERROR:   return DPFLTR_ERROR_LEVEL;
            case LogLevel::FATAL:   return DPFLTR_ERROR_LEVEL;
            default:                return DPFLTR_INFO_LEVEL;
        }
    }
};

// File log sink
class FileLogSink : public ILogSink {
private:
    HANDLE m_file;
    KernelMutex m_mutex;
    
public:
    FileLogSink(const wchar_t* filename) : m_file(INVALID_HANDLE_VALUE) {
        m_file = CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    
    ~FileLogSink() override {
        if (m_file != INVALID_HANDLE_VALUE) {
            CloseHandle(m_file);
        }
    }
    
    void Write(const LogEntry& entry) override {
        ScopedLock lock(m_mutex);
        if (m_file == INVALID_HANDLE_VALUE) {
            return;
        }
        
        std::string message = entry.ToString() + "\n";
        DWORD bytesWritten;
        WriteFile(m_file, message.c_str(), static_cast<DWORD>(message.size()),
                  &bytesWritten, nullptr);
    }
    
    void Flush() override {
        ScopedLock lock(m_mutex);
        if (m_file != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(m_file);
        }
    }
};

// Memory log sink (circular buffer)
class MemoryLogSink : public ILogSink {
private:
    struct LogBufferEntry {
        LogEntry Entry;
        LogBufferEntry* Next;
        
        LogBufferEntry(LogEntry&& entry) 
            : Entry(std::move(entry)), Next(nullptr) {}
    };
    
    LogBufferEntry* m_head;
    LogBufferEntry* m_tail;
    size_t m_capacity;
    size_t m_count;
    KernelMutex m_mutex;
    
public:
    MemoryLogSink(size_t capacity = 1000) 
        : m_head(nullptr), m_tail(nullptr), m_capacity(capacity), m_count(0) {}
    
    ~MemoryLogSink() override {
        Clear();
    }
    
    void Write(const LogEntry& entry) override {
        ScopedLock lock(m_mutex);
        
        auto* newEntry = new LogBufferEntry(LogEntry(entry));
        
        if (!m_head) {
            m_head = m_tail = newEntry;
        } else {
            m_tail->Next = newEntry;
            m_tail = newEntry;
        }
        
        m_count++;
        
        // Remove oldest entries if capacity exceeded
        while (m_count > m_capacity && m_head) {
            auto* oldHead = m_head;
            m_head = m_head->Next;
            delete oldHead;
            m_count--;
        }
    }
    
    void Flush() override {
        // Memory sink doesn't need flushing
    }
    
    std::vector<LogEntry> GetEntries(size_t maxEntries = 0) const {
        ScopedLock lock(m_mutex);
        
        std::vector<LogEntry> entries;
        entries.reserve(maxEntries > 0 ? std::min(maxEntries, m_count) : m_count);
        
        LogBufferEntry* current = m_head;
        size_t count = 0;
        
        while (current && (maxEntries == 0 || count < maxEntries)) {
            entries.push_back(current->Entry);
            current = current->Next;
            count++;
        }
        
        return entries;
    }
    
    void Clear() noexcept {
        ScopedLock lock(m_mutex);
        
        LogBufferEntry* current = m_head;
        while (current) {
            LogBufferEntry* next = current->Next;
            delete current;
            current = next;
        }
        
        m_head = m_tail = nullptr;
        m_count = 0;
    }
    
    size_t GetCount() const noexcept {
        ScopedLock lock(m_mutex);
        return m_count;
    }
};

// Composite log sink (multiple sinks)
class CompositeLogSink : public ILogSink {
private:
    std::vector<std::unique_ptr<ILogSink>> m_sinks;
    KernelMutex m_mutex;
    
public:
    void AddSink(std::unique_ptr<ILogSink> sink) {
        ScopedLock lock(m_mutex);
        m_sinks.push_back(std::move(sink));
    }
    
    void Write(const LogEntry& entry) override {
        ScopedLock lock(m_mutex);
        for (auto& sink : m_sinks) {
            sink->Write(entry);
        }
    }
    
    void Flush() override {
        ScopedLock lock(m_mutex);
        for (auto& sink : m_sinks) {
            sink->Flush();
        }
    }
    
    size_t GetSinkCount() const noexcept {
        ScopedLock lock(m_mutex);
        return m_sinks.size();
    }
    
    void ClearSinks() noexcept {
        ScopedLock lock(m_mutex);
        m_sinks.clear();
    }
};

// Logger class with compile-time configuration
template<typename SinkType = CompositeLogSink, 
         typename LevelConfig = DefaultLogLevel>
class Logger {
private:
    static inline std::unique_ptr<SinkType> s_sink;
    static inline KernelMutex s_mutex;
    
public:
    static void Initialize(std::unique_ptr<SinkType> sink) {
        ScopedLock lock(s_mutex);
        s_sink = std::move(sink);
    }
    
    static void Shutdown() noexcept {
        ScopedLock lock(s_mutex);
        if (s_sink) {
            s_sink->Flush();
            s_sink.reset();
        }
    }
    
    template<LogLevel Level, typename... Args>
    static void Log(std::string_view function, std::string_view file, 
                    int line, Args&&... args) {
        if constexpr (LevelConfig::ShouldLog(Level)) {
            ScopedLock lock(s_mutex);
            if (s_sink) {
                std::ostringstream oss;
                ((oss << std::forward<Args>(args)), ...);
                s_sink->Write(LogEntry(Level, function, file, line, oss.str()));
            }
        }
    }
    
    static void Flush() {
        ScopedLock lock(s_mutex);
        if (s_sink) {
            s_sink->Flush();
        }
    }
    
    static bool IsInitialized() noexcept {
        ScopedLock lock(s_mutex);
        return s_sink != nullptr;
    }
};

// Type-safe logging macros
#define LOG_TRACE(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::TRACE>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_DEBUG(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::DEBUG>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_INFO(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::INFO>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_WARNING(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::WARNING>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_ERROR(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::ERROR>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_FATAL(...) \
    BootkitFramework::Logger<>::Log<BootkitFramework::LogLevel::FATAL>( \
        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

// Compile-time filtered logging
template<bool Enable>
struct ConditionalLog {
    template<typename... Args>
    static void Trace(std::string_view function, std::string_view file, 
                      int line, Args&&... args) {
        if constexpr (Enable) {
            LOG_TRACE(std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    static void Debug(std::string_view function, std::string_view file, 
                      int line, Args&&... args) {
        if constexpr (Enable) {
            LOG_DEBUG(std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    static void Info(std::string_view function, std::string_view file, 
                     int line, Args&&... args) {
        if constexpr (Enable) {
            LOG_INFO(std::forward<Args>(args)...);
        }
    }
};

// Performance logging
class PerformanceLogger {
private:
    struct Measurement {
        std::string Name;
        std::chrono::high_resolution_clock::time_point StartTime;
        std::chrono::high_resolution_clock::time_point EndTime;
        
        std::chrono::microseconds Duration() const {
            return std::chrono::duration_cast<std::chrono::microseconds>(EndTime - StartTime);
        }
    };
    
    std::vector<Measurement> m_measurements;
    KernelMutex m_mutex;
    
public:
    class ScopedMeasurement {
    private:
        PerformanceLogger& m_logger;
        std::string m_name;
        std::chrono::high_resolution_clock::time_point m_start;
        
    public:
        ScopedMeasurement(PerformanceLogger& logger, std::string name)
            : m_logger(logger), m_name(std::move(name)), 
              m_start(std::chrono::high_resolution_clock::now()) {}
        
        ~ScopedMeasurement() {
            auto end = std::chrono::high_resolution_clock::now();
            m_logger.Record(m_name, m_start, end);
        }
    };
    
    void Record(const std::string& name, 
                std::chrono::high_resolution_clock::time_point start,
                std::chrono::high_resolution_clock::time_point end) {
        ScopedLock lock(m_mutex);
        m_measurements.push_back({name, start, end});
    }
    
    std::vector<Measurement> GetMeasurements() const {
        ScopedLock lock(m_mutex);
        return m_measurements;
    }
    
    void Clear() noexcept {
        ScopedLock lock(m_mutex);
        m_measurements.clear();
    }
    
    void DumpToLog() const {
        ScopedLock lock(m_mutex);
        for (const auto& measurement : m_measurements) {
            auto duration = measurement.Duration();
            LOG_INFO("Performance: {} took {} us", 
                     measurement.Name, duration.count());
        }
    }
};

// Audit logging
class AuditLogger {
private:
    struct AuditEntry {
        std::chrono::system_clock::time_point Timestamp;
        std::string User;
        std::string Action;
        std::string Resource;
        std::string Details;
        bool Success;
        
        std::string ToString() const {
            std::ostringstream oss;
            auto time = std::chrono::system_clock::to_time_t(Timestamp);
            std::tm tm;
            localtime_s(&tm, &time);
            
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " "
                << "USER=" << User << " "
                << "ACTION=" << Action << " "
                << "RESOURCE=" << Resource << " "
                << "DETAILS=" << Details << " "
                << "SUCCESS=" << (Success ? "YES" : "NO");
            
            return oss.str();
        }
    };
    
    ThreadSafeVector<AuditEntry> m_entries;
    size_t m_maxEntries;
    
public:
    AuditLogger(size_t maxEntries = 10000) : m_maxEntries(maxEntries) {}
    
    void Log(const std::string& user, const std::string& action,
             const std::string& resource, const std::string& details,
             bool success = true) {
        AuditEntry entry{
            std::chrono::system_clock::now(),
            user,
            action,
            resource,
            details,
            success
        };
        
        m_entries.PushBack(std::move(entry));
        
        // Trim if exceeds maximum
        if (m_entries.Size() > m_maxEntries) {
            m_entries.PopBack();
        }
        
        // Also log to regular logger
        LOG_INFO("Audit: {}", entry.ToString());
    }
    
    std::vector<AuditEntry> GetEntries(size_t maxCount = 0) const {
        std::vector<AuditEntry> entries;
        size_t count = m_entries.Size();
        size_t toGet = maxCount > 0 ? std::min(maxCount, count) : count;
        
        for (size_t i = 0; i < toGet; ++i) {
            entries.push_back(m_entries.At(i));
        }
        
        return entries;
    }
    
    void Clear() noexcept {
        m_entries.Clear();
    }
    
    size_t GetEntryCount() const noexcept {
        return m_entries.Size();
    }
};

// Logging configuration
struct LoggingConfig {
    bool EnableConsoleLogging;
    bool EnableFileLogging;
    bool EnableMemoryLogging;
    std::wstring LogFilePath;
    size_t MemoryLogCapacity;
    LogLevel MinLogLevel;
    
    LoggingConfig()
        : EnableConsoleLogging(true),
          EnableFileLogging(false),
          EnableMemoryLogging(true),
          LogFilePath(L"C:\\BootkitDriver.log"),
          MemoryLogCapacity(1000),
          MinLogLevel(LogLevel::INFO) {}
};

// Logging system initializer
class LoggingSystem {
public:
    static void Initialize(const LoggingConfig& config = LoggingConfig()) {
        auto compositeSink = std::make_unique<CompositeLogSink>();
        
        if (config.EnableConsoleLogging) {
            compositeSink->AddSink(std::make_unique<ConsoleLogSink>());
        }
        
        if (config.EnableFileLogging) {
            compositeSink->AddSink(std::make_unique<FileLogSink>(config.LogFilePath.c_str()));
        }
        
        if (config.EnableMemoryLogging) {
            compositeSink->AddSink(std::make_unique<MemoryLogSink>(config.MemoryLogCapacity));
        }
        
        Logger<>::Initialize(std::move(compositeSink));
        
        LOG_INFO("Logging system initialized");
        LOG_INFO("Console logging: {}", config.EnableConsoleLogging ? "ENABLED" : "DISABLED");
        LOG_INFO("File logging: {}", config.EnableFileLogging ? "ENABLED" : "DISABLED");
        LOG_INFO("Memory logging: {}", config.EnableMemoryLogging ? "ENABLED" : "DISABLED");
        LOG_INFO("Minimum log level: {}", static_cast<int>(config.MinLogLevel));
    }
    
    static void Shutdown() noexcept {
        LOG_INFO("Shutting down logging system");
        Logger<>::Shutdown();
    }
    
    static void Flush() {
        Logger<>::Flush();
    }
};

} // namespace BootkitFramework

// Global logging instances
inline BootkitFramework::PerformanceLogger g_PerformanceLogger;
inline BootkitFramework::AuditLogger g_AuditLogger;

// Performance measurement macro
#define PERF_SCOPE(name) \
    BootkitFramework::PerformanceLogger::ScopedMeasurement _perf_scope_(g_PerformanceLogger, name)

// Audit logging macro
#define AUDIT_LOG(user, action, resource, details, success) \
    g_AuditLogger.Log(user, action, resource, details, success)