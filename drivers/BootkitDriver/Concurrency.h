// Concurrency.h: Thread-safe design patterns using C++11/14/17 concurrency features
// Implements synchronization primitives, lock-free algorithms, and thread-safe containers

#pragma once

#include "ModernCpp.h"
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <list>
#include <map>
#include <functional>
#include <future>

namespace BootkitFramework {

// Kernel-compatible mutex wrapper
class KernelMutex {
private:
    FAST_MUTEX m_mutex;
    
public:
    KernelMutex() {
        ExInitializeFastMutex(&m_mutex);
    }
    
    ~KernelMutex() = default;
    
    // Non-copyable, non-movable
    KernelMutex(const KernelMutex&) = delete;
    KernelMutex& operator=(const KernelMutex&) = delete;
    KernelMutex(KernelMutex&&) = delete;
    KernelMutex& operator=(KernelMutex&&) = delete;
    
    void lock() noexcept {
        ExAcquireFastMutex(&m_mutex);
    }
    
    bool try_lock() noexcept {
        return ExTryToAcquireFastMutex(&m_mutex) != FALSE;
    }
    
    void unlock() noexcept {
        ExReleaseFastMutex(&m_mutex);
    }
};

// Kernel-compatible shared mutex (reader-writer lock)
class KernelSharedMutex {
private:
    EX_PUSH_LOCK m_lock;
    
public:
    KernelSharedMutex() {
        ExInitializePushLock(&m_lock);
    }
    
    ~KernelSharedMutex() = default;
    
    // Non-copyable, non-movable
    KernelSharedMutex(const KernelSharedMutex&) = delete;
    KernelSharedMutex& operator=(const KernelSharedMutex&) = delete;
    KernelSharedMutex(KernelSharedMutex&&) = delete;
    KernelSharedMutex& operator=(KernelSharedMutex&&) = delete;
    
    // Exclusive lock (writer)
    void lock() noexcept {
        ExAcquirePushLockExclusive(&m_lock);
    }
    
    bool try_lock() noexcept {
        return ExTryToAcquirePushLockExclusive(&m_lock) != FALSE;
    }
    
    void unlock() noexcept {
        ExReleasePushLockExclusive(&m_lock);
    }
    
    // Shared lock (reader)
    void lock_shared() noexcept {
        ExAcquirePushLockShared(&m_lock);
    }
    
    bool try_lock_shared() noexcept {
        return ExTryToAcquirePushLockShared(&m_lock) != FALSE;
    }
    
    void unlock_shared() noexcept {
        ExReleasePushLockShared(&m_lock);
    }
};

// Scoped lock templates
template<typename Mutex>
class ScopedLock {
private:
    Mutex& m_mutex;
    
public:
    explicit ScopedLock(Mutex& mutex) noexcept : m_mutex(mutex) {
        m_mutex.lock();
    }
    
    ~ScopedLock() noexcept {
        m_mutex.unlock();
    }
    
    // Non-copyable, non-movable
    ScopedLock(const ScopedLock&) = delete;
    ScopedLock& operator=(const ScopedLock&) = delete;
    ScopedLock(ScopedLock&&) = delete;
    ScopedLock& operator=(ScopedLock&&) = delete;
};

template<typename Mutex>
class ScopedSharedLock {
private:
    Mutex& m_mutex;
    
public:
    explicit ScopedSharedLock(Mutex& mutex) noexcept : m_mutex(mutex) {
        m_mutex.lock_shared();
    }
    
    ~ScopedSharedLock() noexcept {
        m_mutex.unlock_shared();
    }
    
    // Non-copyable, non-movable
    ScopedSharedLock(const ScopedSharedLock&) = delete;
    ScopedSharedLock& operator=(const ScopedSharedLock&) = delete;
    ScopedSharedLock(ScopedSharedLock&&) = delete;
    ScopedSharedLock& operator=(ScopedSharedLock&&) = delete;
};

// Thread-safe queue using kernel mutex
template<typename T, typename Allocator = KernelAllocator<T>>
class ThreadSafeQueue {
private:
    std::queue<T, std::deque<T, Allocator>> m_queue;
    KernelMutex m_mutex;
    
public:
    ThreadSafeQueue() = default;
    
    void Push(const T& value) {
        ScopedLock lock(m_mutex);
        m_queue.push(value);
    }
    
    void Push(T&& value) {
        ScopedLock lock(m_mutex);
        m_queue.push(std::move(value));
    }
    
    template<typename... Args>
    void Emplace(Args&&... args) {
        ScopedLock lock(m_mutex);
        m_queue.emplace(std::forward<Args>(args)...);
    }
    
    bool TryPop(T& value) noexcept {
        ScopedLock lock(m_mutex);
        if (m_queue.empty()) {
            return false;
        }
        value = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }
    
    T Pop() {
        ScopedLock lock(m_mutex);
        if (m_queue.empty()) {
            throw std::runtime_error("Queue is empty");
        }
        T value = std::move(m_queue.front());
        m_queue.pop();
        return value;
    }
    
    bool Empty() const noexcept {
        ScopedLock lock(m_mutex);
        return m_queue.empty();
    }
    
    size_t Size() const noexcept {
        ScopedLock lock(m_mutex);
        return m_queue.size();
    }
    
    void Clear() noexcept {
        ScopedLock lock(m_mutex);
        while (!m_queue.empty()) {
            m_queue.pop();
        }
    }
};

// Thread-safe vector with fine-grained locking
template<typename T, typename Allocator = KernelAllocator<T>>
class ThreadSafeVector {
private:
    std::vector<T, Allocator> m_vector;
    mutable KernelSharedMutex m_mutex;
    
public:
    ThreadSafeVector() = default;
    
    explicit ThreadSafeVector(size_t count) : m_vector(count) {}
    
    ThreadSafeVector(size_t count, const T& value) : m_vector(count, value) {}
    
    // Thread-safe access
    T& At(size_t index) {
        ScopedSharedLock lock(m_mutex);
        if (index >= m_vector.size()) {
            throw std::out_of_range("Index out of range");
        }
        return m_vector[index];
    }
    
    const T& At(size_t index) const {
        ScopedSharedLock lock(m_mutex);
        if (index >= m_vector.size()) {
            throw std::out_of_range("Index out of range");
        }
        return m_vector[index];
    }
    
    // Thread-safe modification
    void PushBack(const T& value) {
        ScopedLock lock(m_mutex);
        m_vector.push_back(value);
    }
    
    void PushBack(T&& value) {
        ScopedLock lock(m_mutex);
        m_vector.push_back(std::move(value));
    }
    
    template<typename... Args>
    void EmplaceBack(Args&&... args) {
        ScopedLock lock(m_mutex);
        m_vector.emplace_back(std::forward<Args>(args)...);
    }
    
    void PopBack() {
        ScopedLock lock(m_mutex);
        if (m_vector.empty()) {
            throw std::runtime_error("Vector is empty");
        }
        m_vector.pop_back();
    }
    
    void Resize(size_t count) {
        ScopedLock lock(m_mutex);
        m_vector.resize(count);
    }
    
    void Resize(size_t count, const T& value) {
        ScopedLock lock(m_mutex);
        m_vector.resize(count, value);
    }
    
    void Clear() noexcept {
        ScopedLock lock(m_mutex);
        m_vector.clear();
    }
    
    // Thread-safe queries
    size_t Size() const noexcept {
        ScopedSharedLock lock(m_mutex);
        return m_vector.size();
    }
    
    bool Empty() const noexcept {
        ScopedSharedLock lock(m_mutex);
        return m_vector.empty();
    }
    
    // Thread-safe iteration
    template<typename Func>
    void ForEach(Func&& func) {
        ScopedSharedLock lock(m_mutex);
        for (auto& item : m_vector) {
            func(item);
        }
    }
    
    template<typename Func>
    void ForEachConst(Func&& func) const {
        ScopedSharedLock lock(m_mutex);
        for (const auto& item : m_vector) {
            func(item);
        }
    }
};

// Thread-safe map with fine-grained locking
template<typename Key, typename Value, 
         typename Compare = std::less<Key>,
         typename Allocator = KernelAllocator<std::pair<const Key, Value>>>
class ThreadSafeMap {
private:
    std::map<Key, Value, Compare, Allocator> m_map;
    mutable KernelSharedMutex m_mutex;
    
public:
    ThreadSafeMap() = default;
    
    // Thread-safe insertion
    template<typename K, typename V>
    std::pair<typename std::map<Key, Value>::iterator, bool> 
    Insert(K&& key, V&& value) {
        ScopedLock lock(m_mutex);
        return m_map.emplace(std::forward<K>(key), std::forward<V>(value));
    }
    
    template<typename K, typename V>
    std::pair<typename std::map<Key, Value>::iterator, bool> 
    InsertOrAssign(K&& key, V&& value) {
        ScopedLock lock(m_mutex);
        auto result = m_map.find(key);
        if (result != m_map.end()) {
            result->second = std::forward<V>(value);
            return {result, false};
        } else {
            return m_map.emplace(std::forward<K>(key), std::forward<V>(value));
        }
    }
    
    // Thread-safe access
    Value& At(const Key& key) {
        ScopedSharedLock lock(m_mutex);
        return m_map.at(key);
    }
    
    const Value& At(const Key& key) const {
        ScopedSharedLock lock(m_mutex);
        return m_map.at(key);
    }
    
    Value& operator[](const Key& key) {
        ScopedLock lock(m_mutex);
        return m_map[key];
    }
    
    // Thread-safe lookup
    typename std::map<Key, Value>::iterator Find(const Key& key) {
        ScopedSharedLock lock(m_mutex);
        return m_map.find(key);
    }
    
    typename std::map<Key, Value>::const_iterator Find(const Key& key) const {
        ScopedSharedLock lock(m_mutex);
        return m_map.find(key);
    }
    
    bool Contains(const Key& key) const {
        ScopedSharedLock lock(m_mutex);
        return m_map.find(key) != m_map.end();
    }
    
    // Thread-safe removal
    size_t Erase(const Key& key) {
        ScopedLock lock(m_mutex);
        return m_map.erase(key);
    }
    
    void Clear() noexcept {
        ScopedLock lock(m_mutex);
        m_map.clear();
    }
    
    // Thread-safe queries
    size_t Size() const noexcept {
        ScopedSharedLock lock(m_mutex);
        return m_map.size();
    }
    
    bool Empty() const noexcept {
        ScopedSharedLock lock(m_mutex);
        return m_map.empty();
    }
    
    // Thread-safe iteration
    template<typename Func>
    void ForEach(Func&& func) {
        ScopedSharedLock lock(m_mutex);
        for (auto& pair : m_map) {
            func(pair.first, pair.second);
        }
    }
    
    template<typename Func>
    void ForEachConst(Func&& func) const {
        ScopedSharedLock lock(m_mutex);
        for (const auto& pair : m_map) {
            func(pair.first, pair.second);
        }
    }
};

// Lock-free stack using atomic operations
template<typename T>
class LockFreeStack {
private:
    struct Node {
        T Data;
        std::atomic<Node*> Next;
        
        Node(const T& data) : Data(data), Next(nullptr) {}
        Node(T&& data) : Data(std::move(data)), Next(nullptr) {}
    };
    
    std::atomic<Node*> m_head;
    
public:
    LockFreeStack() : m_head(nullptr) {}
    
    ~LockFreeStack() {
        Clear();
    }
    
    void Push(const T& value) {
        Node* newNode = new Node(value);
        newNode->Next = m_head.load(std::memory_order_relaxed);
        
        while (!m_head.compare_exchange_weak(newNode->Next, newNode,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
            // Retry until successful
        }
    }
    
    void Push(T&& value) {
        Node* newNode = new Node(std::move(value));
        newNode->Next = m_head.load(std::memory_order_relaxed);
        
        while (!m_head.compare_exchange_weak(newNode->Next, newNode,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
            // Retry until successful
        }
    }
    
    bool TryPop(T& value) noexcept {
        Node* oldHead = m_head.load(std::memory_order_acquire);
        if (!oldHead) {
            return false;
        }
        
        while (!m_head.compare_exchange_weak(oldHead, oldHead->Next,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
            if (!oldHead) {
                return false;
            }
        }
        
        value = std::move(oldHead->Data);
        delete oldHead;
        return true;
    }
    
    bool Empty() const noexcept {
        return m_head.load(std::memory_order_acquire) == nullptr;
    }
    
    void Clear() noexcept {
        Node* current = m_head.exchange(nullptr, std::memory_order_acquire);
        while (current) {
            Node* next = current->Next.load(std::memory_order_relaxed);
            delete current;
            current = next;
        }
    }
};

// Thread pool for kernel-mode execution
class KernelThreadPool {
private:
    struct Task {
        std::function<void()> Function;
        std::promise<void> Promise;
        
        template<typename Func>
        Task(Func&& func) : Function(std::forward<Func>(func)) {}
    };
    
    std::vector<HANDLE> m_threads;
    ThreadSafeQueue<std::unique_ptr<Task>> m_taskQueue;
    std::atomic<bool> m_stop;
    KernelMutex m_mutex;
    
public:
    KernelThreadPool(size_t numThreads = 4) : m_stop(false) {
        for (size_t i = 0; i < numThreads; ++i) {
            HANDLE thread = CreateThread(nullptr, 0, WorkerThread, this, 0, nullptr);
            if (thread) {
                m_threads.push_back(thread);
            }
        }
    }
    
    ~KernelThreadPool() {
        Stop();
    }
    
    template<typename Func>
    std::future<void> Submit(Func&& func) {
        auto task = std::make_unique<Task>(std::forward<Func>(func));
        std::future<void> future = task->Promise.get_future();
        m_taskQueue.Push(std::move(task));
        return future;
    }
    
    void Stop() noexcept {
        m_stop = true;
        
        // Wake up all threads
        for (size_t i = 0; i < m_threads.size(); ++i) {
            Submit([]{}); // Dummy task to wake up threads
        }
        
        // Wait for all threads to finish
        for (HANDLE thread : m_threads) {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        }
        
        m_threads.clear();
    }
    
    size_t GetThreadCount() const noexcept {
        return m_threads.size();
    }
    
private:
    static DWORD WINAPI WorkerThread(LPVOID param) {
        KernelThreadPool* pool = static_cast<KernelThreadPool*>(param);
        pool->WorkerLoop();
        return 0;
    }
    
    void WorkerLoop() {
        while (!m_stop) {
            std::unique_ptr<Task> task;
            if (m_taskQueue.TryPop(task)) {
                try {
                    task->Function();
                    task->Promise.set_value();
                } catch (...) {
                    task->Promise.set_exception(std::current_exception());
                }
            } else {
                // Sleep briefly to avoid busy waiting
                Sleep(1);
            }
        }
    }
};

// Atomic reference counter for kernel objects
template<typename T>
class AtomicRefCount {
private:
    std::atomic<size_t> m_count;
    
public:
    AtomicRefCount(size_t initial = 0) noexcept : m_count(initial) {}
    
    size_t Increment() noexcept {
        return m_count.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    
    size_t Decrement() noexcept {
        return m_count.fetch_sub(1, std::memory_order_acq_rel) - 1;
    }
    
    size_t Get() const noexcept {
        return m_count.load(std::memory_order_relaxed);
    }
    
    bool IsZero() const noexcept {
        return m_count.load(std::memory_order_acquire) == 0;
    }
    
    void Reset(size_t value = 0) noexcept {
        m_count.store(value, std::memory_order_release);
    }
};

// Thread-safe object pool
template<typename T, typename Allocator = KernelAllocator<T>>
class ThreadSafeObjectPool {
private:
    struct PooledObject {
        T Object;
        bool InUse;
        
        template<typename... Args>
        PooledObject(Args&&... args) 
            : Object(std::forward<Args>(args)...), InUse(false) {}
    };
    
    std::vector<PooledObject, Allocator> m_objects;
    std::vector<size_t> m_freeIndices;
    KernelMutex m_mutex;
    
public:
    ThreadSafeObjectPool(size_t initialSize = 0) {
        if (initialSize > 0) {
            ScopedLock lock(m_mutex);
            m_objects.reserve(initialSize);
            for (size_t i = 0; i < initialSize; ++i) {
                m_objects.emplace_back();
                m_freeIndices.push_back(i);
            }
        }
    }
    
    template<typename... Args>
    T* Acquire(Args&&... args) {
        ScopedLock lock(m_mutex);
        
        if (!m_freeIndices.empty()) {
            size_t index = m_freeIndices.back();
            m_freeIndices.pop_back();
            
            PooledObject& pooled = m_objects[index];
            pooled.InUse = true;
            
            // Reconstruct object with new arguments
            pooled.Object.~T();
            new (&pooled.Object) T(std::forward<Args>(args)...);
            
            return &pooled.Object;
        } else {
            // Create new object
            size_t index = m_objects.size();
            m_objects.emplace_back(std::forward<Args>(args)...);
            m_objects.back().InUse = true;
            return &m_objects.back().Object;
        }
    }
    
    void Release(T* object) {
        if (!object) return;
        
        ScopedLock lock(m_mutex);
        
        // Find the object in the pool
        for (size_t i = 0; i < m_objects.size(); ++i) {
            if (&m_objects[i].Object == object) {
                m_objects[i].InUse = false;
                m_freeIndices.push_back(i);
                break;
            }
        }
    }
    
    size_t GetTotalCount() const noexcept {
        ScopedLock lock(m_mutex);
        return m_objects.size();
    }
    
    size_t GetFreeCount() const noexcept {
        ScopedLock lock(m_mutex);
        return m_freeIndices.size();
    }
    
    size_t GetInUseCount() const noexcept {
        ScopedLock lock(m_mutex);
        return m_objects.size() - m_freeIndices.size();
    }
};

} // namespace BootkitFramework

// Convenience aliases
using KernelThreadSafeQueue = BootkitFramework::ThreadSafeQueue<void*>;
using KernelThreadSafeVector = BootkitFramework::ThreadSafeVector<void*>;
using KernelThreadSafeMap = BootkitFramework::ThreadSafeMap<std::string, void*>;
using KernelLockFreeStack = BootkitFramework::LockFreeStack<void*>;
using KernelAtomicRefCount = BootkitFramework::AtomicRefCount<void>;