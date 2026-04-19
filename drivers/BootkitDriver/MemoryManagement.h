// MemoryManagement.h: Custom memory management system for kernel-mode operation
// Implements memory pools, custom allocators, and smart pointers optimized for kernel drivers

#pragma once

#include "ModernCpp.h"
#include <array>
#include <vector>
#include <list>
#include <memory>

namespace BootkitFramework {

// Memory pool configuration
struct MemoryPoolConfig {
    size_t BlockSize;
    size_t NumBlocks;
    POOL_TYPE PoolType;
    ULONG Tag;
    
    constexpr MemoryPoolConfig(size_t blockSize = 4096, size_t numBlocks = 64, 
                               POOL_TYPE poolType = POOL_FLAG_NON_PAGED, ULONG tag = 'BDKT')
        : BlockSize(blockSize), NumBlocks(numBlocks), PoolType(poolType), Tag(tag) {}
};

// Memory pool statistics
struct MemoryPoolStats {
    size_t TotalAllocated;
    size_t TotalFreed;
    size_t CurrentUsage;
    size_t PeakUsage;
    size_t AllocationCount;
    size_t FreeCount;
    
    MemoryPoolStats() noexcept 
        : TotalAllocated(0), TotalFreed(0), CurrentUsage(0), 
          PeakUsage(0), AllocationCount(0), FreeCount(0) {}
};

// Fixed-size memory pool
template<size_t BlockSize, size_t NumBlocks>
class FixedMemoryPool {
private:
    struct Block {
        Block* Next;
        UCHAR Data[BlockSize];
    };
    
    Block* m_freeList;
    std::array<Block, NumBlocks> m_blocks;
    FAST_MUTEX m_mutex;
    MemoryPoolStats m_stats;
    
public:
    FixedMemoryPool() : m_freeList(nullptr) {
        ExInitializeFastMutex(&m_mutex);
        Initialize();
    }
    
    ~FixedMemoryPool() {
        // All blocks should be freed by now
        ScopedFastMutex lock(&m_mutex);
    }
    
    void* Allocate() noexcept {
        ScopedFastMutex lock(&m_mutex);
        
        if (!m_freeList) {
            return nullptr; // Pool exhausted
        }
        
        void* block = m_freeList;
        m_freeList = m_freeList->Next;
        
        // Update statistics
        m_stats.AllocationCount++;
        m_stats.CurrentUsage += BlockSize;
        m_stats.TotalAllocated += BlockSize;
        m_stats.PeakUsage = std::max(m_stats.PeakUsage, m_stats.CurrentUsage);
        
        return block;
    }
    
    void Free(void* block) noexcept {
        if (!block) return;
        
        ScopedFastMutex lock(&m_mutex);
        
        Block* freedBlock = static_cast<Block*>(block);
        freedBlock->Next = m_freeList;
        m_freeList = freedBlock;
        
        // Update statistics
        m_stats.FreeCount++;
        m_stats.CurrentUsage -= BlockSize;
        m_stats.TotalFreed += BlockSize;
    }
    
    const MemoryPoolStats& GetStats() const noexcept {
        return m_stats;
    }
    
    size_t GetFreeCount() const noexcept {
        ScopedFastMutex lock(&m_mutex);
        size_t count = 0;
        Block* current = m_freeList;
        while (current) {
            count++;
            current = current->Next;
        }
        return count;
    }
    
private:
    void Initialize() noexcept {
        // Link all blocks into free list
        for (size_t i = 0; i < NumBlocks - 1; ++i) {
            m_blocks[i].Next = &m_blocks[i + 1];
        }
        m_blocks[NumBlocks - 1].Next = nullptr;
        m_freeList = &m_blocks[0];
    }
};

// Variable-size memory pool
class VariableMemoryPool {
private:
    struct PoolBlock {
        size_t Size;
        bool Free;
        PoolBlock* Next;
        PoolBlock* Prev;
        // Data follows immediately after this struct
    };
    
    void* m_poolBase;
    size_t m_poolSize;
    POOL_TYPE m_poolType;
    ULONG m_tag;
    PoolBlock* m_freeList;
    FAST_MUTEX m_mutex;
    MemoryPoolStats m_stats;
    
public:
    VariableMemoryPool(size_t poolSize, POOL_TYPE poolType = POOL_FLAG_NON_PAGED, ULONG tag = 'BDKT')
        : m_poolSize(poolSize), m_poolType(poolType), m_tag(tag), m_freeList(nullptr) {
        
        ExInitializeFastMutex(&m_mutex);
        Initialize();
    }
    
    ~VariableMemoryPool() {
        ScopedFastMutex lock(&m_mutex);
        if (m_poolBase) {
            ExFreePoolWithTag(m_poolBase, m_tag);
        }
    }
    
    void* Allocate(size_t size) noexcept {
        if (size == 0) return nullptr;
        
        ScopedFastMutex lock(&m_mutex);
        
        // Add header size and align to 8 bytes
        size_t totalSize = AlignSize(sizeof(PoolBlock) + size, 8);
        
        // Find best fit block
        PoolBlock* bestBlock = nullptr;
        PoolBlock* current = m_freeList;
        
        while (current) {
            if (current->Free && current->Size >= totalSize) {
                if (!bestBlock || current->Size < bestBlock->Size) {
                    bestBlock = current;
                }
            }
            current = current->Next;
        }
        
        if (!bestBlock) {
            return nullptr; // No suitable block found
        }
        
        // Split block if it's significantly larger than requested
        if (bestBlock->Size >= totalSize + sizeof(PoolBlock) + 16) {
            PoolBlock* newBlock = reinterpret_cast<PoolBlock*>(
                reinterpret_cast<UCHAR*>(bestBlock) + totalSize);
            newBlock->Size = bestBlock->Size - totalSize;
            newBlock->Free = true;
            newBlock->Next = bestBlock->Next;
            newBlock->Prev = bestBlock;
            
            if (bestBlock->Next) {
                bestBlock->Next->Prev = newBlock;
            }
            bestBlock->Next = newBlock;
            bestBlock->Size = totalSize;
        }
        
        bestBlock->Free = false;
        RemoveFromFreeList(bestBlock);
        
        // Update statistics
        m_stats.AllocationCount++;
        m_stats.CurrentUsage += bestBlock->Size;
        m_stats.TotalAllocated += bestBlock->Size;
        m_stats.PeakUsage = std::max(m_stats.PeakUsage, m_stats.CurrentUsage);
        
        // Return pointer to data (after header)
        return reinterpret_cast<UCHAR*>(bestBlock) + sizeof(PoolBlock);
    }
    
    void Free(void* ptr) noexcept {
        if (!ptr) return;
        
        ScopedFastMutex lock(&m_mutex);
        
        // Get block header
        PoolBlock* block = reinterpret_cast<PoolBlock*>(
            reinterpret_cast<UCHAR*>(ptr) - sizeof(PoolBlock));
        
        if (block->Free) {
            return; // Already freed
        }
        
        block->Free = true;
        
        // Coalesce with adjacent free blocks
        CoalesceBlocks(block);
        
        // Add to free list
        AddToFreeList(block);
        
        // Update statistics
        m_stats.FreeCount++;
        m_stats.CurrentUsage -= block->Size;
        m_stats.TotalFreed += block->Size;
    }
    
    const MemoryPoolStats& GetStats() const noexcept {
        return m_stats;
    }
    
    size_t GetFreeMemory() const noexcept {
        ScopedFastMutex lock(&m_mutex);
        size_t freeMemory = 0;
        PoolBlock* current = m_freeList;
        while (current) {
            freeMemory += current->Size;
            current = current->Next;
        }
        return freeMemory;
    }
    
private:
    void Initialize() noexcept {
        m_poolBase = ExAllocatePool2(m_poolType, m_poolSize, m_tag);
        if (!m_poolBase) {
            return;
        }
        
        // Initialize first block covering entire pool
        PoolBlock* firstBlock = static_cast<PoolBlock*>(m_poolBase);
        firstBlock->Size = m_poolSize;
        firstBlock->Free = true;
        firstBlock->Next = nullptr;
        firstBlock->Prev = nullptr;
        
        m_freeList = firstBlock;
    }
    
    void RemoveFromFreeList(PoolBlock* block) noexcept {
        if (!block->Prev) {
            m_freeList = block->Next;
        } else {
            block->Prev->Next = block->Next;
        }
        
        if (block->Next) {
            block->Next->Prev = block->Prev;
        }
        
        block->Prev = nullptr;
        block->Next = nullptr;
    }
    
    void AddToFreeList(PoolBlock* block) noexcept {
        block->Next = m_freeList;
        block->Prev = nullptr;
        
        if (m_freeList) {
            m_freeList->Prev = block;
        }
        
        m_freeList = block;
    }
    
    void CoalesceBlocks(PoolBlock* block) noexcept {
        // Coalesce with next block if free
        PoolBlock* nextBlock = reinterpret_cast<PoolBlock*>(
            reinterpret_cast<UCHAR*>(block) + block->Size);
        
        if (reinterpret_cast<UCHAR*>(nextBlock) < 
            reinterpret_cast<UCHAR*>(m_poolBase) + m_poolSize && 
            nextBlock->Free) {
            
            RemoveFromFreeList(nextBlock);
            block->Size += nextBlock->Size;
        }
        
        // Coalesce with previous block if free
        if (block->Prev && block->Prev->Free) {
            RemoveFromFreeList(block->Prev);
            block->Prev->Size += block->Size;
            block = block->Prev;
        }
    }
    
    static size_t AlignSize(size_t size, size_t alignment) noexcept {
        return (size + alignment - 1) & ~(alignment - 1);
    }
};

// Memory manager with multiple pools
class MemoryManager {
private:
    struct PoolEntry {
        size_t MinSize;
        size_t MaxSize;
        std::unique_ptr<VariableMemoryPool> Pool;
        
        PoolEntry(size_t minSize, size_t maxSize, size_t poolSize)
            : MinSize(minSize), MaxSize(maxSize), 
              Pool(std::make_unique<VariableMemoryPool>(poolSize)) {}
    };
    
    std::vector<PoolEntry> m_pools;
    FAST_MUTEX m_mutex;
    
public:
    MemoryManager() {
        ExInitializeFastMutex(&m_mutex);
        
        // Create pools for different size ranges
        m_pools.emplace_back(1, 256, 64 * 1024);      // Small allocations
        m_pools.emplace_back(257, 4096, 256 * 1024);  // Medium allocations
        m_pools.emplace_back(4097, 65536, 1 * 1024 * 1024); // Large allocations
    }
    
    void* Allocate(size_t size) noexcept {
        if (size == 0) return nullptr;
        
        ScopedFastMutex lock(&m_mutex);
        
        // Find appropriate pool
        for (auto& pool : m_pools) {
            if (size >= pool.MinSize && size <= pool.MaxSize) {
                return pool.Pool->Allocate(size);
            }
        }
        
        // Fall back to direct allocation
        return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'BDKT');
    }
    
    void Free(void* ptr, size_t size) noexcept {
        if (!ptr) return;
        
        ScopedFastMutex lock(&m_mutex);
        
        // Try to free from pools
        for (auto& pool : m_pools) {
            if (size >= pool.MinSize && size <= pool.MaxSize) {
                pool.Pool->Free(ptr);
                return;
            }
        }
        
        // Fall back to direct free
        ExFreePoolWithTag(ptr, 'BDKT');
    }
    
    // Get statistics for all pools
    std::vector<MemoryPoolStats> GetPoolStats() const {
        ScopedFastMutex lock(&m_mutex);
        std::vector<MemoryPoolStats> stats;
        stats.reserve(m_pools.size());
        
        for (const auto& pool : m_pools) {
            stats.push_back(pool.Pool->GetStats());
        }
        
        return stats;
    }
};

// Global memory manager instance
extern std::unique_ptr<MemoryManager> g_MemoryManager;

// Initialize global memory manager
inline void InitializeMemoryManager() {
    if (!g_MemoryManager) {
        g_MemoryManager = std::make_unique<MemoryManager>();
    }
}

// Clean up global memory manager
inline void CleanupMemoryManager() {
    g_MemoryManager.reset();
}

// Custom allocator using memory manager
template<typename T>
class ManagedAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using size_type = size_t;
    
    ManagedAllocator() noexcept = default;
    
    template<typename U>
    ManagedAllocator(const ManagedAllocator<U>&) noexcept {}
    
    pointer allocate(size_type n) {
        if (n > (std::numeric_limits<size_type>::max() / sizeof(T))) {
            throw std::bad_alloc();
        }
        
        void* p = g_MemoryManager->Allocate(n * sizeof(T));
        if (!p) {
            throw std::bad_alloc();
        }
        
        return static_cast<pointer>(p);
    }
    
    void deallocate(pointer p, size_type n) noexcept {
        g_MemoryManager->Free(p, n * sizeof(T));
    }
    
    template<typename U>
    struct rebind {
        using other = ManagedAllocator<U>;
    };
};

// Smart pointer with custom allocator
template<typename T>
using ManagedUniquePtr = std::unique_ptr<T, std::function<void(T*)>>;

template<typename T>
ManagedUniquePtr<T> MakeManagedUnique(size_t count = 1) {
    T* ptr = static_cast<T*>(g_MemoryManager->Allocate(sizeof(T) * count));
    if (!ptr) {
        throw std::bad_alloc();
    }
    
    // Construct objects
    for (size_t i = 0; i < count; ++i) {
        new (&ptr[i]) T();
    }
    
    return ManagedUniquePtr<T>(ptr, [count](T* p) {
        // Destruct objects
        for (size_t i = 0; i < count; ++i) {
            p[i].~T();
        }
        g_MemoryManager->Free(p, sizeof(T) * count);
    });
}

} // namespace BootkitFramework

// Global memory manager instance
inline std::unique_ptr<BootkitFramework::MemoryManager> g_MemoryManager;