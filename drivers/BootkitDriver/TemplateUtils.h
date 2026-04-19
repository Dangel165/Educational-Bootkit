// TemplateUtils.h: Template metaprogramming utilities for performance optimization and type safety
// Implements compile-time configuration, type traits, and generic algorithms

#pragma once

#include "ModernCpp.h"
#include <type_traits>
#include <utility>
#include <tuple>
#include <variant>
#include <optional>
#include <functional>

namespace BootkitFramework {

// Compile-time string utilities
template<size_t N>
struct FixedString {
    char Data[N];
    
    constexpr FixedString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) {
            Data[i] = str[i];
        }
    }
    
    constexpr operator const char*() const { return Data; }
    constexpr size_t Size() const { return N - 1; }
};

// Compile-time configuration
template<auto Value>
struct ConfigValue {
    static constexpr auto Value = Value;
};

template<bool Enable>
struct FeatureFlag {
    static constexpr bool Enabled = Enable;
    
    template<typename Func>
    static constexpr void ExecuteIfEnabled(Func&& func) {
        if constexpr (Enable) {
            func();
        }
    }
};

// Type traits extensions
namespace TypeTraits {
    
    // Check if type is callable
    template<typename T, typename... Args>
    struct IsCallable {
    private:
        template<typename U>
        static auto Test(int) -> decltype(
            std::declval<U>()(std::declval<Args>()...), std::true_type{});
        
        template<typename>
        static std::false_type Test(...);
        
    public:
        static constexpr bool Value = decltype(Test<T>(0))::value;
    };
    
    // Check if type is iterable
    template<typename T>
    struct IsIterable {
    private:
        template<typename U>
        static auto Test(int) -> decltype(
            std::begin(std::declval<U&>()),
            std::end(std::declval<U&>()),
            std::true_type{});
        
        template<typename>
        static std::false_type Test(...);
        
    public:
        static constexpr bool Value = decltype(Test<T>(0))::value;
    };
    
    // Check if type is container
    template<typename T>
    struct IsContainer {
        static constexpr bool Value = IsIterable<T>::Value && 
                                     !std::is_same<T, std::string>::value &&
                                     !std::is_same<T, std::string_view>::value;
    };
    
    // Get value type of container
    template<typename T>
    struct ContainerValueType {
    private:
        template<typename U>
        static auto Test(int) -> typename U::value_type;
        
        template<typename>
        static void Test(...);
        
    public:
        using Type = decltype(Test<T>(0));
    };
    
    // Check if type is smart pointer
    template<typename T>
    struct IsSmartPointer : std::false_type {};
    
    template<typename T>
    struct IsSmartPointer<std::unique_ptr<T>> : std::true_type {};
    
    template<typename T>
    struct IsSmartPointer<std::shared_ptr<T>> : std::true_type {};
    
    template<typename T>
    struct IsSmartPointer<KernelUniquePtr<T>> : std::true_type {};
    
    template<typename T>
    struct IsSmartPointer<KernelSharedPtr<T>> : std::true_type {};
}

// Compile-time type list
template<typename... Ts>
struct TypeList {};

// Type list operations
template<typename List>
struct TypeListSize;

template<typename... Ts>
struct TypeListSize<TypeList<Ts...>> {
    static constexpr size_t Value = sizeof...(Ts);
};

template<typename List, typename T>
struct TypeListContains;

template<typename T, typename... Ts>
struct TypeListContains<TypeList<Ts...>, T> {
    static constexpr bool Value = (std::is_same_v<T, Ts> || ...);
};

template<typename List, size_t N>
struct TypeListGet;

template<typename T, typename... Ts, size_t N>
struct TypeListGet<TypeList<T, Ts...>, N> {
    using Type = typename TypeListGet<TypeList<Ts...>, N - 1>::Type;
};

template<typename T, typename... Ts>
struct TypeListGet<TypeList<T, Ts...>, 0> {
    using Type = T;
};

// Compile-time integer sequence utilities
template<size_t... Is>
struct IndexSequence {};

template<size_t N, size_t... Is>
struct MakeIndexSequence : MakeIndexSequence<N - 1, N - 1, Is...> {};

template<size_t... Is>
struct MakeIndexSequence<0, Is...> : IndexSequence<Is...> {};

// Compile-time string hashing (FNV-1a)
template<size_t N>
constexpr size_t HashString(const char (&str)[N], size_t I = N) {
    constexpr size_t FNV_PRIME = 1099511628211ULL;
    constexpr size_t FNV_OFFSET = 14695981039346656037ULL;
    
    size_t hash = FNV_OFFSET;
    for (size_t i = 0; i < I - 1; ++i) {
        hash ^= static_cast<size_t>(str[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}

// Type-safe enum with string conversion
template<typename Enum>
class TypeSafeEnum {
private:
    Enum m_value;
    
public:
    constexpr TypeSafeEnum(Enum value) noexcept : m_value(value) {}
    
    constexpr operator Enum() const noexcept { return m_value; }
    
    constexpr bool operator==(TypeSafeEnum other) const noexcept {
        return m_value == other.m_value;
    }
    
    constexpr bool operator!=(TypeSafeEnum other) const noexcept {
        return m_value != other.m_value;
    }
    
    constexpr bool operator<(TypeSafeEnum other) const noexcept {
        return static_cast<std::underlying_type_t<Enum>>(m_value) < 
               static_cast<std::underlying_type_t<Enum>>(other.m_value);
    }
};

// Compile-time mapping from enum to string
template<typename Enum, size_t N>
class EnumStringMap {
private:
    std::pair<Enum, FixedString<64>> m_map[N];
    
public:
    constexpr EnumStringMap(std::initializer_list<std::pair<Enum, FixedString<64>>> list) {
        size_t i = 0;
        for (const auto& pair : list) {
            m_map[i++] = pair;
        }
    }
    
    constexpr const char* ToString(Enum value) const noexcept {
        for (const auto& pair : m_map) {
            if (pair.first == value) {
                return pair.second;
            }
        }
        return "Unknown";
    }
    
    constexpr std::optional<Enum> FromString(const char* str) const noexcept {
        for (const auto& pair : m_map) {
            if (std::strcmp(pair.second, str) == 0) {
                return pair.first;
            }
        }
        return std::nullopt;
    }
};

// Generic visitor pattern
template<typename... Ts>
struct Visitor : Ts... {
    using Ts::operator()...;
};

template<typename... Ts>
Visitor(Ts...) -> Visitor<Ts...>;

// Type-safe variant with visitor support
template<typename... Ts>
using SafeVariant = std::variant<Ts...>;

template<typename Variant, typename... Visitors>
auto VisitVariant(Variant&& variant, Visitors&&... visitors) {
    return std::visit(Visitor{std::forward<Visitors>(visitors)...}, 
                      std::forward<Variant>(variant));
}

// Compile-time function signature checking
template<typename Func>
struct FunctionTraits;

template<typename Ret, typename... Args>
struct FunctionTraits<Ret(Args...)> {
    using ReturnType = Ret;
    using ArgumentTypes = TypeList<Args...>;
    static constexpr size_t Arity = sizeof...(Args);
};

template<typename Ret, typename... Args>
struct FunctionTraits<Ret(*)(Args...)> : FunctionTraits<Ret(Args...)> {};

template<typename Ret, typename Class, typename... Args>
struct FunctionTraits<Ret(Class::*)(Args...)> : FunctionTraits<Ret(Args...)> {
    using ClassType = Class;
};

template<typename Ret, typename Class, typename... Args>
struct FunctionTraits<Ret(Class::*)(Args...) const> : FunctionTraits<Ret(Args...)> {
    using ClassType = Class;
};

template<typename Func>
struct FunctionTraits : FunctionTraits<decltype(&Func::operator())> {};

// Generic algorithm utilities
namespace Algorithm {
    
    // Type-safe min/max
    template<typename T>
    constexpr const T& Min(const T& a, const T& b) noexcept {
        return (b < a) ? b : a;
    }
    
    template<typename T>
    constexpr const T& Max(const T& a, const T& b) noexcept {
        return (a < b) ? b : a;
    }
    
    template<typename T>
    constexpr T Clamp(const T& value, const T& min, const T& max) noexcept {
        return (value < min) ? min : (value > max) ? max : value;
    }
    
    // Compile-time power calculation
    template<typename T>
    constexpr T Power(T base, size_t exponent) noexcept {
        T result = 1;
        while (exponent > 0) {
            if (exponent & 1) {
                result *= base;
            }
            base *= base;
            exponent >>= 1;
        }
        return result;
    }
    
    // Type-safe byte swapping
    template<typename T>
    constexpr T SwapBytes(T value) noexcept {
        static_assert(std::is_integral_v<T>, "SwapBytes requires integral type");
        
        if constexpr (sizeof(T) == 1) {
            return value;
        } else if constexpr (sizeof(T) == 2) {
            return ((value >> 8) & 0xFF) | ((value << 8) & 0xFF00);
        } else if constexpr (sizeof(T) == 4) {
            return ((value >> 24) & 0xFF) |
                   ((value >> 8) & 0xFF00) |
                   ((value << 8) & 0xFF0000) |
                   ((value << 24) & 0xFF000000);
        } else if constexpr (sizeof(T) == 8) {
            return ((value >> 56) & 0xFF) |
                   ((value >> 40) & 0xFF00) |
                   ((value >> 24) & 0xFF0000) |
                   ((value >> 8) & 0xFF000000) |
                   ((value << 8) & 0xFF00000000) |
                   ((value << 24) & 0xFF0000000000) |
                   ((value << 40) & 0xFF000000000000) |
                   ((value << 56) & 0xFF00000000000000);
        }
    }
    
    // Endianness detection and conversion
    constexpr bool IsLittleEndian() noexcept {
        constexpr uint16_t test = 0x0001;
        return reinterpret_cast<const uint8_t*>(&test)[0] == 0x01;
    }
    
    template<typename T>
    constexpr T ToNetworkOrder(T value) noexcept {
        if constexpr (IsLittleEndian()) {
            return SwapBytes(value);
        } else {
            return value;
        }
    }
    
    template<typename T>
    constexpr T FromNetworkOrder(T value) noexcept {
        return ToNetworkOrder(value); // Same operation
    }
}

// Compile-time configuration registry
template<typename Key, typename Value>
class ConfigRegistry {
private:
    struct ConfigEntry {
        Key Key;
        Value Value;
        bool Overridable;
    };
    
    std::vector<ConfigEntry> m_entries;
    
public:
    void Register(Key key, Value value, bool overridable = true) {
        m_entries.push_back({key, value, overridable});
    }
    
    std::optional<Value> Get(Key key) const noexcept {
        for (const auto& entry : m_entries) {
            if (entry.Key == key) {
                return entry.Value;
            }
        }
        return std::nullopt;
    }
    
    bool Set(Key key, Value value) noexcept {
        for (auto& entry : m_entries) {
            if (entry.Key == key && entry.Overridable) {
                entry.Value = value;
                return true;
            }
        }
        return false;
    }
    
    void Clear() noexcept {
        m_entries.clear();
    }
    
    size_t Size() const noexcept {
        return m_entries.size();
    }
};

// Generic factory pattern
template<typename Base, typename Key, typename... Args>
class GenericFactory {
private:
    using CreatorFunc = std::function<std::unique_ptr<Base>(Args...)>;
    std::map<Key, CreatorFunc> m_creators;
    
public:
    template<typename Derived>
    void Register(Key key) {
        static_assert(std::is_base_of_v<Base, Derived>, 
                     "Derived must inherit from Base");
        
        m_creators[key] = [](Args... args) -> std::unique_ptr<Base> {
            return std::make_unique<Derived>(std::forward<Args>(args)...);
        };
    }
    
    std::unique_ptr<Base> Create(Key key, Args... args) const {
        auto it = m_creators.find(key);
        if (it != m_creators.end()) {
            return it->second(std::forward<Args>(args)...);
        }
        return nullptr;
    }
    
    bool IsRegistered(Key key) const noexcept {
        return m_creators.find(key) != m_creators.end();
    }
    
    std::vector<Key> GetRegisteredKeys() const {
        std::vector<Key> keys;
        keys.reserve(m_creators.size());
        for (const auto& pair : m_creators) {
            keys.push_back(pair.first);
        }
        return keys;
    }
};

// Type-safe callback system
template<typename... Args>
class TypeSafeCallback {
private:
    using CallbackFunc = std::function<void(Args...)>;
    CallbackFunc m_callback;
    
public:
    TypeSafeCallback() = default;
    
    template<typename Func>
    TypeSafeCallback(Func&& func) : m_callback(std::forward<Func>(func)) {}
    
    void operator()(Args... args) const {
        if (m_callback) {
            m_callback(std::forward<Args>(args)...);
        }
    }
    
    explicit operator bool() const noexcept {
        return static_cast<bool>(m_callback);
    }
    
    void Reset() noexcept {
        m_callback = nullptr;
    }
    
    template<typename Func>
    void Set(Func&& func) {
        m_callback = std::forward<Func>(func);
    }
};

// Compile-time type ID generation
template<typename T>
struct TypeId {
    static constexpr size_t Value = HashString(__FUNCSIG__);
};

// Type-safe any container
class TypeSafeAny {
private:
    struct BaseHolder {
        virtual ~BaseHolder() = default;
        virtual BaseHolder* Clone() const = 0;
    };
    
    template<typename T>
    struct Holder : BaseHolder {
        T Value;
        
        Holder(const T& value) : Value(value) {}
        Holder(T&& value) : Value(std::move(value)) {}
        
        BaseHolder* Clone() const override {
            return new Holder<T>(Value);
        }
    };
    
    std::unique_ptr<BaseHolder> m_holder;
    size_t m_typeId;
    
public:
    TypeSafeAny() noexcept : m_typeId(0) {}
    
    template<typename T>
    TypeSafeAny(const T& value) 
        : m_holder(std::make_unique<Holder<T>>(value)), 
          m_typeId(TypeId<T>::Value) {}
    
    template<typename T>
    TypeSafeAny(T&& value) 
        : m_holder(std::make_unique<Holder<std::decay_t<T>>>(std::forward<T>(value))),
          m_typeId(TypeId<std::decay_t<T>>::Value) {}
    
    TypeSafeAny(const TypeSafeAny& other) 
        : m_holder(other.m_holder ? other.m_holder->Clone() : nullptr),
          m_typeId(other.m_typeId) {}
    
    TypeSafeAny& operator=(const TypeSafeAny& other) {
        if (this != &other) {
            m_holder.reset(other.m_holder ? other.m_holder->Clone() : nullptr);
            m_typeId = other.m_typeId;
        }
        return *this;
    }
    
    TypeSafeAny(TypeSafeAny&&) = default;
    TypeSafeAny& operator=(TypeSafeAny&&) = default;
    
    template<typename T>
    bool HasType() const noexcept {
        return m_typeId == TypeId<T>::Value;
    }
    
    template<typename T>
    T* TryGet() noexcept {
        if (HasType<T>()) {
            return &static_cast<Holder<T>*>(m_holder.get())->Value;
        }
        return nullptr;
    }
    
    template<typename T>
    const T* TryGet() const noexcept {
        if (HasType<T>()) {
            return &static_cast<const Holder<T>*>(m_holder.get())->Value;
        }
        return nullptr;
    }
    
    template<typename T>
    T& Get() {
        if (auto* ptr = TryGet<T>()) {
            return *ptr;
        }
        throw std::bad_cast();
    }
    
    template<typename T>
    const T& Get() const {
        if (auto* ptr = TryGet<T>()) {
            return *ptr;
        }
        throw std::bad_cast();
    }
    
    bool Empty() const noexcept {
        return m_holder == nullptr;
    }
    
    void Reset() noexcept {
        m_holder.reset();
        m_typeId = 0;
    }
    
    size_t GetTypeId() const noexcept {
        return m_typeId;
    }
};

} // namespace BootkitFramework

// Convenience macros for template metaprogramming
#define TYPE_SAFE_ENUM(name, ...) \
    enum class name { __VA_ARGS__ }; \
    using name##_t = BootkitFramework::TypeSafeEnum<name>;

#define COMPILE_TIME_ASSERT(cond, msg) \
    static_assert(cond, msg)

#define TYPE_TRAIT_CHECK(type, trait) \
    BootkitFramework::TypeTraits::trait<type>::Value

#define CONFIG_VALUE(name, value) \
    static constexpr auto name = BootkitFramework::ConfigValue<value>()

#define FEATURE_FLAG(name, enabled) \
    using name = BootkitFramework::FeatureFlag<enabled>