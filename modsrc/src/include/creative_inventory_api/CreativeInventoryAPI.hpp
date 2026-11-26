#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

namespace creative_inventory_api {

inline constexpr std::uint32_t kApiVersionMajor = 1;
inline constexpr std::uint32_t kApiVersionMinor = 1;
inline constexpr std::uint32_t kApiVersionPatch = 0;

namespace layout::mcbe_1_26_50_4 {

// Exact Android arm64-v8a layouts verified against the supplied
// Minecraft Bedrock 1.26.52.3, 1.26.60.4 and 1.26.62.1 libminecraftpe.so.
inline constexpr std::size_t kItemInstanceSize = 0x80;
inline constexpr std::size_t kCreativeItemEntrySize = 0xB0;
inline constexpr std::size_t kCreativeRegistryItemsBeginOffset = 0x18;
inline constexpr std::size_t kCreativeRegistryItemsEndOffset = 0x20;
inline constexpr std::size_t kCreativeEntryNetIdOffset = 0x24;
inline constexpr std::size_t kCreativeEntryItemInstanceOffset = 0x28;
inline constexpr std::size_t kCreativeInitializerRegistryOffset = 0x20;
inline constexpr std::size_t kItemInstanceAuxOffset = 0x20;
inline constexpr std::size_t kItemRegistryItemsBeginOffset = 0x38;
inline constexpr std::size_t kItemRegistryItemsEndOffset = 0x40;
inline constexpr std::size_t kBedrockSharedPtrSize = 0x08;
inline constexpr std::size_t kMaxRegisteredItems = 32768;
inline constexpr std::uint8_t kCreativeCategoryItems = 4;

static_assert(kItemInstanceAuxOffset + sizeof(std::int16_t) <= kItemInstanceSize);
static_assert(kCreativeEntryItemInstanceOffset + kItemInstanceSize <= kCreativeItemEntrySize);
static_assert(kCreativeRegistryItemsBeginOffset < kCreativeRegistryItemsEndOffset);
static_assert(kItemRegistryItemsBeginOffset < kItemRegistryItemsEndOffset);

} // namespace layout::mcbe_1_26_50_4

enum class Error : std::uint8_t {
    None = 0,
    MinecraftModuleNotFound,
    ExactBuildMismatch,
    NotResolved,
    NullInitializer,
    CreativeRegistryUnavailable,
    ItemRegistryUnavailable,
    InvalidVectorLayout,
    InvalidArgument,
    InvalidIdentifier,
    ItemConstructionFailed,
    ItemNotCanonical,
    UnsafeSyntheticItem,
    DuplicateItem,
    GroupCreationFailed,
    EntryCreationFailed,
    NetIdExhausted,
    AlreadyInstalled,
    HookInstallFailed,
};

char const* errorString(Error error) noexcept;

struct Status {
    Error error{Error::None};
    [[nodiscard]] constexpr bool ok() const noexcept { return error == Error::None; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return ok(); }
};

template <class T>
struct Result {
    T value{};
    Error error{Error::None};
    [[nodiscard]] constexpr bool ok() const noexcept { return error == Error::None; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return ok(); }
};

struct ItemSpec {
    std::string_view identifier;
    std::int16_t aux{0};
    std::uint8_t count{1};
};

struct AddOptions {
    // Skip the exact (Item*, aux) when it already exists anywhere in Creative.
    bool skipIfAlreadyPresent{true};

    // For addItem(identifier), require Item::getFullItemName() to round-trip to
    // exactly the requested identifier. This filters remapped legacy aliases.
    bool requireCanonicalName{true};

    // Synthetic filled_map stacks are blocked by default because map UI can
    // require world-backed MapItemSavedData. A caller with a fully initialized
    // real ItemInstance may use addItemInstance() instead.
    bool allowUnsafeSyntheticItem{false};
};

struct GroupHandle {
    void* native{};
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return native != nullptr; }
};

struct EntryHandle {
    void* native{};
    std::uint32_t netId{};
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return native != nullptr; }
};

struct BatchResult {
    std::size_t added{};
    std::size_t skipped{};
    Error error{Error::None};
    [[nodiscard]] constexpr bool ok() const noexcept { return error == Error::None; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return ok(); }
};

struct EngineBindings {
    using AddLooseCreativeItemsFn = void (*)(void*, void const*);
    using LockItemRegistryFn = std::shared_ptr<void> (*)(void const*);
    using GetCreativeCategoryFn = void* (*)(void*, std::uint8_t);
    using AddChildGroupFn = void* (*)(void*, void const*, void const*);
    using NewItemEntryFn = void* (*)(void*, std::uint32_t const&, void const*);
    using AddCreativeItemEntryFn = void (*)(void*, void*);
    using UpdateNetIdMapFn = void (*)(void*);
    using ItemInstanceNameCtorFn = void (*)(void*, char const*, std::size_t, int, int, void const*);
    using ItemInstanceDtorFn = void (*)(void*);
    using ItemGetItemFn = void* (*)(void const*);
    using ItemGetFullItemNameFn = std::string const& (*)(void const*);

    void* addLooseCreativeItemsTarget{};
    AddLooseCreativeItemsFn addLooseCreativeItemsOriginal{};
    LockItemRegistryFn lockItemRegistry{};
    GetCreativeCategoryFn getCreativeCategory{};
    AddChildGroupFn addChildGroup{};
    NewItemEntryFn newItemEntry{};
    AddCreativeItemEntryFn addCreativeItemEntry{};
    UpdateNetIdMapFn updateNetIdMap{};
    ItemInstanceNameCtorFn itemInstanceNameCtor{};
    ItemInstanceDtorFn itemInstanceDtor{};
    ItemGetItemFn itemGetItem{};
    ItemGetFullItemNameFn itemGetFullItemName{};
};

using RegisteredItemVisitor = bool (*)(void* item, std::string_view canonicalId, void* userData);

class CreativeInventoryAPI {
public:
    CreativeInventoryAPI() = default;
    CreativeInventoryAPI(CreativeInventoryAPI const&) = delete;
    CreativeInventoryAPI& operator=(CreativeInventoryAPI const&) = delete;

    // Scans loaded MCBE code for instruction-aware wildcard signatures
    // version-scoped to known 1.26.52.3, 1.26.60.4 and 1.26.62.1 ARM64 builds. Fixed RVAs are
    // not used as the primary resolver; zero/multiple matches are rejected.
    // resolveExact126443() is retained only as the V1.0.x ABI entry name.
    Status resolveExact126443();
    Status resolve126504() { return resolveExact126443(); }

    // Advanced: provide bindings yourself. The caller owns version validation.
    Status bindVerified(EngineBindings const& bindings);

    [[nodiscard]] bool resolved() const noexcept;
    [[nodiscard]] EngineBindings const& bindings() const noexcept { return mBindings; }

    // Call after vanilla CreativeItemInitializer::addLooseCreativeItems.
    Status attachInitializer(void* initializer);
    void reset() noexcept;

    [[nodiscard]] bool ready() const noexcept;
    [[nodiscard]] void* initializerNative() const noexcept { return mInitializer; }
    [[nodiscard]] void* creativeRegistryNative() const noexcept { return mCreativeRegistry; }

    Result<GroupHandle> createGroup(
        std::string_view name,
        ItemSpec icon = ItemSpec{"minecraft:stone", 0, 1},
        std::uint8_t category = layout::mcbe_1_26_50_4::kCreativeCategoryItems
    );

    Result<GroupHandle> createGroupFromIconInstance(
        std::string_view name,
        void const* iconItemInstance,
        std::uint8_t category = layout::mcbe_1_26_50_4::kCreativeCategoryItems
    );

    // Adds an item constructed from an already-registered identifier.
    Result<EntryHandle> addItem(
        GroupHandle group,
        ItemSpec item,
        AddOptions options = {}
    );

    // Adds/copies an existing ItemInstance. This is the path for a custom item
    // created by another mod's own item-registration/factory layer.
    Result<EntryHandle> addItemInstance(
        GroupHandle group,
        void const* itemInstance,
        AddOptions options = {}
    );

    BatchResult addItems(
        GroupHandle group,
        std::span<ItemSpec const> items,
        AddOptions options = {}
    );

    // Rebuilds CreativeItemRegistry's net-id lookup after a batch of inserts.
    Status finalize();

    Result<std::uint32_t> nextCreativeNetId() const;
    [[nodiscard]] std::size_t creativeEntryCount() const noexcept;
    [[nodiscard]] bool containsVariant(void* item, std::int16_t aux) const noexcept;
    [[nodiscard]] bool containsItemInstance(void const* itemInstance) const noexcept;

    // ItemRegistry helpers using the verified +0x38/+0x40 vector layout.
    Result<std::size_t> registeredItemCount() const;
    Result<void*> findRegisteredItem(std::string_view canonicalId) const;
    Status forEachRegisteredItem(RegisteredItemVisitor visitor, void* userData = nullptr) const;

    // Read-only convenience accessors for valid ItemInstance objects.
    [[nodiscard]] void* itemFromInstance(void const* itemInstance) const noexcept;
    [[nodiscard]] std::int16_t auxFromInstance(void const* itemInstance) const noexcept;
    [[nodiscard]] std::string_view canonicalItemName(void const* item) const noexcept;

private:
    EngineBindings mBindings{};
    void* mInitializer{};
    void* mCreativeRegistry{};
    mutable std::recursive_mutex mMutex;

    Result<EntryHandle> addItemInstanceLocked(
        GroupHandle group,
        void const* itemInstance,
        AddOptions options
    );
};

} // namespace creative_inventory_api
