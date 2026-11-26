#include "creative_inventory_api/CreativeInventoryAPI.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <link.h>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace creative_inventory_api {
namespace {

using namespace layout::mcbe_1_26_50_4;
constexpr std::string_view kMinecraftModule = "libminecraftpe.so";

struct HashedStringExact {
    std::uint64_t hash{};
    std::string text;
    HashedStringExact const* lastMatch{};
};

struct alignas(16) ItemStorage {
    std::array<std::byte, kItemInstanceSize> bytes{};
};

struct ExecutableRange {
    std::uintptr_t start{};
    std::uintptr_t end{};
};

struct ModuleView {
    std::uintptr_t base{};
    std::uintptr_t loadStart{std::numeric_limits<std::uintptr_t>::max()};
    std::uintptr_t loadEnd{};
    std::array<ExecutableRange, 8> executableRanges{};
    std::size_t executableRangeCount{};
    std::array<std::uint8_t, 20> buildId{};
    bool hasBuildId{};
};

struct ParsedSignature {
    std::vector<std::uint8_t> values;
    std::vector<std::uint8_t> masks;
    std::size_t anchorOffset{};
    std::size_t anchorLength{};
};

enum class SignatureScanResult : std::uint8_t {
    Found,
    NotFound,
    NotUnique,
    Invalid,
};

template <class T>
T readValue(void const* base, std::size_t offset) noexcept {
    T value{};
    if (base) std::memcpy(&value, static_cast<std::byte const*>(base) + offset, sizeof(T));
    return value;
}

void* readPointer(void const* base, std::size_t offset) noexcept {
    return readValue<void*>(base, offset);
}

std::uint64_t hashHashedString(std::string_view value) noexcept {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (unsigned char ch : value) {
        hash = static_cast<std::uint64_t>(ch) ^ (0x100000001b3ULL * hash);
    }
    return hash;
}

HashedStringExact makeHashedString(std::string_view value) {
    HashedStringExact result;
    result.text.assign(value.data(), value.size());
    result.hash = hashHashedString(result.text);
    return result;
}

bool validIdentifier(std::string_view id) noexcept {
    if (id.empty() || id.size() > 512) return false;
    const auto colon = id.find(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= id.size()) return false;
    for (unsigned char ch : id) if (ch <= 0x20 || ch == 0x7f) return false;
    return true;
}

bool unsafeSynthetic(std::string_view id) noexcept {
    return id == "minecraft:filled_map";
}

bool isTargetModule(char const* path) noexcept {
    if (!path || !*path) return false;
    const std::string_view p{path};
    return p.size() >= kMinecraftModule.size() &&
           p.substr(p.size() - kMinecraftModule.size()) == kMinecraftModule;
}

constexpr std::array<std::uint8_t, 20> kOldBuildId{0xaf,0xa6,0x2b,0xd3,0x38,0x51,0x61,0xf1,0xfa,0xcf,0xe3,0x6a,0xad,0x58,0xac,0x63,0x99,0x8f,0x46,0xd2};
constexpr std::array<std::uint8_t, 20> kBuildId12523Recorded{0x56,0xde,0x9e,0xed,0x07,0x76,0x31,0xe0,0x3a,0x31,0xf4,0xf5,0x8e,0xb2,0xf0,0xe0,0x00,0x71,0xd3,0x35};
constexpr std::array<std::uint8_t, 20> kBuildId12621{0xc6,0x0f,0xa3,0x29,0x08,0x01,0x9e,0xec,0xae,0x39,0xeb,0xfe,0x7b,0xac,0x57,0x55,0xdc,0x35,0xcd,0xe2};
constexpr std::array<std::uint8_t, 20> kCurrentBuildId{0xeb,0x29,0x1b,0x88,0x3d,0xfd,0xfa,0xff,0x70,0xc4,0x99,0x9c,0x2e,0xab,0xd6,0x18,0x85,0xae,0x3e,0x15};

void extractBuildId(ModuleView& out, dl_phdr_info const& info) noexcept {
    for (ElfW(Half) i=0; i<info.dlpi_phnum; ++i) {
        auto const& ph=info.dlpi_phdr[i];
        if (ph.p_type!=PT_NOTE || ph.p_filesz<36 || ph.p_filesz>1048576) continue;
        auto const* notes=reinterpret_cast<std::uint8_t const*>(out.base+ph.p_vaddr);
        auto const n=static_cast<std::size_t>(ph.p_filesz);
        std::size_t p=0;
        auto readU32=[&](std::size_t off) -> std::uint32_t {
            std::uint32_t v{};
            std::memcpy(&v,notes+off,sizeof(v));
            return v;
        };
        while (p+12<=n) {
            auto const namesz=readU32(p),descsz=readU32(p+4),type=readU32(p+8);
            auto const nameOff=p+12;
            if (namesz>n-nameOff || namesz>1024) break;
            auto const namePad=(static_cast<std::size_t>(namesz)+3u)&~std::size_t{3};
            if (namePad>n-nameOff) break;
            auto const descOff=nameOff+namePad;
            if (descsz>n-descOff) break;
            if (type==NT_GNU_BUILD_ID && namesz==4 && descsz==20 &&
                std::memcmp(notes+nameOff,"GNU",4)==0) {
                std::memcpy(out.buildId.data(),notes+descOff,20);
                out.hasBuildId=true;
                return;
            }
            auto const descPad=(static_cast<std::size_t>(descsz)+3u)&~std::size_t{3};
            if (descPad>n-descOff) break;
            p=descOff+descPad;
        }
    }
}

int moduleCallback(dl_phdr_info* info, std::size_t, void* opaque) noexcept {
    if (!info || !opaque || !isTargetModule(info->dlpi_name)) return 0;
    auto& out = *static_cast<ModuleView*>(opaque);
    out.base = static_cast<std::uintptr_t>(info->dlpi_addr);
    extractBuildId(out,*info);
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        auto const& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0) continue;
        const auto start = out.base + static_cast<std::uintptr_t>(phdr.p_vaddr);
        const auto end = start + static_cast<std::uintptr_t>(phdr.p_memsz);
        out.loadStart = std::min(out.loadStart, start);
        out.loadEnd = std::max(out.loadEnd, end);
        if ((phdr.p_flags & PF_X) != 0 &&
            out.executableRangeCount < out.executableRanges.size()) {
            // Keep each executable PT_LOAD as an independent range. Never merge
            // discontiguous executable mappings: gaps may be PROT_NONE/unmapped.
            out.executableRanges[out.executableRangeCount++] = {start, end};
        }
    }
    return 1;
}

bool findMinecraft(ModuleView& out) noexcept {
    out = {};
    out.loadStart = std::numeric_limits<std::uintptr_t>::max();
    dl_iterate_phdr(&moduleCallback, &out);
    return out.base != 0 && out.loadEnd > out.loadStart && out.executableRangeCount != 0;
}

int hexNibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool parseSignature(std::string_view sig, ParsedSignature& out) {
    out = {};
    std::size_t pos = 0;
    while (pos < sig.size()) {
        while (pos < sig.size() && sig[pos] == ' ') ++pos;
        if (pos >= sig.size()) break;

        const auto tokenStart = pos;
        while (pos < sig.size() && sig[pos] != ' ') ++pos;
        if (pos - tokenStart != 2) return false;

        const char hi = sig[tokenStart];
        const char lo = sig[tokenStart + 1];
        std::uint8_t value = 0;
        std::uint8_t mask = 0;

        if (hi != '?') {
            const int nibble = hexNibble(hi);
            if (nibble < 0) return false;
            value |= static_cast<std::uint8_t>(nibble << 4);
            mask |= 0xf0;
        }
        if (lo != '?') {
            const int nibble = hexNibble(lo);
            if (nibble < 0) return false;
            value |= static_cast<std::uint8_t>(nibble);
            mask |= 0x0f;
        }

        out.values.push_back(value);
        out.masks.push_back(mask);
    }

    if (out.values.empty()) return false;

    // Pick the longest fully-fixed byte run as a fast anchor. The complete
    // nibble mask is still checked before accepting a candidate.
    std::size_t bestOffset = 0;
    std::size_t bestLength = 0;
    for (std::size_t i = 0; i < out.masks.size();) {
        if (out.masks[i] != 0xff) {
            ++i;
            continue;
        }
        const auto runStart = i;
        while (i < out.masks.size() && out.masks[i] == 0xff) ++i;
        const auto runLength = i - runStart;
        if (runLength > bestLength) {
            bestOffset = runStart;
            bestLength = runLength;
        }
    }

    if (bestLength < 4) return false;
    out.anchorOffset = bestOffset;
    out.anchorLength = bestLength;
    return true;
}

bool matchesPattern(std::uint8_t const* bytes, ParsedSignature const& pattern) noexcept {
    for (std::size_t i = 0; i < pattern.values.size(); ++i) {
        if ((bytes[i] & pattern.masks[i]) != pattern.values[i]) return false;
    }
    return true;
}

SignatureScanResult scanUniqueSignature(
    ModuleView const& module,
    std::string_view signature,
    std::uintptr_t& address
) {
    ParsedSignature pattern;
    if (!parseSignature(signature, pattern)) return SignatureScanResult::Invalid;

    std::uintptr_t unique{};
    std::size_t matches = 0;

    for (std::size_t rangeIndex = 0; rangeIndex < module.executableRangeCount; ++rangeIndex) {
        auto const& range = module.executableRanges[rangeIndex];
        if (range.end <= range.start || pattern.values.size() > range.end - range.start) continue;

        auto candidate = (range.start + 3u) & ~std::uintptr_t{3u};
        const auto last = range.end - pattern.values.size();

        for (; candidate <= last; candidate += 4) {
            // Deliberately validate byte-by-byte inside this exact PT_LOAD range.
            // Do not use a wide anchor load/memcmp here: keeping every read
            // bounded to the selected executable mapping prevents page-boundary
            // faults on binaries with discontiguous executable PT_LOAD segments.
            auto const* bytes = reinterpret_cast<std::uint8_t const*>(candidate);
            if (!matchesPattern(bytes, pattern)) continue;
            unique = candidate;
            if (++matches > 1) {
                address = 0;
                return SignatureScanResult::NotUnique;
            }
        }
    }

    if (matches == 0) {
        address = 0;
        return SignatureScanResult::NotFound;
    }

    address = unique;
    return SignatureScanResult::Found;
}

template <class T>
Status bindSignature(T& out, ModuleView const& module, std::string_view signature) {
    std::uintptr_t address{};
    switch (scanUniqueSignature(module, signature, address)) {
    case SignatureScanResult::Found:
        out = reinterpret_cast<T>(address);
        return {};
    case SignatureScanResult::NotFound:
        out = nullptr;
        return {Error::ExactBuildMismatch};
    case SignatureScanResult::NotUnique:
        out = nullptr;
        return {Error::ExactBuildMismatch};
    case SignatureScanResult::Invalid:
        out = nullptr;
        return {Error::ExactBuildMismatch};
    }
    out = nullptr;
    return {Error::ExactBuildMismatch};
}

bool vectorBounds(void const* object, std::size_t beginOffset, std::size_t endOffset,
                  std::byte*& begin, std::byte*& end) noexcept {
    begin = static_cast<std::byte*>(readPointer(object, beginOffset));
    end = static_cast<std::byte*>(readPointer(object, endOffset));
    if (!begin && !end) return true;
    return begin && end && end >= begin;
}

} // namespace

char const* errorString(Error e) noexcept {
    switch (e) {
    case Error::None: return "none";
    case Error::MinecraftModuleNotFound: return "libminecraftpe.so not loaded";
    case Error::ExactBuildMismatch: return "MCBE wildcard signature / executable identity mismatch";
    case Error::NotResolved: return "engine bindings not resolved";
    case Error::NullInitializer: return "CreativeItemInitializer is null";
    case Error::CreativeRegistryUnavailable: return "CreativeItemRegistry unavailable";
    case Error::ItemRegistryUnavailable: return "ItemRegistry unavailable";
    case Error::InvalidVectorLayout: return "native vector layout failed sanity validation";
    case Error::InvalidArgument: return "invalid argument";
    case Error::InvalidIdentifier: return "invalid item identifier";
    case Error::ItemConstructionFailed: return "ItemInstance construction failed";
    case Error::ItemNotCanonical: return "item identifier remapped or is not canonical";
    case Error::UnsafeSyntheticItem: return "synthetic item is unsafe for Creative UI";
    case Error::DuplicateItem: return "exact item variant already exists in Creative";
    case Error::GroupCreationFailed: return "creative group creation failed";
    case Error::EntryCreationFailed: return "creative item entry creation failed";
    case Error::NetIdExhausted: return "creative net-id space exhausted";
    case Error::AlreadyInstalled: return "hook already installed";
    case Error::HookInstallFailed: return "Preloader hook installation failed";
    }
    return "unknown";
}

Status CreativeInventoryAPI::resolveExact126443() {
#if defined(__ANDROID__)
    static_assert(sizeof(std::string) == 0x18, "Android libc++ std::string ABI changed");
    static_assert(sizeof(HashedStringExact) == 0x28, "HashedStringExact layout mismatch");
#endif
    ModuleView module{};
    if (!findMinecraft(module)) return {Error::MinecraftModuleNotFound};

    if (!module.hasBuildId) return {Error::ExactBuildMismatch};
    constexpr std::array<std::string_view, 11> legacySignatures = {
        "FF 03 05 D1 FD 7B 0F A9 FC 67 10 A9 F8 5F 11 A9 F6 57 12 A9 F4 4F 13 A9 FD C3 03 91 55 D0 3B D5 B4 63 01 D1 F3 03 00 AA A8 16 40 F9 A8 83 1F F8 A0 83 1A F8 80 22 00 91 ?? ?? ?? ?? E8 23 00 91",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 04 40 F9 F3 03 08 AA 1F 7D 00 A9 40 01 00 B4 ?? ?? ?? ?? 60 06 00 F9 E0 00 00 B4 88 02 40 F9 68 02 00 F9 88 00 00 B4",
        "09 28 40 F9 89 06 00 B4 20 01 67 9E 28 1C 40 92 00 58 20 0E 00 38 30 2E 0C 00 26 1E 9F 05 00 F1 ?? ?? ?? ?? 2A 05 00 51 4A 01 08 8A ?? ?? ?? ?? 3F 01 08 EB EA 03 08 AA ?? ?? ?? ?? 2A 1D 00 12",
        "FF 03 02 D1 FD 7B 02 A9 FC 6F 03 A9 FA 67 04 A9 F8 5F 05 A9 F6 57 06 A9 F4 4F 07 A9 FD 83 00 91 59 D0 3B D5 28 17 40 F9 A8 83 1F F8 08 1C 40 F9 ?? ?? ?? ?? F4 03 00 AA 00 00 01 91 F5 03 02 AA",
        "FF 83 01 D1 FD 7B 02 A9 F8 5F 03 A9 F6 57 04 A9 F4 4F 05 A9 FD 83 00 91 ?? ?? ?? ?? F3 03 00 AA 6A 74 91 52 E8 16 40 F9 CA 45 B7 72 F5 03 02 AA F6 03 01 AA A8 83 1F F8 14 24 42 A9 E0 07 00 F9",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 ?? ?? ?? ?? F4 03 00 AA 20 A0 00 91 F3 03 01 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 62 40 39 3F 00 20 6B ?? ?? ?? ?? 68 1A 40 F9 00 01 40 F9 ?? ?? ?? ??",
        "FF C3 01 D1 FD 7B 02 A9 F9 1B 00 F9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 83 00 91 56 D0 3B D5 F3 03 00 AA C8 16 40 F9 A8 83 1F F8 08 44 40 F9 ?? ?? ?? ?? 74 42 40 F9 ?? ?? ?? ?? E0 03 14 AA",
        "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 F3 03 00 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 02 00 F9 F3 0B 40 F9 FD 7B C2 A8 C0 03 5F D6 FF 43 03 D1 FD 7B 08 A9 FA 67 09 A9 F8 5F 0A A9 F6 57 0B A9",
        "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F3 03 00 AA 00 3C 40 F9 ?? ?? ?? ?? ?? ?? ?? ?? 7F 3E 00 F9 68 02 00 F9 ?? ?? ?? ?? 08 00 40 F9 08 05 40 F9 00 01 3F D6 60 2A 40 F9 ?? ?? ?? ??",
        "08 04 40 F9 68 00 00 B4 00 01 40 F9 C0 03 5F D6 E0 03 1F AA C0 03 5F D6 ?? ?? ?? ?? F5 0B 00 F9",
        "00 A0 03 91 A1 93 A2 14 00 A0 03 91 C0 03 5F D6 ?? ?? ?? ?? FD 7B 03 A9",
    };
    constexpr std::array<std::string_view, 11> oldSignatures = {
        "FF 03 05 D1 FD 7B 0F A9 FC 67 10 A9 F8 5F 11 A9 F6 57 12 A9 F4 4F 13 A9 FD C3 03 91 55 D0 3B D5 B4 63 01 D1 F3 03 00 AA A8 16 40 F9 A8 83 1F F8 A0 83 1A F8 80 22 00 91 ?? ?? ?? ?? E8 23 00 91",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 04 40 F9 F3 03 08 AA 1F 7D 00 A9 40 01 00 B4 ?? ?? ?? ?? 60 06 00 F9 E0 00 00 B4 88 02 40 F9 68 02 00 F9 88 00 00 B4",
        "09 28 40 F9 89 06 00 B4 20 01 67 9E 28 1C 40 92 00 58 20 0E 00 38 30 2E 0C 00 26 1E 9F 05 00 F1 ?? ?? ?? ?? 2A 05 00 51 4A 01 08 8A ?? ?? ?? ?? 3F 01 08 EB EA 03 08 AA ?? ?? ?? ?? 2A 1D 00 12",
        "FF 03 02 D1 FD 7B 02 A9 FC 6F 03 A9 FA 67 04 A9 F8 5F 05 A9 F6 57 06 A9 F4 4F 07 A9 FD 83 00 91 59 D0 3B D5 28 17 40 F9 A8 83 1F F8 08 1C 40 F9 ?? ?? ?? ?? F4 03 00 AA 00 00 01 91 F5 03 02 AA",
        "FF 83 01 D1 FD 7B 02 A9 F8 5F 03 A9 F6 57 04 A9 F4 4F 05 A9 FD 83 00 91 ?? ?? ?? ?? F3 03 00 AA 6A 74 91 52 E8 16 40 F9 CA 45 B7 72 F5 03 02 AA F6 03 01 AA A8 83 1F F8 14 24 42 A9 E0 07 00 F9",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 ?? ?? ?? ?? F4 03 00 AA 20 A0 00 91 F3 03 01 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 62 40 39 3F 00 20 6B ?? ?? ?? ?? 68 1A 40 F9 00 01 40 F9 ?? ?? ?? ??",
        "FF C3 01 D1 FD 7B 02 A9 F9 1B 00 F9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 83 00 91 56 D0 3B D5 F3 03 00 AA C8 16 40 F9 A8 83 1F F8 08 44 40 F9 ?? ?? ?? ?? 74 42 40 F9 ?? ?? ?? ?? E0 03 14 AA",
        "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 F3 03 00 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 02 00 F9 F3 0B 40 F9 FD 7B C2 A8 C0 03 5F D6 FF 43 03 D1 FD 7B 08 A9 FA 67 09 A9 F8 5F 0A A9 F6 57 0B A9",
        "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F3 03 00 AA 00 3C 40 F9 ?? ?? ?? ?? ?? ?? ?? ?? 7F 3E 00 F9 68 02 00 F9 ?? ?? ?? ?? 08 00 40 F9 08 05 40 F9 00 01 3F D6 60 2A 40 F9 ?? ?? ?? ??",
        "08 04 40 F9 68 00 00 B4 00 01 40 F9 C0 03 5F D6 E0 03 1F AA C0 03 5F D6 ?? ?? ?? ?? F5 0B 00 F9",
        "00 A0 03 91 ?? ?? ?? 14 00 A0 03 91 C0 03 5F D6 ?? ?? ?? ?? FD 7B 03 A9",
    };
    constexpr std::array<std::string_view, 11> newSignatures = {
        "FF 03 05 D1 FD 7B 0F A9 FC 67 10 A9 F8 5F 11 A9 F6 57 12 A9 F4 4F 13 A9 FD C3 03 91 55 D0 3B D5 B4 63 01 D1 F3 03 00 AA A8 16 40 F9 A8 83 1F F8 A0 83 1A F8 80 22 00 91 ?? ?? ?? ?? E8 23 00 91 E0 03 13 AA",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 04 40 F9 1F 7D 00 A9 ?? ?? ?? ?? F3 03 08 AA ?? ?? ?? ?? 60 06 00 F9 ?? ?? ?? ?? 88 02 40 F9 68 02 00 F9 ?? ?? ?? ?? F4 4F 41 A9",
        "09 28 40 F9 ?? ?? ?? ?? 20 01 67 9E 28 1C 40 92 00 58 20 0E 00 38 30 2E 0C 00 26 1E 9F 05 00 F1 ?? ?? ?? ?? 2A 05 00 51 4A 01 08 8A ?? ?? ?? ?? 3F 01 08 EB EA 03 08 AA ?? ?? ?? ?? 2A 1D 00 12",
        "FF 03 02 D1 FD 7B 02 A9 FC 6F 03 A9 FA 67 04 A9 F8 5F 05 A9 F6 57 06 A9 F4 4F 07 A9 FD 83 00 91 5A D0 3B D5 48 17 40 F9 A8 83 1F F8 08 1C 40 F9 ?? ?? ?? ?? F3 03 00 AA 00 00 01 91 F5 03 02 AA F6 03 01 AA ?? ?? ?? ?? 74 1E 40 F9 ?? ?? ?? ??",
        "FF 43 01 D1 FD 7B 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 83 00 91 56 D0 3B D5 F3 03 00 AA 6A 74 91 52 C8 16 40 F9 CA 45 B7 72 E3 03 02 AA E2 03 01 AA A8 83 1F F8 15 24 42 A9 E0 07 00 F9 08 8C 41 F8 A8 02 08 CB BF 02 09 EB 08 FD 44 D3 14 7D 0A 1B B4 43 1F B8 ?? ?? ?? ??",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 ?? ?? ?? ?? F4 03 00 AA 20 A0 00 91 F3 03 01 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 62 40 39 3F 00 20 6B ?? ?? ?? ?? 68 1A 40 F9 00 01 40 F9 ?? ?? ?? ?? E0 03 14 AA",
        "FF C3 01 D1 FD 7B 02 A9 F9 1B 00 F9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 83 00 91 57 D0 3B D5 F3 03 00 AA E8 16 40 F9 A8 83 1F F8 08 44 40 F9 ?? ?? ?? ?? 74 42 40 F9 ?? ?? ?? ?? E0 03 14 AA 15 04 41 F8 ?? ?? ?? ?? E0 03 14 AA ?? ?? ?? ??",
        "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 F3 03 00 AA ?? ?? ?? ?? ?? ?? ?? ?? 08 81 10 91 68 02 00 F9 F3 0B 40 F9 FD 7B C2 A8 C0 03 5F D6 FF 43 03 D1 FD 7B 08 A9 FA 67 09 A9 F8 5F 0A A9 F6 57 0B A9 F4 4F 0C A9 FD 03 02 91",
        "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F3 03 00 AA 00 3C 40 F9 ?? ?? ?? ?? 08 A1 13 91 7F 3E 00 F9 68 02 00 F9 ?? ?? ?? ?? 08 00 40 F9 08 05 40 F9 00 01 3F D6 60 2A 40 F9 ?? ?? ?? ?? 60 2E 00 F9 ?? ?? ?? ??",
        "08 04 40 F9 ?? ?? ?? ?? 00 01 40 F9 C0 03 5F D6 E0 03 1F AA C0 03 5F D6 09 0C 42 78 E8 FF 8F 52 0A 80 5F F8",
        "00 A0 03 91 ?? ?? ?? ?? 00 A0 03 91 C0 03 5F D6 FF 83 01 D1 FD 7B 03 A9 F5 23 00 F9 F4 4F 05 A9 FD C3 00 91 55 D0 3B D5 F4 03 00 AA",
    };
    constexpr std::array<std::string_view, 11> latestSignatures = {
        "FF 03 05 D1 FD 7B 0F A9 FC 67 10 A9 F8 5F 11 A9 F6 57 12 A9 F4 4F 13 A9 FD C3 03 91 55 D0 3B D5 B4 63 01 D1 F3 03 00 AA A8 16 40 F9 A8 83 1F F8 A0 83 1A F8 80 22 00 91 ?? ?? ?? ?? E8 23 00 91 E0 03 13 AA",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 04 40 F9 1F 7D 00 A9 ?? ?? ?? ?? F3 03 08 AA ?? ?? ?? ?? 60 06 00 F9 ?? ?? ?? ?? 88 02 40 F9 68 02 00 F9 ?? ?? ?? ?? F4 4F 41 A9",
        "09 28 40 F9 ?? ?? ?? ?? 20 01 67 9E 28 1C 40 92 00 58 20 0E 00 38 30 2E 0C 00 26 1E 9F 05 00 F1 ?? ?? ?? ?? 2A 05 00 51 4A 01 08 8A ?? ?? ?? ?? 3F 01 08 EB EA 03 08 AA ?? ?? ?? ?? 2A 1D 00 12",
        "FF 03 02 D1 FD 7B 02 A9 FC 6F 03 A9 FA 67 04 A9 F8 5F 05 A9 F6 57 06 A9 F4 4F 07 A9 FD 83 00 91 5A D0 3B D5 48 17 40 F9 A8 83 1F F8 08 1C 40 F9 ?? ?? ?? ?? F3 03 00 AA 00 00 01 91 F5 03 02 AA F6 03 01 AA ?? ?? ?? ?? 74 1E 40 F9 ?? ?? ?? ??",
        "FF 43 01 D1 FD 7B 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 83 00 91 56 D0 3B D5 F3 03 00 AA 6A 74 91 52 C8 16 40 F9 CA 45 B7 72 E3 03 02 AA E2 03 01 AA A8 83 1F F8 15 24 42 A9 E0 07 00 F9 08 8C 41 F8 A8 02 08 CB BF 02 09 EB 08 FD 44 D3 14 7D 0A 1B B4 43 1F B8 ?? ?? ?? ??",
        "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 ?? ?? ?? ?? F4 03 00 AA 20 A0 00 91 F3 03 01 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 62 40 39 3F 00 20 6B ?? ?? ?? ?? 68 1A 40 F9 00 01 40 F9 ?? ?? ?? ?? E0 03 14 AA",
        "FF C3 01 D1 FD 7B 02 A9 F9 1B 00 F9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 83 00 91 57 D0 3B D5 F3 03 00 AA E8 16 40 F9 A8 83 1F F8 08 44 40 F9 ?? ?? ?? ?? 74 42 40 F9 ?? ?? ?? ?? E0 03 14 AA 15 04 41 F8 ?? ?? ?? ?? E0 03 14 AA ?? ?? ?? ??",
        "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 F3 03 00 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 91 68 02 00 F9 F3 0B 40 F9 FD 7B C2 A8 C0 03 5F D6 FF 43 03 D1 FD 7B 08 A9 FA 67 09 A9 F8 5F 0A A9 F6 57 0B A9 F4 4F 0C A9 FD 03 02 91",
        "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F3 03 00 AA 00 3C 40 F9 ?? ?? ?? ?? ?? ?? ?? 91 7F 3E 00 F9 68 02 00 F9 ?? ?? ?? ?? 08 00 40 F9 08 05 40 F9 00 01 3F D6 60 2A 40 F9 ?? ?? ?? ?? 60 2E 00 F9 ?? ?? ?? ??",
        "08 04 40 F9 ?? ?? ?? ?? 00 01 40 F9 C0 03 5F D6 E0 03 1F AA C0 03 5F D6 09 0C 42 78 E8 FF 8F 52 0A 80 5F F8",
        "00 A0 03 91 ?? ?? ?? ?? 00 A0 03 91 C0 03 5F D6 FF 83 01 D1 FD 7B 03 A9 F5 23 00 F9 F4 4F 05 A9 FD C3 00 91 55 D0 3B D5 F4 03 00 AA",
    };
    auto attempt = [&](std::array<std::string_view, 11> const& signatures) -> Status {
        EngineBindings b{};
        auto bind = [&](auto& target, std::size_t idx) -> Status {
            return bindSignature(target, module, signatures[idx]);
        };
        Status status{};
        status=bind(b.addLooseCreativeItemsTarget,0);
        if (!status) return status;
        status=bind(b.lockItemRegistry,1);
        if (!status) return status;
        status=bind(b.getCreativeCategory,2);
        if (!status) return status;
        status=bind(b.addChildGroup,3);
        if (!status) return status;
        status=bind(b.newItemEntry,4);
        if (!status) return status;
        status=bind(b.addCreativeItemEntry,5);
        if (!status) return status;
        status=bind(b.updateNetIdMap,6);
        if (!status) return status;
        status=bind(b.itemInstanceNameCtor,7);
        if (!status) return status;
        status=bind(b.itemInstanceDtor,8);
        if (!status) return status;
        status=bind(b.itemGetItem,9);
        if (!status) return status;
        status=bind(b.itemGetFullItemName,10);
        if (!status) return status;
        return bindVerified(b);
    };
    if (module.buildId==kBuildId12621) return attempt(latestSignatures);
    if (module.buildId==kCurrentBuildId) return attempt(newSignatures);
    if (module.buildId==kBuildId12523Recorded) return attempt(oldSignatures);
    if (module.buildId==kOldBuildId) {
        auto status=attempt(oldSignatures);
        if (status) return status;
        return attempt(legacySignatures);
    }
    return {Error::ExactBuildMismatch};
}

Status CreativeInventoryAPI::bindVerified(EngineBindings const& b) {
    if (!b.addLooseCreativeItemsTarget || !b.lockItemRegistry || !b.getCreativeCategory ||
        !b.addChildGroup || !b.newItemEntry || !b.addCreativeItemEntry || !b.updateNetIdMap ||
        !b.itemInstanceNameCtor || !b.itemInstanceDtor || !b.itemGetItem || !b.itemGetFullItemName) {
        return {Error::InvalidArgument};
    }
    std::lock_guard lock(mMutex);
    mBindings = b;
    mInitializer = nullptr;
    mCreativeRegistry = nullptr;
    return {};
}

bool CreativeInventoryAPI::resolved() const noexcept {
    return mBindings.addLooseCreativeItemsTarget && mBindings.getCreativeCategory &&
           mBindings.newItemEntry && mBindings.itemInstanceNameCtor && mBindings.itemGetItem;
}

Status CreativeInventoryAPI::attachInitializer(void* initializer) {
    if (!resolved()) return {Error::NotResolved};
    if (!initializer) return {Error::NullInitializer};
    auto* registry = readPointer(initializer, kCreativeInitializerRegistryOffset);
    if (!registry) return {Error::CreativeRegistryUnavailable};
    std::lock_guard lock(mMutex);
    mInitializer = initializer;
    mCreativeRegistry = registry;
    return {};
}

void CreativeInventoryAPI::reset() noexcept {
    std::lock_guard lock(mMutex);
    mInitializer = nullptr;
    mCreativeRegistry = nullptr;
}

bool CreativeInventoryAPI::ready() const noexcept { return resolved() && mInitializer && mCreativeRegistry; }

Result<GroupHandle> CreativeInventoryAPI::createGroup(std::string_view name, ItemSpec icon, std::uint8_t category) {
    if (!validIdentifier(icon.identifier) || name.empty()) return {{}, Error::InvalidArgument};
    if (unsafeSynthetic(icon.identifier)) return {{}, Error::UnsafeSyntheticItem};
    if (!ready()) return {{}, Error::CreativeRegistryUnavailable};

    ItemStorage storage{};
    mBindings.itemInstanceNameCtor(storage.bytes.data(), icon.identifier.data(), icon.identifier.size(),
                                   static_cast<int>(icon.count), static_cast<int>(icon.aux), nullptr);
    auto* item = mBindings.itemGetItem(storage.bytes.data());
    if (!item) { mBindings.itemInstanceDtor(storage.bytes.data()); return {{}, Error::ItemConstructionFailed}; }
    auto const canonical = canonicalItemName(item);
    if (canonical != icon.identifier || auxFromInstance(storage.bytes.data()) != icon.aux) {
        mBindings.itemInstanceDtor(storage.bytes.data());
        return {{}, Error::ItemNotCanonical};
    }
    auto result = createGroupFromIconInstance(name, storage.bytes.data(), category);
    mBindings.itemInstanceDtor(storage.bytes.data());
    return result;
}

Result<GroupHandle> CreativeInventoryAPI::createGroupFromIconInstance(
    std::string_view name, void const* iconItemInstance, std::uint8_t category
) {
    if (!ready()) return {{}, Error::CreativeRegistryUnavailable};
    if (name.empty() || !iconItemInstance || !mBindings.itemGetItem(iconItemInstance)) return {{}, Error::InvalidArgument};
    std::lock_guard lock(mMutex);
    auto* categoryPtr = mBindings.getCreativeCategory(mCreativeRegistry, category);
    if (!categoryPtr) return {{}, Error::GroupCreationFailed};
    auto hashed = makeHashedString(name);
    auto* group = mBindings.addChildGroup(categoryPtr, &hashed, iconItemInstance);
    return group ? Result<GroupHandle>{{group}, Error::None}
                 : Result<GroupHandle>{{}, Error::GroupCreationFailed};
}

Result<EntryHandle> CreativeInventoryAPI::addItem(GroupHandle group, ItemSpec spec, AddOptions options) {
    if (!ready()) return {{}, Error::CreativeRegistryUnavailable};
    if (!group || !validIdentifier(spec.identifier) || spec.count == 0) return {{}, Error::InvalidArgument};
    if (unsafeSynthetic(spec.identifier) && !options.allowUnsafeSyntheticItem) return {{}, Error::UnsafeSyntheticItem};

    ItemStorage storage{};
    mBindings.itemInstanceNameCtor(storage.bytes.data(), spec.identifier.data(), spec.identifier.size(),
                                   static_cast<int>(spec.count), static_cast<int>(spec.aux), nullptr);
    auto* item = mBindings.itemGetItem(storage.bytes.data());
    if (!item) { mBindings.itemInstanceDtor(storage.bytes.data()); return {{}, Error::ItemConstructionFailed}; }
    if (auxFromInstance(storage.bytes.data()) != spec.aux) {
        mBindings.itemInstanceDtor(storage.bytes.data()); return {{}, Error::ItemNotCanonical};
    }
    if (options.requireCanonicalName && canonicalItemName(item) != spec.identifier) {
        mBindings.itemInstanceDtor(storage.bytes.data()); return {{}, Error::ItemNotCanonical};
    }
    auto result = addItemInstance(group, storage.bytes.data(), options);
    mBindings.itemInstanceDtor(storage.bytes.data());
    return result;
}

Result<EntryHandle> CreativeInventoryAPI::addItemInstance(GroupHandle group, void const* itemInstance, AddOptions options) {
    std::lock_guard lock(mMutex);
    return addItemInstanceLocked(group, itemInstance, options);
}

Result<EntryHandle> CreativeInventoryAPI::addItemInstanceLocked(
    GroupHandle group, void const* itemInstance, AddOptions options
) {
    if (!ready()) return {{}, Error::CreativeRegistryUnavailable};
    if (!group || !itemInstance) return {{}, Error::InvalidArgument};
    auto* item = itemFromInstance(itemInstance);
    if (!item) return {{}, Error::ItemConstructionFailed};
    const auto aux = auxFromInstance(itemInstance);
    if (options.skipIfAlreadyPresent && containsVariant(item, aux)) return {{}, Error::DuplicateItem};

    auto net = nextCreativeNetId();
    if (!net) return {{}, net.error};
    const std::uint32_t id = net.value;
    auto* entry = mBindings.newItemEntry(mCreativeRegistry, id, itemInstance);
    if (!entry) return {{}, Error::EntryCreationFailed};
    mBindings.addCreativeItemEntry(group.native, entry);
    return {{entry, id}, Error::None};
}

BatchResult CreativeInventoryAPI::addItems(GroupHandle group, std::span<ItemSpec const> specs, AddOptions options) {
    BatchResult out{};
    for (auto const& spec : specs) {
        auto r = addItem(group, spec, options);
        if (r) ++out.added;
        else if (r.error == Error::DuplicateItem || r.error == Error::ItemNotCanonical ||
                 r.error == Error::ItemConstructionFailed || r.error == Error::UnsafeSyntheticItem) ++out.skipped;
        else { out.error = r.error; break; }
    }
    return out;
}

Status CreativeInventoryAPI::finalize() {
    if (!ready()) return {Error::CreativeRegistryUnavailable};
    std::lock_guard lock(mMutex);
    mBindings.updateNetIdMap(mCreativeRegistry);
    return {};
}

Result<std::uint32_t> CreativeInventoryAPI::nextCreativeNetId() const {
    if (!ready()) return {0, Error::CreativeRegistryUnavailable};
    std::byte* begin{}; std::byte* end{};
    if (!vectorBounds(mCreativeRegistry, kCreativeRegistryItemsBeginOffset, kCreativeRegistryItemsEndOffset, begin, end))
        return {0, Error::InvalidVectorLayout};
    if (!begin && !end) return {1, Error::None};
    const auto bytes = static_cast<std::size_t>(end - begin);
    if (bytes % kCreativeItemEntrySize != 0 || bytes / kCreativeItemEntrySize > 65536)
        return {0, Error::InvalidVectorLayout};
    std::uint32_t maxId = 0;
    for (auto* entry = begin; entry < end; entry += kCreativeItemEntrySize)
        maxId = std::max(maxId, readValue<std::uint32_t>(entry, kCreativeEntryNetIdOffset));
    if (maxId == std::numeric_limits<std::uint32_t>::max()) return {0, Error::NetIdExhausted};
    return {maxId + 1, Error::None};
}

std::size_t CreativeInventoryAPI::creativeEntryCount() const noexcept {
    if (!mCreativeRegistry) return 0;
    std::byte* begin{}; std::byte* end{};
    if (!vectorBounds(mCreativeRegistry, kCreativeRegistryItemsBeginOffset, kCreativeRegistryItemsEndOffset, begin, end) ||
        (!begin && !end)) return 0;
    const auto bytes = static_cast<std::size_t>(end - begin);
    if (bytes % kCreativeItemEntrySize != 0) return 0;
    return bytes / kCreativeItemEntrySize;
}

bool CreativeInventoryAPI::containsVariant(void* item, std::int16_t aux) const noexcept {
    if (!item || !mCreativeRegistry) return false;
    std::byte* begin{}; std::byte* end{};
    if (!vectorBounds(mCreativeRegistry, kCreativeRegistryItemsBeginOffset, kCreativeRegistryItemsEndOffset, begin, end) ||
        (!begin && !end)) return false;
    const auto bytes = static_cast<std::size_t>(end - begin);
    if (bytes % kCreativeItemEntrySize != 0 || bytes / kCreativeItemEntrySize > 65536) return false;
    for (auto* entry = begin; entry < end; entry += kCreativeItemEntrySize) {
        auto* inst = entry + kCreativeEntryItemInstanceOffset;
        if (itemFromInstance(inst) == item && auxFromInstance(inst) == aux) return true;
    }
    return false;
}

bool CreativeInventoryAPI::containsItemInstance(void const* inst) const noexcept {
    return inst && containsVariant(itemFromInstance(inst), auxFromInstance(inst));
}

Result<std::size_t> CreativeInventoryAPI::registeredItemCount() const {
    if (!mInitializer || !mBindings.lockItemRegistry) return {0, Error::ItemRegistryUnavailable};
    auto registry = mBindings.lockItemRegistry(mInitializer);
    if (!registry) return {0, Error::ItemRegistryUnavailable};
    std::byte* begin{}; std::byte* end{};
    if (!vectorBounds(registry.get(), kItemRegistryItemsBeginOffset, kItemRegistryItemsEndOffset, begin, end))
        return {0, Error::InvalidVectorLayout};
    if (!begin && !end) return {0, Error::None};
    const auto bytes = static_cast<std::size_t>(end - begin);
    if (bytes % kBedrockSharedPtrSize != 0 || bytes / kBedrockSharedPtrSize > kMaxRegisteredItems)
        return {0, Error::InvalidVectorLayout};
    return {bytes / kBedrockSharedPtrSize, Error::None};
}

Status CreativeInventoryAPI::forEachRegisteredItem(RegisteredItemVisitor visitor, void* userData) const {
    if (!visitor) return {Error::InvalidArgument};
    if (!mInitializer || !mBindings.lockItemRegistry) return {Error::ItemRegistryUnavailable};
    auto registry = mBindings.lockItemRegistry(mInitializer);
    if (!registry) return {Error::ItemRegistryUnavailable};
    std::byte* begin{}; std::byte* end{};
    if (!vectorBounds(registry.get(), kItemRegistryItemsBeginOffset, kItemRegistryItemsEndOffset, begin, end))
        return {Error::InvalidVectorLayout};
    if (!begin && !end) return {};
    const auto bytes = static_cast<std::size_t>(end - begin);
    if (bytes % kBedrockSharedPtrSize != 0 || bytes / kBedrockSharedPtrSize > kMaxRegisteredItems)
        return {Error::InvalidVectorLayout};

    std::unordered_set<void*> seen;
    seen.reserve(bytes / kBedrockSharedPtrSize);
    for (auto* slot = begin; slot < end; slot += kBedrockSharedPtrSize) {
        auto* counter = readPointer(slot, 0);
        auto* item = counter ? readPointer(counter, 0) : nullptr;
        if (!item || !seen.insert(item).second) continue;
        auto name = canonicalItemName(item);
        if (!validIdentifier(name)) continue;
        if (!visitor(item, name, userData)) break;
    }
    return {};
}

Result<void*> CreativeInventoryAPI::findRegisteredItem(std::string_view id) const {
    if (!validIdentifier(id)) return {nullptr, Error::InvalidIdentifier};
    struct FindContext { std::string_view id; void* found{}; } ctx{id, nullptr};
    const auto visitor = [](void* item, std::string_view name, void* opaque) -> bool {
        auto& c = *static_cast<FindContext*>(opaque);
        if (name == c.id) { c.found = item; return false; }
        return true;
    };
    auto st = forEachRegisteredItem(visitor, &ctx);
    if (!st) return {nullptr, st.error};
    return {ctx.found, ctx.found ? Error::None : Error::ItemConstructionFailed};
}

void* CreativeInventoryAPI::itemFromInstance(void const* instance) const noexcept {
    return instance && mBindings.itemGetItem ? mBindings.itemGetItem(instance) : nullptr;
}

std::int16_t CreativeInventoryAPI::auxFromInstance(void const* instance) const noexcept {
    return readValue<std::int16_t>(instance, kItemInstanceAuxOffset);
}

std::string_view CreativeInventoryAPI::canonicalItemName(void const* item) const noexcept {
    if (!item || !mBindings.itemGetFullItemName) return {};
    auto const& s = mBindings.itemGetFullItemName(item);
    return std::string_view{s.data(), s.size()};
}

} // namespace creative_inventory_api
