#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <array>
#include <cinttypes>
#include <map>
#include <mutex>
#include <vector>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {
const uintptr_t kPageSize = getpagesize();

inline auto PageStart(uintptr_t addr) {
    return reinterpret_cast<char *>(addr / kPageSize * kPageSize);
}

inline auto PageEnd(uintptr_t addr) {
    return reinterpret_cast<char *>(reinterpret_cast<uintptr_t>(PageStart(addr)) + kPageSize);
}

struct RegisterInfo {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    std::string symbol;
    void *callback;
    void **backup;
};

std::vector<lsplt::MapInfo> map_cache;
bool map_cache_ready = false;

struct HookInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    bool self;
    [[nodiscard]] bool Match(const RegisterInfo &info) const {
        return info.dev == dev && info.inode == inode && offset >= info.offset_range.first &&
               offset < info.offset_range.second;
    }
};

class HookInfos : public std::map<uintptr_t, HookInfo, std::greater<>> {
public:
    static auto FromMaps(std::vector<lsplt::MapInfo> maps) {
        static ino_t kSelfInode = 0;
        static dev_t kSelfDev = 0;
        HookInfos info;
        if (kSelfInode == 0) {
            auto self = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
            for (auto &map : maps) {
                if (self >= map.start && self < map.end) {
                    kSelfInode = map.inode;
                    kSelfDev = map.dev;
                    LOGV("self inode = %lu", kSelfInode);
                    break;
                }
            }
        }
        for (auto &map : maps) {
            // we basically only care about r-?p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // both of them should not be xom
            if (!map.is_private || !(map.perms & PROT_READ) || map.path.empty() ||
                map.path[0] == '[') {
                continue;
            }
            auto start = map.start;
            const bool self = map.inode == kSelfInode && map.dev == kSelfDev;
            info.emplace(start, HookInfo{{std::move(map)}, {}, 0, nullptr, self});
        }
        return info;
    }

    // filter out ignored
    void Filter(const std::vector<RegisterInfo> &register_info) {
        for (auto iter = begin(); iter != end();) {
            const auto &info = iter->second;
            bool matched = false;
            for (const auto &reg : register_info) {
                if (info.Match(reg)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                LOGV("Match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR,
                     iter->second.path.data(), iter->second.inode, iter->second.start,
                     iter->second.end, iter->second.offset);
                ++iter;
            } else {
                iter = erase(iter);
            }
        }
    }

    void Merge(HookInfos &old) {
        // merge with old map info
        for (auto &info : old) {
            if (!info.second.backup && !info.second.hooks.empty()) {
                // A failed protection restore can split the original mapping.
                auto iter = lower_bound(info.second.end - 1);
                while (iter != end() && iter->first >= info.first) iter = erase(iter);
                emplace(info.first, std::move(info.second));
                continue;
            }
            if (info.second.backup) {
                erase(info.second.backup);
            }
            if (auto iter = find(info.first); iter != end()) {
                iter->second = std::move(info.second);
            } else if (info.second.backup) {
                emplace(info.first, std::move(info.second));
            }
        }
    }

    bool DoHookInPlace(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        static_assert(__atomic_always_lock_free(sizeof(uintptr_t), nullptr));
        auto iter = lower_bound(addr);
        if (iter == end() || addr % alignof(uintptr_t) != 0 ||
            addr < iter->second.start || addr >= iter->second.end ||
            iter->second.end - addr < sizeof(uintptr_t)) {
            errno = EINVAL;
            LOGE("Invalid PLT slot: %d", errno);
            return false;
        }
        auto &info = iter->second;
        auto *slot = reinterpret_cast<uintptr_t *>(addr);
        const auto previous = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
        auto record = info.hooks.find(addr);
        if (previous == callback && record == info.hooks.end()) return true;
        const bool inserted = record == info.hooks.end();
        if (inserted) record = info.hooks.emplace(addr, previous).first;
        const bool protect = !(info.perms & PROT_WRITE);
        if (protect && sys_mprotect(PageStart(addr), kPageSize, info.perms | PROT_WRITE) != 0) {
            if (inserted) info.hooks.erase(record);
            LOGE("Making PLT page writable: %d", errno);
            return false;
        }

        if (previous != callback) {
            // A callback can run as soon as its slot is published.
            if (backup) *backup = previous;
            __atomic_store_n(slot, callback, __ATOMIC_RELEASE);
        }
        if (protect && sys_mprotect(PageStart(addr), kPageSize, info.perms) != 0) {
            const int error = errno;
            __atomic_store_n(slot, previous, __ATOMIC_RELEASE);
            if (sys_mprotect(PageStart(addr), kPageSize, info.perms) == 0) {
                if (inserted) info.hooks.erase(record);
            }
            // Keep the record on a failed rollback so cleanup can retry protection.
            errno = error;
            LOGE("Restoring PLT page protection: %d", errno);
            return false;
        }
        if (record->second == callback) info.hooks.erase(record);
        return true;
    }

    bool DoHook(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        LOGV("Hooking %p", reinterpret_cast<void *>(addr));
        auto iter = lower_bound(addr);
        if (iter == end()) return false;
        // iter.first < addr
        auto &info = iter->second;
        if (info.end <= addr) return false;
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("Backup %p to %p", reinterpret_cast<void *>(addr), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                new_addr = sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                if (new_addr == MAP_FAILED || new_addr != backup_addr) {
                    return false;
                }
                LOGD("Backup with MREMAP_DONTUNMAP failed, tried without it");
            }
            if (auto *new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                          PROT_READ | PROT_WRITE | info.perms,
                                          MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
                new_addr == MAP_FAILED) {
                return false;
            }
            for (uintptr_t src = reinterpret_cast<uintptr_t>(backup_addr), dest = info.start,
                           end = info.start + len;
                 dest < end; src += kPageSize, dest += kPageSize) {
                memcpy(reinterpret_cast<void *>(dest), reinterpret_cast<void *>(src), kPageSize);
            }
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }
        if (info.self) {
            // self hooking, no need backup since we are always dirty
            if (!(info.perms & PROT_WRITE)) {
                info.perms |= PROT_WRITE;
                mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
            }
        }
        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        auto the_backup = *the_addr;
        if (*the_addr != callback) {
            *the_addr = callback;
            if (backup) *backup = the_backup;
            __builtin___clear_cache(PageStart(addr), PageEnd(addr));
        }
        if (auto hook_iter = info.hooks.find(addr); hook_iter != info.hooks.end()) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter);
        } else {
            info.hooks.emplace(addr, the_backup);
        }
        if (info.hooks.empty() && !info.self) {
            LOGD("Restore %p from %p", reinterpret_cast<void *>(info.start),
                 reinterpret_cast<void *>(info.backup));
            // Note that we have to always use sys_mremap here,
            // see
            // https://cs.android.com/android/_/android/platform/bionic/+/4200e260d266fd0c176e71fbd720d0bab04b02db
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    bool DoHook(std::vector<RegisterInfo> &register_info) {
        bool res = true;
        // Preserve unprocessed registrations if a later hook throws.
        while (!register_info.empty()) {
            const auto &reg = register_info.front();
            bool found = false;
            bool committed = true;
            for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
                auto &info = info_iter->second;
                if (info.offset != reg.offset_range.first || !info.Match(reg)) {
                    continue;
                }
                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGD("Hooking %s", reg.symbol.data());
                    const auto addresses = info.elf->FindPltAddr(reg.symbol);
                    for (auto addr : addresses) {
                        found = true;
                        committed =
                            DoHookInPlace(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                          reinterpret_cast<uintptr_t *>(reg.backup)) &&
                            committed;
                    }
                }
            }
            res = found && committed && res;
            register_info.erase(register_info.begin());
        }
        return res;
    }

    bool InvalidateBackup() {
        bool res = true;
        for (auto &[_, info] : *this) {
            if (!info.backup) {
                bool protected_all = true;
                if (!(info.perms & PROT_WRITE)) {
                    for (const auto &[addr, original] : info.hooks) {
                        if (sys_mprotect(PageStart(addr), kPageSize, info.perms) != 0) {
                            LOGE("Restoring PLT page protection during invalidation: %d", errno);
                            protected_all = false;
                        }
                    }
                }
                if (protected_all) info.hooks.clear();
                res = protected_all && res;
                continue;
            }
            for (auto &[addr, backup] : info.hooks) {
                // store new address to backup since we don't need backup
                backup = *reinterpret_cast<uintptr_t *>(addr);
            }
            auto len = info.end - info.start;
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                res = false;
                info.hooks.clear();
                continue;
            }
            if (!mprotect(PageStart(info.start), len, PROT_WRITE)) {
                for (auto &[addr, backup] : info.hooks) {
                    *reinterpret_cast<uintptr_t *>(addr) = backup;
                }
                mprotect(PageStart(info.start), len, info.perms);
            }
            info.hooks.clear();
            info.backup = 0;
        }
        return res;
    }
};

std::mutex hook_mutex;
// Staging buffer for pending hooks, drained by every CommitHook. It holds one or
// two entries in practice, so contiguity is not the point -- capacity survival is:
// erasing does not release the buffer, so after the first commit in a process every
// later register/commit cycle allocates nothing. The std::list it replaced malloc'd
// a node per registration and freed it per commit, forever, on a path that runs in
// each forked app process.
std::vector<RegisterInfo> register_info;
HookInfos hook_info;

HookInfos FreshHookInfo() {
    map_cache = lsplt::MapInfo::Scan();
    map_cache_ready = true;
    return HookInfos::FromMaps(map_cache);
}

HookInfos CachedHookInfo() {
    if (!map_cache_ready) return {};
    return HookInfos::FromMaps(map_cache);
}
}  // namespace

namespace lsplt {
inline namespace v2 {
[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    auto path = "/proc/" + std::string{pid} + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(MapInfo{
                start, end, 0, perm[3] == 'p', off,
                static_cast<dev_t>(makedev(dev_major, dev_minor)), inode, line + path_off});
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

[[maybe_unused]] std::vector<MapInfo> MapInfo::ScanCached() {
    const std::unique_lock lock(hook_mutex);
    return map_cache_ready ? map_cache : std::vector<MapInfo>{};
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = register_info.emplace_back(RegisterInfo{
        dev, inode,
        std::pair{std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()},
        std::string{symbol}, callback, backup});

    LOGV("RegisterHook %lu %s", info.inode, info.symbol.data());
    return true;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = register_info.emplace_back(RegisterInfo{
        dev, inode, std::pair{offset, offset + size}, std::string{symbol}, callback, backup});

    LOGV("RegisterHook %lu %" PRIxPTR "-%" PRIxPTR " %s", info.inode, info.offset_range.first,
         info.offset_range.second, info.symbol.data());
    return true;
}

[[maybe_unused]] bool CommitHook() {
    const std::unique_lock lock(hook_mutex);
    if (register_info.empty()) return true;

    auto new_hook_info = FreshHookInfo();
    if (new_hook_info.empty()) return false;

    new_hook_info.Filter(register_info);

    new_hook_info.Merge(hook_info);
    // update to new map info
    hook_info = std::move(new_hook_info);

    return hook_info.DoHook(register_info);
}

[[maybe_unused]] bool CommitHookCached() {
    const std::unique_lock lock(hook_mutex);
    if (register_info.empty()) return true;
    auto new_hook_info = CachedHookInfo();
    if (new_hook_info.empty()) return false;
    new_hook_info.Filter(register_info);
    new_hook_info.Merge(hook_info);
    hook_info = std::move(new_hook_info);
    return hook_info.DoHook(register_info);
}

[[maybe_unused]] bool ReleaseInactiveCache() {
    const std::unique_lock lock(hook_mutex);
    if (!register_info.empty()) return false;
    for (const auto &[address, info] : hook_info) {
        if (info.backup || !info.hooks.empty()) return false;
    }
    hook_info.clear();
    std::vector<RegisterInfo>().swap(register_info);
    std::vector<MapInfo>().swap(map_cache);
    map_cache_ready = false;
    return true;
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(hook_mutex);
    return hook_info.InvalidateBackup();
}
}  // namespace v2
}  // namespace lsplt
