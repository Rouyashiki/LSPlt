#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <map>
#include <memory>
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
    lsplt::HookOperation operation = lsplt::HookOperation::Replace;
    void *expected_current = nullptr;
};

struct HookLayer {
    uintptr_t callback;
    uintptr_t previous;
};

struct HookChain {
    uintptr_t root = 0;
    bool disconnected = false;
    std::vector<HookLayer> layers;

    uintptr_t Current() const { return layers.empty() ? root : layers.back().callback; }
};

std::vector<lsplt::MapInfo> map_cache;
bool map_cache_ready = false;

struct HookInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    bool self;
    std::map<uintptr_t, HookChain> chains{};
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
                if (protected_all) {
                    info.hooks.clear();
                    info.chains.clear();
                }
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
                info.chains.clear();
                continue;
            }
            if (!mprotect(PageStart(info.start), len, PROT_WRITE)) {
                for (auto &[addr, backup] : info.hooks) {
                    *reinterpret_cast<uintptr_t *>(addr) = backup;
                }
                mprotect(PageStart(info.start), len, info.perms);
            }
            info.hooks.clear();
            info.chains.clear();
            info.backup = 0;
        }
        return res;
    }
};

std::mutex hook_mutex;
// Pending requests are consumed by the next commit, including blocked requests.
std::vector<RegisterInfo> register_info;
HookInfos hook_info;

using lsplt::CommitReport;
using lsplt::CommitStatus;
using lsplt::HookError;
using lsplt::RegistrationResult;

struct Transaction {
    struct Page {
        uintptr_t address;
        int perms;
        bool writable;
    };
    struct Slot {
        uintptr_t address;
        uintptr_t before;
        HookInfo *owner;
        size_t page;
        bool published = false;
        bool erase_record = false;
    };

    RegisterInfo request;
    std::vector<Slot> slots;
    std::vector<Page> pages;
    std::map<uintptr_t, uintptr_t> new_records;
    std::map<uintptr_t, HookChain> new_chains;
    uintptr_t original = 0;
    CommitStatus status = CommitStatus::Rejected;
    HookError error = HookError::None;
    HookError rollback_error = HookError::None;
    int error_number = 0;
    int rollback_error_number = 0;
    bool ever_published = false;
    bool observed = true;

    explicit Transaction(const RegisterInfo &reg)
        : request{reg.dev, reg.inode, reg.offset_range, reg.symbol, reg.callback, nullptr,
                  reg.operation, reg.expected_current} {}

    void Fail(HookError cause, int number) {
        if (error == HookError::None) { error = cause; error_number = number; }
    }

    void RollbackFailure(HookError cause, int number) {
        if (rollback_error == HookError::None) {
            rollback_error = cause;
            rollback_error_number = number;
        }
    }

    static bool MappedRange(uintptr_t address, size_t size, const HookInfo &owner) {
        return std::any_of(map_cache.begin(), map_cache.end(), [&](const auto &map) {
            return map.is_private && (map.perms & PROT_READ) && !map.path.empty() &&
                   map.path[0] != '[' && map.dev == owner.dev && map.inode == owner.inode &&
                   address >= map.start && address < map.end && map.end - address >= size &&
                   map.offset + address - map.start == owner.offset + address - owner.start;
        });
    }

    bool ValidRequest(bool needs_backup) {
        const bool restore = request.operation == lsplt::HookOperation::Restore;
        if (request.dev == 0 || request.inode == 0 || request.symbol.empty() ||
            !request.callback || request.offset_range.first >= request.offset_range.second ||
            (restore && (!request.expected_current || needs_backup)) ||
            (!restore && (request.operation != lsplt::HookOperation::Replace || request.expected_current))) {
            Fail(HookError::InvalidRequest, EINVAL);
            return false;
        }
        return true;
    }

    void PrepareRecord(Slot &slot, bool needs_backup) {
        const auto callback = reinterpret_cast<uintptr_t>(request.callback);
        const auto record = slot.owner->hooks.find(slot.address);
        const bool tracked = record != slot.owner->hooks.end();
        const auto previous_chain = slot.owner->chains.find(slot.address);
        HookChain chain;
        if (request.operation == lsplt::HookOperation::Restore) {
            if (previous_chain != slot.owner->chains.end() && !previous_chain->second.layers.empty() &&
                previous_chain->second.layers.back().callback == reinterpret_cast<uintptr_t>(request.expected_current) &&
                previous_chain->second.layers.back().previous == callback) {
                chain = previous_chain->second;
                chain.layers.pop_back();
            } else {
                if (slot.before == callback || !tracked) return;
                chain.root = callback;
                chain.disconnected = true;
            }
        } else {
            if (slot.before == callback) {
                if (!needs_backup && tracked && record->second == callback &&
                    previous_chain != slot.owner->chains.end() && !previous_chain->second.disconnected)
                    slot.erase_record = true;
                return;
            }
            if (previous_chain != slot.owner->chains.end() && previous_chain->second.Current() == slot.before) {
                chain = previous_chain->second;
            } else {
                chain.root = slot.before;
                chain.disconnected = tracked;
            }
            bool restored = tracked && record->second == callback && !chain.disconnected;
            if (restored) chain.layers.clear();
            if (!restored && !needs_backup) {
                for (size_t i = chain.layers.size(); i > 0; --i) {
                    if (chain.layers[i - 1].previous == callback) {
                        chain.layers.resize(i - 1);
                        restored = true;
                        break;
                    }
                }
            }
            if (!restored) chain.layers.push_back({callback, slot.before});
        }
        const auto baseline = tracked ? record->second : slot.before;
        if (!chain.disconnected && chain.layers.empty() && callback == baseline) {
            slot.erase_record = true;
            return;
        }
        if (!tracked) new_records.emplace(slot.address, baseline);
        new_chains.emplace(slot.address, std::move(chain));
    }

    void CommitRecords() {
        for (const auto &slot : slots) {
            if (slot.erase_record) {
                slot.owner->hooks.erase(slot.address);
                slot.owner->chains.erase(slot.address);
                continue;
            }
            if (auto node = new_records.extract(slot.address); !node.empty())
                slot.owner->hooks.insert(std::move(node));
            if (auto node = new_chains.extract(slot.address); !node.empty()) {
                auto existing = slot.owner->chains.find(slot.address);
                if (existing == slot.owner->chains.end()) slot.owner->chains.insert(std::move(node));
                else std::swap(existing->second, node.mapped());
            }
        }
    }

    bool Prepare(bool needs_backup) {
        static_assert(__atomic_always_lock_free(sizeof(uintptr_t), nullptr));
        std::vector<uintptr_t> addresses;
        bool found_mapping = false, valid_elf = false;
        for (auto &[_, info] : hook_info) {
            if (info.offset != request.offset_range.first || !info.Match(request)) continue;
            if (!MappedRange(info.start, sizeof(ElfW(Ehdr)), info)) continue;
            found_mapping = true;
            if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
            if (!info.elf->Valid()) continue;
            valid_elf = true;
            auto found = info.elf->FindPltAddr(request.symbol);
            addresses.insert(addresses.end(), found.begin(), found.end());
        }
        if (addresses.empty()) {
            Fail(!found_mapping ? HookError::MapUnavailable :
                 !valid_elf ? HookError::InvalidElf : HookError::SymbolNotFound,
                 !valid_elf && found_mapping ? ENOEXEC : ENOENT);
            return false;
        }
        std::sort(addresses.begin(), addresses.end());
        addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
        slots.reserve(addresses.size());
        pages.reserve(addresses.size());
        for (auto address : addresses) {
            auto iter = hook_info.lower_bound(address);
            if (iter == hook_info.end() || address % alignof(uintptr_t) != 0 ||
                address < iter->second.start || address >= iter->second.end ||
                iter->second.end - address < sizeof(uintptr_t) ||
                !iter->second.Match(request) || !iter->second.is_private ||
                !(iter->second.perms & PROT_READ) ||
                !MappedRange(address, sizeof(uintptr_t), iter->second)) {
                Fail(HookError::InvalidSlot, EINVAL);
                return false;
            }
            auto &owner = iter->second;
            auto page_address = reinterpret_cast<uintptr_t>(PageStart(address));
            if (pages.empty() || pages.back().address != page_address)
                pages.push_back({page_address, owner.perms, bool(owner.perms & PROT_WRITE)});
            auto before = __atomic_load_n(reinterpret_cast<uintptr_t *>(address), __ATOMIC_ACQUIRE);
            slots.push_back({address, before, &owner, pages.size() - 1});
        }
        const auto callback = reinterpret_cast<uintptr_t>(request.callback);
        if (request.operation == lsplt::HookOperation::Restore &&
            std::any_of(slots.begin(), slots.end(), [&](const auto &slot) {
                return slot.before != callback &&
                       slot.before != reinterpret_cast<uintptr_t>(request.expected_current);
            })) {
            Fail(HookError::SlotConflict, EBUSY);
            return false;
        }
        if (needs_backup) {
            original = slots.front().before;
            if (original == 0 || std::any_of(slots.begin(), slots.end(), [&](const auto &slot) {
                    return slot.before != original;
                })) {
                Fail(HookError::InconsistentOriginal, EINVAL);
                return false;
            }
            if (original == callback) {
                original = 0;
                for (const auto &slot : slots) {
                    auto chain = slot.owner->chains.find(slot.address);
                    if (chain == slot.owner->chains.end() || chain->second.layers.empty() ||
                        chain->second.Current() != callback || chain->second.layers.back().previous == 0 ||
                        chain->second.layers.back().previous == callback) {
                        Fail(HookError::OriginalUnavailable, ENODATA);
                        return false;
                    }
                    const auto previous = chain->second.layers.back().previous;
                    if (original != 0 && original != previous) {
                        Fail(HookError::InconsistentOriginal, EINVAL);
                        return false;
                    }
                    original = previous;
                }
            }
        }
        // Prepare all metadata before publishing any pointer or changing permissions.
        for (auto &slot : slots) PrepareRecord(slot, needs_backup);
        return true;
    }

    bool RestorePermissions() {
        bool ok = true;
        for (auto &page : pages) {
            if (!page.writable || (page.perms & PROT_WRITE)) continue;
            if (sys_mprotect(reinterpret_cast<void *>(page.address), kPageSize, page.perms) != 0) {
                ok = false;
                RollbackFailure(HookError::ProtectFailed, errno);
            } else {
                page.writable = false;
            }
        }
        return ok;
    }

    bool Rollback(bool recheck_permissions = false) {
        rollback_error = HookError::None;
        rollback_error_number = 0;
        bool ok = true;
        const auto callback = reinterpret_cast<uintptr_t>(request.callback);
        for (auto iter = slots.rbegin(); iter != slots.rend(); ++iter) {
            auto &slot = *iter;
            if (!slot.published) continue;
            auto *address = reinterpret_cast<uintptr_t *>(slot.address);
            auto current = __atomic_load_n(address, __ATOMIC_ACQUIRE);
            if (current == slot.before) { slot.published = false; continue; }
            if (current != callback) {
                RollbackFailure(HookError::SlotConflict, EBUSY);
                ok = false;
                continue;
            }
            auto &page = pages[slot.page];
            // A later retry cannot trust permissions retained in the journal.
            if (recheck_permissions || !page.writable) {
                if (sys_mprotect(reinterpret_cast<void *>(page.address), kPageSize,
                                 page.perms | PROT_WRITE) != 0) {
                    RollbackFailure(HookError::ProtectFailed, errno);
                    ok = false;
                    continue;
                }
                page.writable = true;
            }
            auto expected = callback;
            if (__atomic_compare_exchange_n(address, &expected, slot.before, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ||
                expected == slot.before) {
                slot.published = false;
            } else {
                RollbackFailure(HookError::SlotConflict, EBUSY);
                ok = false;
            }
        }
        ok = RestorePermissions() && ok;
        status = ok ? CommitStatus::RolledBack : CommitStatus::RollbackIncomplete;
        return ok;
    }

    void Execute(void **backup) {
        const auto callback = reinterpret_cast<uintptr_t>(request.callback);
        if (std::all_of(slots.begin(), slots.end(), [&](const auto &slot) {
                return slot.before == callback;
            })) {
            for (const auto &slot : slots) {
                if (__atomic_load_n(reinterpret_cast<uintptr_t *>(slot.address), __ATOMIC_ACQUIRE) != callback) {
                    Fail(HookError::SlotConflict, EBUSY);
                    return;
                }
            }
            if (backup) *backup = reinterpret_cast<void *>(original);
            CommitRecords();
            status = CommitStatus::NoChange;
            return;
        }
        for (auto &page : pages) {
            if (page.writable) continue;
            if (sys_mprotect(reinterpret_cast<void *>(page.address), kPageSize,
                             page.perms | PROT_WRITE) != 0) {
                Fail(HookError::ProtectFailed, errno);
                Rollback();
                return;
            }
            page.writable = true;
        }
        if (backup) *backup = reinterpret_cast<void *>(original);
        for (auto &slot : slots) {
            if (slot.before == callback) continue;
            auto expected = slot.before;
            if (!__atomic_compare_exchange_n(reinterpret_cast<uintptr_t *>(slot.address),
                                             &expected, callback, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                Fail(HookError::SlotConflict, EBUSY);
                Rollback();
                return;
            }
            slot.published = true;
            ever_published = true;
        }
        if (!RestorePermissions()) {
            Fail(rollback_error, rollback_error_number);
            Rollback();
            return;
        }
        for (const auto &slot : slots) {
            if (__atomic_load_n(reinterpret_cast<uintptr_t *>(slot.address), __ATOMIC_ACQUIRE) != callback) {
                Fail(HookError::SlotConflict, EBUSY);
                Rollback();
                return;
            }
        }
        CommitRecords();
        status = CommitStatus::Applied;
    }

    bool ValidateRecovery(const std::vector<lsplt::MapInfo> &maps) {
        observed = std::all_of(slots.begin(), slots.end(), [&](const auto &slot) {
            return std::any_of(maps.begin(), maps.end(), [&](const auto &map) {
                const auto page = pages[slot.page].address;
                return map.is_private && (map.perms & PROT_READ) &&
                       map.dev == slot.owner->dev && map.inode == slot.owner->inode &&
                       page >= map.start && page < map.end && map.end - page >= kPageSize &&
                       map.offset + page - map.start == slot.owner->offset + page - slot.owner->start;
            });
        });
        if (!observed) {
            rollback_error = HookError::MapUnavailable;
            rollback_error_number = ESTALE;
            status = CommitStatus::RollbackIncomplete;
        }
        return observed;
    }

    void PrepareReport(RegistrationResult &result, bool recovery = false) const {
        result.dev = request.dev;
        result.inode = request.inode;
        result.offset_range = request.offset_range;
        result.symbol = request.symbol;
        result.callback = request.callback;
        result.recovery = recovery;
        result.slots.resize(slots.size());
    }

    void FinishReport(RegistrationResult &result) const {
        result.status = status;
        result.error = error;
        result.error_number = error_number;
        result.rollback_error = rollback_error;
        result.rollback_error_number = rollback_error_number;
        result.ever_published = ever_published;
        for (size_t i = 0; i < slots.size(); ++i) {
            const auto &slot = slots[i];
            const auto &page = pages[slot.page];
            result.slots[i] = {slot.address, slot.before,
                observed ? __atomic_load_n(reinterpret_cast<uintptr_t *>(slot.address), __ATOMIC_ACQUIRE) : 0,
                observed, !page.writable || bool(page.perms & PROT_WRITE)};
        }
    }
};

std::unique_ptr<Transaction> pending_rollback;

HookInfos FreshHookInfo() {
    map_cache = lsplt::MapInfo::Scan();
    map_cache_ready = true;
    return HookInfos::FromMaps(map_cache);
}

HookInfos CachedHookInfo() {
    if (!map_cache_ready) return {};
    return HookInfos::FromMaps(map_cache);
}

bool ExecuteRequests(bool cached, const std::vector<RegisterInfo> &requests,
                     std::vector<RegistrationResult> *results,
                     std::vector<RegistrationResult> *recoveries, int &failure) {
    bool success = true;
    bool maps_available = true;
    failure = 0;
    if (results) results->reserve(requests.size() + (results == recoveries && pending_rollback ? 1 : 0));
    if (recoveries && recoveries != results) recoveries->reserve(pending_rollback ? 1 : 0);
    if (pending_rollback) {
        RegistrationResult *result = recoveries ? &recoveries->emplace_back() : nullptr;
        if (result) pending_rollback->PrepareReport(*result, true);
        const auto maps = cached ? map_cache : lsplt::MapInfo::Scan();
        const bool recovered = pending_rollback->ValidateRecovery(maps) && pending_rollback->Rollback(true);
        if (result) pending_rollback->FinishReport(*result);
        if (recovered) pending_rollback.reset();
        else { success = false; failure = EUCLEAN; }
    }
    if (!pending_rollback && !requests.empty()) {
        auto fresh = cached ? CachedHookInfo() : FreshHookInfo();
        if (!fresh.empty()) {
            fresh.Filter(requests);
            fresh.Merge(hook_info);
            hook_info = std::move(fresh);
        } else {
            maps_available = false;
        }
    }
    for (const auto &reg : requests) {
        auto transaction = std::make_unique<Transaction>(reg);
        RegistrationResult *result = results ? &results->emplace_back() : nullptr;
        if (pending_rollback) {
            transaction->status = CommitStatus::Blocked;
            transaction->Fail(HookError::PendingRollback, EUCLEAN);
        } else if (transaction->ValidRequest(reg.backup != nullptr)) {
            if (!maps_available) {
                transaction->Fail(HookError::MapUnavailable, ENOENT);
            } else if (transaction->Prepare(reg.backup != nullptr)) {
                if (result) transaction->PrepareReport(*result);
                transaction->Execute(reg.backup);
            }
        }
        if (result) {
            if (result->symbol.empty()) transaction->PrepareReport(*result);
            transaction->FinishReport(*result);
        }
        if (transaction->status != CommitStatus::Applied && transaction->status != CommitStatus::NoChange) {
            success = false;
            if (failure == 0) failure = transaction->error_number;
        }
        if (transaction->status == CommitStatus::RollbackIncomplete) {
            pending_rollback = std::move(transaction);
            failure = EUCLEAN;
        }
    }
    errno = failure;
    return success;
}

bool Commit(bool cached, CommitReport *report) {
    int failure = 0;
    auto *results = report ? &report->registrations : nullptr;
    const bool success = ExecuteRequests(cached, register_info, results, results, failure);
    register_info.clear();
    if (report) {
        report->success = success;
        report->rollback_pending = bool(pending_rollback);
        report->error_number = failure;
    }
    return success;
}

lsplt::HookBatchReport ApplyRequests(bool cached, const std::vector<lsplt::HookRequest> &requests) {
    std::vector<RegisterInfo> registrations;
    registrations.reserve(requests.size());
    for (const auto &request : requests) {
        registrations.push_back({request.dev, request.inode, request.offset_range,
            std::string{request.symbol}, request.callback, request.backup,
            request.operation, request.expected_current});
    }
    lsplt::HookBatchReport report;
    report.success = ExecuteRequests(cached, registrations, &report.results,
                                    &report.recoveries, report.error_number);
    report.rollback_pending = bool(pending_rollback);
    return report;
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
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) { errno = EINVAL; return false; }

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
    if (dev == 0 || inode == 0 || symbol.empty() || !callback || size == 0 ||
        size > std::numeric_limits<uintptr_t>::max() - offset) { errno = EINVAL; return false; }

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
    return Commit(false, nullptr);
}

[[maybe_unused]] bool CommitHookCached() {
    const std::unique_lock lock(hook_mutex);
    return Commit(true, nullptr);
}

[[maybe_unused]] CommitReport CommitHookDetailed() {
    const std::unique_lock lock(hook_mutex);
    CommitReport report;
    Commit(false, &report);
    return report;
}

[[maybe_unused]] CommitReport CommitHookCachedDetailed() {
    const std::unique_lock lock(hook_mutex);
    CommitReport report;
    Commit(true, &report);
    return report;
}

[[maybe_unused]] HookBatchReport ApplyHooksDetailed(const std::vector<HookRequest> &requests) {
    const std::unique_lock lock(hook_mutex);
    return ApplyRequests(false, requests);
}

[[maybe_unused]] HookBatchReport ApplyHooksCachedDetailed(const std::vector<HookRequest> &requests) {
    const std::unique_lock lock(hook_mutex);
    return ApplyRequests(true, requests);
}

[[maybe_unused]] bool ReleaseInactiveCache() {
    const std::unique_lock lock(hook_mutex);
    if (!register_info.empty() || pending_rollback) return false;
    for (const auto &[address, info] : hook_info) {
        if (info.backup || !info.hooks.empty() || !info.chains.empty()) return false;
    }
    hook_info.clear();
    std::vector<RegisterInfo>().swap(register_info);
    std::vector<MapInfo>().swap(map_cache);
    map_cache_ready = false;
    return true;
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(hook_mutex);
    if (pending_rollback) {
        if (!pending_rollback->ValidateRecovery(MapInfo::Scan()) || !pending_rollback->Rollback(true)) {
            errno = EUCLEAN;
            return false;
        }
        pending_rollback.reset();
    }
    return hook_info.InvalidateBackup();
}
}  // namespace v2
}  // namespace lsplt
