#include "fixture.hpp"

static void normal_cases() {
    for (const auto second : {adjacent, distant}) {
        for (bool writable : {false, true}) {
            clean(); Region r(writable); setup_slots(r, second, false, true);
            void *backup = nullptr;
            register_target(r, &backup);
            auto report = lsplt::CommitHookDetailed();
            CHECK(report.success && report.registrations.size() == 1);
            const auto &entry = report.registrations[0];
            CHECK(entry.status == CommitStatus::Applied && entry.ever_published && entry.slots.size() == 2);
            CHECK(backup == reinterpret_cast<void *>(original_fn)); r.identity();
            register_target(r, &backup);
            report = lsplt::CommitHookCachedDetailed();
            CHECK(report.success && report.registrations[0].status == CommitStatus::NoChange);
            CHECK(backup == reinterpret_cast<void *>(original_fn));
            register_target(r, nullptr, backup); CHECK(lsplt::CommitHookCached());
            expect_values(r, second, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(original_fn));
            r.identity(); clean();
        }
    }
    Region r; setup_slots(r, adjacent, true); void *backup = nullptr;
    register_target(r, &backup); auto report = lsplt::CommitHookDetailed();
    CHECK(!report.success && report.error_number == EINVAL && backup == nullptr);
    CHECK(report.registrations[0].error == HookError::InconsistentOriginal && !report.registrations[0].ever_published);
    expect_values(r, adjacent, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(other_fn));
    CHECK(protect_calls == 0); clean();
    std::puts("PASS normal/duplicate/multi-page/RW/heterogeneous originals");
}
static void rollback_cases() {
    for (const auto second : {adjacent, distant}) {
        clean(); Region r; setup_slots(r, second); void *backup = nullptr;
        const auto fail_restore = second == adjacent ? 2u : 8u;
        register_target(r, &backup); faults(fail_restore);
        auto report = lsplt::CommitHookDetailed();
        CHECK(!report.success && !report.rollback_pending && report.error_number == EACCES);
        CHECK(report.registrations[0].status == CommitStatus::RolledBack && report.registrations[0].ever_published);
        CHECK(report.registrations[0].rollback_error == HookError::None);
        expect_values(r, second, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(original_fn));
        CHECK(backup == reinterpret_cast<void *>(original_fn)); r.identity(); clean();

        register_target(r, &backup); CHECK(lsplt::CommitHook());
        register_target(r, nullptr, backup); faults(fail_restore);
        report = lsplt::CommitHookCachedDetailed();
        CHECK(!report.success && !report.rollback_pending);
        expect_values(r, second, reinterpret_cast<uintptr_t>(replacement_fn), reinterpret_cast<uintptr_t>(replacement_fn));
        CHECK(!lsplt::ReleaseInactiveCache()); r.identity();
        faults(); register_target(r, nullptr, backup); CHECK(lsplt::CommitHookCached()); clean();
    }
    Region r; setup_slots(r, distant); void *backup = nullptr;
    register_target(r, &backup); faults(2);
    auto report = lsplt::CommitHookDetailed();
    CHECK(!report.success && !report.registrations[0].ever_published && backup == nullptr);
    CHECK(!report.rollback_pending); r.identity(); clean();

    register_target(r, &backup); faults(); conflict_cas = 2; conflict_value = reinterpret_cast<uintptr_t>(other_fn);
    report = lsplt::CommitHookDetailed();
    CHECK(!report.success && !report.rollback_pending);
    CHECK(report.registrations[0].error == HookError::SlotConflict && report.registrations[0].ever_published);
    expect_values(r, distant, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(other_fn));
    r.identity(); clean();
    std::puts("PASS failed install/unhook, write-enable failure, foreign slot preservation");
}
static void pending_cases() {
    for (bool cached : {false, true}) {
        clean(); Region first, blocked; setup_slots(first, distant);
        void *backup = nullptr, *untouched = nullptr;
        register_target(first, &backup); register_target(blocked, &untouched);
        faults(8 | 16);
        auto report = lsplt::CommitHookDetailed();
        CHECK(!report.success && report.rollback_pending && report.error_number == EUCLEAN);
        CHECK(report.registrations.size() == 2);
        CHECK(report.registrations[0].status == CommitStatus::RollbackIncomplete);
        CHECK(report.registrations[0].error_number == EACCES && report.registrations[0].rollback_error_number == EACCES);
        CHECK(report.registrations[1].status == CommitStatus::Blocked && untouched == nullptr);
        CHECK(register_info.empty() && !lsplt::ReleaseInactiveCache());
        faults(1); CHECK(!lsplt::InvalidateBackup()); CHECK(pending_rollback);
        faults(); report = cached ? lsplt::CommitHookCachedDetailed() : lsplt::CommitHookDetailed();
        CHECK(report.success && !report.rollback_pending && report.registrations.size() == 1);
        CHECK(report.registrations[0].recovery && report.registrations[0].ever_published);
        expect_values(first, distant, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(original_fn));
        CHECK(blocked.read(target_off) == reinterpret_cast<uintptr_t>(original_fn));
        first.identity(); clean();
    }
    Region r; setup_slots(r, adjacent); void *backup = nullptr;
    register_target(r, &backup); faults(2 | 4);
    auto report = lsplt::CommitHookDetailed();
    CHECK(report.rollback_pending && !lsplt::ReleaseInactiveCache());
    CHECK(!report.registrations[0].slots[0].permissions_restored);
    expect_values(r, adjacent, reinterpret_cast<uintptr_t>(original_fn), reinterpret_cast<uintptr_t>(original_fn));
    backup = reinterpret_cast<void *>(other_fn);
    const auto saved_maps = map_cache;
    map_cache.clear(); faults();
    report = lsplt::CommitHookCachedDetailed();
    CHECK(!report.success && report.rollback_pending);
    CHECK(report.registrations[0].rollback_error == HookError::MapUnavailable);
    CHECK(!report.registrations[0].slots[0].observed);
    map_cache = saved_maps;
    faults(); CHECK(lsplt::CommitHookCached());
    CHECK(backup == reinterpret_cast<void *>(other_fn)); r.identity(); clean();
    std::puts("PASS pending pointer/permission recovery, consumed blocked requests, backup lifetime");
}
static uintptr_t conflict_address;
static void interfere_with_rollback(const void *, int prot) {
    if (!(prot & PROT_WRITE) && protect_calls == 2)
        __atomic_store_n(reinterpret_cast<uintptr_t *>(conflict_address),
                         reinterpret_cast<uintptr_t>(other_fn), __ATOMIC_RELEASE);
}
static void rollback_conflict() {
    clean(); Region r; setup_slots(r, adjacent); void *backup = nullptr;
    register_target(r, &backup); faults(2);
    conflict_address = r.target(); protect_observer = interfere_with_rollback;
    auto report = lsplt::CommitHookDetailed();
    CHECK(report.rollback_pending && report.registrations[0].rollback_error == HookError::SlotConflict);
    CHECK(r.read(target_off) == reinterpret_cast<uintptr_t>(other_fn));
    faults(); report = lsplt::CommitHookCachedDetailed();
    CHECK(report.rollback_pending && r.read(target_off) == reinterpret_cast<uintptr_t>(other_fn));
    CHECK(!lsplt::ReleaseInactiveCache());
    CHECK(mprotect(PageStart(r.target()), kPageSize, PROT_READ | PROT_WRITE) == 0);
    __atomic_store_n(reinterpret_cast<uintptr_t *>(r.target()), reinterpret_cast<uintptr_t>(original_fn), __ATOMIC_RELEASE);
    CHECK(mprotect(PageStart(r.target()), kPageSize, PROT_READ) == 0);
    CHECK(lsplt::CommitHookCached()); clean(); r.identity();
    puts("PASS rollback conflict retains foreign value and recovery journal");
}
static void batch_cases() {
    clean(); Region a, b; void *backup = nullptr;
    register_target(a, &backup);
    register_target(b, nullptr, reinterpret_cast<void *>(replacement_fn), "missing");
    register_target(b, nullptr);
    auto report = lsplt::CommitHookDetailed();
    CHECK(!report.success && report.error_number == ENOENT && report.registrations.size() == 3);
    CHECK(report.registrations[0].status == CommitStatus::Applied);
    CHECK(report.registrations[1].error == HookError::SymbolNotFound);
    CHECK(report.registrations[2].status == CommitStatus::Applied);
    register_target(a, nullptr, backup); register_target(b, nullptr, backup);
    CHECK(lsplt::CommitHookCached()); clean();
    void *mapped = mmap(reinterpret_cast<void *>(b.base), length, PROT_READ, MAP_SHARED | MAP_FIXED, b.fd, 0);
    CHECK(mapped == reinterpret_cast<void *>(b.base));
    register_target(b, nullptr); CHECK(!lsplt::CommitHook() && errno == ENOENT); clean();
    CHECK(!lsplt::RegisterHook(0, 0, "", nullptr, nullptr) && errno == EINVAL);
    std::puts("PASS independent registrations, legacy errno, shared mapping rejection");
}
static void recovery_permission_change() {
    for (int api = 0; api < 3; ++api) {
        for (bool deny_write : {false, true}) {
            clean(); Region r; setup_slots(r, adjacent); void *backup = nullptr;
            register_target(r, &backup); faults(2 | 4);
            conflict_cas = 3; conflict_value = reinterpret_cast<uintptr_t>(other_fn);
            auto report = lsplt::CommitHookDetailed();
            CHECK(report.rollback_pending && pending_rollback->pages[0].writable);
            CHECK(r.read(adjacent) == reinterpret_cast<uintptr_t>(other_fn));
            __atomic_store_n(reinterpret_cast<uintptr_t *>(r.base + adjacent),
                             reinterpret_cast<uintptr_t>(replacement_fn), __ATOMIC_RELEASE);
            CHECK(mprotect(PageStart(r.target()), kPageSize, PROT_READ) == 0);
            auto retry = [&] {
                if (api == 2) return lsplt::InvalidateBackup();
                report = api == 0 ? lsplt::CommitHookDetailed() : lsplt::CommitHookCachedDetailed();
                return report.success;
            };
            faults(deny_write ? 1 : 0);
            if (deny_write) {
                CHECK(!retry() && pending_rollback);
                CHECK(pending_rollback->rollback_error == HookError::ProtectFailed);
                CHECK(r.read(adjacent) == reinterpret_cast<uintptr_t>(replacement_fn));
                CHECK(!lsplt::ReleaseInactiveCache());
                faults();
            }
            CHECK(retry() && !pending_rollback);
            expect_values(r, adjacent, reinterpret_cast<uintptr_t>(original_fn),
                          reinterpret_cast<uintptr_t>(original_fn));
            r.identity(); clean();
        }
    }
    puts("PASS recovery reestablishes externally restored RELRO, including denied write retries");
}
static std::atomic<bool> callback_entered, callback_exit;
static void *live_original;
static uintptr_t forwarding_callback() {
    CHECK(live_original == reinterpret_cast<void *>(original_fn));
    callback_entered = true;
    while (!callback_exit.load()) std::this_thread::yield();
    return reinterpret_cast<uintptr_t (*)()>(live_original)();
}
static void await_callback(const void *, int prot) {
    if (!(prot & PROT_WRITE))
        while (!callback_entered.load()) std::this_thread::yield();
}
static void concurrent_cases() {
    clean(); Region r; setup_slots(r, adjacent);
    std::atomic<bool> stop{false}; std::atomic<unsigned long> bad{0}, samples{0};
    std::thread reader([&] {
        while (!stop.load()) {
            for (auto offset : {uintptr_t(0x1000), uintptr_t(0x35358), uintptr_t(length - sizeof(uintptr_t))})
                if (r.read(offset) != sentinel) ++bad;
            ++samples;
        }
    });
    map_calls = remap_calls = 0;
    for (int i = 0; i < 1000; ++i) {
        void *backup = nullptr; register_target(r, &backup); CHECK(lsplt::CommitHook());
        register_target(r, &backup); CHECK(lsplt::CommitHookCached());
        CHECK(backup == reinterpret_cast<void *>(original_fn));
        register_target(r, nullptr, backup); CHECK(lsplt::CommitHookCached());
    }
    stop = true; reader.join();
    CHECK(samples > 0 && bad == 0 && map_calls == 0 && remap_calls == 0); r.identity(); clean();
    std::printf("PASS concurrent readers cycles=1000 samples=%lu invalid=0 mmap=0 mremap=0\n", samples.load());
    live_original = nullptr; callback_entered = callback_exit = false;
    std::thread caller([&] {
        while (r.read(target_off) != reinterpret_cast<uintptr_t>(forwarding_callback)) std::this_thread::yield();
        CHECK(reinterpret_cast<uintptr_t (*)()>(r.read(target_off))() == 7);
    });
    register_target(r, &live_original, reinterpret_cast<void *>(forwarding_callback));
    faults(2); protect_observer = await_callback;
    const auto report = lsplt::CommitHookDetailed();
    CHECK(!report.success && report.registrations[0].ever_published && !report.rollback_pending);
    CHECK(callback_entered && live_original == reinterpret_cast<void *>(original_fn));
    callback_exit = true; caller.join(); faults(); clean();
    std::puts("PASS callback entered before rollback; original remains callable");
}
int main() {
    normal_cases(); rollback_cases(); pending_cases(); rollback_conflict(); batch_cases();
    recovery_permission_change(); concurrent_cases();
    std::printf("PASS transaction suite pointer_bits=%zu page_size=%lu\n", sizeof(uintptr_t) * 8,
                static_cast<unsigned long>(kPageSize));
}
