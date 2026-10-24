#include "fixture.hpp"

static const auto original = reinterpret_cast<void *>(original_fn);
static const auto replacement = reinterpret_cast<void *>(replacement_fn);
static const auto other = reinterpret_cast<void *>(other_fn);

static lsplt::HookRequest request(Region &r, void *callback = replacement, void **backup = nullptr) {
    return {r.initial.dev, r.initial.inode, "target", callback, backup};
}
static lsplt::HookRequest restore(Region &r, void *callback, void *expected) {
    auto result = request(r, callback);
    result.operation = lsplt::HookOperation::Restore;
    result.expected_current = expected;
    return result;
}
static lsplt::HookBatchReport apply(bool cached, const std::vector<lsplt::HookRequest> &requests) {
    return cached ? lsplt::ApplyHooksCachedDetailed(requests) : lsplt::ApplyHooksDetailed(requests);
}
static void store(Region &r, size_t offset, void *value) {
    CHECK(mprotect(PageStart(r.base + offset), kPageSize, PROT_READ | PROT_WRITE) == 0);
    __atomic_store_n(reinterpret_cast<uintptr_t *>(r.base + offset), reinterpret_cast<uintptr_t>(value), __ATOMIC_RELEASE);
    CHECK(mprotect(PageStart(r.base + offset), kPageSize, PROT_READ) == 0);
}

static void repeated_backup() {
    for (bool cached : {false, true}) {
        for (size_t second : {adjacent, distant}) {
            clean(); Region r; setup_slots(r, second);
            void *backup;
            CHECK(apply(false, {request(r, replacement, &backup)}).success && backup == original);
            faults();
            void *fresh;
            auto report = apply(cached, {request(r, replacement, &fresh)});
            CHECK(report.success && report.results.size() == 1 && report.recoveries.empty());
            CHECK(report.results[0].status == lsplt::CommitStatus::NoChange && !report.results[0].ever_published);
            CHECK(fresh == original && cas_calls == 0 && protect_calls == 0);
            fresh = other;
            register_target(r, &fresh);
            CHECK(lsplt::CommitHookDetailed().success && fresh == original);
            CHECK(apply(cached, {restore(r, original, replacement)}).success);
            r.identity(); clean();
        }
    }
    puts("PASS fresh output-only backup on repeated hooks, legacy and isolated APIs");
}

static void unavailable_backup() {
    clean(); Region r; setup_slots(r, distant, true);
    CHECK(apply(false, {request(r)}).success);
    void *backup = other;
    faults();
    auto report = apply(true, {request(r, replacement, &backup)});
    CHECK(!report.success && report.results[0].error == lsplt::HookError::InconsistentOriginal);
    CHECK(backup == other && cas_calls == 0 && protect_calls == 0);
    CHECK(lsplt::InvalidateBackup());
    report = apply(true, {request(r, replacement, &backup)});
    CHECK(!report.success && report.results[0].error == lsplt::HookError::OriginalUnavailable);
    CHECK(report.error_number == ENODATA && backup == other);
    CHECK(apply(false, {restore(r, original, replacement)}).success);
    r.identity(); clean();
    store(r, target_off, replacement); store(r, distant, replacement);
    report = apply(false, {request(r, replacement, &backup)});
    CHECK(!report.success && report.results[0].error == lsplt::HookError::OriginalUnavailable);
    CHECK(backup == other);
    clean();
    puts("PASS heterogeneous or missing predecessor rejects without output or slot changes");
}

static void hook_chains() {
    for (bool cached : {false, true}) {
        clean(); Region r; setup_slots(r, distant);
        void *first = nullptr, *second = nullptr, *fresh = nullptr;
        CHECK(apply(false, {request(r, replacement, &first)}).success && first == original);
        CHECK(apply(cached, {request(r, other, &second)}).success && second == replacement);
        CHECK(apply(cached, {request(r, other, &fresh)}).success && fresh == replacement);
        faults(4);
        auto failed = apply(cached, {restore(r, replacement, other)});
        CHECK(!failed.success && failed.results[0].status == lsplt::CommitStatus::RolledBack);
        faults(); fresh = nullptr;
        CHECK(apply(cached, {request(r, other, &fresh)}).success && fresh == replacement);
        CHECK(apply(cached, {restore(r, replacement, other)}).success);
        fresh = nullptr;
        CHECK(apply(cached, {request(r, replacement, &fresh)}).success && fresh == original);
        CHECK(apply(cached, {restore(r, original, replacement)}).success);
        r.identity(); clean();
    }
    clean(); Region r;
    CHECK(apply(false, {request(r)}).success);
    store(r, target_off, other);
    void *fresh = nullptr;
    CHECK(apply(false, {request(r, replacement, &fresh)}).success && fresh == other);
    CHECK(apply(false, {restore(r, other, replacement)}).success);
    CHECK(!lsplt::ReleaseInactiveCache());
    fresh = nullptr;
    auto report = apply(false, {request(r, other, &fresh)});
    CHECK(!report.success && report.results[0].error == lsplt::HookError::OriginalUnavailable);
    CHECK(lsplt::InvalidateBackup()); clean();
    puts("PASS direct predecessors, rollback metadata and disconnected external hook chains");
}

static void legacy_restoration() {
    for (bool external : {false, true}) {
        clean(); Region r; void *backup = nullptr;
        register_target(r, &backup); CHECK(lsplt::CommitHook());
        if (external) store(r, target_off, original);
        void *previous = nullptr;
        register_target(r, external ? nullptr : &previous, backup);
        CHECK(lsplt::CommitHookCached());
        if (!external) CHECK(previous == replacement);
        CHECK(r.read(target_off) == reinterpret_cast<uintptr_t>(original));
        r.identity(); clean();
    }
    puts("PASS legacy unhook output and already-restored baseline release");
}

static void isolated_queue() {
    clean(); Region own, queued;
    void *backup = nullptr, *queued_backup = nullptr;
    register_target(queued, &queued_backup);
    register_target(queued, nullptr, replacement, "missing");
    auto report = apply(false, {request(own, replacement, &backup), request(own, replacement, &backup)});
    CHECK(report.success && report.results.size() == 2);
    CHECK(report.results[0].status == lsplt::CommitStatus::Applied);
    CHECK(report.results[1].status == lsplt::CommitStatus::NoChange);
    CHECK(backup == original && queued_backup == nullptr && register_info.size() == 2);
    CHECK(queued.read(target_off) == reinterpret_cast<uintptr_t>(original));
    CHECK(apply(true, {}).success && register_info.size() == 2);
    auto legacy = lsplt::CommitHookDetailed();
    CHECK(!legacy.success && legacy.registrations.size() == 2 && queued_backup == original);
    CHECK(apply(true, {restore(own, original, replacement), restore(queued, original, replacement)}).success);
    clean();
    std::atomic<bool> start{false};
    lsplt::HookBatchReport good, bad;
    lsplt::CommitReport old;
    register_target(queued, &queued_backup, replacement, "missing");
    auto missing = request(own); missing.symbol = "missing";
    std::thread a([&] { while (!start.load()) std::this_thread::yield(); good = apply(false, {request(own, replacement, &backup)}); });
    std::thread b([&] { while (!start.load()) std::this_thread::yield(); bad = apply(false, {missing}); });
    std::thread c([&] { while (!start.load()) std::this_thread::yield(); old = lsplt::CommitHookDetailed(); });
    start = true; a.join(); b.join(); c.join();
    CHECK(good.success && good.results.size() == 1 && good.results[0].symbol == "target");
    CHECK(!bad.success && bad.results.size() == 1 && bad.results[0].symbol == "missing");
    CHECK(!old.success && old.registrations.size() == 1 && old.registrations[0].inode == queued.initial.inode);
    CHECK(apply(false, {restore(own, original, replacement)}).success); clean();
    puts("PASS explicit result ownership, duplicate requests and concurrent legacy queue isolation");
}

static void checked_restore() {
    for (size_t second : {adjacent, distant}) {
        clean(); Region r; setup_slots(r, second);
        CHECK(apply(false, {request(r)}).success);
        store(r, second, other); faults();
        auto report = apply(true, {restore(r, original, replacement)});
        CHECK(!report.success && report.results[0].error == lsplt::HookError::SlotConflict);
        CHECK(cas_calls == 0 && protect_calls == 0 && !lsplt::ReleaseInactiveCache());
        expect_values(r, second, reinterpret_cast<uintptr_t>(replacement), reinterpret_cast<uintptr_t>(other));
        store(r, second, original);
        CHECK(apply(true, {restore(r, original, replacement)}).success); clean();
        CHECK(apply(false, {request(r)}).success); faults();
        conflict_cas = 2; conflict_value = reinterpret_cast<uintptr_t>(other);
        report = apply(true, {restore(r, original, replacement)});
        CHECK(!report.success && report.results[0].status == lsplt::CommitStatus::RolledBack);
        expect_values(r, second, reinterpret_cast<uintptr_t>(replacement), reinterpret_cast<uintptr_t>(other));
        faults(); store(r, second, replacement);
        CHECK(apply(true, {restore(r, original, replacement)}).success); clean(); r.identity();
    }
    puts("PASS foreign pointers before preparation and after snapshot, mixed idempotent restoration");
}

static void pending_and_invalid_requests() {
    clean(); Region r, queued;
    void *backup = nullptr, *queued_backup = nullptr;
    register_target(queued, &queued_backup);
    faults(2 | 4);
    auto report = apply(false, {request(r, replacement, &backup), request(queued)});
    CHECK(!report.success && report.rollback_pending && report.results.size() == 2);
    CHECK(report.results[1].status == lsplt::CommitStatus::Blocked && report.recoveries.empty());
    CHECK(backup == original && queued_backup == nullptr && register_info.size() == 1);
    CHECK(!lsplt::ReleaseInactiveCache());
    faults(); backup = other;
    report = apply(true, {});
    CHECK(report.success && !report.rollback_pending && report.results.empty() && report.recoveries.size() == 1);
    CHECK(report.recoveries[0].ever_published && report.recoveries[0].recovery && backup == other);
    CHECK(queued_backup == nullptr && register_info.size() == 1);
    CHECK(lsplt::CommitHookDetailed().success && queued_backup == original);
    CHECK(apply(true, {restore(queued, original, replacement)}).success); clean();
    auto bad = restore(r, original, replacement); bad.backup = &backup;
    report = apply(false, {bad, request(r, replacement, &backup)});
    CHECK(!report.success && report.results[0].error == lsplt::HookError::InvalidRequest);
    CHECK(report.results[1].status == lsplt::CommitStatus::Applied && backup == original);
    CHECK(apply(true, {restore(r, original, replacement)}).success); clean();
    puts("PASS recovery/result separation, blocked requests, backup lifetime and invalid requests");
}

int main() {
    repeated_backup(); unavailable_backup(); hook_chains(); isolated_queue();
    checked_restore(); pending_and_invalid_requests(); legacy_restoration();
    printf("PASS interface boundaries pointer_bits=%zu\n", sizeof(uintptr_t) * 8);
}
