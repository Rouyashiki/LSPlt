#pragma once

#include <sys/types.h>

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/// \namespace lsplt
namespace lsplt {
inline namespace v2 {

/// \struct MapInfo
/// \brief An entry that describes a line in /proc/self/maps. You can obtain a list of these entries
/// by calling #Scan().
struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    std::string path;

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \param[in] pid The process id to scan. This is "self" by default.
    /// \return A list of \ref MapInfo entries.
    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> Scan(std::string_view pid = "self");

    /// \brief Returns the latest map snapshot captured by #CommitHook().
    /// The snapshot is inherited across fork and does not access procfs.
    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> ScanCached();
};

/// \brief Register a hook to a function by inode. For so within an archive, you should use
/// #RegisterHook(ino_t, uintptr_t, size_t, std::string_view, void *, void **) instead.
/// \param[in] dev The device number of the memory region.
/// \param[in] inode The inode of the library to hook. You can obtain the inode by #stat() or by finding
/// the library in the list returned by #lsplt::v1::MapInfo::Scan().
/// \param[in] symbol The function symbol to hook.
/// \param[in] callback The callback function pointer to call when the function is called.
/// \param[out] backup The backup function pointer which can call the original function. This is
/// optional.
/// \return Whether the hook is successfully registered.
/// \note This function is thread-safe.
/// \note \p backup will not be available until #CommitHook() is called.
/// \note A failed commit may initialize \p backup; it remains valid after publication/rollback.
/// \note You can unhook the function by calling this function with \p callback set to the backup
/// set by previous call.
/// \note Hooks update aligned pointer slots in place and restore page permissions after each write.
/// Unhooking restores the saved pointer while retaining the original file mapping. Private dirty
/// pages may remain. #InvalidateBackup() discards restoration bookkeeping without removing hooks.
/// \see #CommitHook()
/// \see #InvalidateBackup()
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol,
                                                               void *callback, void **backup);

/// \brief Register a hook to a function by inode with offset range. This is useful when hooking
/// a library that is directly loaded from an archive without extraction.
/// \param[in] dev The device number of the memory region.
/// \param[in] inode The inode of the library to hook. You can obtain the inode by #stat() or by finding
/// the library in the list returned by #lsplt::v1::MapInfo::Scan().
/// \param[in] offset The to the library in the file.
/// \param[in] size The upper bound size to the library in the file.
/// \param[in] symbol The function symbol to hook.
/// \param[in] callback The callback function pointer to call when the function is called.
/// \param[out] backup The backup function pointer which can call the original function. This is
/// optional.
/// \return Whether the hook is successfully registered.
/// \note This function is thread-safe.
/// \note \p backup will not be available until #CommitHook() is called.
/// \note A failed commit may initialize \p backup; it remains valid after publication/rollback.
/// \note You can unhook the function by calling this function with \p callback set to the backup
/// set by previous call.
/// \note Hooks update aligned pointer slots in place and restore page permissions after each write.
/// Unhooking restores the saved pointer while retaining the original file mapping. Private dirty
/// pages may remain. #InvalidateBackup() discards restoration bookkeeping without removing hooks.
/// \note You can get the offset range of the library by getting its entry offset and size in the
/// zip file.
/// \note According to the Android linker specification, the \p offset must be page aligned.
/// \note The \p offset must be accurate, otherwise the hook may fail because the ELF header
/// cannot be found.
/// \note The \p size can be inaccurate but should be larger or equal to the library size,
/// otherwise the hook may fail when the hook pointer is beyond the range.
/// \note Empty or overflowing offset ranges are rejected with EINVAL.
/// \see #CommitHook()
/// \see #InvalidateBackup()
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset,
                                                               size_t size, std::string_view symbol,
                                                               void *callback, void **backup);
/// \brief Commit all registered hooks.
/// \return Whether all hooks are successfully committed. If any of the hooks fail to commit,
/// the result is false.
/// \note This function is thread-safe.
/// \note Neither false nor a non-null backup determines whether a callback was published.
/// A published slot may have been rolled back, and its callback may still be executing.
/// Each registration is transactional. Incomplete recovery blocks new writes and cache release.
/// Failure sets errno; use #CommitHookDetailed() to distinguish failure and recovery outcomes.
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool CommitHook();

/// \brief Commit registered hooks using the map state cached by an earlier
/// #CommitHook() call without rescanning /proc/self/maps.
/// \return Whether every registered hook was found and committed.
/// \note This function is intended for a fork child whose mappings still
/// match the state inherited from its parent.
[[maybe_unused, gnu::visibility("default")]] bool CommitHookCached();

enum class CommitStatus {
    Applied, NoChange, Rejected, RolledBack, RollbackIncomplete, Blocked
};

enum class HookError {
    None, MapUnavailable, InvalidElf, SymbolNotFound, InvalidSlot,
    InconsistentOriginal, ProtectFailed, SlotConflict, PendingRollback,
    OriginalUnavailable, InvalidRequest
};

struct SlotResult {
    uintptr_t address = 0;
    uintptr_t before = 0;
    uintptr_t after = 0;
    bool observed = false;
    bool permissions_restored = true;
};

struct RegistrationResult {
    dev_t dev = 0;
    ino_t inode = 0;
    std::pair<uintptr_t, uintptr_t> offset_range{};
    std::string symbol;
    void *callback = nullptr;
    CommitStatus status = CommitStatus::Rejected;
    HookError error = HookError::None;
    HookError rollback_error = HookError::None;
    int error_number = 0;
    int rollback_error_number = 0;
    bool ever_published = false;
    bool recovery = false;
    std::vector<SlotResult> slots;
};

struct CommitReport {
    bool success = true;
    bool rollback_pending = false;
    int error_number = 0;
    std::vector<RegistrationResult> registrations;
};

enum class HookOperation { Replace, Restore };

struct HookRequest {
    dev_t dev = 0;
    ino_t inode = 0;
    std::string_view symbol;
    void *callback = nullptr;
    void **backup = nullptr;
    std::pair<uintptr_t, uintptr_t> offset_range{0, std::numeric_limits<uintptr_t>::max()};
    HookOperation operation = HookOperation::Replace;
    void *expected_current = nullptr;
};

struct HookBatchReport {
    bool success = true;
    bool rollback_pending = false;
    int error_number = 0;
    std::vector<RegistrationResult> results;
    std::vector<RegistrationResult> recoveries;
};

/// Apply only these requests under one lock without consuming the RegisterHook queue.
/// Results correspond one-to-one to input requests; each request is its own transaction.
/// An empty list only retries pending recovery. Requests blocked by recovery are not queued.
/// Restore requires expected_current and a null backup; slots already at callback are accepted.
/// Neither successful restoration nor rollback proves that a callback has stopped executing.
[[maybe_unused, gnu::visibility("default")]] HookBatchReport ApplyHooksDetailed(
    const std::vector<HookRequest> &requests);

/// Same isolated request semantics, using inherited maps without reading procfs.
[[maybe_unused, gnu::visibility("default")]] HookBatchReport ApplyHooksCachedDetailed(
    const std::vector<HookRequest> &requests);

/// Each registration is a transaction; successful sibling registrations are retained.
/// A failed transaction restores its own prior slot values and page permissions, or
/// retains a recovery journal which blocks new writes until a later commit repairs it.
/// Requests blocked by an incomplete rollback are consumed, not replayed later.
/// The report distinguishes publication from final installation. A callback may have
/// run even after a complete rollback: retain its backup and code until safe retirement.
/// A new installation requesting one backup rejects heterogeneous original pointers.
/// Repeated installation fills backup from a consistent, tracked direct predecessor.
/// Missing provenance rejects a backup request with OriginalUnavailable/ENODATA.
/// Backup is output-only; its previous contents are never read.
[[maybe_unused, gnu::visibility("default")]] CommitReport CommitHookDetailed();

/// Same transaction semantics, using inherited maps without reading procfs.
[[maybe_unused, gnu::visibility("default")]] CommitReport CommitHookCachedDetailed();

/// Release cached state only after all hooks and backup mappings are gone.
[[maybe_unused, gnu::visibility("default")]] bool ReleaseInactiveCache();

/// \brief Invalidate backup memory regions
/// Keeps installed hooks in the original mapping and discards restoration bookkeeping after
/// restoring page permissions. Any legacy backup mappings are restored with their hooks reapplied.
/// \return Whether all hooks are successfully invalidated. If any of the hooks fail to invalidate,
/// the result is false.
/// \note This function is thread-safe.
/// \note This will be automatically called when the library is unloaded.
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool InvalidateBackup();
}  // namespace v2
}  // namespace lsplt
