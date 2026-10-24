#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "syscall.hpp"

static unsigned protect_calls, fail_mask, map_calls, remap_calls, cas_calls;
static unsigned conflict_cas;
static uintptr_t conflict_value;
static void (*protect_observer)(const void *, int);
static int test_mprotect(const void *p, size_t len, int prot) {
    ++protect_calls;
    if (protect_observer) protect_observer(p, prot);
    if (protect_calls <= 32 && (fail_mask & (1u << (protect_calls - 1)))) {
        errno = EACCES;
        return -1;
    }
    return sys_mprotect(p, len, prot);
}
template<class... Args> static auto test_mmap(Args... args) {
    ++map_calls; return sys_mmap(args...);
}
template<class... Args> static auto test_mremap(Args... args) {
    ++remap_calls; return sys_mremap(args...);
}
static bool test_cas(uintptr_t *p, uintptr_t *expected, uintptr_t value,
                     bool weak, int success, int failure) {
    ++cas_calls;
    if (cas_calls == conflict_cas) __atomic_store_n(p, conflict_value, __ATOMIC_RELEASE);
    return __atomic_compare_exchange_n(p, expected, value, weak, success, failure);
}
#define sys_mprotect test_mprotect
#define sys_mmap test_mmap
#define sys_mremap test_mremap
#define __atomic_compare_exchange_n test_cas
#include "lsplt.cc"
#undef sys_mprotect
#undef sys_mmap
#undef sys_mremap
#undef __atomic_compare_exchange_n

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); std::abort(); } } while (0)
static constexpr size_t length = 0x39000;
static constexpr size_t target_off = 0x35300;
static constexpr uintptr_t sentinel = 0x12345a78;
static uintptr_t original_fn() { return 7; }
static uintptr_t replacement_fn() { return 11; }

static lsplt::MapInfo mapping(uintptr_t ptr) {
    for (const auto &m : lsplt::MapInfo::Scan()) if (m.start <= ptr && ptr < m.end) return m;
    std::abort();
}
struct Region {
    int fd;
    uintptr_t base;
    lsplt::MapInfo initial;
    explicit Region(bool writable = false) {
        fd = memfd_create("lsplt-inplace-fixture", 0);
        CHECK(fd >= 0);
        std::vector<uintptr_t> bytes(length / sizeof(uintptr_t), sentinel);
        auto *data = reinterpret_cast<unsigned char *>(bytes.data());
        std::memset(data, 0, 0x1000);
        auto *eh = reinterpret_cast<ElfW(Ehdr) *>(data);
        std::memcpy(eh->e_ident, ELFMAG, SELFMAG);
        eh->e_ident[EI_CLASS] = sizeof(uintptr_t) == 8 ? ELFCLASS64 : ELFCLASS32;
        eh->e_ident[EI_DATA] = ELFDATA2LSB;
        eh->e_ident[EI_VERSION] = EV_CURRENT;
        eh->e_version = EV_CURRENT;
        eh->e_type = ET_DYN;
#if defined(__aarch64__)
        eh->e_machine = EM_AARCH64;
        constexpr auto relocation = R_AARCH64_GLOB_DAT;
#elif defined(__arm__)
        eh->e_machine = EM_ARM;
        constexpr auto relocation = R_ARM_GLOB_DAT;
#else
        eh->e_machine = EM_X86_64;
        constexpr auto relocation = R_X86_64_GLOB_DAT;
#endif
        eh->e_ehsize = sizeof(*eh);
        eh->e_phoff = sizeof(*eh);
        eh->e_phnum = 2;
        eh->e_phentsize = sizeof(ElfW(Phdr));
        auto *ph = reinterpret_cast<ElfW(Phdr) *>(data + eh->e_phoff);
        ph[0].p_type = PT_LOAD;
        ph[0].p_memsz = ph[0].p_filesz = length;
        ph[0].p_flags = PF_R;
        ph[1].p_type = PT_DYNAMIC;
        ph[1].p_vaddr = 0x300;
        ph[1].p_memsz = 8 * sizeof(ElfW(Dyn));
        auto *dyn = reinterpret_cast<ElfW(Dyn) *>(data + 0x300);
        const uintptr_t tags[][2] = {{DT_STRTAB, 0x500}, {DT_SYMTAB, 0x600}, {DT_HASH, 0x700},
            {DT_PLTREL, DT_RELA}, {DT_RELA, 0x800}, {DT_RELASZ, sizeof(ElfW(Rela))}, {DT_NULL, 0}};
        for (size_t i = 0; i < 7; ++i) { dyn[i].d_tag = tags[i][0]; dyn[i].d_un.d_val = tags[i][1]; }
        std::memcpy(data + 0x500, "\0target\0", 8);
        auto *sym = reinterpret_cast<ElfW(Sym) *>(data + 0x600);
        sym[1].st_name = 1;
        const uint32_t hash[] = {1, 2, 1, 0, 0};
        std::memcpy(data + 0x700, hash, sizeof(hash));
        auto *rel = reinterpret_cast<ElfW(Rela) *>(data + 0x800);
        rel->r_offset = target_off;
#if __SIZEOF_POINTER__ == 8
        rel->r_info = ELF64_R_INFO(1, relocation);
#else
        rel->r_info = ELF32_R_INFO(1, relocation);
#endif
        *reinterpret_cast<uintptr_t *>(data + target_off) = reinterpret_cast<uintptr_t>(original_fn);
        CHECK(write(fd, data, length) == static_cast<ssize_t>(length));
        auto *mem = mmap(nullptr, length, PROT_READ | (writable ? PROT_WRITE : 0), MAP_PRIVATE, fd, 0);
        CHECK(mem != MAP_FAILED);
        base = reinterpret_cast<uintptr_t>(mem);
        initial = mapping(base);
    }
    ~Region() { munmap(reinterpret_cast<void *>(base), length); close(fd); }
    uintptr_t target() const { return base + target_off; }
    uintptr_t read(uintptr_t off) const { return __atomic_load_n(reinterpret_cast<uintptr_t *>(base + off), __ATOMIC_ACQUIRE); }
    void identity() const {
        for (uintptr_t p = base; p < base + length; p += kPageSize) {
            auto m = mapping(p);
            CHECK(m.dev == initial.dev && m.inode == initial.inode && m.path == initial.path);
            CHECK(m.offset + p - m.start == p - base);
            CHECK(m.perms == initial.perms && m.is_private);
        }
    }
    HookInfos hooks() const {
        HookInfos h;
        h.emplace(base, HookInfo{{initial}, {}, 0, nullptr, false});
        return h;
    }
};

static uintptr_t other_fn() { return 23; }
static constexpr size_t adjacent = target_off + sizeof(uintptr_t);
static constexpr size_t distant = target_off + 0x1000;
static void setup_slots(Region &r, size_t second, bool distinct = false, bool duplicate = false) {
    CHECK(mprotect(reinterpret_cast<void *>(r.base), length, PROT_READ | PROT_WRITE) == 0);
    auto *dyn = reinterpret_cast<ElfW(Dyn) *>(r.base + 0x300);
    dyn[5].d_un.d_val = (duplicate ? 3 : 2) * sizeof(ElfW(Rela));
    auto *rel = reinterpret_cast<ElfW(Rela) *>(r.base + 0x800);
    rel[1] = rel[0]; rel[1].r_offset = second;
    if (duplicate) rel[2] = rel[0];
    *reinterpret_cast<uintptr_t *>(r.base + second) =
        reinterpret_cast<uintptr_t>(distinct ? other_fn : original_fn);
    CHECK(mprotect(reinterpret_cast<void *>(r.base), length, r.initial.perms) == 0);
}
static void faults(unsigned mask = 0) {
    protect_calls = cas_calls = 0; fail_mask = mask;
    conflict_cas = 0; protect_observer = nullptr;
}
static void register_target(Region &r, void **backup, void *callback = reinterpret_cast<void *>(replacement_fn),
                            const char *symbol = "target") {
    CHECK(lsplt::RegisterHook(r.initial.dev, r.initial.inode, symbol, callback, backup));
}
static void clean() { CHECK(lsplt::ReleaseInactiveCache()); faults(); }
static void expect_values(const Region &r, size_t second, uintptr_t first, uintptr_t last) {
    CHECK(r.read(target_off) == first && r.read(second) == last);
}
