// macOS-26 non-`_np` posix_spawn chdir file-actions interposes.
//
// `posix_spawn_file_actions_addchdir` / `_addfchdir` are __API_AVAILABLE(macos(26.0))
// — the non-deprecated replacements for the 10.15 `_np` variants the Rust shim
// (lib.rs) already interposes.  A caller using these instead of the `_np` names
// would otherwise add a child-cwd change WITHOUT being tracked, re-opening the
// Finding-E hole on macOS 26+ (adversarial review).
//
// We interpose them HERE in C, not in Rust, because C can weak-import a
// macos(26.0) symbol: `&fn` becomes a weak reference that binds on macOS 26+ and
// resolves to NULL on older macOS (e.g. the `macos-14` CI runner that loads this
// dylib), where these symbols do not exist and no caller can use them.  A
// `{ replacement, NULL-original }` __interpose tuple is then an inert no-op
// (stable Rust has no weak extern, which is why this lives in C).
//
// LOAD-on-macos-14 needs TWO mechanisms, NOT just the weak_import below:
//   * COMPILE: on a pre-26 SDK the prototypes are absent, so we declare them
//     ourselves with weak_import (see the SDK-version guard further down).
//   * LINK: the kept __interpose tuples emit relocations to these symbols, which
//     are absent from a pre-26 SDK's libSystem stub, so the final cdylib link
//     would fail with "Undefined symbols" BEFORE load.  build.rs passes
//     `-Wl,-U,_posix_spawn_file_actions_add{,f}chdir` (cdylib-scoped) to allow
//     exactly those two symbols undefined at link; paired with weak_import each
//     becomes a weak, dynamically-looked-up undefined that dyld binds on macOS 26+
//     and NULLs on older macOS.  build.rs also pins `-mmacosx-version-min` < 26.
//
// On a successful add we record the file_actions HANDLE (the
// `posix_spawn_file_actions_t *` the caller passes — stable across the object
// reallocs that appending later actions triggers) into the Rust tracker, so the
// `_np` (Rust) and non-`_np` (here) chdir adds feed the SAME CHDIR_FA_SLOTS set,
// and the shared init/destroy interposes (Rust) clear it for both.
//
// Same-image note: the call to the real `posix_spawn_file_actions_addchdir` below
// is a same-image reference (this object is linked into the interposing dylib), so
// it reaches the REAL libSystem function without re-entering our replacement —
// the same "R8" property the Rust `real_*` calls rely on.
#include <spawn.h>
#include <stdint.h>
#include <stddef.h>
#include <Availability.h>

// CRITICAL (adversarial-review HIGH): the parity workflow builds this shim on
// `macos-14`, whose SDK does NOT declare the macОS-26 non-`_np` functions.  If we
// relied on <spawn.h> to declare them, clang would fail at compile time on that
// runner (implicit-declaration error) and the dylib would never build — so the
// weak_import/NULL load behavior would never even be reached.  Declare them
// OURSELVES on pre-26 SDKs, marked `weak_import` so the reference is NULL when the
// running OS lacks the symbol (macOS < 26).  On the macОS-26 SDK <spawn.h> already
// declares them (availability-weak at our sub-26 deployment target), so guard on
// the SDK version to avoid a redeclaration conflict.  `posix_spawn_file_actions_t`
// itself comes from <spawn.h> and exists on every SDK.
#if !defined(__MAC_OS_X_VERSION_MAX_ALLOWED) || __MAC_OS_X_VERSION_MAX_ALLOWED < 260000
extern int posix_spawn_file_actions_addchdir(posix_spawn_file_actions_t *, const char *)
    __attribute__((weak_import));
extern int posix_spawn_file_actions_addfchdir(posix_spawn_file_actions_t *, int)
    __attribute__((weak_import));
#endif

// Defined in lib.rs (#[no_mangle]); feeds the shared chdir-tracking set.
extern void sj_note_chdir_handle(uintptr_t handle);

// Link anchor — referenced by a `#[used]` static in lib.rs.  The two __interpose
// tuples below are static DATA that nothing in the dylib calls, so without a
// referenced symbol the static-archive linker would drop this whole object (and
// the interposes with it).  Referencing this anchor from Rust forces the object —
// and its __interpose section — to be pulled in.
__attribute__((used)) void sj_spawn_chdir_np2_anchor(void) {}

static int sj_fa_addchdir(posix_spawn_file_actions_t *fa, const char *path) {
    // The interpose original is the weak symbol; on macOS < 26 it is NULL so this
    // replacement is never installed.  NULL-check defensively anyway.
    if (posix_spawn_file_actions_addchdir == NULL) {
        return -1;
    }
    int rc = posix_spawn_file_actions_addchdir(fa, path);
    if (rc == 0) {
        sj_note_chdir_handle((uintptr_t)fa);
    }
    return rc;
}

static int sj_fa_addfchdir(posix_spawn_file_actions_t *fa, int filedes) {
    if (posix_spawn_file_actions_addfchdir == NULL) {
        return -1;
    }
    int rc = posix_spawn_file_actions_addfchdir(fa, filedes);
    if (rc == 0) {
        sj_note_chdir_handle((uintptr_t)fa);
    }
    return rc;
}

// Mach-O __interpose tuples: { replacement, original }.  `original` is the weak
// symbol address — the REAL libSystem function on macOS 26+, or NULL on older
// macOS (then the tuple is an inert no-op).
__attribute__((used, section("__DATA,__interpose")))
static const void *const sj_interpose_addchdir[2] = {
    (const void *)&sj_fa_addchdir,
    (const void *)&posix_spawn_file_actions_addchdir,
};

__attribute__((used, section("__DATA,__interpose")))
static const void *const sj_interpose_addfchdir[2] = {
    (const void *)&sj_fa_addfchdir,
    (const void *)&posix_spawn_file_actions_addfchdir,
};
