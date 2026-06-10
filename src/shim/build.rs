fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    // Rerun this build script (→ recompile the cc objects → relink the dylib)
    // whenever either C source changes.  The `cc` crate does NOT reliably emit
    // `rerun-if-changed` for its inputs here (verified: the build-script output
    // had none), and — importantly — the moment ANY `rerun-if-*` directive is
    // present (e.g. a future one), cargo stops watching the whole package by
    // default, so a C edit could silently reuse a stale object/dylib.  List both
    // C inputs explicitly to make the cached-dylib bust reliable (adversarial-
    // review HIGH 2026-06).  build.rs itself is always watched by cargo.
    println!("cargo:rerun-if-changed=src/open_variadic.c");
    println!("cargo:rerun-if-changed=src/sj_spawn_chdir_np2.c");

    // Pin the cc object's deployment target to the dylib floor (11.0, the same
    // pin as SHIM_PINNED_MINOS in scripts/build.ts) so a newer host SDK default
    // can never raise this object's minOS above the final cdylib link's.
    // (macOS-only: the CARGO_CFG_TARGET_OS guard above already skips this whole
    // body for Linux, where clang/gcc would reject the flag.)
    cc::Build::new()
        .file("src/open_variadic.c")
        .flag("-mmacosx-version-min=11.0")
        .warnings(false)
        .compile("scriptjail_open_variadic");

    // macOS-26 non-`_np` posix_spawn chdir interposes (see src/sj_spawn_chdir_np2.c).
    // Pin the deployment target < 26 so the SDK marks the macos(26.0) symbols
    // `weak_import`: they bind on macOS 26+ and resolve to NULL on older macOS
    // (e.g. the macos-14 CI runner), where a `{ replacement, NULL }` __interpose
    // tuple is an inert no-op and the dylib still loads.  Compiled separately so
    // open_variadic.c's target is untouched.  (Stable Rust cannot express a weak
    // extern, which is why this interpose lives in C.)
    cc::Build::new()
        .file("src/sj_spawn_chdir_np2.c")
        .flag("-mmacosx-version-min=11.0")
        .warnings(false)
        .compile("scriptjail_spawn_chdir_np2");

    // The macOS-26 non-`_np` symbols are ABSENT from pre-26 SDK libSystem stubs
    // (only the `_np` forms exist before macOS 26 — verified in MacOSX15.4.sdk's
    // libSystem.tbd).  `weak_import` lets sj_spawn_chdir_np2.c COMPILE on such an
    // SDK, but the kept `__interpose` tuples emit relocations to those symbols, so
    // the final cdylib LINK still fails on a pre-26 SDK (e.g. the macos-14 parity
    // runner) with "Undefined symbols … _posix_spawn_file_actions_add{,f}chdir"
    // BEFORE the intended runtime weak-NULL behavior is ever reached (adversarial-
    // review HIGH 2026-06).  Allow EXACTLY those two symbols to be undefined at
    // link: `-U` defers each to a dynamic lookup which, paired with the C
    // `weak_import` reference (weak undefined), dyld binds to the real function on
    // macOS 26+ and to NULL on older macOS (inert `{ replacement, NULL }` tuple).
    // Scoped to the cdylib and to the two EXACT symbols so no OTHER undefined
    // symbol is ever masked.  On the macOS-26 SDK the symbols ARE in the stub, so
    // these `-U` flags are a harmless no-op.
    println!("cargo:rustc-link-arg-cdylib=-Wl,-U,_posix_spawn_file_actions_addchdir");
    println!("cargo:rustc-link-arg-cdylib=-Wl,-U,_posix_spawn_file_actions_addfchdir");
}
