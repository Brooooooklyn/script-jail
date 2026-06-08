fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("src/open_variadic.c")
        .warnings(false)
        .compile("scriptjail_open_variadic");
}
