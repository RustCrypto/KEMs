//! Compiler-version compatibility configuration for x86 SIMD kernels.

use std::{env, process::Command};

fn rustc_version() -> Option<(u32, u32)> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let version = stdout.split_whitespace().nth(1)?;
    let mut components = version.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    Some((major, minor))
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=TARGET");

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return;
    }

    // AVX-512/AVX-VNNI intrinsics and the safe `target_feature` calling rules
    // used by the synchronized implementation require Rust 1.95. Older x86
    // compilers use the same constant-time scalar paths as `force-scalar`.
    let supports_simd = match rustc_version() {
        Some((1, minor)) => minor >= 95,
        Some((major, _)) => major > 1,
        None => false,
    };

    if !supports_simd {
        println!("cargo:rustc-cfg=feature=\"force-scalar\"");
    }
}
