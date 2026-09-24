//! Compiles bpf/killline.bpf.c with clang into a BPF object that is embedded
//! in the binary. Requires clang and libbpf headers (libbpf-dev). If they are
//! missing the crate still builds, and the sensor reports at runtime that it
//! was built without eBPF support -- so the core and CLI remain testable on
//! machines without a BPF toolchain.
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../bpf");
    let src = root.join("killline.bpf.c");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("killline.bpf.o");
    println!("cargo:rerun-if-changed={}", src.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("vmlinux_min.h").display()
    );
    println!("cargo:rerun-if-env-changed=KILLLINE_CLANG");
    println!("cargo:rustc-check-cfg=cfg(killline_no_bpf)");

    let clang = env::var("KILLLINE_CLANG").unwrap_or_else(|_| "clang".into());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        Ok(other) => other.to_string().leak(),
        Err(_) => "x86",
    };
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-target", "bpf", "-Wall", "-Werror"])
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .arg("-I")
        .arg(&root)
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status();
    match status {
        Ok(s) if s.success() => {}
        // A present-but-failing compiler is a real error, never a silent
        // fallback to a build that cannot monitor anything.
        Ok(s) => panic!("compiling {} failed with {}", src.display(), s),
        Err(e) => {
            println!(
                "cargo:warning=clang not found ({}); building WITHOUT the eBPF sensor. \
                 Install clang and libbpf-dev. The monitor will refuse to start.",
                e
            );
            std::fs::write(&out, b"").unwrap();
            println!("cargo:rustc-cfg=killline_no_bpf");
        }
    }
}
