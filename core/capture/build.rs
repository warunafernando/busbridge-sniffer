//! Link the BUSBRIDGE C library into the capture crate.
//!
//! Static rather than the DLL, for the same reason the GUI does it: the tools
//! ship as single executables, with no "busbridge.dll was not found" for
//! someone who moved one. `setupapi` and `advapi32` are what the enumeration
//! code needs.
//!
//! The library lives in the BUSBRIDGE tree next door, which is where the boards
//! and their transport already are. BUSBRIDGE_LIB_DIR overrides it.
//!
//! Override the search path with BUSBRIDGE_LIB_DIR when the C library lives
//! somewhere other than the default build output.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "x86" => "x86",
        _ => "x64",
    };

    let lib_dir = env::var("BUSBRIDGE_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // ../../.. from core/capture is the sniffer root; the BUSBRIDGE
            // tree is its sibling.
            manifest
                .parent().unwrap()      // core
                .parent().unwrap()      // sniffer
                .parent().unwrap()      // STMicro
                .join("busbridge")
                .join("windows")
                .join("build")
                .join(arch)
        });

    if !lib_dir.join("busbridge_static.lib").exists() {
        panic!(
            "busbridge_static.lib not found in {}\n\
             Build the C library first:  windows\\build.ps1\n\
             Or point BUSBRIDGE_LIB_DIR at it.",
            lib_dir.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=busbridge_static");
    // The three the C library's own link line uses. winusb is the one that is
    // easy to miss: windowsuild.ps1 passes it when building the DLL, but a
    // static library carries no link directives, so every consumer of it has to
    // name winusb itself or the WinUsb_* calls come back unresolved.
    println!("cargo:rustc-link-lib=dylib=setupapi");
    println!("cargo:rustc-link-lib=dylib=advapi32");
    println!("cargo:rustc-link-lib=dylib=winusb");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BUSBRIDGE_LIB_DIR");
    println!(
        "cargo:rerun-if-changed={}",
        lib_dir.join("busbridge_static.lib").display()
    );
}
