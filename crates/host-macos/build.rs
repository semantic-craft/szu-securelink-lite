fn main() {
    println!("cargo:rerun-if-changed=include/securelink_client.h");
    println!("cargo:rerun-if-changed=../../platforms/macos/src/NativeGlassBackground.h");
    println!("cargo:rerun-if-changed=../../platforms/macos/src/SettingsLayout.h");
    println!("cargo:rerun-if-changed=../../platforms/macos/src/WindowPresentation.h");
    println!("cargo:rerun-if-changed=../../platforms/macos/src/SecureLinkNativeApp.mm");

    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .cpp(true)
            .file("../../platforms/macos/src/SecureLinkNativeApp.mm")
            .flag("-std=c++17")
            .flag("-fobjc-arc")
            .flag("-Wno-deprecated-declarations")
            .include("include")
            .include("../../platforms/macos/src")
            .compile("securelink_macos_native_ui");

        println!("cargo:rustc-link-lib=framework=Cocoa");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
