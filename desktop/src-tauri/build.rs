fn main() {
    let mut attrs = tauri_build::Attributes::new();
    // On Windows, embed a manifest that asks for administrator rights (UAC).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        attrs = attrs.windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows-app-manifest.xml")),
        );
    }
    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}
