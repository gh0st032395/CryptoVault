//! Generates the Tauri context: the configuration, the capabilities, and the
//! build of the interface that gets embedded in the binary.

fn main() {
    // `generate_context!` reads `ui/dist` at compile time and cargo has no way
    // to know it. Without these lines, changing the interface and rebuilding
    // produces a binary containing the *previous* interface — which is
    // indistinguishable from a change that did not work, and costs an afternoon
    // the first time it happens.
    println!("cargo:rerun-if-changed=../../ui/dist");
    println!("cargo:rerun-if-changed=../../ui/dist/index.html");

    tauri_build::build();
}
