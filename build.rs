use std::process::Command;

fn main() {
    let hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=LYNXX_BUILD_HASH={hash}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    // AUTH_URL is read at compile-time via `env!` in
    // integrations::keyx — required, no default. Re-run this build
    // script whenever it changes so the baked-in const reflects the
    // latest value, and so the build correctly fails if the var is
    // unset.
    println!("cargo:rerun-if-env-changed=AUTH_URL");
}
