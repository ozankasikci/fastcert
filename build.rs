fn main() {
    // Pass version information to the build
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );

    // Get git commit hash if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        && output.status.success()
    {
        let git_hash = String::from_utf8_lossy(&output.stdout);
        println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
    }
}
