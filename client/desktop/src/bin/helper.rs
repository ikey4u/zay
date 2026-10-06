#[cfg(target_os = "macos")]
fn main() {
    let result = (|| -> anyhow::Result<()> {
        if !zay::desktop::run_helper_if_requested()? {
            zay::desktop::run_native_privileged_helper()?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "macos"))]
fn main() {
    std::process::exit(1);
}
