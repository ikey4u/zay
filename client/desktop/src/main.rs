#[cfg(target_os = "macos")]
mod backend;
#[cfg(target_os = "macos")]
mod desktop;

#[cfg(target_os = "macos")]
fn main() {
    // Elevated launches run only the headless worker and return here. The
    // original GUI process stays open and never relaunches as administrator.
    match zay::desktop::run_helper_if_requested() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
    desktop::run();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Zay Desktop currently supports macOS only.");
    std::process::exit(1);
}
