#[cfg(target_os = "macos")]
mod backend;
#[cfg(target_os = "macos")]
mod desktop;

#[cfg(target_os = "macos")]
fn main() {
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
