#![windows_subsystem = "windows"]
// above declaration keeps the window hidden

mod nonstd;
mod stdlib;

// UM link
fn main() {
    stdlib::link_loop();
}