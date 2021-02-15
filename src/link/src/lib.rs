pub mod stdlib;
pub mod nonstd;

#[no_mangle]
pub extern fn main() {
    stdlib::link_loop();
}
