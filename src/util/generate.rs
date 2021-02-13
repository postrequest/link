use std::fs;
use std::io::prelude::*;

fn generate_help() {
    println!("generate <ip:port>");
    println!("  example: generate 10.10.10.10:8443");
    println!("  example: generate link.com:8443");
}

fn generate_has_dependencies() -> bool {
    // check if cargo exists if not prompt for install
    if std::process::Command::new("cargo")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().is_err() {
            println!("cargo not installed, the following command may help:");
            println!("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
            return false
    }
    // check if rustup exists if not prompt for install
    if std::process::Command::new("rustup")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().is_err() {
            println!("rustup not installed, the following command may help:");
            println!("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
            return false
    }
    // check if mingw64 and mingw64 binutils exist
    if std::process::Command::new("/usr/bin/x86_64-w64-mingw32-gcc")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().is_err() {
            println!("mingw64 not installed");
            return false
    }
    if std::process::Command::new("/usr/x86_64-w64-mingw32/bin/ar")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().is_err() {
            println!("mingw64 binutils not installed");
            return false
    }
    // check if ~/.cargo/config contains cross toolchain
    let home_dir = match std::env::var("HOME") {
        Err(e)      => { println!("{}", e); return false},
        Ok(home)    => home,
    };
    let cargo_conf_dir = format!("{}/.cargo/config", home_dir);
    let cross_conf = "[target.x86_64-pc-windows-gnu]\nlinker = \"/usr/bin/x86_64-w64-mingw32-gcc\"\nar = \"/usr/$ARCH-w64-mingw32/bin/ar\"";
    if fs::metadata(cargo_conf_dir.as_str()).is_err() {
        println!("cargo config does not exist: ~/.cargo/config");
        println!("cross platform configuration should contain:\n");
        println!("{}:\n{}\n", cargo_conf_dir, cross_conf);
        println!("once complete add the windows rust-std with:\nrustup target add x86_64-pc-windows-gnu");
        return false
    }
    // check if rust-std for x86_64-pc-windows-gnu target installed
    let rustup_win_lib_dir = format!("{}/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-pc-windows-gnu", home_dir);
    if fs::metadata(rustup_win_lib_dir.as_str()).is_err() {
        println!("rustup does not have x86_64-pc-windows-gnu target, the following command may help:");
        println!("rustup target add x86_64-pc-windows-gnu");
        return false
    }
    return true
}

pub fn generate(args: Vec<String>) {
    if args.len() == 1 {
        generate_help();
        return
    }
    // check for dependencies
    if generate_has_dependencies() == false {
        return
    }
    // rs files
    let main = format!("{}", String::from_utf8_lossy(include_bytes!("../link/src/main.rs")));
    let nonstd = format!("{}", String::from_utf8_lossy(include_bytes!("../link/src/nonstd.rs")));
    let cargo = format!("{}", String::from_utf8_lossy(include_bytes!("../link/Cargo.toml")));
    let build = format!(
        "fn main(){{println!(\"cargo:rustc-env=CALLBACK={}\");}}",
        args[1],
    );
    let prev_dir_path = std::env::current_dir().unwrap();
    let link_dir_path = "/tmp/link_current";
    let link_exec_path = "/tmp/link_current/target/x86_64-pc-windows-gnu/release/link.exe";
    let link_dir_src_path = format!("{}/src", link_dir_path);
    let dest_link_path = format!("{}/link.exe", prev_dir_path.clone().display());
    // check for first build
    if fs::metadata(link_dir_path).is_err() {
        println!("first link build will take time");
    }
    // create temp directory and change dir
    match fs::create_dir_all(link_dir_src_path) {
        Err(e)          => {println!("{}", e); return},
        Ok(link_dir)    => link_dir,
    };
    if std::env::set_current_dir(link_dir_path).is_err() {
        println!("could not change directory");
        return
    }
    // write files to link dir
    let mut output_file = fs::File::create("./src/main.rs").expect("could not write file");
    output_file.write_all(main.as_bytes()).expect("could not write contents to output file");
    output_file = fs::File::create("./src/nonstd.rs").expect("could not write file");
    output_file.write_all(nonstd.as_bytes()).expect("could not write contents to output file");
    output_file = fs::File::create("Cargo.toml").expect("could not write file");
    output_file.write_all(cargo.as_bytes()).expect("could not write contents to output file");
    output_file = fs::File::create("build.rs").expect("could not write file");
    output_file.write_all(build.as_bytes()).expect("could not write contents to output file");
    // TODO
    // run cargo fetch --release, then build with --offline for efficiency
    // create link executable
    println!("please wait...");
    let output = std::process::Command::new("cargo")
        .args(&["build", "--release", "--target", "x86_64-pc-windows-gnu"])
        .env("RUSTFLAGS", "-C link-arg=-s")
        .output();
    match output {
        Err(e)  => println!("{}", e),
        Ok(_)   => println!("link succesfully built"),
    }
    // return to previous path
    if std::env::set_current_dir(prev_dir_path.clone()).is_err() {
        println!("could not change back to previous directory");
        return
    }
    // copy file to current dir
    let link_copy = fs::copy(link_exec_path, dest_link_path);
    match link_copy {
        Err(e)  => println!("{}", e),
        Ok(_)   => println!("output: link.exe"),
    }
}
