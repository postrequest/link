use std::{
    fs,
    io::prelude::*,
    os::unix::fs::OpenOptionsExt,
    process::Command,
};

// internal packages
use crate::util;

fn donut_create() -> bool {
    util::sharp::create_link_dir();
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return false;
        }
        Ok(home) => home,
    };
    let link_path = format!("{}/.link", home_dir);
    let third_party_path = format!("{}/3rdparty", link_path);
    let donut_path = format!("{}/3rdparty/donut", link_path);
    if !fs::metadata(donut_path.as_str()).is_ok() {
        if !fs::metadata(third_party_path.as_str()).is_ok() {
            match fs::create_dir_all(third_party_path.as_str()) {
                Err(e) => {
                    println!("{}", e);
                    return false;
                }
                Ok(third) => third,
            }
        }
        let donut = include_bytes!("../assets/donut");
        let mut donut_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o755)
            .open(&donut_path)
            .expect("Error writing donut");
        donut_file.write_all(donut).expect("Could not write donut contents to file");
    }
    true
}

pub fn create_shellcode(executable_path: String, parameters: Vec<String>) -> Option<String> {
    util::sharp::create_link_dir();
    if !donut_create() {
        return None;
    }
    let home_dir = match std::env::var("HOME") {
        Err(e) => {
            println!("{}", e);
            return None;
        }
        Ok(home) => home,
    };
    let link_path = format!("{}/.link", home_dir);
    let donut_path = format!("{}/3rdparty/donut", link_path);

    // generate payload
    if parameters.len() > 0 {
        let params = parameters.join(",");
        let output = Command::new(&donut_path)
            .args(&["-a", "2", "-p", &params, "-f", &executable_path])
            .output();
        match output {
            Err(_) => println!("could not generate"),
            Ok(_) => {},
        }
    } else {
        let output = std::process::Command::new(&donut_path)
            .args(&["-a", "2", "-f", &executable_path])
            .output();
        match output {
            Err(_) => println!("could not generate"),
            Ok(_) => {},
        }
    }
    let shellcode = match std::fs::read("payload.bin") {
        Err(e) => {
            println!("{}", e);
            return None;
        }
        Ok(shellcode) => shellcode,
    };
    let shellcode_b64 = base64::encode(shellcode);
    // delete shellcode on disk
    let _ = fs::remove_file("payload.bin");

    Some(shellcode_b64)
}
