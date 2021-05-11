use std::fs;
use std::ffi::c_void;
use goblin::pe::PE;

use crate::stdlib::get_wide;

pub fn refresh_dlls() {
    // load dlls
    let kernel32_bytes = match fs::read("C:\\Windows\\System32\\kernel32.dll") {
        Err(_) => return,
        Ok(kernel32) => kernel32,
    };
    let ntdll_bytes = match fs::read("C:\\Windows\\System32\\ntdll.dll") {
        Err(_) => return,
        Ok(ntdll) => ntdll,
    };
    // parse dlls
    let kernel32 = PE::parse(&kernel32_bytes).unwrap();
    let ntdll = PE::parse(&ntdll_bytes).unwrap();
    // find .text sections
    let mut k32_text_ptr: *mut c_void = 0 as _;
    let mut k32_text_size: usize = 0;
    let mut ntdll_text_ptr: *mut c_void = 0 as _;
    let mut ntdll_text_size: usize = 0;
    for i in 0..kernel32.sections.len() {
        if kernel32.sections[i].name().unwrap() == ".text" {
            k32_text_ptr = kernel32.sections[i].pointer_to_raw_data as *mut c_void;
            k32_text_size = kernel32.sections[i].size_of_raw_data as usize;
            break;
        }
    }
    for i in 0..ntdll.sections.len() {
        if ntdll.sections[i].name().unwrap() == ".text" {
            ntdll_text_ptr = ntdll.sections[i].pointer_to_raw_data as *mut c_void;
            ntdll_text_size = ntdll.sections[i].size_of_raw_data as usize;
            break;
        }
    }
    // get dll handles
    let loaded_k32 = unsafe {winapi::um::libloaderapi::LoadLibraryExW(get_wide("kernel32.dll").as_ptr(), 0 as _, 0 as _)};
    let loaded_ntdll = unsafe {winapi::um::libloaderapi::LoadLibraryExW(get_wide("ntdll.dll").as_ptr(), 0 as _, 0 as _)};
    // get .text address of dll
    let loaded_k32_text = unsafe{(loaded_k32 as *mut c_void).offset(0x1000)};
    let loaded_ntdll_text = unsafe{(loaded_ntdll as *mut c_void).offset(0x1000)};
    // write .text section of known good bytes into potentially bad dlls in memory
    // kernel32
    let pid = std::process::id();
    let handle = unsafe {winapi::um::processthreadsapi::OpenProcess(
        winapi::um::winnt::PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};
    let mut old_protect: u32 = 0;
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_k32_text,
        k32_text_size,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        &mut old_protect
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        loaded_k32_text,
        k32_text_ptr,
        k32_text_size,
        &mut ret_len
    )};
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_k32_text,
        k32_text_size,
        old_protect,
        &mut old_protect
    )};
    // ntdll
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_ntdll_text,
        ntdll_text_size,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        &mut old_protect
    )};
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        loaded_ntdll_text,
        ntdll_text_ptr,
        ntdll_text_size,
        &mut ret_len
    )};
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_ntdll_text,
        ntdll_text_size,
        old_protect,
        &mut old_protect
    )};
}
