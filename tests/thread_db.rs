use nix::sys::personality::Persona;
use nix::sys::signal::raise;
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::{signal, uio};
use nix::unistd::Pid;
use nix::{libc, sys};
use object::elf::DT_DEBUG;
use object::{Object, ObjectSection};
use serial_test::serial;
use std::error::Error;
use std::io::IoSliceMut;
use std::os::unix::prelude::CommandExt;
use std::process::Command;
use std::time::Duration;
use std::{fs, mem, thread};
use thread_db::Lib;

#[test]
#[serial]
fn test_n_threads() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::ptrace::traceme().unwrap();
            let thread = thread::spawn(|| std::thread::sleep(Duration::from_millis(2000)));

            raise(signal::SIGSTOP).unwrap();

            thread.join().unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();

            assert_eq!(process.thread_count().unwrap(), 2);

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[test]
#[serial]
fn test_find_thread_by_lwpid() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::ptrace::traceme().unwrap();
            let thread = thread::spawn(|| thread::sleep(Duration::from_millis(1000)));

            raise(signal::SIGSTOP).unwrap();

            thread.join().unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();
            let thread = process.get_thread(child);

            assert!(thread.is_ok());
            assert!(thread.unwrap().validate().is_ok());

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[test]
#[serial]
fn test_collect_threads() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::ptrace::traceme().unwrap();
            let thread = thread::spawn(|| thread::sleep(Duration::from_millis(1000)));

            raise(signal::SIGSTOP).unwrap();

            thread.join().unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();
            let threads = process.collect_threads().unwrap();

            assert_eq!(threads.len(), 2);

            assert!(threads[0].validate().is_ok());
            assert!(threads[1].validate().is_ok());

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[test]
#[serial]
fn test_thread_info() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::ptrace::traceme().unwrap();
            let thread = thread::spawn(|| thread::sleep(Duration::from_millis(1000)));

            raise(signal::SIGSTOP).unwrap();

            thread.join().unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();
            let threads = process.collect_threads().unwrap();

            let thread_info_0 = threads[0].info().unwrap();
            let thread_info_1 = threads[1].info().unwrap();

            assert_ne!(thread_info_0.ti_lid, thread_info_1.ti_lid);
            assert!(
                thread_info_0.ti_lid == child.as_raw() || thread_info_1.ti_lid == child.as_raw()
            );

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[test]
#[serial]
fn test_thread_tls_base() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::personality::set(Persona::ADDR_NO_RANDOMIZE).unwrap();
            sys::ptrace::traceme().unwrap();
            let thread = thread::spawn(|| std::thread::sleep(Duration::from_millis(1000)));

            raise(signal::SIGSTOP).unwrap();
            thread.join().unwrap();
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();
            let childs = process.collect_threads().unwrap();

            assert_eq!(childs.len(), 2);

            let tls_base_0 = childs[0].tls_base(1).unwrap();
            let tls_base_1 = childs[1].tls_base(1).unwrap();

            assert!(!tls_base_0.is_null());
            assert!(!tls_base_1.is_null());
            assert_ne!(tls_base_0, tls_base_1);

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[test]
#[serial]
fn test_thread_get_tls_addr() {
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork().unwrap() } {
        ForkResult::Child => {
            sys::personality::set(Persona::ADDR_NO_RANDOMIZE).unwrap();
            sys::ptrace::traceme().unwrap();
            Command::new("./target/debug/tls_test").exec();
        }
        ForkResult::Parent { child } => {
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();
            sys::ptrace::cont(child, None).unwrap();
            sys::wait::waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();

            let bin_data = fs::read("./target/debug/tls_test").unwrap();
            let object = object::File::parse(&*bin_data).unwrap();

            let lib = Lib::try_load().unwrap();
            let process = lib.attach(child).unwrap();

            let childs = process.collect_threads().unwrap();

            let first_map = &proc_maps::get_process_maps(child.as_raw()).unwrap()[0];
            let rendezvous = resolve_rendezvous(child, &object, first_map.start()).unwrap();

            let link_map: usize = rendezvous.link_map as usize;

            // todo tls variables offsets are selected manually, perhaps this part should be simplified
            let tls_addr = childs[0].tls_addr(link_map, 44).unwrap();
            let thread_loc_var = read_from_proc::<i32>(child, &mut (tls_addr as usize)).unwrap();
            assert_eq!(thread_loc_var, 3);

            let tls_addr = childs[1].tls_addr(link_map, 44).unwrap();
            let thread_loc_var = read_from_proc::<i32>(child, &mut (tls_addr as usize)).unwrap();
            assert_eq!(thread_loc_var, 4);

            sys::ptrace::cont(child, None).unwrap();
            let status = sys::wait::waitpid(child, None).unwrap();
            assert!(matches!(status, WaitStatus::Exited(_, 0)));
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Rendezvous {
    r_version: i32,
    link_map: *const libc::c_void,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct LinkMap {
    l_addr: *mut libc::c_void, /* Difference between the
                               address in the ELF file and
                               the address in memory */
    l_name: *const libc::c_char, /* Absolute pathname where
                                 object was found */
    l_ld: *mut libc::c_void, /* Dynamic section of the
                             shared object */
    l_next: *mut libc::c_void,
    l_prev: *mut libc::c_void,
}

fn read_from_proc<T: Copy>(pid: Pid, addr: &mut usize) -> Result<T, Box<dyn Error>> {
    let size = mem::size_of::<T>();
    let mut buff = vec![0; size];
    let local_iov = IoSliceMut::new(buff.as_mut_slice());
    let remote_iov = RemoteIoVec {
        base: *addr,
        len: size,
    };
    let mut local_iov_vec = vec![local_iov];

    uio::process_vm_readv(pid, local_iov_vec.as_mut_slice(), &[remote_iov])?;
    let ptr = local_iov_vec[0].as_ptr();

    let val_ptr: *const T = ptr.cast::<T>();
    let val = unsafe { *val_ptr };

    *addr += size;

    Ok(val)
}

fn resolve_rendezvous(
    pid: Pid,
    obj: &object::File,
    base_map_addr: usize,
) -> Result<Rendezvous, Box<dyn Error>> {
    let dyn_sect = obj.section_by_name(".dynamic").unwrap();
    let mut addr = dyn_sect.address() as usize;
    addr += base_map_addr;

    let mut val = read_from_proc::<usize>(pid, &mut addr).unwrap();

    while val != 0 {
        if val == DT_DEBUG as usize {
            let mut rend_addr = read_from_proc::<usize>(pid, &mut addr).unwrap();
            let rendezvous = read_from_proc::<Rendezvous>(pid, &mut rend_addr)?;
            return Ok(rendezvous);
        }

        val = read_from_proc::<usize>(pid, &mut addr).unwrap();
    }

    unreachable!()
}
