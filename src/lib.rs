pub mod ffi;
mod proc_service;

use crate::ffi::{
    ProcHandle, TdErr, TdTaStats, TdThrAgent, TdThrHandle, TdThrInfo, TdThrState, ThreadDb,
};
use dlopen::wrapper::Container;
use nix::libc;
use nix::unistd::Pid;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::{io, mem};

#[derive(Debug, thiserror::Error)]
pub enum ThreadDbError {
    #[error("thread_db error: {0:?}")]
    LibError(TdErr),
    #[error(transparent)]
    LoadError(#[from] dlopen::Error),
    #[error("make process handle error: {0}")]
    ProcHandleError(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, ThreadDbError>;

macro_rules! td_call {
    ($td_expr: expr) => {{
        let err = $td_expr;
        match err {
            TdErr::Ok => Ok(()),
            _ => Err(ThreadDbError::LibError(err)),
        }
    }};
}

pub struct Lib {
    inner: Container<ThreadDb>,
}

impl Lib {
    const LIB_THREAD_DB: &'static str = "libthread_db.so.1";

    pub fn try_load() -> Result<Self> {
        let container: Container<ThreadDb> = unsafe { Container::load(Self::LIB_THREAD_DB)? };
        unsafe {
            td_call!(container.td_init())?;
        }

        Ok(Self { inner: container })
    }

    pub fn attach(&self, process_pid: Pid) -> Result<Process> {
        let mut proc_handle = Box::pin(ProcHandle::new(process_pid)?);
        let mut thread_agent: *mut TdThrAgent = std::ptr::null_mut();

        unsafe {
            td_call!(self.inner.td_ta_new(
                &mut *proc_handle as *mut ProcHandle,
                &mut thread_agent as *mut *mut TdThrAgent,
            ))?;
        }

        Ok(Process {
            lib: &self.inner,
            proc_handle,
            thread_agent,
        })
    }
}

/// Represent linux process.
pub struct Process<'a> {
    lib: &'a Container<ThreadDb>,
    #[allow(unused)]
    proc_handle: Pin<Box<ProcHandle>>,
    thread_agent: *mut TdThrAgent,
}

impl<'a> Process<'a> {
    /// Returns process thread count.
    pub fn thread_count(&self) -> Result<i32> {
        let mut result: i32 = -1;
        unsafe { td_call!(self.lib.td_ta_get_nthreads(self.thread_agent, &mut result))? };
        Ok(result)
    }

    /// Returns process thread with lwpid == pid.
    /// If thread not exists returns generic `TdErr::Err` (unfortunately this behavior is set in thread_db impl).
    #[cfg(target_arch = "x86_64")]
    pub fn get_thread(&self, pid: Pid) -> Result<Thread> {
        unsafe {
            let mut handle: TdThrHandle = MaybeUninit::zeroed().assume_init();

            td_call!(self.lib.td_ta_map_lwp2thr(
                self.thread_agent,
                pid.as_raw(),
                &mut handle as *mut TdThrHandle,
            ))?;

            Ok(Thread {
                lib: self.lib,
                handle,
            })
        }
    }

    /// Returns all process threads.
    pub fn collect_threads(&self) -> Result<Vec<Thread>> {
        // Appends the thread handle to the Vec<Process> in cbdata.
        unsafe extern "C" fn thr_iter_callback(
            handle: *const TdThrHandle,
            cbdata: *mut libc::c_void,
        ) -> i32 {
            let threads = cbdata as *mut Vec<TdThrHandle>;
            (*threads).push(*handle);
            0
        }

        let mut handles: Vec<TdThrHandle> = Vec::new();
        unsafe {
            let sigmask = nix::sys::signal::SigSet::empty();
            let mut c_sigmask = *sigmask.as_ref();
            td_call!(self.lib.td_ta_thr_iter(
                self.thread_agent,
                thr_iter_callback,
                &mut handles as *mut _ as *mut libc::c_void,
                TdThrState::AnyState,
                0,
                &mut c_sigmask,
                0,
            ))?;
        }
        Ok(handles
            .into_iter()
            .map(|handle| Thread {
                lib: self.lib,
                handle,
            })
            .collect())
    }

    /// Enable collecting statistics for process associated with TA.
    /// ! This function not implemented in glibc.
    pub fn enable_stats(&mut self, enable: bool) -> Result<()> {
        unsafe {
            td_call!(self
                .lib
                .td_ta_enable_stats(self.thread_agent, enable as i32))
        }
    }

    /// Reset statistics.
    /// ! This function not implemented in glibc.
    pub fn reset_stats(&mut self) -> Result<()> {
        unsafe { td_call!(self.lib.td_ta_reset_stats(self.thread_agent)) }
    }

    /// Retrieve statistics from process associated with TA.
    /// ! This function not implemented in glibc.
    pub fn get_stats(&self) -> Result<TdTaStats> {
        let mut stats = MaybeUninit::<TdTaStats>::uninit();
        unsafe {
            td_call!(self
                .lib
                .td_ta_get_stats(self.thread_agent, stats.as_mut_ptr()))?;
            Ok(stats.assume_init())
        }
    }
}

impl<'a> Drop for Process<'a> {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = td_call!(self.lib.td_ta_delete(self.thread_agent)) {
                panic!("thread_db: td_ta_delete returns {}", e);
            }
        }
    }
}

/// Represent linux lwp.
pub struct Thread<'a> {
    lib: &'a Container<ThreadDb>,
    handle: TdThrHandle,
}

impl<'a> Thread<'a> {
    /// Validate that TH is a thread handle.
    pub fn validate(&self) -> Result<()> {
        unsafe { td_call!(self.lib.td_thr_validate(&self.handle)) }
    }

    pub fn info(&self) -> Result<TdThrInfo> {
        unsafe {
            let mut info = MaybeUninit::<TdThrInfo>::uninit();
            td_call!(self.lib.td_thr_get_info(&self.handle, info.as_mut_ptr()))?;
            Ok(info.assume_init())
        }
    }

    /// Get address of the given module's TLS storage area for the given thread.
    /// Note that for a given running process the module ID for the main executable will always be 1.
    pub fn tls_base(&self, modid: u32) -> Result<*const libc::c_void> {
        unsafe {
            let mut base_addr: *mut libc::c_void = mem::zeroed();
            td_call!(self.lib.td_thr_tlsbase(
                &self.handle,
                modid,
                &mut base_addr as *mut *mut libc::c_void
            ))?;
            Ok(base_addr)
        }
    }

    /// Get address of thread local variable.
    /// map_addr - address of module link_map struct.
    pub fn tls_addr(&self, map_addr: usize, offset: usize) -> Result<*const libc::c_void> {
        unsafe {
            let mut addr: *mut libc::c_void = mem::zeroed();
            td_call!(self.lib.td_thr_tls_get_addr(
                &self.handle,
                map_addr as *const libc::c_void,
                offset,
                &mut addr as *mut *mut libc::c_void
            ))?;
            Ok(addr)
        }
    }
}
