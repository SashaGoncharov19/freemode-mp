//! Process management — Job Objects for process lifecycle control.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows::core::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, SetInformationJobObject, JobObjectExtendedLimitInformation,
};
use windows::Win32::System::Threading::{
    CreateJobObjectW, OpenJobObjectW, PROCESS_CREATE_PROCESS, JOB_OBJECT_BASIC_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};

/// Manages a game process via Windows Job Object.
pub struct JobManager {
    job_handle: HANDLE,
}

impl JobManager {
    /// Create a new Job Object with kill-on-close and breakaway enabled.
    pub fn new(name: &str) -> Result<Self> {
        let job_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Try to open existing job, or create new
            let job_handle = CreateJobObjectW(None, &job_name)?;

            // Set limits: kill all processes when job closes
            let info = JOB_OBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
                ActiveLimitFlags: 0,
                ..Default::default()
            };

            let extended_info = JOB_OBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: info,
                ..Default::default()
            };

            SetInformationJobObject(
                job_handle,
                JobObjectExtendedLimitInformation,
                Some(&extended_info),
                std::mem::size_of::<JOB_OBJECT_EXTENDED_LIMIT_INFORMATION>(),
            )?;

            Ok(JobManager { job_handle })
        }
    }

    /// Add a process to this job.
    pub fn add_process(&self, process_handle: HANDLE) -> Result<()> {
        unsafe {
            AssignProcessToJobObject(self.job_handle, process_handle)?;
            Ok(())
        }
    }

    /// Check if a process is in this job.
    pub fn is_process_in_job(&self, process_handle: HANDLE) -> Result<bool> {
        unsafe {
            let mut in_job = false;
            IsProcessInJob(process_handle, self.job_handle, &mut in_job);
            Ok(in_job)
        }
    }

    /// Get the raw job handle.
    pub fn handle(&self) -> HANDLE {
        self.job_handle
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.job_handle).ok();
        }
    }
}

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// Wait for a process to appear by name.
pub fn wait_for_process(name: &str, timeout_secs: u64) -> Option<u32> {
    use std::thread;
    use std::time::Duration;
    use sysinfo::{ProcessExt, System, SystemExt};

    let mut sys = System::new_all();
    let start = std::time::Instant::now();

    loop {
        sys.refresh_processes();
        if let Some((_, proc)) = sys.processes().iter().find(|(_, p)| p.name() == name) {
            return Some(proc.pid().as_u32());
        }

        if start.elapsed() > Duration::from_secs(timeout_secs) {
            return None;
        }

        thread::sleep(Duration::from_millis(500));
    }
}

/// Get information about a running process.
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    use sysinfo::{ProcessExt, System, SystemExt};

    let mut sys = System::new_all();
    sys.refresh_processes();

    sys.processes().get_by_pid(&pid.into()).map(|proc| {
        ProcessInfo {
            pid,
            name: proc.name().to_string_lossy().to_string(),
            path: proc.exe().to_string_lossy().to_string(),
        }
    })
}
