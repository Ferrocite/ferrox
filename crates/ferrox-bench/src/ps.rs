use std::fmt;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSource {
    ProcStat,
    PsTime,
    GetProcessTimes,
}

impl CpuSource {
    pub fn current() -> Self {
        match Host::current() {
            Host::Linux => Self::ProcStat,
            Host::Windows => Self::GetProcessTimes,
            Host::Macos | Host::Other => Self::PsTime,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcStat => "/proc/<pid>/stat",
            Self::PsTime => "ps -o time=",
            Self::GetProcessTimes => "GetProcessTimes",
        }
    }

    pub fn resolution_millis(self) -> u64 {
        match self {
            Self::ProcStat => (1_000 / clock_ticks_per_second().max(1)).max(1),
            Self::PsTime if Host::current() == Host::Macos => 10,
            Self::GetProcessTimes => 1,
            Self::PsTime => 1_000,
        }
    }
}

const FALLBACK_TICKS_PER_SECOND: u64 = 100;

fn clock_ticks_per_second() -> u64 {
    static TICKS: OnceLock<u64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .filter(|t: &u64| *t > 0)
            .unwrap_or(FALLBACK_TICKS_PER_SECOND)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Linux,
    Macos,
    Windows,
    Other,
}

impl Host {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }

    fn args(self, pid: u32) -> Vec<String> {
        let mut args = vec!["-o".into(), "rss=".into(), "-o".into(), "time=".into()];
        if self == Self::Linux {
            args.extend(["-o".into(), "nlwp=".into()]);
        }
        args.extend(["-p".into(), pid.to_string()]);
        args
    }
}

/// What crossed the process's boundary through the VFS `read`/`write` paths: `rchar`/`wchar` and the
/// `syscr`/`syscw` that carried them. A `splice` or a `send`/`recv` socket crossing names neither, so a
/// small tally here says the instrument did not see the path, not that no bytes moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Io {
    pub read_calls: u64,
    pub write_calls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl Io {
    pub fn calls(&self) -> u64 {
        self.read_calls + self.write_calls
    }

    pub fn bytes(&self) -> u64 {
        self.read_bytes + self.write_bytes
    }

    /// The run's own crossing: each counter is monotonic, so the pair it reports is a difference.
    pub fn since(&self, first: &Io) -> Option<Io> {
        Some(Io {
            read_calls: self.read_calls.checked_sub(first.read_calls)?,
            write_calls: self.write_calls.checked_sub(first.write_calls)?,
            read_bytes: self.read_bytes.checked_sub(first.read_bytes)?,
            write_bytes: self.write_bytes.checked_sub(first.write_bytes)?,
        })
    }

    /// What the run crossed, read as the tallest sample that reached each counter rather than the last
    /// one's: the tally is a sum over the tasks still alive, so a thread-per-flow relay's worker
    /// threads take their counters with them when they exit and its final sample is the idle leader.
    /// A process whose tallies survive to the end already reports its tallest sample last, so this is
    /// the same pair `since` gives it; per-counter maxing keeps the task walk's floor, because each
    /// counter's own peak still bounds only what was counted.
    pub fn window(samples: impl IntoIterator<Item = Io>) -> Option<Io> {
        let mut samples = samples.into_iter();
        let first = samples.next()?;
        let tallest = samples.fold(first, |tall, io| Io {
            read_calls: tall.read_calls.max(io.read_calls),
            write_calls: tall.write_calls.max(io.write_calls),
            read_bytes: tall.read_bytes.max(io.read_bytes),
            write_bytes: tall.write_bytes.max(io.write_bytes),
        });
        tallest.since(&first)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub elapsed_ms: u128,
    pub rss_kib: u64,
    pub cpu_millis: u64,
    /// What the process itself ran; `None` on a source that has no split, i.e. a `ps` line.
    pub user_millis: Option<u64>,
    /// What the kernel ran on its behalf; the pair sums to `cpu_millis` wherever both exist.
    pub sys_millis: Option<u64>,
    pub threads: Option<u64>,
    /// The kernel's own tally of what the process asked it to move; `None` where there is no such file.
    pub io: Option<Io>,
}

#[derive(Debug)]
pub enum SampleError {
    Spawn(std::io::Error),
    Output {
        stderr: String,
    },
    Cpu {
        pid: u32,
        stderr: String,
    },
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Win32 {
        call: &'static str,
        code: u32,
    },
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "cannot run ps: {e}"),
            Self::Output { stderr } => write!(f, "ps reported no sample: {stderr}"),
            Self::Cpu { pid, stderr } => {
                write!(f, "cannot read cpu from /proc/{pid}/stat: {stderr}")
            }
            Self::Win32 { call, code } => write!(f, "{call} failed, GetLastError {code}"),
        }
    }
}

pub fn resolution_millis() -> u64 {
    CpuSource::current().resolution_millis()
}

pub fn sample(host: Host, pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
    #[cfg(target_os = "windows")]
    if host == Host::Windows {
        return win32::sample(pid, elapsed_ms);
    }
    let _ = host;
    let output = Command::new("ps")
        .args(host.args(pid))
        .output()
        .map_err(SampleError::Spawn)?;
    if !output.status.success() {
        return Err(SampleError::Output {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| SampleError::Output {
            stderr: format!("no sample line for pid {pid}"),
        })?;
    let mut sample = parse(line, elapsed_ms).ok_or(SampleError::Output {
        stderr: format!("unparsable ps sample `{line}`"),
    })?;
    if host == Host::Linux {
        let (user, sys) = proc_stat_cpu(pid).ok_or(SampleError::Cpu {
            pid,
            stderr: format!("no utime/stime in /proc/{pid}/stat"),
        })?;
        sample.cpu_millis = user + sys;
        sample.user_millis = Some(user);
        sample.sys_millis = Some(sys);
        sample.io = proc_io(pid);
    }
    Ok(sample)
}

/// What the process's threads crossed the boundary for, as one tally.
///
/// A relay's syscalls are made by its worker threads, not the one the harness spawned, so every task
/// under `/proc/<pid>/task/` is read and summed rather than trusting a single file; a task that dies
/// mid-walk only ever drops its own line, so the tally stays a floor. No `/proc` at all, or a runner
/// that hides it, is no tally rather than a failed run.
fn proc_io(pid: u32) -> Option<Io> {
    walked_io(pid).map(|(io, _tasks)| io)
}

/// The tally, with how many of the process's tasks were read into it: one task is the leader alone,
/// which is what a run's zero has to be told apart from.
fn walked_io(pid: u32) -> Option<(Io, usize)> {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).ok()?;
    let mut total: Option<(Io, usize)> = None;
    for task in tasks.flatten() {
        let Ok(text) = std::fs::read_to_string(task.path().join("io")) else {
            continue;
        };
        let Some(io) = parse_io(&text) else { continue };
        total = Some(match total {
            Some((sum, seen)) => (
                Io {
                    read_calls: sum.read_calls.saturating_add(io.read_calls),
                    write_calls: sum.write_calls.saturating_add(io.write_calls),
                    read_bytes: sum.read_bytes.saturating_add(io.read_bytes),
                    write_bytes: sum.write_bytes.saturating_add(io.write_bytes),
                },
                seen + 1,
            ),
            None => (io, 1),
        });
    }
    total
}

pub fn parse_io(text: &str) -> Option<Io> {
    let mut read_calls = None;
    let mut write_calls = None;
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(count) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "syscr:" => read_calls = Some(count),
            "syscw:" => write_calls = Some(count),
            "rchar:" => read_bytes = Some(count),
            "wchar:" => write_bytes = Some(count),
            _ => {}
        }
    }
    Some(Io {
        read_calls: read_calls?,
        write_calls: write_calls?,
        read_bytes: read_bytes?,
        write_bytes: write_bytes?,
    })
}

pub fn parse(line: &str, elapsed_ms: u128) -> Option<Sample> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    let rss_kib = fields[0].parse::<u64>().ok()?;
    let cpu_millis = parse_time_millis(fields[1])?;
    let threads = fields.get(2).and_then(|raw| raw.parse::<u64>().ok());
    Some(Sample {
        elapsed_ms,
        rss_kib,
        cpu_millis,
        user_millis: None,
        sys_millis: None,
        threads,
        io: None,
    })
}

pub fn parse_time_millis(raw: &str) -> Option<u64> {
    let (days, time) = match raw.split_once('-') {
        Some((days, time)) => (days.parse::<u64>().ok()?, time),
        None => (0, raw),
    };
    let parts: Vec<&str> = time.split(':').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let seconds: f64 = parts.last()?.parse().ok()?;
    let mut total = days
        .checked_mul(86_400_000)?
        .checked_add((seconds * 1000.0).round() as u64)?;
    for (offset, part) in parts[..parts.len() - 1].iter().enumerate() {
        let scale = 60u64.checked_pow((parts.len() - 1 - offset) as u32)?;
        total = total.checked_add(
            part.parse::<u64>()
                .ok()?
                .checked_mul(scale)?
                .checked_mul(1000)?,
        )?;
    }
    Some(total)
}

fn proc_stat_cpu(pid: u32) -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    proc_stat_times(&stat, clock_ticks_per_second())
}

fn proc_stat_times(stat: &str, ticks_per_second: u64) -> Option<(u64, u64)> {
    let (_, rest) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let millis = |index: usize| {
        fields
            .get(index)?
            .parse::<u64>()
            .ok()?
            .checked_mul(1_000)?
            .checked_div(ticks_per_second)
    };
    Some((millis(11)?, millis(12)?))
}

#[cfg(test)]
const FIXTURE_HZ: u64 = 100;

#[cfg(target_os = "windows")]
mod win32 {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{Sample, SampleError};

    fn failed(call: &'static str) -> SampleError {
        let code = unsafe { GetLastError() };
        SampleError::Win32 { call, code }
    }

    pub(super) fn sample(pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle == 0 {
            return Err(failed("OpenProcess"));
        }
        let sample = read(handle, pid, elapsed_ms);
        unsafe {
            CloseHandle(handle);
        }
        sample
    }

    fn read(handle: HANDLE, pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let times = unsafe {
            GetProcessTimes(
                handle,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if times == 0 {
            return Err(failed("GetProcessTimes"));
        }

        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        let memory = unsafe { GetProcessMemoryInfo(handle, &raw mut counters, counters.cb) };
        if memory == 0 {
            return Err(failed("GetProcessMemoryInfo"));
        }

        Ok(Sample {
            elapsed_ms,
            rss_kib: (counters.PeakWorkingSetSize / 1024) as u64,
            cpu_millis: super::cpu_millis_from_ticks(
                filetime_ticks(exit),
                filetime_ticks(kernel) + filetime_ticks(user),
            ),
            // A live process has no exit time, so the pair is the whole of `cpu_millis`.
            user_millis: Some(super::ticks_to_millis(filetime_ticks(user))),
            sys_millis: Some(super::ticks_to_millis(filetime_ticks(kernel))),
            threads: thread_count(pid).ok(),
            io: None,
        })
    }

    fn filetime_ticks(ft: FILETIME) -> u64 {
        super::ticks_from_parts(ft.dwHighDateTime, ft.dwLowDateTime)
    }

    fn thread_count(pid: u32) -> Result<u64, SampleError> {
        let snapshot = (0..4)
            .find_map(|_| {
                let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
                if handle == INVALID_HANDLE_VALUE || handle == 0 {
                    None
                } else {
                    Some(handle)
                }
            })
            .ok_or_else(|| failed("CreateToolhelp32Snapshot"))?;
        let count = count_threads(snapshot, pid);
        unsafe {
            CloseHandle(snapshot);
        }
        count
    }

    fn count_threads(snapshot: HANDLE, pid: u32) -> Result<u64, SampleError> {
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };
        let first = unsafe { Thread32First(snapshot, &raw mut entry) };
        if first == 0 {
            return Err(failed("Thread32First"));
        }
        let mut owners = vec![entry.th32OwnerProcessID];
        loop {
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snapshot, &raw mut entry) } == 0 {
                return Ok(super::count_owned(owners, pid));
            }
            owners.push(entry.th32OwnerProcessID);
        }
    }
}

#[cfg(any(target_os = "windows", test))]
pub fn ticks_from_parts(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(any(target_os = "windows", test))]
pub fn ticks_to_millis(ticks: u64) -> u64 {
    (ticks / 10_000) + u64::from((ticks % 10_000) >= 5_000)
}

#[cfg(any(target_os = "windows", test))]
pub fn cpu_millis_from_ticks(exit: u64, cpu: u64) -> u64 {
    ticks_to_millis(cpu.saturating_sub(exit))
}

#[cfg(any(target_os = "windows", test))]
fn count_owned(owners: impl IntoIterator<Item = u32>, pid: u32) -> u64 {
    owners.into_iter().filter(|owner| *owner == pid).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filetime_is_its_high_half_shifted_up() {
        assert_eq!(ticks_from_parts(0, 1), 1);
        assert_eq!(ticks_from_parts(0, u32::MAX), u64::from(u32::MAX));
        assert_eq!(ticks_from_parts(1, 0), 1 << 32);
        assert_eq!(ticks_from_parts(0, 10_000_000), 10_000_000);
    }

    #[test]
    fn ticks_round_to_the_nearest_millisecond() {
        assert_eq!(ticks_to_millis(0), 0);
        assert_eq!(ticks_to_millis(4_999), 0);
        assert_eq!(ticks_to_millis(5_000), 1, "half a millisecond rounds up");
        assert_eq!(ticks_to_millis(9_999), 1);
        assert_eq!(ticks_to_millis(10_000), 1);
        assert_eq!(ticks_to_millis(10_000_000), 1_000, "one second");
        assert_eq!(ticks_to_millis(u64::MAX), ticks_to_millis(u64::MAX));
        assert!(ticks_to_millis(u64::MAX) > 0);
    }

    #[test]
    fn cpu_excludes_what_the_process_had_already_spent() {
        assert_eq!(cpu_millis_from_ticks(0, 100_000_000), 10_000);
        assert_eq!(cpu_millis_from_ticks(10_000_000, 100_000_000), 9_000);
        assert_eq!(cpu_millis_from_ticks(20_000_000, 10_000_000), 0);
    }

    #[test]
    fn threads_are_counted_by_owner() {
        assert_eq!(count_owned(Vec::new(), 7), 0);
        assert_eq!(count_owned([7], 7), 1);
        assert_eq!(count_owned([7, 7, 7], 7), 3);
        assert_eq!(count_owned([1, 2, 7, 7, 9], 7), 2);
        assert_eq!(count_owned([1, 2, 3], 7), 0);
    }

    #[test]
    fn windows_resolves_far_more_finely_than_a_ps() {
        assert_eq!(CpuSource::GetProcessTimes.as_str(), "GetProcessTimes");
        assert_eq!(CpuSource::GetProcessTimes.resolution_millis(), 1);
        assert!(
            CpuSource::GetProcessTimes.resolution_millis() < CpuSource::PsTime.resolution_millis(),
            "a 100-nanosecond counter is finer than anything ps formats"
        );
    }

    #[test]
    fn parses_every_ps_time_shape() {
        assert_eq!(parse_time_millis("0.34"), Some(340));
        assert_eq!(parse_time_millis("1.50"), Some(1500));
        assert_eq!(parse_time_millis("12:34"), Some(754_000));
        assert_eq!(parse_time_millis("1:02:03"), Some(3_723_000));
        assert_eq!(parse_time_millis("2-00:00:00"), Some(172_800_000));
        assert_eq!(parse_time_millis("10-11:12:13"), Some(904_333_000));
        assert!(parse_time_millis("10-00:00:01").unwrap() > 864_000_000);
    }

    #[test]
    fn rejects_time_it_cannot_read() {
        for bad in ["", "-", "abc", "1:2:3:4", "1:x", "x:00"] {
            assert_eq!(parse_time_millis(bad), None, "{bad} must not parse");
        }
    }

    #[test]
    fn reads_rss_time_and_threads_in_order() {
        let s = parse("  12345 0:01.23 17 ", 500).expect("sample");
        assert_eq!(s.rss_kib, 12_345);
        assert_eq!(s.cpu_millis, 1230);
        assert_eq!(s.threads, Some(17));
        assert_eq!(s.elapsed_ms, 500);
    }

    #[test]
    fn macos_line_reports_no_thread_count() {
        let s = parse(" 4096 0:00.50 ", 0).expect("sample");
        assert_eq!(s.rss_kib, 4096);
        assert_eq!(s.cpu_millis, 500);
        assert_eq!(s.threads, None);
    }

    #[test]
    fn a_truncated_line_is_not_a_sample() {
        assert_eq!(parse("", 0), None);
        assert_eq!(parse("4096", 0), None);
        assert_eq!(parse("x 0:00.01", 0), None);
    }

    #[test]
    fn linux_asks_for_threads_and_macos_does_not() {
        assert!(Host::Linux.args(7).contains(&"nlwp=".to_owned()));
        assert!(!Host::Macos.args(7).contains(&"nlwp=".to_owned()));
        assert!(
            !Host::Windows.args(7).contains(&"nlwp=".to_owned()),
            "and windows never gets as far as ps at all"
        );
        for host in [Host::Linux, Host::Macos, Host::Windows, Host::Other] {
            let args = host.args(7);
            assert_eq!(args.first().map(String::as_str), Some("-o"));
            assert_eq!(args.last().map(String::as_str), Some("7"));
        }
    }

    #[test]
    fn the_kernel_tally_reads_the_four_lines_a_run_is_measured_by() {
        let io = parse_io(
            "rchar: 1091073826\nwchar: 1091072274\nsyscr: 35181\nsyscw: 33930\n\
             read_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n",
        )
        .expect("a whole tally");
        assert_eq!(io.read_calls, 35_181);
        assert_eq!(io.write_calls, 33_930);
        assert_eq!(io.read_bytes, 1_091_073_826);
        assert_eq!(io.write_bytes, 1_091_072_274);
        assert_eq!(io.calls(), 69_111, "the pair is one count of asks");
        assert_eq!(io.bytes(), 2_182_146_100, "and one count of bytes");
    }

    #[test]
    fn a_tally_missing_a_line_it_needs_is_no_tally() {
        for short in [
            "",
            "rchar: 1\nwchar: 2\nsyscr: 3\n",
            "rchar: n/a\nwchar: 2\nsyscr: 3\nsyscw: 4\n",
            "rchar 1\nwchar 2\nsyscr 3\nsyscw 4\n",
        ] {
            assert_eq!(parse_io(short), None, "{short:?} cannot be a whole tally");
        }
    }

    /// A writer thread that is not the leader has to land in the tally, and land in it once: the
    /// upper bound is what a walk over `/proc/<pid>/task/` cannot reach and a shared-per-thread
    /// reading of it would blow straight through.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_tally_counts_the_thread_that_made_the_writes() {
        const WRITTEN: u64 = 16 << 20;
        let pid = std::process::id();
        let before = proc_io(pid).expect("a linux process has per-thread io counters");
        let path = std::env::temp_dir().join(format!("ferrox-io-tally-{pid}"));
        let file_path = path.clone();
        let (done, wait_done) = std::sync::mpsc::channel::<()>();
        let (release, wait_release) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let mut file = std::fs::File::create(&file_path).expect("a temp file to write into");
            let zeroes = vec![0u8; 1 << 16];
            let mut left = WRITTEN as usize;
            while left > 0 {
                let take = left.min(zeroes.len());
                file.write_all(&zeroes[..take])
                    .expect("a write reaches the kernel");
                left -= take;
            }
            drop(file);
            done.send(()).expect("the tally is taken while parked");
            wait_release
                .recv()
                .expect("the parked writer thread is released");
        });
        wait_done
            .recv()
            .expect("the writer thread finishes its bytes");
        let after = proc_io(pid).expect("the tally is still readable");
        let delta = after.since(&before).expect("a counter only rises");
        assert!(
            delta.write_bytes >= WRITTEN,
            "{WRITTEN} B written by a worker thread, the tally saw {} B",
            delta.write_bytes
        );
        assert!(
            delta.write_bytes < WRITTEN * 2,
            "{WRITTEN} B written once, the tally reports {} B",
            delta.write_bytes
        );
        release.send(()).expect("the writer thread is parked");
        writer.join().expect("the writer thread ends");
        let _ = std::fs::remove_file(&path);
    }

    /// The engine is a *child* process, so the tally has to cross that boundary and land each byte
    /// once: a walk that reads `/proc/self` fine and a descendant's tasks not at all would bless the
    /// probe and then report a relay's run as zero, while a per-task file that already held the thread
    /// group's total would report the same bytes once per task.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_tally_counts_a_child_process_s_worker_thread() {
        const WRITTEN: u64 = 16 << 20;
        if let Some(job) = child_job() {
            return run_child_job(&job, WRITTEN as usize);
        }
        let path = std::env::temp_dir().join(format!("ferrox-io-child-{}", std::process::id()));
        let mut child = spawn_tally_child(
            "a_tally_counts_a_child_process_s_worker_thread",
            "file",
            &path.display().to_string(),
        );
        let pid = child.id();
        let mut seen: Option<(Io, usize)> = None;
        for _ in 0..400 {
            let tally = walked_io(pid);
            if tally
                .as_ref()
                .is_some_and(|(io, _)| io.write_bytes >= WRITTEN)
            {
                seen = tally;
                break;
            }
            seen = tally.or(seen);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let (io, tasks) = seen.unwrap_or_else(|| panic!("pid {pid} gives no tally at all"));
        assert!(
            io.write_bytes >= WRITTEN,
            "{WRITTEN} B written by a worker thread of a child, the tally of {tasks} tasks saw {} B",
            io.write_bytes
        );
        assert!(
            io.write_bytes < WRITTEN * 2,
            "{WRITTEN} B written once, the tally of {tasks} tasks reports {} B",
            io.write_bytes
        );
        release(&mut child);
        let _ = std::fs::remove_file(&path);
    }

    /// What the tally cannot see at all is a socket: `TcpStream` reaches the kernel through `send` and
    /// `recv`, and only `read`/`write` are counted, so a child that moves 16 MiB over loopback shows
    /// its startup bytes while the same child writing to a file shows every one of them. Every
    /// `io_*_per_gib` in the artefact is to be read against this row — a Rust engine's zero is the
    /// instrument's blind spot, not its traffic, and it says nothing about a Go engine's non-zero.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_tally_is_blind_to_a_socket_crossing_in_a_child_process() {
        const MOVED: u64 = 16 << 20;
        const BLIND: u64 = MOVED / 16;
        if let Some(job) = child_job() {
            return run_child_job(&job, MOVED as usize);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback sink");
        let addr = listener.local_addr().expect("its address");
        let mut child = spawn_tally_child(
            "the_tally_is_blind_to_a_socket_crossing_in_a_child_process",
            "socket",
            &addr.to_string(),
        );
        let pid = child.id();
        let mut sink = accept_bounded(&listener, pid);
        sink.set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .expect("the sink is drained within the run");
        let mut drained = vec![0u8; 1 << 16];
        let mut moved: u64 = 0;
        while moved < MOVED {
            use std::io::Read;
            let take = drained.len().min((MOVED - moved) as usize);
            let read = sink
                .read(&mut drained[..take])
                .expect("the child's bytes arrive");
            assert_ne!(
                read, 0,
                "the socket crossing ends after {moved} B of {MOVED}"
            );
            moved += read as u64;
        }
        let (io, tasks) = walked_io(pid).expect("the child process has a tally");
        assert!(
            io.bytes() < BLIND,
            "{MOVED} B crossed a socket and the tally of {tasks} tasks saw {} B: the reading is \
             counting the crossing after all, so the row above is wrong",
            io.bytes()
        );
        release(&mut child);
    }

    /// The job a spawned child runs instead of the test that spawned it.
    #[cfg(target_os = "linux")]
    fn child_job() -> Option<String> {
        std::env::var("FERROX_IO_CHILD").ok()
    }

    #[cfg(target_os = "linux")]
    fn spawn_tally_child(test: &str, job: &str, argument: &str) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .arg(test)
            .env("FERROX_IO_CHILD", job)
            .env("FERROX_IO_CHILD_ARG", argument)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("the tally reads a spawned process")
    }

    /// A child that never connects has to fail this witness rather than park it, so the accept is
    /// polled against a deadline instead of blocking on a connection that is not coming.
    #[cfg(target_os = "linux")]
    fn accept_bounded(listener: &std::net::TcpListener, pid: u32) -> std::net::TcpStream {
        use std::io::ErrorKind;
        listener
            .set_nonblocking(true)
            .expect("the sink accepts without blocking");
        for _ in 0..400 {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("the sink drains in blocking mode");
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => panic!("the sink cannot accept: {error}"),
            }
        }
        panic!("pid {pid} never connected to the loopback sink");
    }

    /// Closing the child's stdin is what ends its park; the parent takes the pipe before it waits.
    #[cfg(target_os = "linux")]
    fn release(child: &mut std::process::Child) {
        drop(child.stdin.take());
        let _ = child.wait();
    }

    /// The child's half of both witnesses: the bytes are made by a thread that is not the leader, and
    /// that thread then parks, so the parent reads a tally whose subject still has every
    /// byte-making task alive. A task that exits takes its own `rchar`/`wchar` out of
    /// `/proc/<pid>/task/` with it, so a walk over a finished writer would report the leader's
    /// startup bytes and call a 16 MiB crossing invisible even if the kernel had counted it.
    #[cfg(target_os = "linux")]
    fn run_child_job(job: &str, written: usize) {
        use std::io::{Read, Write};
        let argument =
            std::env::var("FERROX_IO_CHILD_ARG").expect("the child is told its argument");
        let (done, wait_done) = std::sync::mpsc::channel::<()>();
        let (park, writer_parked) = std::sync::mpsc::channel::<()>();
        let to_file = job == "file";
        std::thread::spawn(move || {
            let mut sink: Box<dyn Write> = if to_file {
                Box::new(
                    std::fs::File::create(&argument)
                        .expect("the child opens its file with a write"),
                )
            } else {
                Box::new(
                    std::net::TcpStream::connect(&argument)
                        .expect("the child reaches the loopback sink"),
                )
            };
            let zeroes = vec![0u8; 1 << 16];
            let mut left = written;
            while left > 0 {
                let take = left.min(zeroes.len());
                sink.write_all(&zeroes[..take])
                    .expect("the child's bytes reach the kernel");
                left -= take;
            }
            let _ = sink.flush();
            let _ = done.send(());
            let _ = writer_parked.recv();
        });
        let _ = wait_done.recv();
        let mut one = [0u8; 1];
        let _ = std::io::stdin().read(&mut one);
        drop(park);
    }

    #[test]
    fn the_tally_delta_is_the_run_and_stops_when_a_counter_rewinds() {
        let first = Io {
            read_calls: 10,
            write_calls: 20,
            read_bytes: 300,
            write_bytes: 400,
        };
        let last = Io {
            read_calls: 12,
            write_calls: 22,
            read_bytes: 360,
            write_bytes: 420,
        };
        let run = last.since(&first).expect("a monotonic pair");
        assert_eq!(run.calls(), 4);
        assert_eq!(run.bytes(), 80);
        let rewound = Io {
            read_calls: 9,
            ..last
        };
        assert_eq!(
            rewound.since(&first),
            None,
            "a counter that went backwards is not a difference to report"
        );
    }

    /// A run whose tallies survive to the end already reports its tallest sample last, so the window
    /// is the same pair and a process that does not fan out cannot move under it.
    #[test]
    fn a_window_over_samples_that_only_rise_is_the_last_since_the_first() {
        let first = Io {
            read_calls: 10,
            write_calls: 20,
            read_bytes: 300,
            write_bytes: 400,
        };
        let middle = Io {
            read_calls: 40,
            write_calls: 60,
            read_bytes: 900,
            write_bytes: 1_600,
        };
        let last = Io {
            read_calls: 70,
            write_calls: 90,
            read_bytes: 2_000,
            write_bytes: 3_000,
        };
        assert_eq!(
            Io::window([first, middle, last]),
            last.since(&first),
            "the tallest of a rising run is its last sample"
        );
    }

    /// A counter that fell when its thread exited keeps its peak, and a counter that kept rising is
    /// still read off the last sample: the window is per counter, not one sample chosen over another.
    #[test]
    fn a_window_keeps_the_counter_that_fell_when_its_thread_exited() {
        let window = Io::window([
            Io {
                read_calls: 1,
                write_calls: 0,
                read_bytes: 100,
                write_bytes: 0,
            },
            Io {
                read_calls: 9,
                write_calls: 700,
                read_bytes: 4_000,
                write_bytes: 8 << 20,
            },
            Io {
                read_calls: 12,
                write_calls: 3,
                read_bytes: 4_200,
                write_bytes: 0,
            },
        ])
        .expect("three tallies are a window");
        assert_eq!(
            window.write_calls, 700,
            "the joined thread's calls are priced"
        );
        assert_eq!(
            window.write_bytes,
            8 << 20,
            "and so are the bytes it wrote, though no sample holds both"
        );
        assert_eq!(
            window.read_calls, 11,
            "a counter that only rises is still the last over the first"
        );
        assert_eq!(window.read_bytes, 4_100);
    }

    /// The collapse the window exists for, measured on a thread this test really joined: exiting
    /// takes the counters out of the tally, so the last sample's delta reports the run as the idle
    /// leader's own bytes. That a live thread's writes reach the tally at all is
    /// `a_tally_counts_the_thread_that_made_the_writes`; this is the half it cannot see.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_joined_writer_thread_leaves_its_bytes_for_the_window_to_keep() {
        const WRITTEN: u64 = 8 << 20;
        let pid = std::process::id();
        let start = proc_io(pid).expect("a linux process has per-thread io counters");
        let path = std::env::temp_dir().join(format!("ferrox-io-window-{pid}"));
        let file_path = path.clone();
        let (written, wait_written) = std::sync::mpsc::channel::<()>();
        let (release, wait_release) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let mut file = std::fs::File::create(&file_path).expect("a temp file to write into");
            let zeroes = vec![0u8; 1 << 16];
            let mut left = WRITTEN as usize;
            while left > 0 {
                let take = left.min(zeroes.len());
                file.write_all(&zeroes[..take])
                    .expect("a write reaches the kernel");
                left -= take;
            }
            drop(file);
            written
                .send(())
                .expect("the peak tally is taken while the writer lives");
            wait_release
                .recv()
                .expect("the parked writer thread is released");
        });
        wait_written
            .recv()
            .expect("the writer thread finishes its bytes");
        let alive = proc_io(pid).expect("the tally is readable while its writer lives");
        release.send(()).expect("the writer thread is parked");
        writer.join().expect("the writer thread ends");
        let joined = proc_io(pid).expect("the tally is readable after its writer ends");
        assert!(
            alive.write_bytes >= joined.write_bytes + WRITTEN / 2,
            "{} B written by a thread that then exited: the tally fell from {} B to {} B",
            WRITTEN,
            alive.write_bytes,
            joined.write_bytes
        );
        let window = Io::window([start, alive, joined]).expect("three tallies are a window");
        let last_run = joined.since(&start).map_or(0, |io| io.write_bytes);
        assert!(
            window.write_bytes >= last_run + WRITTEN / 2,
            "the last sample prices the run at {last_run} B where its own peak reached {} B",
            window.write_bytes
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn proc_stat_reads_a_sub_second_cpu_that_ps_rounds_away() {
        let line = "1234 (ferrox-zer) S 1 1234 1234 0 -1 4194304 5000 0 0 0 \
                    9 4 0 0 20 0 3 0 1000 2000 0 0 0 0 0 0 0 0 0 0 0 0 0 \
                    0 20 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(
            proc_stat_times(line, FIXTURE_HZ),
            Some((90, 40)),
            "9 ticks of utime and 4 of stime at 100 Hz are 90 ms and 40 ms"
        );
        assert_eq!(
            parse_time_millis("00:00:00"),
            Some(0),
            "and this is the ps reading of the same process that it replaces"
        );
    }

    #[test]
    fn proc_stat_finds_the_fields_past_a_comm_with_spaces_in_it() {
        let line = "1234 (Web Content (tab)) R 1 2 3 0 0 0 0 0 0 0 7 5 0 0 20 0 1 \
                    0 100 200 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
                    0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(proc_stat_times(line, FIXTURE_HZ), Some((70, 50)));
        assert_eq!(
            proc_stat_times(line, 1_000),
            Some((7, 5)),
            "the same line at 1 kHz is a tenth of it, so the divisor is used"
        );
    }

    #[test]
    fn proc_stat_rejects_a_line_it_cannot_read() {
        for bad in ["", "1234 (x", "1234 (x) S 1 2"] {
            assert_eq!(
                proc_stat_times(bad, FIXTURE_HZ),
                None,
                "{bad} must not parse"
            );
        }
        assert_eq!(
            proc_stat_times("1234 (x) S 1 2 3 0 0 0 0 0 0 0 9 4", 0),
            None,
            "a zero divisor resolves nothing"
        );
    }

    #[test]
    fn only_a_source_with_two_counters_offers_a_split() {
        let line = "1234 (x) S 1 2 3 0 0 0 0 0 0 0 90 40";
        let (user, sys) = proc_stat_times(line, FIXTURE_HZ).expect("two fields");
        assert_eq!((user, sys), (900, 400));
        let ps_only = parse("4096 0:01.30 3", 0).expect("sample");
        assert_eq!(ps_only.user_millis, None, "a ps line has no split");
        assert_eq!(ps_only.sys_millis, None);
    }

    #[cfg(unix)]
    #[test]
    fn a_live_sample_reports_the_source_it_used() {
        let pid = std::process::id();
        let s = sample(Host::current(), pid, 0).expect("this process is sampleable");
        let floor = resolution_millis();
        assert_eq!(CpuSource::current().resolution_millis(), floor);
        assert!(floor > 0, "a published resolution of zero resolves nothing");
        assert!(s.rss_kib > 0, "a running process has a resident set");
        match Host::current() {
            Host::Linux => {
                let before = proc_stat_cpu(pid)
                    .map(|(u, s)| u + s)
                    .expect("this process has a /proc entry");
                let sampled = sample(Host::current(), pid, 0).expect("this process is sampleable");
                let after = proc_stat_cpu(pid)
                    .map(|(u, s)| u + s)
                    .expect("this process has a /proc entry");
                assert!(
                    before <= sampled.cpu_millis && sampled.cpu_millis <= after,
                    "linux cpu comes from /proc only: {sampled:?} against {before}..={after}"
                );
                assert_eq!(
                    sampled
                        .user_millis
                        .zip(sampled.sys_millis)
                        .map(|(u, s)| u + s),
                    Some(sampled.cpu_millis),
                    "the two /proc counters are the whole of the one cpu number"
                );
                assert!(floor <= 10, "/proc resolves a tick, not a second");
                assert!(s.threads.is_some(), "linux ps can count threads");
            }
            Host::Macos => {
                assert_eq!(floor, 10, "macOS ps prints hundredths");
                assert!(s.threads.is_none(), "macOS ps cannot count threads");
                assert_eq!(s.user_millis, None, "a ps line offers no split here");
            }
            #[cfg(target_os = "windows")]
            Host::Windows => {
                let s = sample(host, pid, 0).expect("windows samples through the API");
                assert!(
                    s.cpu_millis < 60_000,
                    "this process has not used a CPU-minute"
                );
                assert!(s.rss_kib > 0, "a running process has a resident set");
                assert!(
                    s.threads.is_some(),
                    "ToolHelp counts this process's threads"
                );
            }
            #[cfg(not(target_os = "windows"))]
            Host::Windows => assert_eq!(floor, CpuSource::GetProcessTimes.resolution_millis()),
            Host::Other => assert_eq!(floor, 1_000),
        }
    }

    #[test]
    fn the_published_resolution_is_the_current_sources_own() {
        let source = CpuSource::current();
        assert_eq!(resolution_millis(), source.resolution_millis());
        assert!(resolution_millis() > 0, "a floor of zero resolves nothing");
        assert_eq!(
            source,
            match Host::current() {
                Host::Linux => CpuSource::ProcStat,
                Host::Windows => CpuSource::GetProcessTimes,
                Host::Macos | Host::Other => CpuSource::PsTime,
            },
            "the source a row names must be the branch sample() takes"
        );
    }
}
