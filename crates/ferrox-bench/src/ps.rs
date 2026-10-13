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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub elapsed_ms: u128,
    pub rss_kib: u64,
    pub cpu_millis: u64,
    pub threads: Option<u64>,
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
        sample.cpu_millis = proc_stat_cpu(pid).ok_or(SampleError::Cpu {
            pid,
            stderr: format!("no utime/stime in /proc/{pid}/stat"),
        })?;
    }
    Ok(sample)
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
        threads,
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

fn proc_stat_cpu(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    proc_stat_millis(&stat, clock_ticks_per_second())
}

fn proc_stat_millis(stat: &str, ticks_per_second: u64) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ticks = fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)?;
    let millis = ticks.checked_mul(1_000)?;
    millis.checked_div(ticks_per_second)
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
            threads: thread_count(pid).ok(),
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
    fn proc_stat_reads_a_sub_second_cpu_that_ps_rounds_away() {
        let line = "1234 (ferrox-zer) S 1 1234 1234 0 -1 4194304 5000 0 0 0 \
                    9 4 0 0 20 0 3 0 1000 2000 0 0 0 0 0 0 0 0 0 0 0 0 0 \
                    0 20 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(
            proc_stat_millis(line, FIXTURE_HZ),
            Some(130),
            "9 + 4 ticks at 100 Hz is 130 ms"
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
        assert_eq!(proc_stat_millis(line, FIXTURE_HZ), Some(120));
        assert_eq!(
            proc_stat_millis(line, 1_000),
            Some(12),
            "the same line at 1 kHz is a twelfth of it, so the divisor is used"
        );
    }

    #[test]
    fn proc_stat_rejects_a_line_it_cannot_read() {
        for bad in ["", "1234 (x", "1234 (x) S 1 2"] {
            assert_eq!(
                proc_stat_millis(bad, FIXTURE_HZ),
                None,
                "{bad} must not parse"
            );
        }
        assert_eq!(
            proc_stat_millis("1234 (x) S 1 2 3 0 0 0 0 0 0 0 9 4", 0),
            None,
            "a zero divisor resolves nothing"
        );
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
                let before = proc_stat_cpu(pid).expect("this process has a /proc entry");
                let sampled = sample(Host::current(), pid, 0).expect("this process is sampleable");
                let after = proc_stat_cpu(pid).expect("this process has a /proc entry");
                assert!(
                    before <= sampled.cpu_millis && sampled.cpu_millis <= after,
                    "linux cpu comes from /proc only: {sampled:?} against {before}..={after}"
                );
                assert!(floor <= 10, "/proc resolves a tick, not a second");
                assert!(s.threads.is_some(), "linux ps can count threads");
            }
            Host::Macos => {
                assert_eq!(floor, 10, "macOS ps prints hundredths");
                assert!(s.threads.is_none(), "macOS ps cannot count threads");
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
