//! Counting allocator for tests: the window is thread-local and one at a time process-wide, so an unmeasured thread adds nothing. The binary that wants it installs `Counting` as its `#[global_allocator]`, which is how a test in one crate counts what another crate allocates.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static ZEROED: AtomicUsize = AtomicUsize::new(0);
static BUSY: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct Counting;

/// Closes the window even when the measured closure panics, so a set flag cannot charge a later test.
struct Window;

impl Drop for Window {
    fn drop(&mut self) {
        COUNTING.with(|counting| counting.set(false));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub allocs: usize,
    pub bytes: usize,
    pub zeroed: usize,
}

/// Counts what the closure allocates on this thread, and only that.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Counts) {
    let one_at_a_time = BUSY.lock().expect("the window is not poisoned");
    let window = Window;
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ZEROED.store(0, Ordering::Relaxed);
    COUNTING.with(|counting| counting.set(true));
    let out = f();
    drop(window);
    // Read the counters while the lock is still held: a concurrent window's reset could otherwise land between the last allocation and the read, and a test would count zero for a closure that allocated.
    let counts = Counts {
        allocs: ALLOCS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        zeroed: ZEROED.load(Ordering::Relaxed),
    };
    drop(one_at_a_time);
    (out, counts)
}

impl Default for Counting {
    fn default() -> Self {
        Self
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            ZEROED.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(test)]
#[global_allocator]
static ALLOC: Counting = Counting;

#[cfg(test)]
mod tests {
    use super::*;

    /// The window counts this thread and stops there, so a closure's allocations are not the binary's.
    #[test]
    fn the_window_counts_this_thread_and_only_this_thread() {
        let handle = std::thread::spawn(|| {
            let elsewhere = vec![0u8; 1 << 16];
            std::hint::black_box(&elsewhere);
        });
        handle.join().expect("the other thread finishes");
        let ((), counts) = measure(|| {
            let mine = vec![0u8; 64];
            std::hint::black_box(&mine);
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (1, 64, 1),
            "the other thread's 64 KiB is not in a window it was not part of"
        );
    }

    /// A `Vec` growing into itself is a reallocation a buffer could have avoided.
    #[test]
    fn growth_is_a_reallocation_and_a_prefilled_one_is_not() {
        let ((), grown) = measure(|| {
            let mut v = Vec::new();
            for at in 0..64 {
                v.push(at);
            }
            std::hint::black_box(&v);
        });
        assert!(grown.allocs > 1, "growing pays a reallocation per step");
        let ((), filled) = measure(|| {
            let v = vec![0u8; 64];
            std::hint::black_box(&v);
        });
        assert_eq!(filled.allocs, 1, "one buffer, allocated once");
    }

    /// Relay-buffer shape: capacity plus `set_len` asks for the bytes without the zero fill `vec![0u8; n]` pays for.
    #[test]
    fn an_uninitialised_tail_is_allocated_but_not_filled() {
        #[allow(
            clippy::uninit_vec,
            reason = "the window never reads through the buffer, only at it"
        )]
        fn capacity_and_len(len: usize) -> Vec<u8> {
            let mut buf = Vec::with_capacity(len);
            // SAFETY: nothing reads the bytes this leaves uninitialised, so no uninitialised value is observed.
            unsafe { buf.set_len(len) };
            buf
        }
        let ((), bare) = measure(|| {
            let buf = capacity_and_len(16_384);
            std::hint::black_box(&buf);
        });
        let ((), zeroed) = measure(|| {
            let buf = vec![0u8; 16_384];
            std::hint::black_box(&buf);
        });
        assert_eq!(
            (bare.allocs, bare.bytes, bare.zeroed),
            (zeroed.allocs, zeroed.bytes, 0),
            "the same allocation and the same bytes, and the fill is the only difference"
        );
        assert_eq!(
            zeroed.zeroed, 1,
            "`vec![0u8; n]` is one zero-filled allocation"
        );
    }
}
