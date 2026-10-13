use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    /// The window is open on the thread that opened it, so a thread outside measurement cannot charge its allocations to a window it has nothing to do with.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static ZEROED: AtomicUsize = AtomicUsize::new(0);

pub struct Counting;

#[inline]
fn tally(size: usize) {
    if COUNTING.with(Cell::get) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ZEROED.fetch_add(1, Ordering::Relaxed);
        }
        tally(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Closes the window on a panic, so a left-set flag cannot charge later allocations on this thread to a window that ended.
struct Window;

impl Drop for Window {
    fn drop(&mut self) {
        COUNTING.with(|counting| counting.set(false));
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub allocs: usize,
    pub bytes: usize,
    pub zeroed: usize,
}

impl Counts {
    pub fn per_iter(&self, iters: u64) -> f64 {
        self.allocs as f64 / iters as f64
    }

    pub fn bytes_per_iter(&self, iters: u64) -> f64 {
        self.bytes as f64 / iters as f64
    }
}

pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Counts) {
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ZEROED.store(0, Ordering::Relaxed);
    COUNTING.with(|counting| counting.set(true));
    let _window = Window;
    let out = f();
    (
        out,
        Counts {
            allocs: ALLOCS.load(Ordering::Relaxed),
            bytes: BYTES.load(Ordering::Relaxed),
            zeroed: ZEROED.load(Ordering::Relaxed),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Three relaxed stores an `Arc` owns, not a `Barrier`: a barrier's `wait` allocates inside the window it is only there to hold open.
    #[test]
    fn a_window_counts_its_own_thread_and_not_another() {
        const OPEN: usize = 1;
        const DONE: usize = 2;
        let phase = Arc::new(AtomicUsize::new(0));
        let worker = {
            let phase = Arc::clone(&phase);
            std::thread::spawn(move || {
                while phase.load(Ordering::Acquire) < OPEN {
                    std::hint::spin_loop();
                }
                let other = vec![0u8; 1 << 16];
                std::hint::black_box(&other);
                phase.store(DONE, Ordering::Release);
            })
        };
        let ((), counts) = measure(|| {
            phase.store(OPEN, Ordering::Release);
            while phase.load(Ordering::Acquire) < DONE {
                std::hint::spin_loop();
            }
            let mine = vec![0u8; 64];
            std::hint::black_box(&mine);
        });
        worker.join().expect("the other thread finishes");
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (1, 64, 1),
            "the window is this thread's alone: the 64 KiB the other thread \
             allocated while it was open is not in it, and this thread's one \
             zero-filled 64-byte vector is"
        );
    }
}
