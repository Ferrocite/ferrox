//! One bound for the management services: a slot is held for a connection's whole life, so the
//! accept loop can refuse rather than grow a thread per peer.

use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct Slots {
    active: AtomicUsize,
    max: usize,
}

pub(crate) struct Slot<'a>(&'a Slots);

impl Slots {
    pub(crate) const fn new(max: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max,
        }
    }

    pub(crate) fn acquire(&self) -> Option<Slot<'_>> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Slot(self)),
                Err(current) => active = current,
            }
        }
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_refused_past_its_bound_and_returned_on_drop() {
        let slots = Slots::new(2);
        let first = slots.acquire().expect("first");
        let second = slots.acquire().expect("second");
        assert!(slots.acquire().is_none(), "the bound is the cap");
        drop(first);
        let third = slots.acquire().expect("a returned slot");
        drop((second, third));
        assert!(slots.acquire().is_some(), "every slot came back");
    }
}
