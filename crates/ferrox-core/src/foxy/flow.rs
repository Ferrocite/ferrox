//! Flow credit for one HTTP/2 window: the bytes the peer may send before it needs a `WINDOW_UPDATE`. A stream has one and a connection has another, and they are separate windows because a connection's credit is spent by every stream's bytes at once — one type, used once per window.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    bytes: i64,
}

impl Window {
    /// The window starts at the protocol default until the peer's settings say otherwise.
    #[must_use]
    pub const fn new(bytes: i64) -> Self {
        Self { bytes }
    }

    /// Raises the window by what the peer granted.
    pub fn add(&mut self, increment: u32) {
        self.bytes = self.bytes.saturating_add(i64::from(increment));
    }

    /// Moves the window by a change in the peer's `INITIAL_WINDOW_SIZE`: the setting applies to every stream, open or not, so a stream that is already running gains or loses the difference.
    pub fn shift(&mut self, delta: i64) {
        self.bytes = if delta >= 0 {
            self.bytes.saturating_add(delta)
        } else {
            // The magnitude is clamped before it is subtracted: a delta of `i64::MIN` cast to `i64` is still negative, and subtracting it would grow the window instead of emptying it.
            self.bytes
                .saturating_sub(delta.unsigned_abs().min(i64::MAX as u64) as i64)
        };
    }

    #[must_use]
    pub fn allows(&self, len: u32) -> bool {
        self.bytes >= i64::from(len)
    }

    /// Spends `len` bytes of credit. Only call this after `allows`.
    pub fn take(&mut self, len: u32) {
        self.bytes -= i64::from(len);
    }

    /// The credit left in the window.
    #[must_use]
    pub fn left(&self) -> u32 {
        self.bytes.max(0) as u32
    }
}

/// HTTP/2 spends at most the peer-advertised maximum frame size per DATA frame, so a longer slice is several frames.
#[must_use]
pub fn frame_size(available: usize, max_frame: usize) -> u32 {
    let capped = available.min(max_frame.max(1));
    u32::try_from(capped).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_allows_exactly_what_is_left_of_it() {
        let window = Window::new(10);
        assert!(window.allows(10));
        assert!(!window.allows(11), "one byte over is refused");
    }

    #[test]
    fn spending_credit_leaves_exactly_what_is_left() {
        let mut window = Window::new(100);
        window.take(30);
        assert_eq!(window.left(), 70);
        window.add(5);
        assert_eq!(window.left(), 75);
    }

    #[test]
    fn a_settings_change_moves_the_window_it_names() {
        let mut window = Window::new(65_535);
        window.add(1_048_576 - 65_535);
        assert_eq!(window.left(), 1_048_576);
    }

    #[test]
    fn a_peer_that_shrinks_its_window_takes_the_credit_back() {
        let mut window = Window::new(1_048_576);
        window.shift(-(1_048_576 - 65_535));
        assert_eq!(window.left(), 65_535);
        window.shift(i64::MIN);
        assert_eq!(window.left(), 0, "a window never goes below nothing");
    }

    #[test]
    fn a_peer_that_grows_its_window_raises_every_stream() {
        let mut window = Window::new(65_535);
        window.shift(1_048_576 - 65_535);
        assert_eq!(window.left(), 1_048_576);
    }

    #[test]
    fn credit_never_wraps_even_when_the_peer_over_announces() {
        let mut window = Window::new(i64::MAX - 1);
        window.add(u32::MAX);
        assert_eq!(window.left(), u32::MAX);
    }

    #[test]
    fn one_frame_is_at_most_the_peer_maximum() {
        assert_eq!(frame_size(1_000_000, 16_384), 16_384);
        assert_eq!(frame_size(100, 16_384), 100);
        assert_eq!(
            frame_size(1_000_000, 0),
            1,
            "a peer that allows nothing gets one byte"
        );
        assert_eq!(frame_size(usize::MAX, 16_384), 16_384);
    }
}
