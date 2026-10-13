#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsafeOptIn {
    plaintext_to_public: bool,
    unsafe_fingerprint: bool,
}

impl UnsafeOptIn {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            plaintext_to_public: false,
            unsafe_fingerprint: false,
        }
    }

    #[must_use]
    pub const fn allow_plaintext_to_public(mut self) -> Self {
        self.plaintext_to_public = true;
        self
    }

    #[must_use]
    pub const fn allow_unsafe_fingerprint(mut self) -> Self {
        self.unsafe_fingerprint = true;
        self
    }

    #[must_use]
    pub const fn plaintext_to_public(self) -> bool {
        self.plaintext_to_public
    }

    #[must_use]
    pub const fn unsafe_fingerprint(self) -> bool {
        self.unsafe_fingerprint
    }
}

impl Default for UnsafeOptIn {
    fn default() -> Self {
        Self::none()
    }
}
