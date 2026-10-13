#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: u32,
}

impl RoundTripInfo {
    #[must_use]
    pub fn new(min_rtt: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt,
            updated_timestamp: 0,
        }
    }

    pub fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp) < 3000 {
            return;
        }
        self.updated_timestamp = current;
        self.rto = rto;
    }

    pub fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFF_FFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            self.variation = (3u32.wrapping_mul(self.variation).wrapping_add(delta)) / 4;
            self.srtt = (7u32.wrapping_mul(self.srtt).wrapping_add(rtt)) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.variation {
            self.srtt.wrapping_add(4u32.wrapping_mul(self.variation))
        } else {
            self.srtt.wrapping_add(self.variation)
        };
        let rto = rto.min(10_000);
        self.rto = rto.wrapping_mul(5) / 4;
        self.updated_timestamp = current;
    }

    #[must_use]
    pub fn timeout(&self) -> u32 {
        self.rto
    }

    #[must_use]
    pub fn smoothed_time(&self) -> u32 {
        self.srtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_rtt_seeds_the_estimate() {
        let mut r = RoundTripInfo::new(50);
        r.update(100, 0);
        assert_eq!(r.smoothed_time(), 100);
        assert_eq!(r.timeout(), (100 + 4 * 50) * 5 / 4);
    }

    #[test]
    fn rto_is_capped_at_ten_seconds_and_widened() {
        let mut r = RoundTripInfo::new(50);
        r.update(0, 0);
        r.update(0x7FFF_FF00, 1000);
        assert_eq!(r.timeout(), 12_500);
    }

    #[test]
    fn update_peer_rto_is_rate_limited_to_3s() {
        let mut r = RoundTripInfo::new(50);
        r.update(100, 100);
        r.update_peer_rto(400, 200);
        assert_ne!(r.timeout(), 400);
        r.update_peer_rto(400, 3500);
        assert_eq!(r.timeout(), 400);
    }

    #[test]
    fn the_srtt_floor_is_min_rtt() {
        let mut r = RoundTripInfo::new(200);
        r.update(300, 0);
        r.update(10, 100);
        assert!(r.smoothed_time() >= 200);
    }
}
