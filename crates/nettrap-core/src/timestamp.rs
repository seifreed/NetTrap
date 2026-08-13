pub type Timestamp = chrono::DateTime<chrono::Utc>;

pub fn now() -> Timestamp {
    chrono::Utc::now()
}

pub fn unix_timestamp() -> i64 {
    system_time_unix_secs(std::time::SystemTime::now())
}

pub fn unix_timestamp_ms() -> i128 {
    system_time_unix_millis(std::time::SystemTime::now())
}

pub fn unix_timestamp_ns() -> i128 {
    system_time_unix_nanos(std::time::SystemTime::now())
}

fn system_time_unix_secs(now: std::time::SystemTime) -> i64 {
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(err) => {
            let before_epoch = err.duration();
            let Ok(seconds) = i64::try_from(before_epoch.as_secs()) else {
                return i64::MIN;
            };
            let borrow = i64::from(before_epoch.subsec_nanos() != 0);
            seconds
                .checked_add(borrow)
                .and_then(|seconds| seconds.checked_neg())
                .unwrap_or(i64::MIN)
        }
    }
}

fn system_time_unix_millis(now: std::time::SystemTime) -> i128 {
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i128::try_from(elapsed.as_millis()).unwrap_or(i128::MAX),
        Err(err) => {
            let before_epoch = err.duration();
            let millis = i128::try_from(before_epoch.as_millis()).unwrap_or(i128::MAX);
            let borrow = i128::from(before_epoch.subsec_nanos() % 1_000_000 != 0);
            millis
                .checked_add(borrow)
                .and_then(|millis| millis.checked_neg())
                .unwrap_or(i128::MIN)
        }
    }
}

fn system_time_unix_nanos(now: std::time::SystemTime) -> i128 {
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i128::try_from(elapsed.as_nanos()).unwrap_or(i128::MAX),
        Err(err) => i128::try_from(err.duration().as_nanos())
            .ok()
            .and_then(i128::checked_neg)
            .unwrap_or(i128::MIN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unix_timestamp_helpers_preserve_pre_epoch_times() {
        let pre_epoch = std::time::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch time should be representable");

        assert_eq!(system_time_unix_secs(pre_epoch), -1);
        assert_eq!(system_time_unix_millis(pre_epoch), -1_000);
        assert_eq!(system_time_unix_nanos(pre_epoch), -1_000_000_000);
    }

    #[test]
    fn unix_timestamp_seconds_borrow_for_pre_epoch_fractional_instants() {
        let pre_epoch = std::time::UNIX_EPOCH
            .checked_sub(Duration::new(0, 500_000_000))
            .expect("pre-epoch time should be representable");

        assert_eq!(system_time_unix_secs(pre_epoch), -1);
        assert_eq!(system_time_unix_millis(pre_epoch), -500);
        assert_eq!(system_time_unix_nanos(pre_epoch), -500_000_000);
    }

    #[test]
    fn unix_timestamp_millis_borrow_for_submillisecond_pre_epoch_instants() {
        let pre_epoch = std::time::UNIX_EPOCH
            .checked_sub(Duration::new(0, 500_000))
            .expect("pre-epoch time should be representable");

        assert_eq!(system_time_unix_secs(pre_epoch), -1);
        assert_eq!(system_time_unix_millis(pre_epoch), -1);
        assert_eq!(system_time_unix_nanos(pre_epoch), -500_000);
    }

    #[test]
    #[cfg(not(windows))]
    fn unix_timestamp_seconds_saturate_for_representable_deep_pre_epoch_times() {
        let pre_epoch = std::time::UNIX_EPOCH
            .checked_sub(Duration::from_secs(i64::MAX as u64 + 1))
            .expect("deep pre-epoch time should be representable");

        assert_eq!(system_time_unix_secs(pre_epoch), i64::MIN);
    }
}
