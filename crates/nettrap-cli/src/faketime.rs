//! FakeTime mode — manipulates time for all services to trigger malware time-bombs.
//! When enabled, all timestamps returned by NetTrap services use fake_now() instead of Utc::now().

use std::sync::atomic::{AtomicI64, Ordering};

/// Global time delta in seconds (added to real time)
static TIME_DELTA: AtomicI64 = AtomicI64::new(0);

/// Maximum absolute faketime delta (~100 years). Keeps the resulting time
/// arithmetic well inside chrono's representable range so `fake_now()` can
/// never overflow/panic.
const MAX_FAKETIME_DELTA_SECS: i64 = 100 * 365 * 86400;

fn clamp_delta(secs: i64) -> i64 {
    secs.clamp(-MAX_FAKETIME_DELTA_SECS, MAX_FAKETIME_DELTA_SECS)
}

/// Get current time with faketime delta applied
pub fn fake_now() -> chrono::DateTime<chrono::Utc> {
    let delta = TIME_DELTA.load(Ordering::Relaxed);
    fake_now_at(chrono::Utc::now(), delta)
}

/// Get the current faketime delta in seconds
pub fn get_delta() -> i64 {
    TIME_DELTA.load(Ordering::Relaxed)
}

/// Set the faketime delta
pub fn set_delta(delta_secs: i64) {
    let delta_secs = clamp_delta(delta_secs);
    TIME_DELTA.store(delta_secs, Ordering::Relaxed);
    tracing::info!(
        "FakeTime delta set to {} seconds ({} days)",
        delta_secs,
        delta_secs / 86400
    );
}

/// Add to the current delta (clamped to ±100 years to prevent overflow)
pub fn add_delta(secs: i64) {
    let current = TIME_DELTA.load(Ordering::Relaxed);
    let new_val = clamp_delta(current.saturating_add(secs));
    TIME_DELTA.store(new_val, Ordering::Relaxed);
}

fn fake_now_at(now: chrono::DateTime<chrono::Utc>, delta: i64) -> chrono::DateTime<chrono::Utc> {
    let Some(delta) = chrono::Duration::try_seconds(delta) else {
        return if delta >= 0 {
            chrono::DateTime::<chrono::Utc>::MAX_UTC
        } else {
            chrono::DateTime::<chrono::Utc>::MIN_UTC
        };
    };

    now.checked_add_signed(delta).unwrap_or_else(|| {
        if delta > chrono::Duration::seconds(0) {
            chrono::DateTime::<chrono::Utc>::MAX_UTC
        } else {
            chrono::DateTime::<chrono::Utc>::MIN_UTC
        }
    })
}

/// Start the auto-increment daemon task
pub async fn run_auto_increment(config: crate::config::FakeTimeConfig) {
    if !config.enabled || config.auto_delay_secs == 0 || config.auto_increment_secs == 0 {
        return;
    }

    if config.init_delta != 0 {
        set_delta(config.init_delta);
    }

    tracing::info!(
        "FakeTime auto-increment: +{} seconds every {} seconds",
        config.auto_increment_secs,
        config.auto_delay_secs
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(config.auto_delay_secs)).await;
        add_delta(config.auto_increment_secs);
        let total = get_delta();
        tracing::debug!(
            "FakeTime auto-increment: delta now {} seconds ({:.1} days)",
            total,
            total as f64 / 86400.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_delta_bounds_extreme_config_values() {
        assert_eq!(clamp_delta(i64::MAX), MAX_FAKETIME_DELTA_SECS);
        assert_eq!(clamp_delta(i64::MIN), -MAX_FAKETIME_DELTA_SECS);
        assert_eq!(clamp_delta(3600), 3600);
        assert_eq!(clamp_delta(0), 0);
    }

    #[test]
    fn fake_now_never_panics_for_extreme_delta() {
        set_delta(i64::MAX);
        let _ = fake_now();
        set_delta(i64::MIN);
        let _ = fake_now();
        set_delta(0);
    }

    #[test]
    fn fake_now_saturates_when_adjustment_exceeds_chrono_range() {
        let base = chrono::DateTime::from_timestamp(0, 0).expect("valid instant");

        assert_eq!(
            fake_now_at(base, i64::MAX),
            chrono::DateTime::<chrono::Utc>::MAX_UTC
        );
        assert_eq!(
            fake_now_at(base, i64::MIN),
            chrono::DateTime::<chrono::Utc>::MIN_UTC
        );
    }
}
