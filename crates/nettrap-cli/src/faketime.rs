//! FakeTime mode — manipulates time for all services to trigger malware time-bombs.
//! When enabled, all timestamps returned by NetTrap services use fake_now() instead of Utc::now().

use std::sync::atomic::{AtomicI64, Ordering};

/// Global time delta in seconds (added to real time)
static TIME_DELTA: AtomicI64 = AtomicI64::new(0);

/// Get current time with faketime delta applied
pub fn fake_now() -> chrono::DateTime<chrono::Utc> {
    let delta = TIME_DELTA.load(Ordering::Relaxed);
    chrono::Utc::now() + chrono::Duration::seconds(delta)
}

/// Get the current faketime delta in seconds
pub fn get_delta() -> i64 {
    TIME_DELTA.load(Ordering::Relaxed)
}

/// Set the faketime delta
pub fn set_delta(delta_secs: i64) {
    TIME_DELTA.store(delta_secs, Ordering::Relaxed);
    tracing::info!(
        "FakeTime delta set to {} seconds ({} days)",
        delta_secs,
        delta_secs / 86400
    );
}

/// Add to the current delta (clamped to ±100 years to prevent overflow)
pub fn add_delta(secs: i64) {
    const MAX_DELTA: i64 = 100 * 365 * 86400; // ~100 years
    let current = TIME_DELTA.load(Ordering::Relaxed);
    let new_val = current.saturating_add(secs).clamp(-MAX_DELTA, MAX_DELTA);
    TIME_DELTA.store(new_val, Ordering::Relaxed);
}

/// Start the auto-increment daemon task
pub async fn run_auto_increment(config: crate::config::FakeTimeConfig) {
    if !config.enabled || config.auto_delay_secs == 0 || config.auto_increment_secs == 0 {
        return;
    }

    // Set initial delta
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
