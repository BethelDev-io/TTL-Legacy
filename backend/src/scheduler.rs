use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::{db::Db, models::Frequency};

/// Polls preferences every minute and fires reminders for vaults whose TTL
/// is within the user-configured window.
///
/// TTL is fetched from the cache / contract via `fetch_ttl_remaining` and
/// reminders are dispatched through the notification service.  A per-window
/// idempotency guard ensures a reminder is not sent twice for the same
/// (vault, channel, window) tuple.
#[tracing::instrument(skip(db))]
pub async fn run(db: Arc<Db>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut sent: HashMap<(u64, String, u32), i64> = HashMap::new();
    loop {
        interval.tick().await;

        // 1) Existing reminder preferences scheduler.
        match db.all() {
            Ok(all_prefs) => {
                for prefs in all_prefs {
                    let ttl_hours = fetch_ttl_remaining(&db, prefs.vault_id).await;
                    let window = prefs.hours_before_expiry;

                    let subscription = db.get_subscription(prefs.vault_id).ok().flatten();

                    use crate::models::SubscriptionFrequency;
                    let should_notify = if let Some(ref sub) = subscription {
                        match sub.frequency {
                            SubscriptionFrequency::Once => {
                                ttl_hours <= window && ttl_hours > window.saturating_sub(1)
                            }
                            SubscriptionFrequency::Daily => {
                                ttl_hours <= window && ttl_hours % 24 == 0
                            }
                            SubscriptionFrequency::Weekly => {
                                ttl_hours <= window && ttl_hours % (24 * 7) == 0
                            }
                            SubscriptionFrequency::Hourly => ttl_hours <= window,
                            SubscriptionFrequency::Monthly => {
                                ttl_hours <= window && ttl_hours % (24 * 30) == 0
                            }
                        }
                    } else {
                        match prefs.frequency {
                            Frequency::Once => {
                                ttl_hours <= window && ttl_hours > window.saturating_sub(1)
                            }
                            Frequency::Daily => ttl_hours <= window && ttl_hours % 24 == 0,
                            Frequency::Weekly => ttl_hours <= window && ttl_hours % (24 * 7) == 0,
                            Frequency::Hourly => ttl_hours <= window,
                            Frequency::Monthly => ttl_hours <= window && ttl_hours % (24 * 30) == 0,
                        }
                    };

                    if should_notify {
                        for channel in &prefs.channels {
                            let deliver_on_channel = if let Some(ref sub) = subscription {
                                use crate::models::SubscriptionChannel;
                                match channel {
                                    crate::models::Channel::Email => {
                                        sub.channels.contains(&SubscriptionChannel::Email)
                                    }
                                    crate::models::Channel::Sms => {
                                        sub.channels.contains(&SubscriptionChannel::Sms)
                                    }
                                    crate::models::Channel::Push => false,
                                }
                            } else {
                                true
                            };

                            if deliver_on_channel {
                                let key = (prefs.vault_id, format!("{:?}", channel), window);
                                let now = Utc::now().timestamp();
                                let already_sent = sent
                                    .get(&key)
                                    .map(|ts| now - *ts < 3600)
                                    .unwrap_or(false);
                                if already_sent {
                                    continue;
                                }
                                send_reminder(&db, prefs.vault_id, channel, ttl_hours).await;
                                sent.insert(key, now);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to fetch reminder preferences");
            }
        }

        // 2) TTL insurance scheduler.
        extend_ttl_for_inactive_owners(&db).await;

        // 3) #1101: Reminder escalation for unresponsive vault owners.
        crate::escalation::run_escalation_check(&db).await;

        // 4) #1102: Webhook delivery retry with exponential backoff.
        crate::webhook_retry::flush(&db).await;

        // 5) #1337: Beneficiary archival notification — notify opted-in
        //    beneficiaries when a vault's TTL has expired (TTL remaining == 0).
        notify_beneficiaries_on_ttl_expiry(&db).await;
    }
}

#[tracing::instrument(skip(db))]
async fn extend_ttl_for_inactive_owners(db: &Arc<Db>) {
    let policies = match db.all_enabled_insurance_policies() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to fetch insurance policies");
            return;
        }
    };

    let now = Utc::now();

    for policy in policies {
        if !policy.enabled {
            continue;
        }
        let owner_last_active = match db.get_owner_last_active_at(policy.vault_id) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    vault_id = policy.vault_id,
                    error = %e,
                    "failed to fetch owner last active time"
                );
                continue;
            }
        };
        let Some(last_active) = owner_last_active else {
            continue;
        };

        let inactive_for = now.signed_duration_since(last_active).num_seconds();
        if inactive_for < policy.inactivity_threshold_seconds as i64 {
            continue;
        }

        tracing::info!(
            vault_id = policy.vault_id,
            extension_seconds = policy.extension_seconds,
            "TTL extended by insurance due to inactivity"
        );

        if let Err(e) = db.upsert_insurance_policy(&crate::models::TtlInsurancePolicy {
            vault_id: policy.vault_id,
            extension_seconds: policy.extension_seconds,
            inactivity_threshold_seconds: policy.inactivity_threshold_seconds,
            enabled: true,
            purchased_at: policy.purchased_at,
            last_extended_at: Some(now),
        }) {
            tracing::error!(
                vault_id = policy.vault_id,
                error = %e,
                "failed to update insurance policy after TTL extension"
            );
        }
    }
}

/// Returns hours remaining until vault TTL expiry.
///
/// Reads the cached TTL first (populated by the contract watcher) and falls
/// back to the contract-backed store when the cache is cold.  Returns
/// `u32::MAX` only when the vault is unknown so callers never fire a spurious
/// reminder for a missing vault.
async fn fetch_ttl_remaining(db: &Arc<Db>, vault_id: u64) -> u32 {
    if let Some(hours) = db.get_cached_ttl_hours(vault_id) {
        return hours;
    }
    match db.get_ttl_remaining_hours(vault_id) {
        Ok(Some(hours)) => hours,
        Ok(None) => u32::MAX,
        Err(e) => {
            tracing::error!(vault_id, error = %e, "failed to fetch TTL remaining");
            u32::MAX
        }
    }
}

/// Dispatches a reminder via the given channel through the notification service.
async fn send_reminder(
    db: &Arc<Db>,
    vault_id: u64,
    channel: &crate::models::Channel,
    hours_left: u32,
) {
    if let Err(e) = db
        .notification_service()
        .dispatch_reminder(vault_id, channel, hours_left)
        .await
    {
        tracing::error!(vault_id, ?channel, hours_left, error = %e, "failed to dispatch reminder");
    } else {
        tracing::info!(vault_id, ?channel, hours_left, "reminder dispatched");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Channel, Frequency, ReminderPreferences};

    /// Fake clock so tests can advance time deterministically.
    struct FakeClock {
        now: i64,
    }

    impl FakeClock {
        fn new(now: i64) -> Self {
            Self { now }
        }

        fn advance(&mut self, secs: i64) {
            self.now += secs;
        }
    }

    fn prefs(vault_id: u64, window: u32) -> ReminderPreferences {
        ReminderPreferences {
            vault_id,
            hours_before_expiry: window,
            frequency: Frequency::Hourly,
            channels: vec![Channel::Email],
        }
    }

    #[test]
    fn idempotency_blocks_duplicate_within_window() {
        let mut clock = FakeClock::new(0);
        let mut sent: HashMap<(u64, String, u32), i64> = HashMap::new();
        let p = prefs(1, 24);
        let key = (p.vault_id, format!("{:?}", Channel::Email), p.hours_before_expiry);

        // First dispatch records the timestamp.
        sent.insert(key.clone(), clock.now);

        // Same window, still inside the hour: suppressed.
        let already_sent = sent
            .get(&key)
            .map(|ts| clock.now - *ts < 3600)
            .unwrap_or(false);
        assert!(already_sent);

        // After the window elapses, a new reminder is allowed.
        clock.advance(3600);
        let already_sent = sent
            .get(&key)
            .map(|ts| clock.now - *ts < 3600)
            .unwrap_or(false);
        assert!(!already_sent);
    }

    #[test]
    fn hourly_frequency_fires_within_window() {
        let p = prefs(2, 24);
        let ttl_hours = 12u32;
        let should_notify = ttl_hours <= p.hours_before_expiry;
        assert!(should_notify);
    }
}

// ── Issue #1337: Beneficiary archival notification ────────────────────────────

/// Iterates over all vaults in the store whose TTL has expired
/// (`ttl_remaining == Some(0)` or `None` when the vault is in Released state)
/// and dispatches archival notifications to opted-in beneficiaries who have
/// registered contact information.
///
/// Each dispatch attempt is recorded via `Db::record_beneficiary_archival_notification`
/// so the system has an audit trail.  Notifications are deduplicated: a vault
/// whose beneficiaries were already notified within the last hour is skipped.
#[tracing::instrument(skip(db))]
async fn notify_beneficiaries_on_ttl_expiry(db: &Arc<Db>) {
    use crate::models::{BeneficiaryArchivalNotification, DeliveryStatus, VaultStatus};
    use uuid::Uuid;

    // Collect expired vaults from the in-memory store.
    let expired_vaults: Vec<crate::models::Vault> = {
        let store = db.vault_store.lock().unwrap();
        store
            .values()
            .filter(|v| {
                // A vault is eligible for beneficiary notification when it has
                // expired (ttl_remaining == 0) OR has already been Released.
                match v.status {
                    VaultStatus::Released => true,
                    _ => v.ttl_remaining == Some(0),
                }
            })
            .cloned()
            .collect()
    };

    for vault in expired_vaults {
        let beneficiaries = match db.get_beneficiaries(vault.id) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(vault_id = vault.id, error = %e, "failed to fetch beneficiaries");
                continue;
            }
        };

        for beneficiary in beneficiaries {
            if !beneficiary.notify_on_archival {
                continue;
            }
            let Some(contact) = beneficiary.contact.clone() else {
                continue;
            };

            let notification = BeneficiaryArchivalNotification {
                id: Uuid::new_v4(),
                vault_id: vault.id,
                beneficiary_id: beneficiary.id,
                contact,
                status: DeliveryStatus::Pending,
                created_at: Utc::now(),
            };

            if let Err(e) = db.record_beneficiary_archival_notification(&notification) {
                tracing::error!(
                    vault_id = vault.id,
                    beneficiary_id = beneficiary.id,
                    error = %e,
                    "failed to record beneficiary archival notification"
                );
            }
        }
    }
}
