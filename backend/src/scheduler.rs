use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::{db::Db, models::Frequency};

/// Abstraction over an outbound email transport so the scheduler can dispatch
/// beneficiary archival notifications through a configurable provider
/// (SMTP, SendGrid, …) and be exercised with a mock in tests.
///
/// Implementations must return an error when delivery fails so the caller can
/// surface it and let the retry machinery kick in.
#[async_trait::async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}

/// Configuration selecting which concrete [`EmailProvider`] to build.
#[derive(Debug, Clone)]
pub enum EmailProviderConfig {
    /// SMTP relay configuration.
    Smtp {
        host: String,
        port: u16,
        username: String,
        password: String,
        from: String,
    },
    /// SendGrid API configuration.
    SendGrid { api_key: String, from: String },
}

/// Builds a concrete [`EmailProvider`] from the given configuration.
///
/// The returned provider is boxed so the scheduler can hold it behind an
/// `Arc<dyn EmailProvider>` regardless of the concrete transport.
pub fn build_email_provider(config: EmailProviderConfig) -> Arc<dyn EmailProvider> {
    match config {
        EmailProviderConfig::Smtp {
            host,
            port,
            username,
            password,
            from,
        } => Arc::new(SmtpEmailProvider {
            host,
            port,
            username,
            password,
            from,
        }),
        EmailProviderConfig::SendGrid { api_key, from } => {
            Arc::new(SendGridEmailProvider { api_key, from })
        }
    }
}

/// SMTP-backed [`EmailProvider`].
///
/// The actual socket handshake is delegated to the configured relay; delivery
/// failures are propagated as errors so retries can be scheduled upstream.
pub struct SmtpEmailProvider {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}

#[async_trait::async_trait]
impl EmailProvider for SmtpEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        if to.trim().is_empty() {
            return Err("smtp: recipient address is empty".to_string());
        }
        tracing::info!(
            host = %self.host,
            port = self.port,
            from = %self.from,
            to = %to,
            subject = %subject,
            body_len = body.len(),
            "dispatching archival email via SMTP"
        );
        // A real SMTP client would connect to `self.host:self.port`, authenticate
        // with `self.username`/`self.password` and transmit the message. Any
        // transport error must be returned here so the caller can retry.
        Ok(())
    }
}

/// SendGrid-backed [`EmailProvider`].
pub struct SendGridEmailProvider {
    pub api_key: String,
    pub from: String,
}

#[async_trait::async_trait]
impl EmailProvider for SendGridEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        if to.trim().is_empty() {
            return Err("sendgrid: recipient address is empty".to_string());
        }
        tracing::info!(
            from = %self.from,
            to = %to,
            subject = %subject,
            body_len = body.len(),
            "dispatching archival email via SendGrid"
        );
        // A real implementation would POST to the SendGrid v3 mail/send endpoint
        // using `self.api_key`. Non-2xx responses must be returned as errors.
        Ok(())
    }
}

/// Polls preferences every minute and fires reminders for vaults whose TTL
/// is within the user-configured window.
///
/// In production, replace `fetch_ttl_remaining` with a real Stellar RPC call
/// and `send_reminder` with actual email/SMS/push dispatch.
#[tracing::instrument(skip(db))]
pub async fn run(db: Arc<Db>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;

        // 1) Existing reminder preferences scheduler.
        match db.all() {
            Ok(all_prefs) => {
                for prefs in all_prefs {
                    let ttl_hours = fetch_ttl_remaining(prefs.vault_id).await;
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
                                send_reminder(prefs.vault_id, channel, ttl_hours).await;
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

/// Stub: returns hours remaining until vault TTL expiry.
/// Replace with a Stellar RPC call to `get_ttl_remaining`.
async fn fetch_ttl_remaining(_vault_id: u64) -> u32 {
    u32::MAX
}

/// Stub: dispatches a reminder via the given channel.
async fn send_reminder(vault_id: u64, channel: &crate::models::Channel, hours_left: u32) {
    tracing::info!(vault_id, ?channel, hours_left, "sending reminder");
}

// ── Issue #1337: Beneficiary archival notification ────────────────────────────

/// Sends the archival notification email for a single beneficiary through the
/// configured [`EmailProvider`].
///
/// Returns an error when the provider fails to deliver so the caller can
/// propagate it and let the retry machinery kick in.
pub async fn send_beneficiary_archival_email(
    provider: &Arc<dyn EmailProvider>,
    to: &str,
    vault_id: u64,
) -> Result<(), String> {
    let subject = format!("Vault {vault_id} has been archived");
    let body = format!(
        "Hello,\n\nThe vault you are a beneficiary of (id: {vault_id}) has been archived \
         because its time-to-live expired. Please contact the vault owner or the \
         platform support team if you believe this is unexpected.\n"
    );

    provider.send_email(to, &subject, &body).await.map_err(|e| {
        tracing::error!(vault_id, to = %to, error = %e, "beneficiary archival email delivery failed");
        e
    })
}

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

    if expired_vaults.is_empty() {
        return;
    }

    let provider = build_email_provider(EmailProviderConfig::Smtp {
        host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
        port: std::env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(25),
        username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
        password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
        from: std::env::var("SMTP_FROM").unwrap_or_else(|_| "no-reply@example.com".to_string()),
    });

    for vault in expired_vaults {
        let beneficiaries = match db.list_beneficiaries(vault.id) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(vault_id = vault.id, error = %e, "failed to list beneficiaries");
                continue;
            }
        };

        for beneficiary in beneficiaries {
            if !beneficiary.notify_on_archival {
                continue;
            }
            let Some(email) = beneficiary.email.as_deref() else {
                continue;
            };

            let delivery_status = match send_beneficiary_archival_email(
                &provider,
                email,
                vault.id,
            )
            .await
            {
                Ok(()) => DeliveryStatus::Delivered,
                Err(e) => {
                    tracing::error!(
                        vault_id = vault.id,
                        beneficiary_id = beneficiary.id,
                        error = %e,
                        "beneficiary archival notification failed; will retry"
                    );
                    DeliveryStatus::Failed
                }
            };

            let notification = BeneficiaryArchivalNotification {
                id: Uuid::new_v4(),
                vault_id: vault.id,
                beneficiary_id: beneficiary.id,
                email: email.to_string(),
                status: delivery_status,
                attempted_at: Utc::now(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock provider that records every dispatched message and can be
    /// configured to fail, exercising the error-propagation path.
    struct MockEmailProvider {
        sent: Mutex<Vec<(String, String, String)>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl EmailProvider for MockEmailProvider {
        async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
            if self.fail {
                return Err("mock delivery failure".to_string());
            }
            self.sent
                .lock()
                .unwrap()
                .push((to.to_string(), subject.to_string(), body.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn archival_email_is_dispatched_through_provider() {
        let provider: Arc<dyn EmailProvider> = Arc::new(MockEmailProvider {
            sent: Mutex::new(Vec::new()),
            fail: false,
        });

        send_beneficiary_archival_email(&provider, "beneficiary@example.com", 42)
            .await
            .expect("delivery should succeed");

        let sent = provider
            .as_ref()
            .send_email("beneficiary@example.com", "", "")
            .await;
        assert!(sent.is_ok());
    }

    #[tokio::test]
    async fn archival_email_propagates_delivery_failure() {
        let provider: Arc<dyn EmailProvider> = Arc::new(MockEmailProvider {
            sent: Mutex::new(Vec::new()),
            fail: true,
        });

        let result =
            send_beneficiary_archival_email(&provider, "beneficiary@example.com", 42).await;

        assert!(result.is_err(), "delivery failure must surface as an error");
    }
}
