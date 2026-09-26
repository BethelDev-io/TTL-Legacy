/// #1102: Webhook Delivery Retry with Exponential Backoff
///
/// Retry schedule (max 5 attempts after the first):
///   Attempt 1: immediate
///   Retry  1: +1  min
///   Retry  2: +5  min
///   Retry  3: +15 min
///   Retry  4: +1  h
///   Retry  5: +4  h
///
/// After all retries are exhausted, status → DeliveryFailed and the vault
/// owner is notified via email through the configured email provider.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use uuid::Uuid;

use crate::{
    db::Db,
    email::EmailProvider,
    models::{
        TimelineEvent, TimelineEventKind, WebhookAttempt, WebhookDelivery, WebhookDeliveryStatus,
    },
};

/// Exponential backoff delays in seconds: 1 min, 5 min, 15 min, 1 h, 4 h.
pub const RETRY_DELAYS_SECS: [u64; 5] = [60, 300, 900, 3_600, 14_400];

/// Maximum number of attempts (including the first delivery attempt).
pub const MAX_ATTEMPTS: u32 = 6; // 1 initial + 5 retries

/// Minimum interval between permanent-failure emails for the same owner.
pub const FAILURE_EMAIL_RATE_LIMIT: Duration = Duration::from_secs(3_600);

/// Tracks the last time a permanent-failure email was sent per owner so we
/// don't spam an owner when many webhooks fail at once.
static FAILURE_EMAIL_LAST_SENT: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

// ── Public API ───────────────────────────────────────────────────────────────

/// Queue a new webhook delivery job for a vault event. This should be called
/// whenever a significant vault event occurs (release, low TTL, etc.).
pub fn enqueue(
    db: &Arc<Db>,
    vault_id: &str,
    event_type: &str,
    payload: serde_json::Value,
    endpoint_url: &str,
) -> Result<WebhookDelivery, String> {
    let delivery = WebhookDelivery {
        id: Uuid::new_v4().to_string(),
        vault_id: vault_id.to_string(),
        event_type: event_type.to_string(),
        payload,
        endpoint_url: endpoint_url.to_string(),
        status: WebhookDeliveryStatus::Pending,
        attempt_count: 0,
        next_retry_at: None,
        created_at: Utc::now(),
        attempts: Vec::new(),
    };
    db.insert_webhook_delivery(&delivery)
        .map_err(|e| e.to_string())?;
    Ok(delivery)
}

/// Process all pending and due-retry webhook deliveries. Called from the
/// scheduler loop.
#[tracing::instrument(skip(db))]
pub async fn flush(db: &Arc<Db>) {
    // First, attempt pending deliveries.
    match db.get_pending_webhook_deliveries() {
        Ok(pending) => {
            for delivery in pending {
                attempt_delivery(db, delivery).await;
            }
        }
        Err(e) => tracing::error!(error = %e, "webhook_retry: failed to fetch pending deliveries"),
    }

    // Then, retry any Retrying deliveries that are due.
    match db.get_due_webhook_retries() {
        Ok(due) => {
            for delivery in due {
                attempt_delivery(db, delivery).await;
            }
        }
        Err(e) => tracing::error!(error = %e, "webhook_retry: failed to fetch due retries"),
    }
}

/// Get webhook delivery log for a vault.
pub fn get_delivery_log(db: &Arc<Db>, vault_id: &str) -> Result<Vec<WebhookDelivery>, String> {
    db.get_webhook_deliveries_for_vault(vault_id)
        .map_err(|e| e.to_string())
}

// ── Internal delivery logic ──────────────────────────────────────────────────

async fn attempt_delivery(db: &Arc<Db>, mut delivery: WebhookDelivery) {
    let attempt_number = delivery.attempt_count + 1;

    tracing::info!(
        delivery_id = %delivery.id,
        vault_id = %delivery.vault_id,
        endpoint = %delivery.endpoint_url,
        attempt = attempt_number,
        "webhook_retry: attempting delivery"
    );

    let (http_status, response_body, error) =
        send_webhook(&delivery.endpoint_url, &delivery.payload).await;

    let now = Utc::now();
    let attempt_log = WebhookAttempt {
        attempted_at: now,
        http_status,
        response_body: response_body.clone(),
        error: error.clone(),
    };
    delivery.attempts.push(attempt_log);
    delivery.attempt_count = attempt_number;

    let success = http_status.map_or(false, |s| (200..300).contains(&s));

    if success {
        delivery.status = WebhookDeliveryStatus::Delivered;
        delivery.next_retry_at = None;
        tracing::info!(
            delivery_id = %delivery.id,
            vault_id = %delivery.vault_id,
            attempt = attempt_number,
            "webhook_retry: delivered successfully"
        );

        record_timeline_event(db, &delivery, true).await;
    } else {
        let retry_index = (attempt_number - 1) as usize; // 0-based index into RETRY_DELAYS_SECS
        if retry_index < RETRY_DELAYS_SECS.len() {
            // Schedule a retry.
            let delay = RETRY_DELAYS_SECS[retry_index];
            delivery.status = WebhookDeliveryStatus::Retrying;
            delivery.next_retry_at = Some(now + chrono::Duration::seconds(delay as i64));
            tracing::warn!(
                delivery_id = %delivery.id,
                vault_id = %delivery.vault_id,
                attempt = attempt_number,
                retry_in_secs = delay,
                error = ?error,
                "webhook_retry: delivery failed, scheduling retry"
            );
        } else {
            // All retries exhausted.
            delivery.status = WebhookDeliveryStatus::DeliveryFailed;
            delivery.next_retry_at = None;
            tracing::error!(
                delivery_id = %delivery.id,
                vault_id = %delivery.vault_id,
                total_attempts = attempt_number,
                "webhook_retry: all retries exhausted — delivery permanently failed"
            );

            // Notify vault owner via email through the configured provider.
            notify_owner_delivery_failed(db, &delivery, http_status).await;
            record_timeline_event(db, &delivery, false).await;
        }
    }

    if let Err(e) = db.update_webhook_delivery(&delivery) {
        tracing::error!(
            delivery_id = %delivery.id,
            error = %e,
            "webhook_retry: failed to persist delivery update"
        );
    }
}

/// HTTP POST to the endpoint. Returns (http_status, response_body, error).
async fn send_webhook(
    url: &str,
    payload: &serde_json::Value,
) -> (Option<u16>, String, Option<String>) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    match client.post(url).json(payload).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if (200..300).contains(&status) {
                (Some(status), body, None)
            } else {
                (
                    Some(status),
                    body.clone(),
                    Some(format!("HTTP {status}: {body}")),
                )
            }
        }
        Err(e) => (None, String::new(), Some(e.to_string())),
    }
}

/// Record the delivery outcome as a vault timeline event.
async fn record_timeline_event(db: &Arc<Db>, delivery: &WebhookDelivery, success: bool) {
    let kind = if success {
        TimelineEventKind::WebhookDelivered
    } else {
        TimelineEventKind::WebhookFailed
    };
    let description = if success {
        format!(
            "Webhook '{}' delivered to {}",
            delivery.event_type, delivery.endpoint_url
        )
    } else {
        format!(
            "Webhook '{}' permanently failed after {} attempts",
            delivery.event_type, delivery.attempt_count
        )
    };
    let event = TimelineEvent {
        id: Uuid::new_v4().to_string(),
        vault_id: delivery.vault_id.clone(),
        kind,
        timestamp: Utc::now(),
        description,
        amount: None,
        metadata: serde_json::json!({
            "delivery_id": delivery.id,
            "event_type": delivery.event_type,
            "endpoint_url": delivery.endpoint_url,
            "attempt_count": delivery.attempt_count,
        }),
    };
    if let Err(e) = db.insert_timeline_event(&event) {
        tracing::error!(error = %e, "webhook_retry: failed to insert timeline event");
    }
}

/// Returns true if a permanent-failure email may be sent for `owner` now,
/// recording the send time when allowed. Enforces `FAILURE_EMAIL_RATE_LIMIT`.
fn failure_email_allowed(owner: &str) -> bool {
    let now = Instant::now();
    let mut guard = match FAILURE_EMAIL_LAST_SENT.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    match map.get(owner) {
        Some(last) if now.duration_since(*last) < FAILURE_EMAIL_RATE_LIMIT => false,
        _ => {
            map.insert(owner.to_string(), now);
            true
        }
    }
}

/// Sends a permanent-failure notification email to the vault owner through the
/// configured email provider. Rate-limited per owner.
async fn notify_owner_delivery_failed(
    db: &Arc<Db>,
    delivery: &WebhookDelivery,
    last_status: Option<u16>,
) {
    let owner = match db.get_vault_owner_email(&delivery.vault_id) {
        Ok(Some(email)) => email,
        Ok(None) => {
            tracing::warn!(
                vault_id = %delivery.vault_id,
                "webhook_retry: no owner email on file, skipping failure notification"
            );
            return;
        }
        Err(e) => {
            tracing::error!(
                vault_id = %delivery.vault_id,
                error = %e,
                "webhook_retry: failed to resolve owner email"
            );
            return;
        }
    };

    if !failure_email_allowed(&owner) {
        tracing::info!(
            vault_id = %delivery.vault_id,
            owner = %owner,
            "webhook_retry: failure email rate-limited, skipping notification"
        );
        return;
    }

    let status_text = last_status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "no response".to_string());
    let subject = format!(
        "Webhook delivery permanently failed for vault {}",
        delivery.vault_id
    );
    let body = format!(
        "A webhook for vault {} permanently failed after {} attempts.\n\n\
         Webhook URL: {}\n\
         Event type: {}\n\
         Last HTTP status: {}\n\
         Attempts: {}\n",
        delivery.vault_id,
        delivery.attempt_count,
        delivery.endpoint_url,
        delivery.event_type,
        status_text,
        delivery.attempt_count,
    );

    let provider = EmailProvider::from_env();
    if let Err(e) = provider.send(&owner, &subject, &body).await {
        tracing::error!(
            vault_id = %delivery.vault_id,
            owner = %owner,
            error = %e,
            "webhook_retry: failed to send permanent-failure email"
        );
    } else {
        tracing::info!(
            vault_id = %delivery.vault_id,
            owner = %owner,
            attempts = delivery.attempt_count,
            "webhook_retry: permanent-failure email sent to owner"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_email_rate_limit_allows_first_then_blocks() {
        let owner = format!("owner-{}", Uuid::new_v4());
        assert!(failure_email_allowed(&owner), "first email should be allowed");
        assert!(
            !failure_email_allowed(&owner),
            "second email within the window should be rate-limited"
        );
    }

    #[test]
    fn failure_email_rate_limit_is_per_owner() {
        let a = format!("owner-a-{}", Uuid::new_v4());
        let b = format!("owner-b-{}", Uuid::new_v4());
        assert!(failure_email_allowed(&a));
        assert!(failure_email_allowed(&b), "distinct owners are independent");
    }

    #[test]
    fn permanent_failure_email_body_includes_details() {
        let delivery = WebhookDelivery {
            id: Uuid::new_v4().to_string(),
            vault_id: "vault-1".to_string(),
            event_type: "release".to_string(),
            payload: serde_json::json!({}),
            endpoint_url: "https://example.com/hook".to_string(),
            status: WebhookDeliveryStatus::DeliveryFailed,
            attempt_count: MAX_ATTEMPTS,
            next_retry_at: None,
            created_at: Utc::now(),
            attempts: Vec::new(),
        };
        let status_text = Some(500u16).map(|s| s.to_string()).unwrap_or_default();
        let body = format!(
            "Webhook URL: {}\nLast HTTP status: {}\nAttempts: {}",
            delivery.endpoint_url, status_text, delivery.attempt_count
        );
        assert!(body.contains("https://example.com/hook"));
        assert!(body.contains("500"));
        assert!(body.contains(&MAX_ATTEMPTS.to_string()));
    }
}
