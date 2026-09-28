use std::sync::Arc;

use actix_web::{
    http::StatusCode,
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse, Responder,
};
use chrono::DateTime;
use serde::Deserialize;
use tracing::instrument;

use crate::{
    audit,
    db::{AppState, Db},
    error::AppError,
    handlers::{
        claim_vesting_bonus_handler, get_vesting_bonus_handler, parse_scenario_types,
        simulate_release_handler,
    },
    models::{
        AuditLogEntry, ClaimBonusRequest, ReminderPreferences, SetPreferencesRequest,
        SetSubscriptionRequest, SimulateReleaseQuery, SimulateReleaseResponse, Subscription,
        VaultReleaseHistory,
    },
};

// ── Health & readiness probes (#1489) ────────────────────────────────────────

/// GET /health
///
/// Cheap liveness probe: confirms the process is up and serving requests.
/// Intentionally performs no dependency checks so it stays fast and cannot
/// flap when the DB or RPC is temporarily unreachable.
#[instrument]
pub async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(serde::Serialize)]
pub struct ReadinessResponse {
    pub status: &'static str,
    pub checks: ReadinessChecks,
}

#[derive(serde::Serialize)]
pub struct ReadinessChecks {
    pub db: &'static str,
    pub rpc: &'static str,
}

/// GET /ready
///
/// Readiness probe: verifies that dependencies (DB connection and Soroban RPC)
/// are reachable before the instance is considered ready to serve traffic.
#[instrument(skip(state))]
pub async fn ready(
    state: Data<Arc<AppState>>,
) -> Result<Json<ReadinessResponse>, AppError> {
    let db_ok = state.db.ping().is_ok();
    let rpc_ok = state.rpc.ping().await.is_ok();

    let checks = ReadinessChecks {
        db: if db_ok { "ok" } else { "unavailable" },
        rpc: if rpc_ok { "ok" } else { "unavailable" },
    };

    if db_ok && rpc_ok {
        Ok(Json(ReadinessResponse {
            status: "ready",
            checks,
        }))
    } else {
        Err(AppError::ServiceUnavailable(Json(ReadinessResponse {
            status: "not_ready",
            checks,
        })))
    }
}

#[derive(Deserialize)]
pub struct RemindersQuery {
    pub include_deleted: Option<bool>,
}

#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn list_vault_reminders(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
    query: Query<RemindersQuery>,
) -> Result<Json<Vec<ReminderPreferences>>, AppError> {
    let db = &state.db;
    let records = if query.include_deleted.unwrap_or(false) {
        db.all_reminders_including_deleted(vault_id.into_inner())?
    } else {
        match db.get(vault_id.into_inner()) {
            Ok(p) => vec![p],
            Err(_) => vec![],
        }
    };
    Ok(Json(records))
}

#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn delete_preferences(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
) -> Result<StatusCode, AppError> {
    state.db.soft_delete_reminder(vault_id.into_inner())?;
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip(state, req), fields(vault_id = %vault_id))]
pub async fn set_preferences(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
    req: HttpRequest,
    body: Json<SetPreferencesRequest>,
) -> Result<(StatusCode, Json<ReminderPreferences>), AppError> {
    let db = &state.db;
    if body.channels.is_empty() {
        return Err(AppError::InvalidInput("channels must not be empty".into()));
    }
    if body.hours_before_expiry == 0 {
        return Err(AppError::InvalidInput(
            "hours_before_expiry must be > 0".into(),
        ));
    }

    // #825: Idempotency key support
    if let Some(idem_key) = req
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(cached) = db.check_idempotency(idem_key) {
            let cached_prefs: ReminderPreferences =
                serde_json::from_str(&cached.response_body).unwrap();
            return Ok((StatusCode::OK, Json(cached_prefs)));
        }
    }

    let prefs = ReminderPreferences {
        vault_id: vault_id.into_inner(),
        channels: body.channels.clone(),
        hours_before_expiry: body.hours_before_expiry,
        frequency: body.frequency.clone(),
        deleted_at: None,
    };
    db.upsert(&prefs)?;

    // Store idempotency record if key was provided
    if let Some(idem_key) = req
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
    {
        let body_json = serde_json::to_string(&prefs).unwrap();
        db.store_idempotency(idem_key, 200, &body_json);
    }

    Ok((StatusCode::OK, Json(prefs)))
}

#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn get_preferences(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
) -> Result<Json<ReminderPreferences>, AppError> {
    let db = &state.db;
    match db.get(vault_id.into_inner()) {
        Ok(prefs) => Ok(Json(prefs)),
        Err(_e) => Err(AppError::NotFound),
    }
}

// ── Unsubscribe endpoint (#828) ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UnsubscribeQuery {
    pub token: String,
}

#[instrument(skip(state))]
pub async fn unsubscribe(
    state: Data<Arc<AppState>>,
    query: Query<UnsubscribeQuery>,
) -> Result<HttpResponse, AppError> {
    let db = &state.db;
    match db.process_unsubscribe(&query.token) {
        Ok(owner) => Ok(HttpResponse::Ok()
            .body(format!("You ({owner}) have been unsubscribed from reminder emails."))),
        Err(_) => Err(AppError::InvalidInput(
            "Invalid or expired unsubscribe token".into(),
        )),
    }
}

// ── Token-based reminder check-in endpoint (#1286) ──────────────────────────

#[derive(Deserialize)]
pub struct ReminderTokenQuery {
    pub token: String,
}

#[derive(serde::Serialize)]
pub struct ResolveReminderTokenResponse {
    pub vault_id: String,
    pub owner: String,
}

#[instrument(skip(state))]
pub async fn resolve_reminder_token(
    state: Data<Arc<AppState>>,
    query: Query<ReminderTokenQuery>,
) -> Result<Json<ResolveReminderTokenResponse>, AppError> {
    let db = &state.db;
    match db.resolve_reminder_token(&query.token) {
        Ok((vault_id, owner)) => Ok(Json(ResolveReminderTokenResponse { vault_id, owner })),
        Err(_) => Err(AppError::InvalidInput(
            "Invalid or expired reminder token".into(),
        )),
    }
}

// ── Vault subscription endpoints ─────────────────────────────────────────────

/// POST /api/vaults/:vault_id/subscriptions
///
/// Create or update vault-level notification subscription settings.
#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn set_subscription(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
    body: Json<SetSubscriptionRequest>,
) -> Result<(StatusCode, Json<Subscription>), AppError> {
    if body.channels.is_empty() {
        return Err(AppError::InvalidInput("channels must not be empty".into()));
    }

    let sub = Subscription {
        vault_id: vault_id.into_inner(),
        owner: body.owner.clone(),
        channels: body.channels.clone(),
        frequency: body.frequency.clone(),
    };
    state.db.upsert_subscription(&sub)?;
    Ok((StatusCode::OK, Json(sub)))
}

/// DELETE /api/vaults/:vault_id/subscriptions
///
/// Remove vault-level notification subscription settings.
#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn delete_subscription(
    state: Data<Arc<AppState>>,
    vault_id: Path<u64>,
) -> Result<StatusCode, AppError> {
    state.db.delete_subscription(vault_id.into_inner())?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Audit log export endpoint (#1493) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditExportQuery {
    /// Export format: `csv` (default) or `json`.
    pub format: Option<String>,
}

/// GET /vaults/{id}/audit/export?format=csv|json
///
/// Exports the vault's audit trail. Only the vault owner may export. The
/// response is streamed so large audit histories are not buffered in memory.
#[instrument(skip(state), fields(vault_id = %vault_id))]
pub async fn export_vault_audit(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<u64>,
    Query(query): Query<AuditExportQuery>,
    headers: HeaderMap,
) -> Result<Response<Body>, AppError> {
    let format = query.format.as_deref().unwrap_or("csv").to_ascii_lowercase();
    if format != "csv" && format != "json" {
        return Err(AppError::InvalidInput(
            "format must be 'csv' or 'json'".into(),
        ));
    }

    // Authorize: only the vault owner may export the audit trail.
    let requester = headers
        .get("x-owner")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let owner = state.db.vault_owner(vault_id)?;
    if owner != requester {
        return Err(AppError::Forbidden);
    }

    let entries = state.db.list_audit_entries(vault_id)?;

    let (content_type, body) = if format == "json" {
        let mut buf = String::from("[");
        for (i, entry) in entries.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            buf.push_str(&serde_json::to_string(entry).map_err(|_| AppError::Internal)?);
        }
        buf.push(']');
        ("application/json", buf)
    } else {
        let mut buf = String::from("timestamp,event,actor,details\n");
        for entry in &entries {
            buf.push_str(&csv_field(&entry.timestamp.to_rfc3339()));
            buf.push(',');
            buf.push_str(&csv_field(&entry.event));
            buf.push(',');
            buf.push_str(&csv_field(&entry.actor));
            buf.push(',');
            buf.push_str(&csv_field(&entry.details));
            buf.push('\n');
        }
        ("text/csv", buf)
    };

    // Stream the export in chunks instead of buffering the whole payload.
    let stream = futures::stream::iter(
        body.into_bytes()
            .chunks(8 * 1024)
            .map(|chunk| Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>(),
    );

    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"audit-export\""),
    );
    Ok(response)
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

// ── Release Simulator endpoint ────────────────────────────────────────────────

/// GET /api/vaults/:vault_id/simulate-release?scenarios=no_check_ins,consistent_check_ins,missed_check_in_dates&missed_count=2
#[instrument(skip(db), fields(vault_id = %vault_id))]
pub async fn simulate_release(
    db: Data<Arc<Db>>,
    vault_id: Path<String>,
    query: Query<SimulateReleaseQuery>,
) -> Result<Json<SimulateReleaseResponse>, AppError> {
    let scenarios = parse_scenario_types(&query.scenarios)?;
    let response = simulate_release_handler(
        &db,
        vault_id.into_inner(),
        scenarios,
        query.missed_count,
    )
    .await?;
    Ok(Json(response))
}
