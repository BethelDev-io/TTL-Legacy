use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;

use crate::{db::Db, error::ApiError, models::AuditLogEntry};

/// Axum middleware that logs every API request to the audit log.
pub async fn audit_middleware(
    State(db): State<Arc<Db>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Skip internal routes to reduce noise and avoid recursion
    if path == "/health" || path == "/ready" || path.starts_with("/api/audit-logs") {
        return next.run(req).await;
    }

    let ip = extract_client_ip(req.headers());
    let user_id = extract_user_id(req.headers());

    let response = next.run(req).await;
    let status = response.status();

    let result = if status.is_success() {
        "success"
    } else if status.is_server_error() {
        "error"
    } else {
        "failure"
    };

    // Only log API routes
    if path.starts_with("/api/") {
        let entry = AuditLogEntry {
            id: 0,
            timestamp: Utc::now(),
            user_id,
            action: method.to_string(),
            resource: path,
            result: result.to_string(),
            ip_address: ip,
            details: Some(serde_json::json!({
                "status_code": status.as_u16(),
            })),
        };

        if let Err(e) = db.insert_audit_log(&entry) {
            tracing::error!(error = %e, "failed to persist audit log entry");
        }
    }

    response
}

/// Helper: write a structured audit entry for state modifications.
pub async fn log_state_modification(
    db: &Arc<Db>,
    action: &str,
    resource: &str,
    result: &str,
    headers: &HeaderMap,
    details: Option<serde_json::Value>,
) {
    let entry = AuditLogEntry {
        id: 0,
        timestamp: Utc::now(),
        user_id: extract_user_id(headers),
        action: action.to_string(),
        resource: resource.to_string(),
        result: result.to_string(),
        ip_address: extract_client_ip(headers),
        details,
    };
    if let Err(e) = db.insert_audit_log(&entry) {
        tracing::error!(error = %e, "failed to persist audit log entry");
    }
}

/// Helper: record an escalation attempt in the audit log.
///
/// Escalation runs from background tasks (no request headers), so this
/// variant takes explicit actor/ip values and is safe to call from the
/// scheduler without an `axum` request context.
pub async fn log_escalation_attempt(
    db: &Arc<Db>,
    vault_id: &str,
    tier: u8,
    recipient: &str,
    result: &str,
    details: Option<serde_json::Value>,
) {
    let mut merged = details.unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = merged.as_object_mut() {
        obj.insert("vault_id".to_string(), serde_json::json!(vault_id));
        obj.insert("tier".to_string(), serde_json::json!(tier));
        obj.insert("recipient".to_string(), serde_json::json!(recipient));
    }

    let entry = AuditLogEntry {
        id: 0,
        timestamp: Utc::now(),
        user_id: "system:escalation".to_string(),
        action: "escalation.dispatch".to_string(),
        resource: format!("vault/{vault_id}"),
        result: result.to_string(),
        ip_address: "internal".to_string(),
        details: Some(merged),
    };
    if let Err(e) = db.insert_audit_log(&entry) {
        tracing::error!(error = %e, "failed to persist escalation audit log entry");
    }
}

/// Check that the request carries a valid admin API key.
pub fn authorize_admin(headers: &HeaderMap) -> Result<(), ApiError> {
    let api_key = std::env::var("ADMIN_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Ok(());
    }
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match auth_header.strip_prefix("Bearer ") {
        Some(token) if token == api_key => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid admin API key required",
        )),
    }
}

/// Query parameters for the audit log export endpoint.
#[derive(Debug, Deserialize)]
pub struct AuditExportQuery {
    /// Requested export format: `csv` (default) or `json`.
    #[serde(default)]
    pub format: Option<String>,
}

/// `GET /vaults/{id}/audit/export`
///
/// Streams the vault's audit trail to the vault owner as CSV or JSON.
pub async fn export_vault_audit(
    State(db): State<Arc<Db>>,
    Path(vault_id): Path<String>,
    Query(query): Query<AuditExportQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let requester = extract_user_id(&headers);
    if requester.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
        ));
    }

    let owner = db.vault_owner(&vault_id).map_err(|e| {
        tracing::error!(error = %e, "failed to load vault owner");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load vault",
        )
    })?;

    let owner = match owner {
        Some(owner) => owner,
        None => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "vault not found",
            ))
        }
    };

    if owner != requester {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only the vault owner may export the audit trail",
        ));
    }

    let format = query.format.as_deref().unwrap_or("csv").to_ascii_lowercase();
    let entries = db.list_vault_audit_logs(&vault_id).map_err(|e| {
        tracing::error!(error = %e, "failed to load vault audit logs");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load audit trail",
        )
    })?;

    match format.as_str() {
        "json" => {
            let body = serde_json::to_vec(&entries).map_err(|e| {
                tracing::error!(error = %e, "failed to serialize audit trail");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to serialize audit trail",
                )
            })?;
            Ok((
                StatusCode::OK,
                [("content-type", "application/json")],
                Body::from(body),
            )
                .into_response())
        }
        "csv" => {
            let mut out = String::from(
                "id,timestamp,user_id,action,resource,result,ip_address,details\n",
            );
            for entry in &entries {
                out.push_str(&csv_row(entry));
            }
            Ok((
                StatusCode::OK,
                [("content-type", "text/csv; charset=utf-8")],
                Body::from(out),
            )
                .into_response())
        }
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_format",
            &format!("unsupported export format: {other}"),
        )),
    }
}

/// Render a single audit entry as a CSV row (with a trailing newline).
fn csv_row(entry: &AuditLogEntry) -> String {
    let details = entry
        .details
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_default();
    let fields = [
        entry.id.to_string(),
        entry.timestamp.to_rfc3339(),
        entry.user_id.clone(),
        entry.action.clone(),
        entry.resource.clone(),
        entry.result.clone(),
        entry.ip_address.clone(),
        details,
    ];
    let mut row = fields
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    row
}

/// Escape a CSV field per RFC 4180 when it contains special characters.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(val) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return val
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
    }
    if let Some(val) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return val.to_string();
    }
    "unknown".to_string()
}

fn extract_user_id(headers: &HeaderMap) -> String {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn test_db() -> Arc<Db> {
        Arc::new(Db::in_memory().expect("in-memory db"))
    }

    fn seed_vault(db: &Arc<Db>, vault_id: &str, owner: &str) {
        db.create_vault(vault_id, owner).expect("create vault");
        db.insert_audit_log(&AuditLogEntry {
            id: 0,
            timestamp: Utc::now(),
            user_id: owner.to_string(),
            action: "GET".to_string(),
            resource: format!("/api/vaults/{vault_id}"),
            result: "success".to_string(),
            ip_address: "127.0.0.1".to_string(),
            details: Some(serde_json::json!({"status_code": 200})),
        })
        .expect("insert audit log");
    }

    fn app(db: Arc<Db>) -> axum::Router {
        axum::Router::new()
            .route("/vaults/:id/audit/export", axum::routing::get(export_vault_audit))
            .with_state(db)
    }

    #[tokio::test]
    async fn owner_can_export_csv() {
        let db = test_db();
        seed_vault(&db, "v1", "owner-1");
        let response = app(db)
            .oneshot(
                HttpRequest::builder()
                    .uri("/vaults/v1/audit/export")
                    .header("x-user-id", "owner-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.starts_with("id,timestamp,user_id,action,resource,result,ip_address,details"));
        assert!(text.contains("owner-1"));
    }

    #[tokio::test]
    async fn owner_can_export_json() {
        let db = test_db();
        seed_vault(&db, "v1", "owner-1");
        let response = app(db)
            .oneshot(
                HttpRequest::builder()
                    .uri("/vaults/v1/audit/export?format=json")
                    .header("x-user-id", "owner-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.is_array());
    }

    #[tokio::test]
    async fn non_owner_is_forbidden() {
        let db = test_db();
        seed_vault(&db, "v1", "owner-1");
        let response = app(db)
            .oneshot(
                HttpRequest::builder()
                    .uri("/vaults/v1/audit/export")
                    .header("x-user-id", "intruder")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unauthenticated_is_rejected() {
        let db = test_db();
        seed_vault(&db, "v1", "owner-1");
        let response = app(db)
            .oneshot(
                HttpRequest::builder()
                    .uri("/vaults/v1/audit/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_format_is_rejected() {
        let db = test_db();
        seed_vault(&db, "v1", "owner-1");
        let response = app(db)
            .oneshot(
                HttpRequest::builder()
                    .uri("/vaults/v1/audit/export?format=xml")
                    .header("x-user-id", "owner-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
