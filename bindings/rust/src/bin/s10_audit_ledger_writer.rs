use argus_contracts::argusverify::canonical_json;
use argus_contracts::hash_bytes;
use postgres::types::Json;
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process;
use std::time::Duration;

const AUDIT_TIP_ADVISORY_LOCK_KEY: i64 = 5_038_301_002;
const ANCHOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const ANCHOR_IO_TIMEOUT: Duration = Duration::from_secs(15);
const ZERO_HASH: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Deserialize)]
struct AuditAppendRequest {
    event_type: String,
    payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct AuditAnchorRequest {
    schema: String,
    sequence: i64,
    previous_root: String,
    root: String,
    event_hash: String,
}

#[derive(Debug, Deserialize)]
struct AuditAnchorResponse {
    sequence: i64,
    root: String,
    event_hash: String,
    artifact_ref: String,
    content_hash: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: AuditAppendRequest = serde_json::from_str(&input)?;
    validate_request(&request)?;

    let dsn = required_env("ARGUS_S10_AUDIT_POSTGRES_DSN")?;
    let role = required_env("ARGUS_S10_AUDIT_POSTGRES_ROLE")?;
    let anchor = AuditAnchorClient::from_env()?;
    let mut client = Client::connect(&dsn, NoTls)?;
    client.batch_execute(&format!("SET ROLE {};", checked_identifier(&role)?))?;

    let mut transaction = client.transaction()?;
    transaction.batch_execute(
        "SET LOCAL statement_timeout = '30s';\n\
         SET LOCAL idle_in_transaction_session_timeout = '30s';",
    )?;
    transaction.query_one(
        "SELECT pg_advisory_xact_lock($1);",
        &[&AUDIT_TIP_ADVISORY_LOCK_KEY],
    )?;
    let tip = transaction.query_opt(
        "SELECT e.sequence, e.event_hash, a.root \
         FROM s10.audit_event AS e \
         JOIN s10.audit_anchor AS a USING (sequence) \
         ORDER BY e.sequence DESC LIMIT 1;",
        &[],
    )?;
    let (sequence, previous_hash, previous_root) = match tip {
        Some(row) => (
            row.get::<_, i64>(0) + 1,
            row.get::<_, String>(1),
            row.get::<_, String>(2),
        ),
        None => (1, ZERO_HASH.to_string(), ZERO_HASH.to_string()),
    };
    let event_hash = audit_event_hash(
        sequence,
        &request.event_type,
        &request.payload,
        &previous_hash,
    );
    let root = next_merkle_root(&previous_root, &event_hash, sequence);
    let anchor_request = AuditAnchorRequest {
        schema: "argus.s10.audit-anchor.v1".to_string(),
        sequence,
        previous_root: previous_root.clone(),
        root: root.clone(),
        event_hash: event_hash.clone(),
    };
    let anchor_response = anchor
        .create(&anchor_request)
        .map_err(|error| format!("audit anchor request failed: {error}"))?;
    validate_anchor_response(&anchor_request, &anchor_response)
        .map_err(|error| format!("audit anchor response mismatch: {error}"))?;

    transaction.query_one(
        "SELECT s10.append_audit_event($1,$2,$3,$4,$5,$6,$7,$8,$9);",
        &[
            &sequence,
            &request.event_type,
            &Json(&request.payload),
            &previous_hash,
            &event_hash,
            &previous_root,
            &root,
            &anchor_response.artifact_ref,
            &anchor_response.content_hash,
        ],
    )?;
    transaction.commit()?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "sequence": sequence,
            "event_type": request.event_type,
            "payload": request.payload,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
            "anchor": {
                "root": root,
                "artifact_ref": anchor_response.artifact_ref,
                "content_hash": anchor_response.content_hash,
            },
        }))?
    );
    Ok(())
}

fn validate_request(request: &AuditAppendRequest) -> Result<(), Box<dyn Error>> {
    if request.event_type.trim().is_empty() {
        return Err("audit event_type is required".into());
    }
    if !request.payload.is_object() {
        return Err("audit payload must be a JSON object".into());
    }
    Ok(())
}

fn audit_event_hash(
    sequence: i64,
    event_type: &str,
    payload: &Value,
    previous_hash: &str,
) -> String {
    hash_bytes(
        canonical_json(&json!({
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
            "sequence": sequence,
        }))
        .expect("audit event JSON canonicalization cannot fail")
        .as_bytes(),
    )
}

fn next_merkle_root(previous_root: &str, event_hash: &str, sequence: i64) -> String {
    hash_bytes(format!("{previous_root}|{event_hash}|{sequence}").as_bytes())
}

fn validate_anchor_response(
    request: &AuditAnchorRequest,
    response: &AuditAnchorResponse,
) -> Result<(), Box<dyn Error>> {
    if response.sequence != request.sequence {
        return Err("sequence".into());
    }
    if response.root != request.root {
        return Err("root".into());
    }
    if response.event_hash != request.event_hash {
        return Err("event_hash".into());
    }
    if response.artifact_ref.is_empty() {
        return Err("artifact_ref".into());
    }
    if !is_blake3_hash(&response.content_hash) {
        return Err("content_hash".into());
    }
    Ok(())
}

fn is_blake3_hash(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    })
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(format!("{name} is required").into()),
    }
}

fn checked_identifier(value: &str) -> Result<&str, Box<dyn Error>> {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        Ok(value)
    } else {
        Err(format!("unsupported SQL identifier: {value}").into())
    }
}

struct AuditAnchorClient {
    endpoint: HttpEndpoint,
    auth_token: String,
}

impl AuditAnchorClient {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            endpoint: HttpEndpoint::parse(
                &required_env("ARGUS_S10_AUDIT_ANCHOR_URL")?,
                env_flag("ARGUS_S10_ALLOW_INSECURE_AUDIT_ANCHOR"),
            )?,
            auth_token: required_env("ARGUS_S10_AUDIT_ANCHOR_AUTH_TOKEN")?,
        })
    }

    fn create(&self, request: &AuditAnchorRequest) -> Result<AuditAnchorResponse, Box<dyn Error>> {
        let body = serde_json::to_string(request)?;
        let response = http_post_json(&self.endpoint, &self.auth_token, &body)?;
        if response.status != 201 {
            return Err(format!("anchor service returned HTTP {}", response.status).into());
        }
        Ok(serde_json::from_str(&response.body)?)
    }
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
}

impl HttpEndpoint {
    fn parse(url: &str, allow_insecure: bool) -> Result<Self, Box<dyn Error>> {
        if url.starts_with("https://") {
            return Err("https:// audit anchor URLs require a TLS/mTLS-capable writer".into());
        }
        let rest = url
            .strip_prefix("http://")
            .ok_or("audit anchor URL must use https://, or explicit local HTTP")?;
        if !allow_insecure {
            return Err(
                "ARGUS_S10_ALLOW_INSECURE_AUDIT_ANCHOR=1 is required for http:// audit anchors"
                    .into(),
            );
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            (host.to_string(), port.parse::<u16>()?)
        } else {
            (authority.to_string(), 80)
        };
        if host.is_empty() {
            return Err("audit anchor URL host is required".into());
        }
        Ok(Self {
            host,
            port,
            path: format!("/{path}"),
        })
    }

    fn authority(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

fn http_post_json(
    endpoint: &HttpEndpoint,
    auth_token: &str,
    body: &str,
) -> Result<HttpResponse, Box<dyn Error>> {
    if auth_token.contains(['\r', '\n']) {
        return Err("audit anchor auth token contains invalid characters".into());
    }
    let mut stream = connect(endpoint)?;
    stream.set_read_timeout(Some(ANCHOR_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(ANCHOR_IO_TIMEOUT))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.authority(),
        auth_token,
        body.len(),
        body,
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or("audit anchor returned a malformed HTTP response")?;
    Ok(HttpResponse {
        status: parse_http_status(head)?,
        body: body.to_string(),
    })
}

fn connect(endpoint: &HttpEndpoint) -> Result<TcpStream, Box<dyn Error>> {
    let addresses = (endpoint.host.as_str(), endpoint.port).to_socket_addrs()?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, ANCHOR_CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.into()),
        None => Err("audit anchor host resolved to no addresses".into()),
    }
}

fn parse_http_status(head: &str) -> Result<u16, Box<dyn Error>> {
    let status_line = head
        .lines()
        .next()
        .ok_or("audit anchor response was empty")?;
    let mut parts = status_line.split_whitespace();
    if !parts.next().unwrap_or("").starts_with("HTTP/") {
        return Err("audit anchor returned a malformed status line".into());
    }
    Ok(parts
        .next()
        .ok_or("audit anchor status code is missing")?
        .parse::<u16>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_event_hash_matches_declared_field_order_independently() {
        let payload = json!({"z": 1, "a": {"d": 2, "b": 3}});
        let first = audit_event_hash(1, "sandbox.launched", &payload, ZERO_HASH);
        let reordered: Value = serde_json::from_str(r#"{"a":{"b":3,"d":2},"z":1}"#).unwrap();
        let second = audit_event_hash(1, "sandbox.launched", &reordered, ZERO_HASH);
        assert_eq!(first, second);
        assert!(is_blake3_hash(&first));
    }

    #[test]
    fn audit_payload_float_parsing_preserves_python_roundtrip_bits() {
        let request: AuditAppendRequest = serde_json::from_str(
            r#"{"event_type":"meter.sample","payload":{"usage":{"cost_usd":9.507422199628005e-05}}}"#,
        )
        .unwrap();
        let parsed = request.payload["usage"]["cost_usd"].as_f64().unwrap();
        let expected = 9.507422199628005e-05_f64;

        assert_eq!(parsed.to_bits(), expected.to_bits());
    }

    #[test]
    fn anchor_response_must_bind_sequence_root_and_event_hash() {
        let request = AuditAnchorRequest {
            schema: "argus.s10.audit-anchor.v1".to_string(),
            sequence: 3,
            previous_root: ZERO_HASH.to_string(),
            root: hash_bytes(b"root"),
            event_hash: hash_bytes(b"event"),
        };
        let response = AuditAnchorResponse {
            sequence: 3,
            root: request.root.clone(),
            event_hash: request.event_hash.clone(),
            artifact_ref: "artifact:anchor".to_string(),
            content_hash: hash_bytes(b"payload"),
        };
        assert!(validate_anchor_response(&request, &response).is_ok());
        let mismatch = AuditAnchorResponse {
            root: ZERO_HASH.to_string(),
            ..response
        };
        assert_eq!(
            validate_anchor_response(&request, &mismatch)
                .unwrap_err()
                .to_string(),
            "root"
        );
    }

    #[test]
    fn plain_http_anchor_requires_explicit_local_override() {
        let error =
            HttpEndpoint::parse("http://s10-supervisor:8080/v1/internal/audit-anchor", false)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("ARGUS_S10_ALLOW_INSECURE_AUDIT_ANCHOR=1"));
    }
}
