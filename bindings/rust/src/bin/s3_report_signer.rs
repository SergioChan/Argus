use argus_contracts::{sign_report, C3_SIGNATURE_ALGORITHM};
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::process;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request_value: Value = serde_json::from_str(&input)?;
    if contains_request_secret_material(&request_value) {
        return Err("S3_SIGNER_SECRET_IN_REQUEST: request must not include secret material; vault key material must be supplied out-of-band".into());
    }
    let request = request_value
        .as_object()
        .ok_or("S3_SIGNER_REQUEST_INVALID: request must be a JSON object")?;
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let key_id = required_string(request.get("key_id"), "key_id")?;
    let report = request
        .get("report")
        .ok_or("S3_SIGNER_REQUEST_INVALID: report is required")?
        .clone();
    if !report.is_object() {
        return Err("S3_SIGNER_REPORT_INVALID: report must be a JSON object".into());
    }

    let key_set = load_key_set()?;
    let key = key_set
        .keys
        .iter()
        .find(|item| item.key_id == key_id)
        .ok_or("S3_SIGNER_KEY_UNKNOWN: key not found")?;
    if key.revoked {
        return Err("S3_SIGNER_KEY_REVOKED: key is revoked".into());
    }
    if key.secret.is_empty() {
        return Err("S3_SIGNER_KEY_EMPTY: key secret is empty".into());
    }

    let signed_report = sign_report(&report, key_id, key.secret.as_bytes())?;
    let signature_value = signed_report
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|signature| signature.get("value"))
        .and_then(Value::as_str)
        .ok_or("S3_SIGNER_RESPONSE_INVALID: signed report did not contain a signature value")?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "request_id": request_id,
            "provider": key_set.provider,
            "key_id": key_id,
            "algorithm": C3_SIGNATURE_ALGORITHM,
            "signature_value": signature_value,
            "signed_report": signed_report,
            "secret_exposed": false,
        }))?
    );
    Ok(())
}

fn required_string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("S3_SIGNER_REQUEST_INVALID: {field} must be a non-empty string").into())
}

fn contains_request_secret_material(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let normalized = key.replace(['-', '_'], "").to_ascii_lowercase();
            matches!(normalized.as_str(), "secret" | "privatekey")
                || contains_request_secret_material(value)
        }),
        Value::Array(items) => items.iter().any(contains_request_secret_material),
        _ => false,
    }
}

#[derive(Debug)]
struct SignerKeySet {
    provider: String,
    keys: Vec<SignerKey>,
}

#[derive(Debug)]
struct SignerKey {
    key_id: String,
    secret: String,
    revoked: bool,
}

fn load_key_set() -> Result<SignerKeySet, Box<dyn Error>> {
    let raw = match env::var("ARGUS_S3_SIGNER_KEYS_JSON") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => match env::var("ARGUS_S3_SIGNER_KEY_FILE") {
            Ok(path) if !path.trim().is_empty() => fs::read_to_string(path)?,
            _ => {
                return Err("S3_SIGNER_KEY_MATERIAL_UNAVAILABLE: vault key material is required via ARGUS_S3_SIGNER_KEYS_JSON or ARGUS_S3_SIGNER_KEY_FILE".into());
            }
        },
    };
    parse_key_set(&raw)
}

fn parse_key_set(raw: &str) -> Result<SignerKeySet, Box<dyn Error>> {
    let value: Value = serde_json::from_str(raw)?;
    let object = value
        .as_object()
        .ok_or("S3_SIGNER_KEY_MATERIAL_INVALID: key material must be a JSON object")?;
    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .unwrap_or("rust-local-vault")
        .to_string();
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("S3_SIGNER_KEY_MATERIAL_INVALID: keys must be an array")?;
    let mut parsed = Vec::new();
    for entry in keys {
        let entry = entry
            .as_object()
            .ok_or("S3_SIGNER_KEY_MATERIAL_INVALID: key entry must be an object")?;
        parsed.push(SignerKey {
            key_id: entry
                .get("key_id")
                .and_then(Value::as_str)
                .filter(|item| !item.is_empty())
                .ok_or("S3_SIGNER_KEY_MATERIAL_INVALID: key_id is required")?
                .to_string(),
            secret: entry
                .get("secret")
                .and_then(Value::as_str)
                .filter(|item| !item.is_empty())
                .ok_or("S3_SIGNER_KEY_MATERIAL_INVALID: secret is required")?
                .to_string(),
            revoked: entry
                .get("revoked")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    Ok(SignerKeySet {
        provider,
        keys: parsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_set_loads_provider_and_revocation_metadata() -> Result<(), Box<dyn Error>> {
        let key_set = parse_key_set(
            r#"{"provider":"unit-vault","keys":[{"key_id":"s3-key","secret":"s3-secret","revoked":true}]}"#,
        )?;

        assert_eq!(key_set.provider, "unit-vault");
        assert_eq!(key_set.keys[0].key_id, "s3-key");
        assert!(key_set.keys[0].revoked);
        Ok(())
    }

    #[test]
    fn parse_key_set_rejects_missing_secret() {
        let error = parse_key_set(r#"{"keys":[{"key_id":"s3-key"}]}"#)
            .expect_err("key material without a secret must fail");

        assert!(error.to_string().contains("secret is required"));
    }

    #[test]
    fn request_secret_detection_is_recursive() {
        let request = json!({
            "request_id": "req-1",
            "key_id": "s3-key",
            "report": {
                "referee": {
                    "private_key": "must-not-cross-boundary"
                }
            }
        });

        assert!(contains_request_secret_material(&request));
    }
}
