use argus_contracts::{ArtifactRecordDraft, CheckpointSigner, PostgresLedgerWriter};
use postgres::{Client, NoTls};
use serde_json::json;
use std::env;
use std::error::Error;
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
    let draft: ArtifactRecordDraft = serde_json::from_str(&input)?;
    let dsn = required_env("ARGUS_S8_RUST_LEDGER_DSN")
        .or_else(|_| required_env("ARGUS_S8_POSTGRES_DSN"))?;
    let role = env::var("ARGUS_S8_RUST_LEDGER_ROLE")
        .ok()
        .or_else(|| env::var("ARGUS_S8_POSTGRES_ROLE").ok());
    let signer_key_id = required_env("ARGUS_S8_CHECKPOINT_SIGNER_KEY_ID")?;
    let signing_key = required_env("ARGUS_S8_CHECKPOINT_SIGNING_KEY")?;

    let mut client = Client::connect(&dsn, NoTls)?;
    if let Some(role) = role.as_deref().filter(|value| !value.is_empty()) {
        client.batch_execute(&format!("SET ROLE {};", checked_identifier(role)?))?;
    }

    let mut writer = PostgresLedgerWriter::from_client(client);
    writer.commit_artifact_record(&draft)?;
    let signer = CheckpointSigner::new(signer_key_id, signing_key.into_bytes());
    let checkpoint = writer.append_latest_checkpoint(&signer)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "ok",
            "checkpoint": checkpoint,
        }))?
    );
    Ok(())
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
