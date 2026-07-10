use crate::hash::{hash_bytes, BLAKE3_PREFIX};
use chrono::{DateTime, Utc};
#[cfg(test)]
use hmac::{Hmac, KeyInit, Mac};
use postgres::types::Json;
use postgres::{Client, GenericClient, NoTls};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use sha2::Sha256;
use std::error::Error;
use std::fmt;

#[cfg(test)]
const CHECKPOINT_SIGNATURE_ALGORITHM: &str = "hmac-sha256";
const CHECKPOINT_SIGNATURE_PREFIX: &str = "hmac-sha256:";
const LEDGER_TRANSACTION_TIMEOUT_SQL: &str = "
SET LOCAL statement_timeout = '15s';
SET LOCAL idle_in_transaction_session_timeout = '15s';
";
const LEDGER_TIP_ADVISORY_LOCK_KEY: i64 = 5_038_300_801;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ArtifactRecordDraft {
    pub artifact_id: String,
    pub content_hash: String,
    pub kind: String,
    pub producer: Value,
    pub lineage: Value,
    pub record_hash: String,
    pub merkle_seq: i64,
    pub claim_tier: String,
    pub validation_report_ref: Option<String>,
    pub input_refs: Vec<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub size_bytes: Option<i64>,
}

impl ArtifactRecordDraft {
    pub fn ran_toy(
        artifact_id: impl Into<String>,
        content_hash: impl Into<String>,
        kind: impl Into<String>,
        producer: Value,
        lineage: Value,
        record_hash: impl Into<String>,
        merkle_seq: i64,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            content_hash: content_hash.into(),
            kind: kind.into(),
            producer,
            lineage,
            record_hash: record_hash.into(),
            merkle_seq,
            claim_tier: "ran-toy".to_string(),
            validation_report_ref: None,
            input_refs: Vec::new(),
            created_at: None,
            size_bytes: None,
        }
    }
}

pub struct PostgresLedgerWriter {
    client: Client,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSigner {
    key_id: String,
    secret: Vec<u8>,
}

#[cfg(test)]
impl CheckpointSigner {
    pub fn new(key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            secret: secret.into(),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sign(&self, sequence: i64, root: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC accepts any key size");
        mac.update(checkpoint_signature_payload(sequence, root, &self.key_id).as_bytes());
        format!(
            "{CHECKPOINT_SIGNATURE_PREFIX}{}",
            hex_lower(&mac.finalize().into_bytes())
        )
    }

    pub fn verify(&self, checkpoint: &MerkleCheckpoint) -> bool {
        checkpoint.signer_key_id == self.key_id
            && checkpoint
                .signature
                .starts_with(CHECKPOINT_SIGNATURE_PREFIX)
            && constant_time_eq(
                checkpoint.signature.as_bytes(),
                self.sign(checkpoint.sequence, &checkpoint.root).as_bytes(),
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MerkleCheckpoint {
    pub sequence: i64,
    pub root: String,
    pub signature: String,
    pub signer_key_id: String,
}

#[derive(Debug)]
pub enum LedgerCommitError {
    Postgres(postgres::Error),
    CheckpointSigner(String),
    CheckpointMismatch(&'static str),
}

impl fmt::Display for LedgerCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(error) => write!(formatter, "{error}"),
            Self::CheckpointSigner(error) => write!(formatter, "checkpoint signer failed: {error}"),
            Self::CheckpointMismatch(reason) => {
                write!(formatter, "checkpoint signer mismatch: {reason}")
            }
        }
    }
}

impl Error for LedgerCommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(error) => Some(error),
            Self::CheckpointSigner(_) | Self::CheckpointMismatch(_) => None,
        }
    }
}

impl From<postgres::Error> for LedgerCommitError {
    fn from(error: postgres::Error) -> Self {
        Self::Postgres(error)
    }
}

impl PostgresLedgerWriter {
    pub fn connect(params: &str) -> Result<Self, postgres::Error> {
        Ok(Self {
            client: Client::connect(params, NoTls)?,
        })
    }

    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    pub fn commit_artifact_record(
        &mut self,
        draft: &ArtifactRecordDraft,
    ) -> Result<(), postgres::Error> {
        let mut transaction = self.client.transaction()?;
        apply_ledger_transaction_timeouts(&mut transaction)?;
        lock_ledger_tip(&mut transaction)?;
        let existing_sequence = existing_merkle_sequence(&mut transaction, &draft.artifact_id)?;
        let (sequence, previous_root) = if let Some(sequence) = existing_sequence {
            (sequence, String::new())
        } else {
            next_ledger_position(&mut transaction)?
        };
        let inserted = commit_artifact_record(&mut transaction, draft, sequence)?;
        if inserted {
            let root = next_ledger_root(&previous_root, &draft.record_hash, sequence);
            transaction.execute(
                "
                SELECT s8.append_ledger_leaf($1, $2, $3, $4, $5);
                ",
                &[
                    &draft.artifact_id,
                    &draft.record_hash,
                    &sequence,
                    &previous_root,
                    &root,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn commit_artifact_record_with_checkpoint<F>(
        &mut self,
        draft: &ArtifactRecordDraft,
        sign_checkpoint: F,
    ) -> Result<Option<MerkleCheckpoint>, LedgerCommitError>
    where
        F: FnOnce(i64, &str) -> Result<MerkleCheckpoint, String>,
    {
        let mut transaction = self.client.transaction()?;
        apply_ledger_transaction_timeouts(&mut transaction)?;
        lock_ledger_tip(&mut transaction)?;
        let existing_sequence = existing_merkle_sequence(&mut transaction, &draft.artifact_id)?;
        let (sequence, previous_root) = if let Some(sequence) = existing_sequence {
            (sequence, String::new())
        } else {
            next_ledger_position(&mut transaction)?
        };
        let inserted = commit_artifact_record(&mut transaction, draft, sequence)?;
        if !inserted {
            let checkpoint = checkpoint_for_sequence(&mut transaction, sequence)?;
            transaction.commit()?;
            return Ok(checkpoint);
        }

        let root = next_ledger_root(&previous_root, &draft.record_hash, sequence);
        transaction.execute(
            "
            SELECT s8.append_ledger_leaf($1, $2, $3, $4, $5);
            ",
            &[
                &draft.artifact_id,
                &draft.record_hash,
                &sequence,
                &previous_root,
                &root,
            ],
        )?;
        let checkpoint =
            sign_checkpoint(sequence, &root).map_err(LedgerCommitError::CheckpointSigner)?;
        validate_checkpoint_for_tip(&checkpoint, sequence, &root)?;
        transaction.execute(
            "
            SELECT s8.append_merkle_checkpoint($1, $2, $3, $4);
            ",
            &[
                &checkpoint.sequence,
                &checkpoint.root,
                &checkpoint.signature,
                &checkpoint.signer_key_id,
            ],
        )?;
        transaction.commit()?;
        Ok(Some(checkpoint))
    }

    #[cfg(test)]
    pub fn append_latest_checkpoint(
        &mut self,
        signer: &CheckpointSigner,
    ) -> Result<Option<MerkleCheckpoint>, postgres::Error> {
        let mut transaction = self.client.transaction()?;
        apply_ledger_transaction_timeouts(&mut transaction)?;
        lock_ledger_tip(&mut transaction)?;
        let Some((sequence, root)) = latest_ledger_leaf(&mut transaction)? else {
            transaction.commit()?;
            return Ok(None);
        };
        let checkpoint = MerkleCheckpoint {
            sequence,
            root: root.clone(),
            signature: signer.sign(sequence, &root),
            signer_key_id: signer.key_id().to_string(),
        };
        transaction.execute(
            "
            SELECT s8.append_merkle_checkpoint($1, $2, $3, $4);
            ",
            &[
                &checkpoint.sequence,
                &checkpoint.root,
                &checkpoint.signature,
                &checkpoint.signer_key_id,
            ],
        )?;
        transaction.commit()?;
        Ok(Some(checkpoint))
    }

    pub fn latest_ledger_tip(&mut self) -> Result<Option<(i64, String)>, postgres::Error> {
        latest_ledger_leaf(&mut self.client)
    }

    pub fn append_checkpoint(
        &mut self,
        checkpoint: &MerkleCheckpoint,
    ) -> Result<(), postgres::Error> {
        let mut transaction = self.client.transaction()?;
        apply_ledger_transaction_timeouts(&mut transaction)?;
        lock_ledger_tip(&mut transaction)?;
        transaction.execute(
            "
            SELECT s8.append_merkle_checkpoint($1, $2, $3, $4);
            ",
            &[
                &checkpoint.sequence,
                &checkpoint.root,
                &checkpoint.signature,
                &checkpoint.signer_key_id,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn into_client(self) -> Client {
        self.client
    }
}

fn apply_ledger_transaction_timeouts<C: GenericClient>(
    client: &mut C,
) -> Result<(), postgres::Error> {
    client.batch_execute(LEDGER_TRANSACTION_TIMEOUT_SQL)
}

fn lock_ledger_tip<C: GenericClient>(client: &mut C) -> Result<(), postgres::Error> {
    client.query_one(
        "SELECT pg_advisory_xact_lock($1);",
        &[&LEDGER_TIP_ADVISORY_LOCK_KEY],
    )?;
    Ok(())
}

fn commit_artifact_record<C: GenericClient>(
    client: &mut C,
    draft: &ArtifactRecordDraft,
    merkle_seq: i64,
) -> Result<bool, postgres::Error> {
    let producer = Json(&draft.producer);
    let lineage = Json(&draft.lineage);
    let row = client.query_one(
        "
            SELECT s8.commit_artifact_record(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
            );
            ",
        &[
            &draft.artifact_id,
            &draft.content_hash,
            &draft.kind,
            &producer,
            &lineage,
            &draft.record_hash,
            &merkle_seq,
            &draft.claim_tier,
            &draft.validation_report_ref,
            &draft.input_refs,
            &draft.created_at,
            &draft.size_bytes,
        ],
    )?;
    Ok(row.get(0))
}

fn existing_merkle_sequence<C: GenericClient>(
    client: &mut C,
    artifact_id: &str,
) -> Result<Option<i64>, postgres::Error> {
    let row = client.query_opt(
        "
        SELECT merkle_seq
        FROM s8.artifact_record
        WHERE artifact_id = $1;
        ",
        &[&artifact_id],
    )?;
    Ok(row.map(|row| row.get(0)))
}

fn next_ledger_position<C: GenericClient>(
    client: &mut C,
) -> Result<(i64, String), postgres::Error> {
    if let Some((sequence, root)) = latest_ledger_leaf(client)? {
        Ok((sequence + 1, root))
    } else {
        Ok((1, zero_ledger_root()))
    }
}

fn latest_ledger_leaf<C: GenericClient>(
    client: &mut C,
) -> Result<Option<(i64, String)>, postgres::Error> {
    let latest = client.query_opt(
        "
        SELECT sequence, root
        FROM s8.ledger_leaf
        ORDER BY sequence DESC
        LIMIT 1;
        ",
        &[],
    )?;
    if let Some(row) = latest {
        let sequence: i64 = row.get(0);
        let root: String = row.get(1);
        Ok(Some((sequence, root)))
    } else {
        Ok(None)
    }
}

fn checkpoint_for_sequence<C: GenericClient>(
    client: &mut C,
    sequence: i64,
) -> Result<Option<MerkleCheckpoint>, postgres::Error> {
    let checkpoint = client.query_opt(
        "
        SELECT seq, root, signature, signer_key_id
        FROM s8.merkle_checkpoint
        WHERE seq = $1;
        ",
        &[&sequence],
    )?;
    Ok(checkpoint.map(|row| MerkleCheckpoint {
        sequence: row.get(0),
        root: row.get(1),
        signature: row.get(2),
        signer_key_id: row.get(3),
    }))
}

fn validate_checkpoint_for_tip(
    checkpoint: &MerkleCheckpoint,
    sequence: i64,
    root: &str,
) -> Result<(), LedgerCommitError> {
    if checkpoint.sequence != sequence {
        return Err(LedgerCommitError::CheckpointMismatch("sequence"));
    }
    if checkpoint.root != root {
        return Err(LedgerCommitError::CheckpointMismatch("root"));
    }
    if !checkpoint
        .signature
        .starts_with(CHECKPOINT_SIGNATURE_PREFIX)
    {
        return Err(LedgerCommitError::CheckpointMismatch("signature_algorithm"));
    }
    if checkpoint.signer_key_id.is_empty() {
        return Err(LedgerCommitError::CheckpointMismatch("signer_key_id"));
    }
    Ok(())
}

fn next_ledger_root(previous_root: &str, record_hash: &str, sequence: i64) -> String {
    hash_bytes(format!("{previous_root}|{record_hash}|{sequence}").as_bytes())
}

fn zero_ledger_root() -> String {
    format!("{BLAKE3_PREFIX}{}", "0".repeat(64))
}

#[cfg(test)]
fn checkpoint_signature_payload(sequence: i64, root: &str, signer_key_id: &str) -> String {
    format!(
        "argus-s8-merkle-checkpoint-v1\nalgorithm:{CHECKPOINT_SIGNATURE_ALGORITHM}\nseq:{sequence}\nroot:{root}\nsigner_key_id:{signer_key_id}\n"
    )
}

#[cfg(test)]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    static POSTGRES_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn writer_enforces_single_writer_fail_closed_semantics_in_real_postgres(
    ) -> Result<(), Box<dyn Error>> {
        let Some(postgres) = TestPostgres::start()? else {
            return Ok(());
        };
        let mut writer = postgres.ledger_writer()?;
        let dataset = draft("c4://artifact/happy-dataset", 1, "dataset", &[], None);
        let report = draft(
            "c4://artifact/happy-report",
            2,
            "validation_report",
            &[],
            None,
        );
        let model = draft(
            "c4://artifact/happy-model",
            3,
            "model",
            &["c4://artifact/happy-dataset"],
            Some("c4://artifact/happy-report"),
        );
        let idempotent_dataset = draft("c4://artifact/idempotent-dataset", 4, "dataset", &[], None);
        let rollback_model = draft(
            "c4://artifact/rollback-model",
            5,
            "model",
            &["c4://artifact/missing"],
            None,
        );

        writer.commit_artifact_record(&dataset)?;
        writer.commit_artifact_record(&report)?;
        writer.commit_artifact_record(&model)?;
        writer.commit_artifact_record(&idempotent_dataset)?;
        writer.commit_artifact_record(&idempotent_dataset)?;
        let rollback_error = writer
            .commit_artifact_record(&rollback_model)
            .expect_err("missing input ref must fail");
        let checkpoint_signer =
            CheckpointSigner::new("s8-ledger-key", b"s8-ledger-secret".to_vec());
        let checkpoint = writer
            .append_latest_checkpoint(&checkpoint_signer)?
            .expect("non-empty ledger has a checkpoint");
        let repeated_checkpoint = writer
            .append_latest_checkpoint(&checkpoint_signer)?
            .expect("checkpoint append is idempotent");
        let conflicting_signer =
            CheckpointSigner::new("s8-ledger-key-rotated", b"rotated-secret".to_vec());
        let checkpoint_conflict = writer
            .append_latest_checkpoint(&conflicting_signer)
            .expect_err("existing checkpoint cannot be overwritten by a different signer");

        let mut admin = postgres.admin_client()?;
        let record_count = scalar_i64(&mut admin, "SELECT count(*) FROM s8.artifact_record;")?;
        let input_edge_count = scalar_i64(
            &mut admin,
            "
            SELECT count(*)
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/happy-dataset'
              AND descendant_id = 'c4://artifact/happy-model'
              AND depth = 1;
            ",
        )?;
        let report_edge_count = scalar_i64(
            &mut admin,
            "
            SELECT count(*)
            FROM s8.lineage_closure
            WHERE ancestor_id = 'c4://artifact/happy-report'
              AND descendant_id = 'c4://artifact/happy-model'
              AND depth = 1;
            ",
        )?;
        let idempotent_count = scalar_i64(
            &mut admin,
            "SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/idempotent-dataset';",
        )?;
        let rollback_record_count = scalar_i64(
            &mut admin,
            "SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/rollback-model';",
        )?;
        let leaf_count = scalar_i64(&mut admin, "SELECT count(*) FROM s8.ledger_leaf;")?;
        let latest_leaf = admin.query_one(
            "
            SELECT sequence, root
            FROM s8.ledger_leaf
            ORDER BY sequence DESC
            LIMIT 1;
            ",
            &[],
        )?;
        let latest_sequence: i64 = latest_leaf.get(0);
        let latest_root: String = latest_leaf.get(1);
        let dataset_row = admin.query_one(
            "
            SELECT merkle_seq, size_bytes, created_at
            FROM s8.artifact_record
            WHERE artifact_id = $1;
            ",
            &[&dataset.artifact_id],
        )?;
        let dataset_merkle_seq: i64 = dataset_row.get(0);
        let dataset_size_bytes: Option<i64> = dataset_row.get(1);
        let dataset_created_at: DateTime<Utc> = dataset_row.get(2);
        let checkpoint_count =
            scalar_i64(&mut admin, "SELECT count(*) FROM s8.merkle_checkpoint;")?;
        let persisted_checkpoint = admin.query_one(
            "
            SELECT seq, root, signature, signer_key_id
            FROM s8.merkle_checkpoint
            WHERE seq = $1;
            ",
            &[&latest_sequence],
        )?;
        let persisted_checkpoint = MerkleCheckpoint {
            sequence: persisted_checkpoint.get(0),
            root: persisted_checkpoint.get(1),
            signature: persisted_checkpoint.get(2),
            signer_key_id: persisted_checkpoint.get(3),
        };
        let mut expected_root = zero_ledger_root();
        for (sequence, draft) in [&dataset, &report, &model, &idempotent_dataset]
            .into_iter()
            .enumerate()
        {
            expected_root =
                next_ledger_root(&expected_root, &draft.record_hash, (sequence + 1) as i64);
        }

        drop(admin);
        let mut ledger_client = postgres.ledger_client()?;
        let direct_insert_error = ledger_client
            .execute(
                "
                INSERT INTO s8.artifact_record (
                    artifact_id, content_hash, kind, producer, lineage, record_hash, merkle_seq
                ) VALUES (
                    'c4://artifact/direct',
                    'blake3:0000000000000000000000000000000000000000000000000000000000000009',
                    'dataset',
                    '{}'::jsonb,
                    '{}'::jsonb,
                    'blake3:0000000000000000000000000000000000000000000000000000000000001009',
                    9
                );
                ",
                &[],
            )
            .expect_err("writer role must not insert records directly");
        let direct_leaf_insert_error = ledger_client
            .execute(
                "
                INSERT INTO s8.ledger_leaf (
                    sequence, artifact_id, record_hash, previous_root, root
                ) VALUES (
                    99,
                    'c4://artifact/happy-dataset',
                    'blake3:0000000000000000000000000000000000000000000000000000000000001001',
                    'blake3:0000000000000000000000000000000000000000000000000000000000000000',
                    'blake3:0000000000000000000000000000000000000000000000000000000000009999'
                );
                ",
                &[],
            )
            .expect_err("writer role must not insert ledger leaves directly");
        let direct_checkpoint_insert_error = ledger_client
            .execute(
                "
                INSERT INTO s8.merkle_checkpoint (seq, root, signature, signer_key_id)
                VALUES (
                    4,
                    'blake3:0000000000000000000000000000000000000000000000000000000000009999',
                    'hmac-sha256:bad',
                    'direct-writer'
                );
                ",
                &[],
            )
            .expect_err("writer role must not insert checkpoints directly");

        assert_eq!(record_count, 4);
        assert_eq!(input_edge_count, 1);
        assert_eq!(report_edge_count, 1);
        assert_eq!(idempotent_count, 1);
        assert_eq!(leaf_count, 4);
        assert_eq!(latest_sequence, 4);
        assert_eq!(latest_root, expected_root);
        assert_eq!(dataset_merkle_seq, 1);
        assert_eq!(dataset_size_bytes, Some(10));
        assert_eq!(
            dataset_created_at,
            *dataset.created_at.as_ref().expect("draft has created_at")
        );
        assert_eq!(checkpoint_count, 1);
        assert_eq!(checkpoint, repeated_checkpoint);
        assert_eq!(checkpoint, persisted_checkpoint);
        assert!(checkpoint_signer.verify(&persisted_checkpoint));
        assert_eq!(
            sqlstate(&checkpoint_conflict).as_deref(),
            Some("23505"),
            "{checkpoint_conflict:?}"
        );
        assert_eq!(
            sqlstate(&rollback_error).as_deref(),
            Some("23503"),
            "{rollback_error:?}"
        );
        assert_eq!(rollback_record_count, 0);
        assert_eq!(
            sqlstate(&direct_insert_error).as_deref(),
            Some("42501"),
            "{direct_insert_error:?}"
        );
        assert_eq!(
            sqlstate(&direct_leaf_insert_error).as_deref(),
            Some("42501"),
            "{direct_leaf_insert_error:?}"
        );
        assert_eq!(
            sqlstate(&direct_checkpoint_insert_error).as_deref(),
            Some("42501"),
            "{direct_checkpoint_insert_error:?}"
        );
        Ok(())
    }

    #[test]
    fn writer_rolls_back_record_and_leaf_when_checkpoint_signer_is_unavailable(
    ) -> Result<(), Box<dyn Error>> {
        let Some(postgres) = TestPostgres::start()? else {
            return Ok(());
        };
        let mut writer = postgres.ledger_writer()?;
        let record = draft("c4://artifact/s10-down-model", 6, "model", &[], None);

        let error = writer
            .commit_artifact_record_with_checkpoint(&record, |_sequence, _root| {
                Err("s10 checkpoint signer unavailable".to_string())
            })
            .expect_err("S10 signer outage must reject the whole ledger commit");

        match error {
            LedgerCommitError::CheckpointSigner(reason) => {
                assert!(reason.contains("s10 checkpoint signer unavailable"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut admin = postgres.admin_client()?;
        assert_eq!(
            scalar_i64(
                &mut admin,
                "SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/s10-down-model';",
            )?,
            0
        );
        assert_eq!(
            scalar_i64(&mut admin, "SELECT count(*) FROM s8.ledger_leaf;")?,
            0
        );
        assert_eq!(
            scalar_i64(&mut admin, "SELECT count(*) FROM s8.merkle_checkpoint;")?,
            0
        );
        drop(admin);

        let signer = CheckpointSigner::new("s8-ledger-key", b"s8-ledger-secret".to_vec());
        let checkpoint = writer
            .commit_artifact_record_with_checkpoint(&record, |sequence, root| {
                Ok(MerkleCheckpoint {
                    sequence,
                    root: root.to_string(),
                    signature: signer.sign(sequence, root),
                    signer_key_id: signer.key_id().to_string(),
                })
            })?
            .expect("successful commit returns checkpoint");

        let mut admin = postgres.admin_client()?;
        assert_eq!(
            scalar_i64(
                &mut admin,
                "SELECT count(*) FROM s8.artifact_record WHERE artifact_id = 'c4://artifact/s10-down-model';",
            )?,
            1
        );
        assert_eq!(
            scalar_i64(&mut admin, "SELECT count(*) FROM s8.ledger_leaf;")?,
            1
        );
        assert_eq!(
            scalar_i64(&mut admin, "SELECT count(*) FROM s8.merkle_checkpoint;")?,
            1
        );
        assert!(signer.verify(&checkpoint));
        Ok(())
    }

    #[test]
    fn concurrent_checkpointed_writers_serialize_the_merkle_tip() -> Result<(), Box<dyn Error>> {
        let Some(postgres) = TestPostgres::start()? else {
            return Ok(());
        };
        let dsn = postgres.connection_string();
        let signer = CheckpointSigner::new("s8-ledger-key", b"s8-ledger-secret".to_vec());
        let barrier = Arc::new(Barrier::new(6));
        let handles = (1..=5)
            .map(|sequence| {
                let dsn = dsn.clone();
                let signer = signer.clone();
                let barrier = Arc::clone(&barrier);
                let record = draft(
                    &format!("c4://artifact/concurrent-{sequence}"),
                    sequence,
                    "dataset",
                    &[],
                    None,
                );
                thread::spawn(move || -> Result<MerkleCheckpoint, String> {
                    let mut client = Client::connect(&dsn, NoTls).map_err(|error| error.to_string())?;
                    client
                        .batch_execute("SET ROLE argus_s8_ledger_writer;")
                        .map_err(|error| error.to_string())?;
                    let mut writer = PostgresLedgerWriter::from_client(client);
                    barrier.wait();
                    writer
                        .commit_artifact_record_with_checkpoint(&record, |tip_sequence, root| {
                            Ok(MerkleCheckpoint {
                                sequence: tip_sequence,
                                root: root.to_string(),
                                signature: signer.sign(tip_sequence, root),
                                signer_key_id: signer.key_id().to_string(),
                            })
                        })
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "concurrent insert unexpectedly returned no checkpoint".to_string())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            let checkpoint = handle
                .join()
                .map_err(|_| "concurrent ledger writer thread panicked")?
                .map_err(|error| format!("concurrent ledger writer failed: {error}"))?;
            assert!(signer.verify(&checkpoint));
        }

        let mut admin = postgres.admin_client()?;
        assert_eq!(scalar_i64(&mut admin, "SELECT count(*) FROM s8.artifact_record;")?, 5);
        assert_eq!(scalar_i64(&mut admin, "SELECT count(*) FROM s8.ledger_leaf;")?, 5);
        assert_eq!(scalar_i64(&mut admin, "SELECT max(sequence) FROM s8.ledger_leaf;")?, 5);
        Ok(())
    }

    #[test]
    fn writer_sets_transaction_timeouts_with_local_scope() -> Result<(), Box<dyn Error>> {
        let Some(postgres) = TestPostgres::start()? else {
            return Ok(());
        };
        let mut client = postgres.ledger_client()?;
        let baseline_statement_timeout = scalar_string(&mut client, "SHOW statement_timeout;")?;
        let baseline_idle_timeout =
            scalar_string(&mut client, "SHOW idle_in_transaction_session_timeout;")?;

        {
            let mut transaction = client.transaction()?;
            apply_ledger_transaction_timeouts(&mut transaction)?;
            assert_eq!(
                scalar_string(&mut transaction, "SHOW statement_timeout;")?,
                "15s"
            );
            assert_eq!(
                scalar_string(&mut transaction, "SHOW idle_in_transaction_session_timeout;")?,
                "15s"
            );
            transaction.commit()?;
        }

        assert_eq!(
            scalar_string(&mut client, "SHOW statement_timeout;")?,
            baseline_statement_timeout
        );
        assert_eq!(
            scalar_string(&mut client, "SHOW idle_in_transaction_session_timeout;")?,
            baseline_idle_timeout
        );
        Ok(())
    }

    struct TestPostgres {
        root: Option<PathBuf>,
        data_dir: Option<PathBuf>,
        port: u16,
        database: String,
        preexisting_roles: Vec<String>,
        managed_cluster: bool,
        _guard: MutexGuard<'static, ()>,
    }

    impl TestPostgres {
        fn start() -> Result<Option<Self>, Box<dyn Error>> {
            if !["initdb", "pg_ctl"]
                .iter()
                .all(|command| command_exists(command))
            {
                return Self::start_existing_postgres();
            }

            let guard = POSTGRES_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let root = unique_temp_dir("argus-s8-rust-postgres");
            fs::create_dir_all(&root)?;
            let data_dir = root.join("pgdata");
            let port = free_port()?;
            let postgres = Self {
                root: Some(root),
                data_dir: Some(data_dir),
                port,
                database: "postgres".to_string(),
                preexisting_roles: Vec::new(),
                managed_cluster: true,
                _guard: guard,
            };
            if let Err(error) = postgres.init() {
                if error
                    .to_string()
                    .contains("could not create shared memory segment")
                {
                    eprintln!(
                        "falling back to existing local Postgres for Rust S8 ledger tests: {error}"
                    );
                    drop(postgres);
                    return Self::start_existing_postgres();
                }
                return Err(error);
            }
            Ok(Some(postgres))
        }

        fn start_existing_postgres() -> Result<Option<Self>, Box<dyn Error>> {
            let guard = POSTGRES_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let port = local_pg_port();
            let database = format!(
                "argus_s8_rust_test_{}_{}",
                std::process::id(),
                unique_suffix()
            );
            let mut admin = match Client::connect(&connection_string_for(port, "postgres"), NoTls) {
                Ok(client) => client,
                Err(error) => {
                    eprintln!("skipping Rust S8 ledger Postgres tests: existing local Postgres unavailable: {error}");
                    return Ok(None);
                }
            };
            let preexisting_roles = existing_roles(&mut admin)?;
            admin.batch_execute(&format!("CREATE DATABASE {database};"))?;
            drop(admin);

            let postgres = Self {
                root: None,
                data_dir: None,
                port,
                database,
                preexisting_roles,
                managed_cluster: false,
                _guard: guard,
            };
            postgres.apply_schema()?;
            Ok(Some(postgres))
        }

        fn init(&self) -> Result<(), Box<dyn Error>> {
            run_checked(
                Command::new("initdb")
                    .arg("-A")
                    .arg("trust")
                    .arg("--nosync")
                    .arg("-D")
                    .arg(
                        self.data_dir
                            .as_ref()
                            .expect("managed cluster has data dir"),
                    ),
            )?;
            run_checked(
                Command::new("pg_ctl")
                    .arg("-D")
                    .arg(
                        self.data_dir
                            .as_ref()
                            .expect("managed cluster has data dir"),
                    )
                    .arg("-l")
                    .arg(
                        self.root
                            .as_ref()
                            .expect("managed cluster has root")
                            .join("postgres.log"),
                    )
                    .arg("-o")
                    .arg(format!("-p {} -c listen_addresses=127.0.0.1", self.port))
                    .arg("-w")
                    .arg("start"),
            )?;
            self.apply_schema()?;
            Ok(())
        }

        fn apply_schema(&self) -> Result<(), Box<dyn Error>> {
            let mut client = self.admin_client()?;
            for migration in migration_paths()? {
                let schema = fs::read_to_string(migration)?;
                client.batch_execute(&schema)?;
            }
            Ok(())
        }

        fn admin_client(&self) -> Result<Client, postgres::Error> {
            Client::connect(&self.connection_string(), NoTls)
        }

        fn ledger_client(&self) -> Result<Client, postgres::Error> {
            let mut client = self.admin_client()?;
            client.batch_execute("SET ROLE argus_s8_ledger_writer;")?;
            Ok(client)
        }

        fn ledger_writer(&self) -> Result<PostgresLedgerWriter, postgres::Error> {
            Ok(PostgresLedgerWriter::from_client(self.ledger_client()?))
        }

        fn connection_string(&self) -> String {
            connection_string_for(self.port, &self.database)
        }
    }

    impl Drop for TestPostgres {
        fn drop(&mut self) {
            if self.managed_cluster {
                if let Some(data_dir) = &self.data_dir {
                    let _ = Command::new("pg_ctl")
                        .arg("-D")
                        .arg(data_dir)
                        .arg("-m")
                        .arg("fast")
                        .arg("-w")
                        .arg("stop")
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                if let Some(root) = &self.root {
                    let _ = fs::remove_dir_all(root);
                }
                return;
            }

            if let Ok(mut admin) =
                Client::connect(&connection_string_for(self.port, "postgres"), NoTls)
            {
                let _ = admin.batch_execute(&format!("DROP DATABASE IF EXISTS {};", self.database));
                for role in ["argus_s8_ledger_writer", "argus_s8_reader"] {
                    if !self
                        .preexisting_roles
                        .iter()
                        .any(|existing| existing == role)
                    {
                        let _ = admin.batch_execute(&format!("DROP ROLE IF EXISTS {role};"));
                    }
                }
            }
        }
    }

    fn draft(
        artifact_id: &str,
        sequence: i64,
        kind: &str,
        input_refs: &[&str],
        validation_report_ref: Option<&str>,
    ) -> ArtifactRecordDraft {
        let input_refs_json: Vec<Value> = input_refs.iter().map(|value| json!(value)).collect();
        let input_refs = input_refs
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let mut draft = ArtifactRecordDraft::ran_toy(
            artifact_id,
            format!("blake3:{sequence:064x}"),
            kind,
            json!({"subsystem": "S6", "version": "1.0.0"}),
            json!({
                "input_refs": input_refs_json,
                "code_ref": format!("git:{sequence}"),
                "environment_digest": format!("oci:{sequence}"),
                "seeds": []
            }),
            format!("blake3:{:064x}", sequence + 1000),
            sequence + 1000,
        );
        draft.input_refs = input_refs;
        draft.validation_report_ref = validation_report_ref.map(str::to_string);
        draft.created_at = Some(
            DateTime::parse_from_rfc3339("2026-07-02T00:00:00Z")
                .expect("valid fixture instant")
                .with_timezone(&Utc),
        );
        draft.size_bytes = Some(sequence * 10);
        draft
    }

    fn scalar_i64(client: &mut Client, sql: &str) -> Result<i64, postgres::Error> {
        Ok(client.query_one(sql, &[])?.get(0))
    }

    fn scalar_string<C: postgres::GenericClient>(
        client: &mut C,
        sql: &str,
    ) -> Result<String, postgres::Error> {
        Ok(client.query_one(sql, &[])?.get(0))
    }

    fn sqlstate(error: &postgres::Error) -> Option<String> {
        error
            .as_db_error()
            .map(|db_error| db_error.code().code().to_string())
    }

    fn free_port() -> Result<u16, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    fn command_exists(command: &str) -> bool {
        Command::new(command)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn existing_roles(client: &mut Client) -> Result<Vec<String>, postgres::Error> {
        let rows = client.query(
            "
            SELECT rolname
            FROM pg_roles
            WHERE rolname IN ('argus_s8_reader', 'argus_s8_ledger_writer')
            ORDER BY rolname;
            ",
            &[],
        )?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    fn connection_string_for(port: u16, database: &str) -> String {
        let user = env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "postgres".to_string());
        format!("host=127.0.0.1 port={port} dbname={database} user={user}")
    }

    fn local_pg_port() -> u16 {
        env::var("PGPORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(5432)
    }

    fn run_checked(command: &mut Command) -> Result<(), Box<dyn Error>> {
        let output = command.output()?;
        if !output.status.success() {
            let message = format!(
                "command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(io::Error::new(io::ErrorKind::Other, message).into());
        }
        Ok(())
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            unique_suffix()
        ))
    }

    fn unique_suffix() -> u128 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        nanos
    }

    fn migration_paths() -> Result<Vec<PathBuf>, Box<dyn Error>> {
        let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("bindings directory exists")
            .parent()
            .expect("repository root exists")
            .join("db")
            .join("s8");
        let mut migrations = fs::read_dir(migrations_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        migrations.retain(|path| path.extension().is_some_and(|extension| extension == "sql"));
        migrations.sort();
        Ok(migrations)
    }
}
