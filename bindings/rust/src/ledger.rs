use crate::hash::{hash_bytes, BLAKE3_PREFIX};
use postgres::types::Json;
use postgres::{Client, GenericClient, NoTls};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
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
        }
    }
}

pub struct PostgresLedgerWriter {
    client: Client,
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
        let inserted = commit_artifact_record(&mut transaction, draft)?;
        if inserted {
            let (sequence, previous_root) = next_ledger_position(&mut transaction)?;
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

    pub fn into_client(self) -> Client {
        self.client
    }
}

fn commit_artifact_record<C: GenericClient>(
    client: &mut C,
    draft: &ArtifactRecordDraft,
) -> Result<bool, postgres::Error> {
    let producer = Json(&draft.producer);
    let lineage = Json(&draft.lineage);
    let row = client.query_one(
        "
            SELECT s8.commit_artifact_record(
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
            );
            ",
        &[
            &draft.artifact_id,
            &draft.content_hash,
            &draft.kind,
            &producer,
            &lineage,
            &draft.record_hash,
            &draft.merkle_seq,
            &draft.claim_tier,
            &draft.validation_report_ref,
            &draft.input_refs,
        ],
    )?;
    Ok(row.get(0))
}

fn next_ledger_position<C: GenericClient>(
    client: &mut C,
) -> Result<(i64, String), postgres::Error> {
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
        Ok((sequence + 1, root))
    } else {
        Ok((1, zero_ledger_root()))
    }
}

fn next_ledger_root(previous_root: &str, record_hash: &str, sequence: i64) -> String {
    hash_bytes(format!("{previous_root}|{record_hash}|{sequence}").as_bytes())
}

fn zero_ledger_root() -> String {
    format!("{BLAKE3_PREFIX}{}", "0".repeat(64))
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
    use std::sync::{Mutex, MutexGuard};
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

        assert_eq!(record_count, 4);
        assert_eq!(input_edge_count, 1);
        assert_eq!(report_edge_count, 1);
        assert_eq!(idempotent_count, 1);
        assert_eq!(leaf_count, 4);
        assert_eq!(latest_sequence, 4);
        assert_eq!(latest_root, expected_root);
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
            let schema = fs::read_to_string(schema_path())?;
            let mut client = self.admin_client()?;
            client.batch_execute(&schema)?;
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
            sequence,
        );
        draft.input_refs = input_refs;
        draft.validation_report_ref = validation_report_ref.map(str::to_string);
        draft
    }

    fn scalar_i64(client: &mut Client, sql: &str) -> Result<i64, postgres::Error> {
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

    fn schema_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("bindings directory exists")
            .parent()
            .expect("repository root exists")
            .join("db")
            .join("s8")
            .join("001_append_only_schema.sql")
    }
}
