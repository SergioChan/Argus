use argus_contracts::{ArtifactRecordDraft, MerkleCheckpoint, PostgresLedgerWriter};
use postgres::{Client, NoTls};
use serde_json::json;
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process;
use std::time::Duration;

const CHECKPOINT_SIGNER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CHECKPOINT_SIGNER_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
    let signer = checkpoint_signer_from_env()?;

    let mut client = Client::connect(&dsn, NoTls)?;
    if let Some(role) = role.as_deref().filter(|value| !value.is_empty()) {
        client.batch_execute(&format!("SET ROLE {};", checked_identifier(role)?))?;
    }

    let mut writer = PostgresLedgerWriter::from_client(client);
    let checkpoint = writer.commit_artifact_record_with_checkpoint(&draft, |sequence, root| {
        signer
            .sign(sequence, root)
            .map_err(|error| error.to_string())
    })?;
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

struct HttpCheckpointSigner {
    endpoint: HttpEndpoint,
    auth_token: String,
}

impl HttpCheckpointSigner {
    fn sign(&self, sequence: i64, root: &str) -> Result<MerkleCheckpoint, Box<dyn Error>> {
        let body = serde_json::to_string(&json!({
            "sequence": sequence,
            "root": root,
        }))?;
        let response = http_post_json(&self.endpoint, &self.auth_token, &body)?;
        if response.status != 201 {
            return Err(format!("checkpoint signer returned HTTP {}", response.status).into());
        }
        let checkpoint: MerkleCheckpoint = serde_json::from_str(&response.body)?;
        if checkpoint.sequence != sequence {
            return Err("checkpoint signer returned a mismatched sequence".into());
        }
        if checkpoint.root != root {
            return Err("checkpoint signer returned a mismatched root".into());
        }
        if !checkpoint.signature.starts_with("hmac-sha256:") {
            return Err("checkpoint signer returned an unsupported signature algorithm".into());
        }
        if checkpoint.signer_key_id.is_empty() {
            return Err("checkpoint signer returned an empty signer key id".into());
        }
        Ok(checkpoint)
    }
}

fn checkpoint_signer_from_env() -> Result<HttpCheckpointSigner, Box<dyn Error>> {
    Ok(HttpCheckpointSigner {
        endpoint: HttpEndpoint::parse(&required_env("ARGUS_S8_CHECKPOINT_SIGNER_URL")?)?,
        auth_token: required_env("ARGUS_S8_CHECKPOINT_SIGNER_AUTH_TOKEN")?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
}

impl HttpEndpoint {
    fn parse(url: &str) -> Result<Self, Box<dyn Error>> {
        let rest = url
            .strip_prefix("http://")
            .ok_or("checkpoint signer URL must use http://")?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err("checkpoint signer URL host is required".into());
        }
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            (host.to_string(), port.parse::<u16>()?)
        } else {
            (authority.to_string(), 80)
        };
        if host.is_empty() {
            return Err("checkpoint signer URL host is required".into());
        }
        Ok(Self {
            host,
            port,
            path: format!("/{}", path),
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
    let mut stream = connect_checkpoint_signer(endpoint)?;
    stream.set_read_timeout(Some(CHECKPOINT_SIGNER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CHECKPOINT_SIGNER_IO_TIMEOUT))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.authority(),
        auth_token,
        body.as_bytes().len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or("checkpoint signer returned a malformed HTTP response")?;
    let status = parse_http_status(head)?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}

fn connect_checkpoint_signer(endpoint: &HttpEndpoint) -> Result<TcpStream, Box<dyn Error>> {
    let addresses = (endpoint.host.as_str(), endpoint.port).to_socket_addrs()?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CHECKPOINT_SIGNER_CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.into()),
        None => Err("checkpoint signer host resolved to no socket addresses".into()),
    }
}

fn parse_http_status(head: &str) -> Result<u16, Box<dyn Error>> {
    let status_line = head
        .lines()
        .next()
        .ok_or("checkpoint signer response was empty")?;
    let mut parts = status_line.split_whitespace();
    let protocol = parts.next().unwrap_or("");
    if !protocol.starts_with("HTTP/") {
        return Err("checkpoint signer returned a malformed status line".into());
    }
    let status = parts
        .next()
        .ok_or("checkpoint signer status code is missing")?
        .parse::<u16>()?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn http_endpoint_parses_compose_service_url() -> Result<(), Box<dyn Error>> {
        let endpoint =
            HttpEndpoint::parse("http://s10-supervisor:8080/v1/internal/s8-checkpoint-signatures")?;

        assert_eq!(endpoint.host, "s10-supervisor");
        assert_eq!(endpoint.port, 8080);
        assert_eq!(endpoint.path, "/v1/internal/s8-checkpoint-signatures");
        assert_eq!(endpoint.authority(), "s10-supervisor:8080");
        Ok(())
    }

    #[test]
    fn http_checkpoint_signer_uses_s10_signature_response() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept signer request");
            let mut buffer = [0u8; 2048];
            let bytes_read = stream.read(&mut buffer).expect("read signer request");
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);
            assert!(request.contains("Authorization: Bearer signer-token"));
            assert!(request.contains("\"sequence\":7"));
            assert!(request.contains("\"root\":\"blake3:abc\""));
            let body = serde_json::to_string(&json!({
                "sequence": 7,
                "root": "blake3:abc",
                "signature": "hmac-sha256:abc123",
                "signer_key_id": "argus-m0-s8-checkpoint",
            }))
            .expect("encode response");
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.as_bytes().len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        let signer = HttpCheckpointSigner {
            endpoint: HttpEndpoint::parse(&format!("http://127.0.0.1:{port}/sign"))?,
            auth_token: "signer-token".to_string(),
        };

        let checkpoint = signer.sign(7, "blake3:abc")?;
        handle.join().expect("signer thread joined");

        assert_eq!(checkpoint.sequence, 7);
        assert_eq!(checkpoint.root, "blake3:abc");
        assert_eq!(checkpoint.signature, "hmac-sha256:abc123");
        assert_eq!(checkpoint.signer_key_id, "argus-m0-s8-checkpoint");
        Ok(())
    }
}
