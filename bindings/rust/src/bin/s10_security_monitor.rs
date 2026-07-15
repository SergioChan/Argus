use chrono::{DateTime, SecondsFormat, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socket2::{Domain, Socket, Type};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const SERVICE_NAME: &str = "argus-s10-security-monitor";
const BRIDGE_ENGINE_NAME: &str = "argus-host-security";
const MODERN_EBPF_ENGINE_NAME: &str = "falco-modern-ebpf";
const GVISOR_ENGINE_NAME: &str = "gvisor-runtime-monitor";
const TRUSTWRITE_RULE: &str = "Argus trust path write attempt";
const ESCAPE_RULE: &str = "Argus sandbox escape indicator";
const DEFAULT_BIND: &str = "0.0.0.0:8765";
const DEFAULT_PROC_ROOT: &str = "/host/proc";
const DEFAULT_FALCO_BIN: &str = "/usr/bin/falco";
const DEFAULT_RULES_PATH: &str = "/etc/falco/argus_rules.yaml";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_EVENTS_PER_REGISTRATION: usize = 4096;
const MAX_DEDUPLICATION_KEYS: usize = 8192;
const GVISOR_WIRE_VERSION: u32 = 1;
const GVISOR_WIRE_HEADER_SIZE: usize = 8;
const GVISOR_MAX_PACKET_BYTES: usize = 64 * 1024;
const GVISOR_MAX_LOG_READ_BYTES: u64 = 1024 * 1024;
const GVISOR_MESSAGE_SYSCALL_RAW: u16 = 6;
const GVISOR_MESSAGE_SYSCALL_OPEN: u16 = 7;
const GVISOR_MESSAGE_SYSCALL_WRITE: u16 = 34;
const OPEN_ACCESS_MODE_MASK: u32 = 0x3;
const OPEN_WRITE_ONLY: u32 = 0x1;
const OPEN_READ_WRITE: u32 = 0x2;
const OPEN_CREATE: u32 = 0x40;
const OPEN_TRUNCATE: u32 = 0x200;
const OPEN_APPEND: u32 = 0x400;

#[derive(Clone, PartialEq, Message)]
struct GvisorHandshake {
    #[prost(uint32, tag = "1")]
    version: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GvisorContextData {
    #[prost(int64, tag = "1")]
    time_ns: i64,
    #[prost(int32, tag = "2")]
    thread_id: i32,
    #[prost(int32, tag = "4")]
    thread_group_id: i32,
    #[prost(string, tag = "6")]
    container_id: String,
    #[prost(string, tag = "8")]
    cwd: String,
    #[prost(string, tag = "9")]
    process_name: String,
}

#[derive(Clone, PartialEq, Message)]
struct GvisorExit {
    #[prost(int64, tag = "1")]
    result: i64,
    #[prost(int64, tag = "2")]
    errorno: i64,
}

#[derive(Clone, PartialEq, Message)]
struct GvisorOpen {
    #[prost(message, optional, tag = "1")]
    context_data: Option<GvisorContextData>,
    #[prost(message, optional, tag = "2")]
    exit: Option<GvisorExit>,
    #[prost(uint64, tag = "3")]
    sysno: u64,
    #[prost(int64, tag = "4")]
    fd: i64,
    #[prost(string, tag = "5")]
    fd_path: String,
    #[prost(string, tag = "6")]
    pathname: String,
    #[prost(uint32, tag = "7")]
    flags: u32,
    #[prost(uint32, tag = "8")]
    mode: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GvisorWrite {
    #[prost(message, optional, tag = "1")]
    context_data: Option<GvisorContextData>,
    #[prost(message, optional, tag = "2")]
    exit: Option<GvisorExit>,
    #[prost(uint64, tag = "3")]
    sysno: u64,
    #[prost(int64, tag = "4")]
    fd: i64,
    #[prost(string, tag = "5")]
    fd_path: String,
    #[prost(uint64, tag = "6")]
    count: u64,
    #[prost(bool, tag = "7")]
    has_offset: bool,
    #[prost(int64, tag = "8")]
    offset: i64,
    #[prost(uint32, tag = "9")]
    flags: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GvisorRawSyscall {
    #[prost(message, optional, tag = "1")]
    context_data: Option<GvisorContextData>,
    #[prost(message, optional, tag = "2")]
    exit: Option<GvisorExit>,
    #[prost(uint64, tag = "4")]
    sysno: u64,
    #[prost(uint64, tag = "5")]
    arg1: u64,
    #[prost(uint64, tag = "6")]
    arg2: u64,
    #[prost(uint64, tag = "7")]
    arg3: u64,
    #[prost(uint64, tag = "8")]
    arg4: u64,
    #[prost(uint64, tag = "9")]
    arg5: u64,
    #[prost(uint64, tag = "10")]
    arg6: u64,
}

#[derive(Deserialize)]
struct GvisorDebugLog {
    msg: String,
    level: String,
    time: String,
}

struct GvisorPacket<'a> {
    message_type: u16,
    dropped_count: u32,
    payload: &'a [u8],
}

#[derive(Default)]
struct GvisorLogCursor {
    offset: u64,
    remainder: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SensorEngine {
    ModernEbpf,
    Gvisor,
}

impl SensorEngine {
    fn as_str(self) -> &'static str {
        match self {
            Self::ModernEbpf => MODERN_EBPF_ENGINE_NAME,
            Self::Gvisor => GVISOR_ENGINE_NAME,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IsolationClass {
    Docker,
    Gvisor,
    Firecracker,
}

impl IsolationClass {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "docker" => Ok(Self::Docker),
            "gvisor" => Ok(Self::Gvisor),
            "firecracker" => Ok(Self::Firecracker),
            _ => Err("isolation_class must be docker, gvisor, or firecracker".into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Gvisor => "gvisor",
            Self::Firecracker => "firecracker",
        }
    }

    fn engine(self) -> SensorEngine {
        match self {
            Self::Gvisor => SensorEngine::Gvisor,
            Self::Docker | Self::Firecracker => SensorEngine::ModernEbpf,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRequest {
    sandbox_id: String,
    job_id: String,
    isolation_class: String,
    runtime_kind: String,
    #[serde(default)]
    container_id: Option<String>,
    #[serde(default)]
    process_id: Option<u32>,
    #[serde(default)]
    cgroup_v2_path: Option<String>,
    #[serde(default)]
    trust_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RuntimeIdentity {
    Container {
        container_id: String,
    },
    HostProcess {
        process_id: u32,
        cgroup_v2_path: String,
    },
}

#[derive(Clone, Debug)]
struct Registration {
    sandbox_id: String,
    job_id: String,
    isolation_class: IsolationClass,
    engine: SensorEngine,
    runtime_kind: String,
    identity: RuntimeIdentity,
    trust_paths: Vec<String>,
}

impl RegistrationRequest {
    fn validate(self) -> Result<Registration, String> {
        if !valid_identifier(&self.sandbox_id) || !valid_identifier(&self.job_id) {
            return Err("sandbox_id and job_id must be non-empty control-plane identifiers".into());
        }
        validate_trust_paths(&self.trust_paths)?;
        let isolation_class = IsolationClass::parse(&self.isolation_class)?;
        match (isolation_class, self.runtime_kind.as_str()) {
            (IsolationClass::Docker | IsolationClass::Gvisor, "container")
            | (IsolationClass::Firecracker, "host_process") => {}
            _ => {
                return Err(
                    "isolation_class and runtime_kind do not identify the same boundary".into(),
                )
            }
        }
        let identity = match self.runtime_kind.as_str() {
            "container" => {
                let container_id = self
                    .container_id
                    .filter(|value| is_lower_hex(value, 64, 64))
                    .ok_or("container registration requires a full lowercase container ID")?;
                if self.process_id.is_some() || self.cgroup_v2_path.is_some() {
                    return Err(
                        "container registration cannot include host process identity".into(),
                    );
                }
                RuntimeIdentity::Container { container_id }
            }
            "host_process" => {
                if self.container_id.is_some() {
                    return Err(
                        "host-process registration cannot include container identity".into(),
                    );
                }
                let process_id = self
                    .process_id
                    .filter(|value| *value > 0)
                    .ok_or("host-process registration requires a positive process ID")?;
                let expected_cgroup = format!("/argus-firecracker/{}", self.sandbox_id);
                let cgroup_v2_path = self
                    .cgroup_v2_path
                    .filter(|value| value == &expected_cgroup)
                    .ok_or(
                        "host-process registration requires its exact Argus Firecracker cgroup",
                    )?;
                RuntimeIdentity::HostProcess {
                    process_id,
                    cgroup_v2_path,
                }
            }
            _ => return Err("runtime_kind must be container or host_process".into()),
        };
        Ok(Registration {
            sandbox_id: self.sandbox_id,
            job_id: self.job_id,
            isolation_class,
            engine: isolation_class.engine(),
            runtime_kind: self.runtime_kind,
            identity,
            trust_paths: self.trust_paths,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct HostSecurityEvent {
    event_id: String,
    sequence: u64,
    kind: String,
    severity: String,
    engine: String,
    rule: String,
    observed_at: String,
    sandbox_id: String,
    job_id: String,
    isolation_class: String,
    runtime_kind: String,
    container_id: Option<String>,
    process_id: u32,
    syscall: String,
    result: i64,
    path: Option<String>,
}

impl HostSecurityEvent {
    fn bind_event_id(&mut self) -> Result<(), String> {
        let mut payload = BTreeMap::new();
        payload.insert("container_id", json!(self.container_id));
        payload.insert("engine", json!(self.engine));
        payload.insert("job_id", json!(self.job_id));
        payload.insert("kind", json!(self.kind));
        payload.insert("isolation_class", json!(self.isolation_class));
        payload.insert("observed_at", json!(self.observed_at));
        payload.insert("path", json!(self.path));
        payload.insert("process_id", json!(self.process_id));
        payload.insert("result", json!(self.result));
        payload.insert("rule", json!(self.rule));
        payload.insert("runtime_kind", json!(self.runtime_kind));
        payload.insert("sandbox_id", json!(self.sandbox_id));
        payload.insert("sequence", json!(self.sequence));
        payload.insert("severity", json!(self.severity));
        payload.insert("syscall", json!(self.syscall));
        let canonical = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
        self.event_id = format!("blake3:{}", blake3::hash(&canonical).to_hex());
        Ok(())
    }
}

#[derive(Debug)]
struct RegistrationState {
    registration: Registration,
    cursor: u64,
    events: VecDeque<HostSecurityEvent>,
    seen_fingerprints: HashSet<String>,
}

#[derive(Debug, Default)]
struct MonitorState {
    registrations: HashMap<String, RegistrationState>,
    overflowed: bool,
}

struct SensorRuntime {
    configured: bool,
    running: AtomicBool,
    degraded: AtomicBool,
    child: Mutex<Option<Child>>,
}

impl SensorRuntime {
    fn new(configured: bool) -> Self {
        Self {
            configured,
            running: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            child: Mutex::new(None),
        }
    }
}

struct SharedState {
    monitor: Mutex<MonitorState>,
    modern_ebpf: SensorRuntime,
    gvisor: SensorRuntime,
    proc_root: PathBuf,
}

impl SharedState {
    #[cfg(test)]
    fn new(proc_root: PathBuf) -> Self {
        Self::new_with_gvisor(proc_root, false)
    }

    fn new_with_gvisor(proc_root: PathBuf, gvisor_configured: bool) -> Self {
        Self {
            monitor: Mutex::new(MonitorState::default()),
            modern_ebpf: SensorRuntime::new(true),
            gvisor: SensorRuntime::new(gvisor_configured),
            proc_root,
        }
    }

    fn sensor(&self, engine: SensorEngine) -> &SensorRuntime {
        match engine {
            SensorEngine::ModernEbpf => &self.modern_ebpf,
            SensorEngine::Gvisor => &self.gvisor,
        }
    }

    fn mark_sensor_unhealthy(&self, engine: SensorEngine) {
        self.sensor(engine).running.store(false, Ordering::SeqCst);
    }

    fn mark_sensor_degraded(&self, engine: SensorEngine) {
        let sensor = self.sensor(engine);
        sensor.degraded.store(true, Ordering::SeqCst);
        sensor.running.store(false, Ordering::SeqCst);
    }

    fn source_health(&self, engine: SensorEngine) -> SensorHealth {
        let sensor = self.sensor(engine);
        if sensor.configured {
            let mut child = sensor.child.lock().expect("Falco child lock poisoned");
            if let Some(process) = child.as_mut() {
                match process.try_wait() {
                    Ok(Some(status)) => {
                        eprintln!("{} exited unexpectedly with {status}", engine.as_str());
                        self.mark_sensor_unhealthy(engine);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!("{} process health check failed: {error}", engine.as_str());
                        self.mark_sensor_unhealthy(engine);
                    }
                }
            }
        }
        SensorHealth {
            configured: sensor.configured,
            running: sensor.running.load(Ordering::SeqCst),
            degraded: sensor.degraded.load(Ordering::SeqCst),
        }
    }

    fn health(&self) -> HealthSnapshot {
        let modern_ebpf = self.source_health(SensorEngine::ModernEbpf);
        let gvisor = self.source_health(SensorEngine::Gvisor);
        let overflowed = self
            .monitor
            .lock()
            .expect("monitor state lock poisoned")
            .overflowed;
        HealthSnapshot {
            modern_ebpf,
            gvisor,
            overflowed,
        }
    }

    fn register(&self, request: RegistrationRequest) -> Result<Registration, ApiError> {
        let registration = request
            .validate()
            .map_err(|error| ApiError::new(400, error))?;
        let health = self.health();
        if health.overflowed || !health.source(registration.engine).healthy() {
            return Err(ApiError::new(
                503,
                format!(
                    "host security sensor is not healthy: {}",
                    registration.engine.as_str()
                ),
            ));
        }
        let mut monitor = self.monitor.lock().expect("monitor state lock poisoned");
        if monitor.registrations.contains_key(&registration.sandbox_id) {
            return Err(ApiError::new(409, "sandbox is already registered"));
        }
        if monitor
            .registrations
            .values()
            .any(|state| state.registration.identity == registration.identity)
        {
            return Err(ApiError::new(409, "runtime identity is already registered"));
        }
        monitor.registrations.insert(
            registration.sandbox_id.clone(),
            RegistrationState {
                registration: registration.clone(),
                cursor: 0,
                events: VecDeque::new(),
                seen_fingerprints: HashSet::new(),
            },
        );
        Ok(registration)
    }

    fn unregister(&self, sandbox_id: &str) -> Result<(), ApiError> {
        let mut monitor = self.monitor.lock().expect("monitor state lock poisoned");
        if monitor.registrations.remove(sandbox_id).is_none() {
            return Err(ApiError::new(404, "sandbox registration was not found"));
        }
        Ok(())
    }

    fn poll(&self, sandbox_id: &str, after: u64) -> Result<PollResponse, ApiError> {
        let health = self.health();
        let mut monitor = self.monitor.lock().expect("monitor state lock poisoned");
        let state = monitor
            .registrations
            .get_mut(sandbox_id)
            .ok_or_else(|| ApiError::new(404, "sandbox registration was not found"))?;
        if after > state.cursor {
            return Err(ApiError::new(
                400,
                "poll cursor is ahead of the sensor cursor",
            ));
        }
        while state
            .events
            .front()
            .map(|event| event.sequence <= after)
            .unwrap_or(false)
        {
            state.events.pop_front();
        }
        let events = state
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .cloned()
            .collect();
        Ok(PollResponse {
            sandbox_id: sandbox_id.to_string(),
            cursor: state.cursor,
            healthy: health.source(state.registration.engine).healthy(),
            engine: state.registration.engine.as_str().to_string(),
            overflowed: health.overflowed,
            events,
        })
    }

    fn ingest_falco_line(
        &self,
        engine: SensorEngine,
        line: &str,
    ) -> Result<Option<HostSecurityEvent>, String> {
        let alert: Value = serde_json::from_str(line)
            .map_err(|error| format!("Falco emitted malformed JSON: {error}"))?;
        let rule = alert
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kind = match rule {
            TRUSTWRITE_RULE => "trustwrite",
            ESCAPE_RULE => "escape",
            _ => return Ok(None),
        };
        if alert.get("priority").and_then(Value::as_str) != Some("Critical")
            || alert.get("source").and_then(Value::as_str) != Some("syscall")
        {
            return Err("Falco Argus rules must emit Critical syscall events".into());
        }
        let observed_at = required_string(&alert, "time")?;
        DateTime::parse_from_rfc3339(&observed_at)
            .map_err(|_| "Falco event time is not RFC3339".to_string())?;
        let output_fields = alert
            .get("output_fields")
            .and_then(Value::as_object)
            .ok_or("Falco event omitted output_fields")?;
        let process_id = parse_u32_field(output_fields.get("proc.pid"))
            .or_else(|| parse_u32_field(output_fields.get("proc.vpid")))
            .or_else(|| parse_u32_field(output_fields.get("thread.vtid")))
            .ok_or("Falco event omitted a valid process identity")?;
        let syscall =
            field_string(output_fields.get("evt.type")).ok_or("Falco event omitted evt.type")?;
        let result = parse_i64_field(
            output_fields
                .get("evt.rawres")
                .or_else(|| output_fields.get("evt.res")),
        )
        .ok_or("Falco event omitted a numeric evt.rawres")?;
        let observed_container_id = field_string(output_fields.get("container.id"))
            .filter(|value| is_lower_hex(value, 12, 64));
        let path = event_path(output_fields);

        self.ingest_security_observation(
            engine,
            observed_container_id.as_deref(),
            process_id,
            kind,
            rule,
            observed_at,
            syscall,
            result,
            path,
        )
    }

    fn ingest_gvisor_packet(&self, raw: &[u8]) -> Result<Option<HostSecurityEvent>, String> {
        let packet = decode_gvisor_packet(raw)?;
        if packet.dropped_count != 0 {
            self.mark_sensor_degraded(SensorEngine::Gvisor);
            return Err(format!(
                "gVisor remote sink reported {} dropped events",
                packet.dropped_count
            ));
        }
        match packet.message_type {
            GVISOR_MESSAGE_SYSCALL_OPEN => {
                let point = GvisorOpen::decode(packet.payload)
                    .map_err(|error| format!("gVisor open event protobuf is invalid: {error}"))?;
                self.ingest_gvisor_open(point)
            }
            GVISOR_MESSAGE_SYSCALL_WRITE => {
                let point = GvisorWrite::decode(packet.payload)
                    .map_err(|error| format!("gVisor write event protobuf is invalid: {error}"))?;
                self.ingest_gvisor_write(point)
            }
            GVISOR_MESSAGE_SYSCALL_RAW => {
                let point = GvisorRawSyscall::decode(packet.payload)
                    .map_err(|error| format!("gVisor raw syscall protobuf is invalid: {error}"))?;
                self.ingest_gvisor_raw_syscall(point)
            }
            _ => Ok(None),
        }
    }

    fn ingest_gvisor_open(&self, point: GvisorOpen) -> Result<Option<HostSecurityEvent>, String> {
        let exit = point
            .exit
            .as_ref()
            .ok_or("gVisor open event must be an exit tracepoint")?;
        if !open_has_write_intent(point.flags) {
            return Ok(None);
        }
        let context = point
            .context_data
            .as_ref()
            .ok_or("gVisor open event omitted context data")?;
        let syscall = gvisor_open_syscall_name(point.sysno)
            .ok_or("gVisor open event used an unsupported syscall number")?;
        let path = resolve_gvisor_open_path(context, &point)
            .ok_or("gVisor open event omitted a normalized absolute path")?;
        let observed_at = gvisor_observed_at(context.time_ns)?;
        let process_id = gvisor_process_id(context)?;
        let result = gvisor_result(exit)?;
        self.ingest_security_observation(
            SensorEngine::Gvisor,
            Some(&context.container_id),
            process_id,
            "trustwrite",
            TRUSTWRITE_RULE,
            observed_at,
            syscall.to_string(),
            result,
            Some(path),
        )
    }

    fn ingest_gvisor_write(&self, point: GvisorWrite) -> Result<Option<HostSecurityEvent>, String> {
        let exit = point
            .exit
            .as_ref()
            .ok_or("gVisor write event must be an exit tracepoint")?;
        let context = point
            .context_data
            .as_ref()
            .ok_or("gVisor write event omitted context data")?;
        let Some(path) = normalize_absolute_path(Path::new(&point.fd_path)) else {
            return Ok(None);
        };
        let syscall = gvisor_write_syscall_name(point.sysno)
            .ok_or("gVisor write event used an unsupported syscall number")?;
        self.ingest_security_observation(
            SensorEngine::Gvisor,
            Some(&context.container_id),
            gvisor_process_id(context)?,
            "trustwrite",
            TRUSTWRITE_RULE,
            gvisor_observed_at(context.time_ns)?,
            syscall.to_string(),
            gvisor_result(exit)?,
            Some(path),
        )
    }

    fn ingest_gvisor_raw_syscall(
        &self,
        point: GvisorRawSyscall,
    ) -> Result<Option<HostSecurityEvent>, String> {
        let exit = point
            .exit
            .as_ref()
            .ok_or("gVisor raw syscall event must be an exit tracepoint")?;
        let Some(syscall) = gvisor_dangerous_syscall_name(point.sysno) else {
            return Ok(None);
        };
        let context = point
            .context_data
            .as_ref()
            .ok_or("gVisor raw syscall event omitted context data")?;
        self.ingest_security_observation(
            SensorEngine::Gvisor,
            Some(&context.container_id),
            gvisor_process_id(context)?,
            "escape",
            ESCAPE_RULE,
            gvisor_observed_at(context.time_ns)?,
            syscall.to_string(),
            gvisor_result(exit)?,
            None,
        )
    }

    fn ingest_gvisor_seccomp_log(
        &self,
        container_id: &str,
        line: &str,
    ) -> Result<Option<HostSecurityEvent>, String> {
        if !is_lower_hex(container_id, 64, 64) {
            return Err("gVisor seccomp audit path did not contain a full container ID".into());
        }
        if !self.has_gvisor_container_registration(container_id) {
            return Ok(None);
        }
        let record: GvisorDebugLog = serde_json::from_str(line)
            .map_err(|error| format!("gVisor debug audit emitted malformed JSON: {error}"))?;
        if record.level != "debug" {
            return Ok(None);
        }
        DateTime::parse_from_rfc3339(&record.time)
            .map_err(|_| "gVisor debug audit time is not RFC3339".to_string())?;
        let Some((process_id, sysno)) = parse_gvisor_seccomp_denial(&record.msg)? else {
            return Ok(None);
        };
        let Some(syscall) = gvisor_dangerous_syscall_name(sysno) else {
            return Ok(None);
        };
        self.ingest_security_observation(
            SensorEngine::Gvisor,
            Some(container_id),
            process_id,
            "escape",
            ESCAPE_RULE,
            record.time,
            syscall.to_string(),
            -1,
            None,
        )
    }

    fn has_gvisor_container_registration(&self, container_id: &str) -> bool {
        self.monitor
            .lock()
            .expect("monitor state lock poisoned")
            .registrations
            .values()
            .any(|state| {
                state.registration.engine == SensorEngine::Gvisor
                    && matches!(
                        &state.registration.identity,
                        RuntimeIdentity::Container { container_id: registered }
                            if registered == container_id
                    )
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_security_observation(
        &self,
        engine: SensorEngine,
        observed_container_id: Option<&str>,
        process_id: u32,
        kind: &str,
        rule: &str,
        observed_at: String,
        syscall: String,
        result: i64,
        path: Option<String>,
    ) -> Result<Option<HostSecurityEvent>, String> {
        DateTime::parse_from_rfc3339(&observed_at)
            .map_err(|_| "security event time is not RFC3339".to_string())?;

        let mut monitor = self.monitor.lock().expect("monitor state lock poisoned");
        let matching_ids: Vec<String> = monitor
            .registrations
            .values()
            .filter(|state| {
                registration_matches_event(
                    &state.registration,
                    engine,
                    observed_container_id.as_deref(),
                    process_id,
                    &self.proc_root,
                )
            })
            .map(|state| state.registration.sandbox_id.clone())
            .collect();
        if matching_ids.is_empty() {
            return Ok(None);
        }
        if matching_ids.len() != 1 {
            return Err("security event matched multiple sandbox registrations".into());
        }
        let sandbox_id = &matching_ids[0];
        let state = monitor
            .registrations
            .get_mut(sandbox_id)
            .expect("matched registration disappeared");
        if kind == "trustwrite"
            && !path
                .as_deref()
                .map(|candidate| trust_path_matches(candidate, &state.registration.trust_paths))
                .unwrap_or(false)
        {
            return Ok(None);
        }
        let fingerprint = event_fingerprint(
            kind,
            rule,
            &observed_at,
            &state.registration,
            engine,
            process_id,
            &syscall,
            result,
            path.as_deref(),
        )?;
        if state.seen_fingerprints.contains(&fingerprint) {
            return Ok(None);
        }
        if state.events.len() >= MAX_EVENTS_PER_REGISTRATION
            || state.seen_fingerprints.len() >= MAX_DEDUPLICATION_KEYS
        {
            monitor.overflowed = true;
            return Err("security monitor event buffer overflowed".into());
        }
        state.seen_fingerprints.insert(fingerprint);
        state.cursor += 1;
        let container_id = match &state.registration.identity {
            RuntimeIdentity::Container { container_id } => Some(container_id.clone()),
            RuntimeIdentity::HostProcess { .. } => None,
        };
        let mut event = HostSecurityEvent {
            event_id: String::new(),
            sequence: state.cursor,
            kind: kind.to_string(),
            severity: "Sev-1".to_string(),
            engine: engine.as_str().to_string(),
            rule: rule.to_string(),
            observed_at,
            sandbox_id: state.registration.sandbox_id.clone(),
            job_id: state.registration.job_id.clone(),
            isolation_class: state.registration.isolation_class.as_str().to_string(),
            runtime_kind: state.registration.runtime_kind.clone(),
            container_id,
            process_id,
            syscall,
            result,
            path,
        };
        event.bind_event_id()?;
        state.events.push_back(event.clone());
        Ok(Some(event))
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct SensorHealth {
    configured: bool,
    running: bool,
    degraded: bool,
}

impl SensorHealth {
    fn healthy(self) -> bool {
        self.configured && self.running && !self.degraded
    }
}

#[derive(Clone, Copy, Debug)]
struct HealthSnapshot {
    modern_ebpf: SensorHealth,
    gvisor: SensorHealth,
    overflowed: bool,
}

impl HealthSnapshot {
    fn source(self, engine: SensorEngine) -> SensorHealth {
        match engine {
            SensorEngine::ModernEbpf => self.modern_ebpf,
            SensorEngine::Gvisor => self.gvisor,
        }
    }

    fn status(self) -> &'static str {
        if self.overflowed || !self.modern_ebpf.healthy() {
            "error"
        } else if self.gvisor.configured && !self.gvisor.healthy() {
            "degraded"
        } else {
            "ok"
        }
    }
}

#[derive(Serialize)]
struct PollResponse {
    sandbox_id: String,
    cursor: u64,
    healthy: bool,
    engine: String,
    overflowed: bool,
    events: Vec<HostSecurityEvent>,
}

#[derive(Debug)]
struct ApiError {
    status: u16,
    message: String,
}

impl ApiError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn is_lower_hex(value: &str, min_length: usize, max_length: usize) -> bool {
    (min_length..=max_length).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_trust_paths(paths: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for raw in paths {
        let path = Path::new(raw);
        let normalized: PathBuf = path.components().collect();
        if raw.is_empty()
            || raw.contains('\0')
            || raw == "/"
            || !path.is_absolute()
            || normalized.to_string_lossy() != raw.as_str()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err("trust paths must be normalized absolute non-root paths".into());
        }
        if !seen.insert(raw) {
            return Err("trust paths must be unique".into());
        }
    }
    Ok(())
}

fn required_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("Falco event omitted {key}"))
}

fn field_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(item)) if !item.is_empty() && item != "<NA>" => Some(item.clone()),
        Some(Value::Number(item)) => Some(item.to_string()),
        _ => None,
    }
}

fn parse_u32_field(value: Option<&Value>) -> Option<u32> {
    field_string(value)?.parse().ok().filter(|item| *item > 0)
}

fn parse_i64_field(value: Option<&Value>) -> Option<i64> {
    field_string(value)?.parse().ok()
}

fn event_path(fields: &serde_json::Map<String, Value>) -> Option<String> {
    [
        "fd.name",
        "evt.arg.name",
        "evt.arg.pathname",
        "evt.arg.path",
        "evt.arg.target",
        "fs.path.name",
        "fs.path.source",
        "fs.path.target",
    ]
    .iter()
    .find_map(|key| field_string(fields.get(*key)))
    .filter(|path| path.starts_with('/') && !path.contains('\0'))
}

fn trust_path_matches(candidate: &str, trust_paths: &[String]) -> bool {
    trust_paths.iter().any(|trust_path| {
        candidate == trust_path
            || candidate
                .strip_prefix(trust_path)
                .map(|suffix| suffix.starts_with('/'))
                .unwrap_or(false)
    })
}

#[cfg(test)]
fn encode_gvisor_packet(message_type: u16, dropped_count: u32, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(GVISOR_WIRE_HEADER_SIZE + payload.len());
    encoded.extend_from_slice(&(GVISOR_WIRE_HEADER_SIZE as u16).to_le_bytes());
    encoded.extend_from_slice(&message_type.to_le_bytes());
    encoded.extend_from_slice(&dropped_count.to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_gvisor_packet(raw: &[u8]) -> Result<GvisorPacket<'_>, String> {
    if raw.len() < GVISOR_WIRE_HEADER_SIZE || raw.len() > GVISOR_MAX_PACKET_BYTES {
        return Err("gVisor remote packet size is outside the accepted bounds".into());
    }
    let header_size = usize::from(u16::from_le_bytes([raw[0], raw[1]]));
    if !(GVISOR_WIRE_HEADER_SIZE..=raw.len()).contains(&header_size) {
        return Err("gVisor remote packet header size is invalid".into());
    }
    Ok(GvisorPacket {
        message_type: u16::from_le_bytes([raw[2], raw[3]]),
        dropped_count: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        payload: &raw[header_size..],
    })
}

fn open_has_write_intent(flags: u32) -> bool {
    matches!(
        flags & OPEN_ACCESS_MODE_MASK,
        OPEN_WRITE_ONLY | OPEN_READ_WRITE
    ) || flags & (OPEN_CREATE | OPEN_TRUNCATE | OPEN_APPEND) != 0
}

fn gvisor_process_id(context: &GvisorContextData) -> Result<u32, String> {
    if !is_lower_hex(&context.container_id, 64, 64) {
        return Err("gVisor event omitted a full lowercase container ID".into());
    }
    u32::try_from(if context.thread_group_id > 0 {
        context.thread_group_id
    } else {
        context.thread_id
    })
    .ok()
    .filter(|value| *value > 0)
    .ok_or_else(|| "gVisor event omitted a positive process identity".into())
}

fn gvisor_observed_at(time_ns: i64) -> Result<String, String> {
    if time_ns <= 0 {
        return Err("gVisor event omitted a positive observation timestamp".into());
    }
    let seconds = time_ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(time_ns.rem_euclid(1_000_000_000))
        .map_err(|_| "gVisor event timestamp nanoseconds are invalid")?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .ok_or_else(|| "gVisor event timestamp is outside RFC3339 bounds".into())
}

fn gvisor_result(exit: &GvisorExit) -> Result<i64, String> {
    if exit.errorno < 0 || exit.errorno > 4095 {
        return Err("gVisor syscall exit errno is invalid".into());
    }
    Ok(if exit.errorno == 0 {
        exit.result
    } else {
        -exit.errorno
    })
}

fn resolve_gvisor_open_path(context: &GvisorContextData, point: &GvisorOpen) -> Option<String> {
    let pathname = Path::new(&point.pathname);
    if pathname.is_absolute() {
        return normalize_absolute_path(pathname);
    }
    let base = if Path::new(&point.fd_path).is_absolute() {
        Path::new(&point.fd_path)
    } else {
        Path::new(&context.cwd)
    };
    normalize_absolute_path(&base.join(pathname))
}

fn normalize_absolute_path(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => parts.push(part),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::Prefix(_) => return None,
        }
    }
    let mut normalized = PathBuf::from("/");
    for part in parts {
        normalized.push(part);
    }
    normalized.to_str().map(str::to_string)
}

#[cfg(target_arch = "x86_64")]
fn gvisor_open_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        2 => Some("open"),
        85 => Some("creat"),
        257 => Some("openat"),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn gvisor_open_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        56 => Some("openat"),
        _ => None,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gvisor_open_syscall_name(_sysno: u64) -> Option<&'static str> {
    None
}

#[cfg(target_arch = "x86_64")]
fn gvisor_write_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        1 | 18 | 20 | 296 | 328 => Some("write"),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn gvisor_write_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        64 | 66 | 68 | 70 | 287 => Some("write"),
        _ => None,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gvisor_write_syscall_name(_sysno: u64) -> Option<&'static str> {
    None
}

#[cfg(target_arch = "x86_64")]
fn gvisor_dangerous_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        101 => Some("ptrace"),
        165 => Some("mount"),
        166 => Some("umount2"),
        246 => Some("kexec_load"),
        250 => Some("keyctl"),
        272 => Some("unshare"),
        308 => Some("setns"),
        321 => Some("bpf"),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn gvisor_dangerous_syscall_name(sysno: u64) -> Option<&'static str> {
    match sysno {
        39 => Some("umount2"),
        40 => Some("mount"),
        97 => Some("unshare"),
        104 => Some("kexec_load"),
        117 => Some("ptrace"),
        219 => Some("keyctl"),
        268 => Some("setns"),
        280 => Some("bpf"),
        _ => None,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gvisor_dangerous_syscall_name(_sysno: u64) -> Option<&'static str> {
    None
}

fn parse_gvisor_seccomp_denial(message: &str) -> Result<Option<(u32, u64)>, String> {
    let marker = "] Syscall ";
    let Some(marker_index) = message.rfind(marker) else {
        return Ok(None);
    };
    let syscall_text = &message[marker_index + marker.len()..];
    let Some((raw_sysno, outcome)) = syscall_text.split_once(": ") else {
        return Err("gVisor seccomp audit syscall message is malformed".into());
    };
    if outcome != "denied by seccomp" {
        return Ok(None);
    }
    let sysno = raw_sysno
        .parse::<u64>()
        .map_err(|_| "gVisor seccomp audit syscall number is invalid")?;
    let prefix = &message[..marker_index];
    let task_fields = prefix
        .rsplit_once('[')
        .map(|(_, fields)| fields)
        .ok_or("gVisor seccomp audit omitted task identity")?;
    let raw_pid = task_fields
        .split_once(':')
        .map(|(pid, _)| pid)
        .ok_or("gVisor seccomp audit task identity is malformed")?
        .trim()
        .split('(')
        .next()
        .unwrap_or_default()
        .trim();
    let process_id = raw_pid
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("gVisor seccomp audit process identity is invalid")?;
    Ok(Some((process_id, sysno)))
}

fn registration_matches_event(
    registration: &Registration,
    engine: SensorEngine,
    observed_container_id: Option<&str>,
    process_id: u32,
    proc_root: &Path,
) -> bool {
    if registration.engine != engine {
        return false;
    }
    match &registration.identity {
        RuntimeIdentity::Container { container_id } => observed_container_id
            .map(|observed| container_id.starts_with(observed))
            .unwrap_or(false),
        RuntimeIdentity::HostProcess {
            process_id: registered_pid,
            cgroup_v2_path,
        } => {
            process_belongs_to_registration(process_id, *registered_pid, cgroup_v2_path, proc_root)
        }
    }
}

fn process_belongs_to_registration(
    event_pid: u32,
    registered_pid: u32,
    cgroup_v2_path: &str,
    proc_root: &Path,
) -> bool {
    let mut current = event_pid;
    let mut saw_registered_pid = false;
    let mut saw_registered_cgroup = false;
    let mut visited = HashSet::new();
    for _ in 0..64 {
        if current == 0 || !visited.insert(current) {
            break;
        }
        if current == registered_pid {
            saw_registered_pid = true;
        }
        if process_cgroups(proc_root, current)
            .iter()
            .any(|path| path == cgroup_v2_path)
        {
            saw_registered_cgroup = true;
        }
        if saw_registered_pid && saw_registered_cgroup {
            return true;
        }
        current = process_parent_pid(proc_root, current).unwrap_or(0);
    }
    false
}

fn process_cgroups(proc_root: &Path, pid: u32) -> Vec<String> {
    fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .map(str::to_string)
        .collect()
}

fn process_parent_pid(proc_root: &Path, pid: u32) -> Option<u32> {
    fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

#[allow(clippy::too_many_arguments)]
fn event_fingerprint(
    kind: &str,
    rule: &str,
    observed_at: &str,
    registration: &Registration,
    engine: SensorEngine,
    process_id: u32,
    syscall: &str,
    result: i64,
    path: Option<&str>,
) -> Result<String, String> {
    let mut payload = BTreeMap::new();
    payload.insert("job_id", json!(registration.job_id));
    payload.insert("kind", json!(kind));
    payload.insert("engine", json!(engine.as_str()));
    payload.insert(
        "isolation_class",
        json!(registration.isolation_class.as_str()),
    );
    payload.insert("observed_at", json!(observed_at));
    payload.insert("path", json!(path));
    payload.insert("process_id", json!(process_id));
    payload.insert("result", json!(result));
    payload.insert("rule", json!(rule));
    payload.insert("sandbox_id", json!(registration.sandbox_id));
    payload.insert("syscall", json!(syscall));
    let canonical = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    Ok(blake3::hash(&canonical).to_hex().to_string())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn is_authorized(request: &Request, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .map(|header| constant_time_equal(header.value.as_str().as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

fn read_request_json(request: &mut Request) -> Result<Value, ApiError> {
    let mut body = String::new();
    request
        .as_reader()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_string(&mut body)
        .map_err(|_| ApiError::new(400, "request body could not be read"))?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::new(
            413,
            "request body exceeded the control-plane limit",
        ));
    }
    serde_json::from_str(&body).map_err(|_| ApiError::new(400, "request body is not valid JSON"))
}

fn respond_json(request: Request, status: u16, payload: Value) -> Result<(), String> {
    let encoded = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
    let content_type = Header::from_bytes("Content-Type", "application/json")
        .map_err(|_| "failed to construct Content-Type header".to_string())?;
    request
        .respond(
            Response::from_string(encoded)
                .with_status_code(StatusCode(status))
                .with_header(content_type),
        )
        .map_err(|error| error.to_string())
}

fn respond_api_error(request: Request, error: ApiError) -> Result<(), String> {
    respond_json(request, error.status, json!({"error": error.message}))
}

fn parse_poll_url(url: &str) -> Option<(&str, u64)> {
    let prefix = "/v1/registrations/";
    let (path, query) = url.split_once('?')?;
    let sandbox_id = path.strip_prefix(prefix)?.strip_suffix("/events")?;
    if !valid_identifier(sandbox_id) {
        return None;
    }
    let raw_after = query.strip_prefix("after=")?;
    Some((sandbox_id, raw_after.parse().ok()?))
}

fn parse_registration_url(url: &str) -> Option<&str> {
    let sandbox_id = url.strip_prefix("/v1/registrations/")?;
    if valid_identifier(sandbox_id) {
        Some(sandbox_id)
    } else {
        None
    }
}

fn handle_request(
    mut request: Request,
    state: &Arc<SharedState>,
    auth_token: &str,
) -> Result<(), String> {
    if !is_authorized(&request, auth_token) {
        return respond_json(request, 401, json!({"error": "unauthorized"}));
    }
    let method = request.method().clone();
    let url = request.url().to_string();
    if method == Method::Get && url == "/healthz" {
        let health = state.health();
        let sources = BTreeMap::from([
            (MODERN_EBPF_ENGINE_NAME, health.modern_ebpf),
            (GVISOR_ENGINE_NAME, health.gvisor),
        ]);
        return respond_json(
            request,
            200,
            json!({
                "service": SERVICE_NAME,
                "status": health.status(),
                "engine": BRIDGE_ENGINE_NAME,
                "overflowed": health.overflowed,
                "sources": sources,
            }),
        );
    }
    if method == Method::Post && url == "/v1/registrations" {
        let raw = match read_request_json(&mut request) {
            Ok(value) => value,
            Err(error) => return respond_api_error(request, error),
        };
        let registration_request: RegistrationRequest = match serde_json::from_value(raw) {
            Ok(value) => value,
            Err(_) => {
                return respond_api_error(
                    request,
                    ApiError::new(400, "registration fields are invalid"),
                )
            }
        };
        return match state.register(registration_request) {
            Ok(registration) => respond_json(
                request,
                201,
                json!({
                    "registered": true,
                    "sandbox_id": registration.sandbox_id,
                    "job_id": registration.job_id,
                    "isolation_class": registration.isolation_class.as_str(),
                    "runtime_kind": registration.runtime_kind,
                    "engine": registration.engine.as_str(),
                    "cursor": 0,
                }),
            ),
            Err(error) => respond_api_error(request, error),
        };
    }
    if method == Method::Get {
        if let Some((sandbox_id, after)) = parse_poll_url(&url) {
            return match state.poll(sandbox_id, after) {
                Ok(poll) => respond_json(
                    request,
                    200,
                    serde_json::to_value(poll).map_err(|error| error.to_string())?,
                ),
                Err(error) => respond_api_error(request, error),
            };
        }
    }
    if method == Method::Delete {
        if let Some(sandbox_id) = parse_registration_url(&url) {
            let sandbox_id = sandbox_id.to_string();
            return match state.unregister(&sandbox_id) {
                Ok(()) => respond_json(
                    request,
                    200,
                    json!({"registered": false, "sandbox_id": sandbox_id}),
                ),
                Err(error) => respond_api_error(request, error),
            };
        }
    }
    respond_json(request, 404, json!({"error": "not found"}))
}

fn start_gvisor_source(
    state: &Arc<SharedState>,
    socket_path: &Path,
    log_root: &Path,
    log_poll_interval: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !socket_path.is_absolute() || socket_path == Path::new("/") {
        return Err("ARGUS_S10_GVISOR_SOCKET_PATH must be an absolute non-root path".into());
    }
    if !log_root.is_absolute() || !log_root.is_dir() {
        return Err("ARGUS_S10_GVISOR_LOG_ROOT must be an existing absolute directory".into());
    }
    let parent = socket_path
        .parent()
        .filter(|path| *path != Path::new("/"))
        .ok_or("gVisor socket path must have a dedicated parent directory")?;
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() {
            return Err("gVisor socket path exists and is not a Unix socket".into());
        }
        fs::remove_file(socket_path)?;
    }

    let listener = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
    listener.bind(&socket2::SockAddr::unix(socket_path)?)?;
    listener.listen(128)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;

    let listener_state = Arc::clone(state);
    thread::spawn(move || loop {
        match listener.accept() {
            Ok((connection, _)) => {
                let client_state = Arc::clone(&listener_state);
                thread::spawn(move || {
                    if let Err(error) = handle_gvisor_client(connection, &client_state) {
                        eprintln!("gVisor remote sink client failed: {error}");
                        client_state.mark_sensor_degraded(SensorEngine::Gvisor);
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("gVisor remote sink listener failed: {error}");
                listener_state.mark_sensor_unhealthy(SensorEngine::Gvisor);
                return;
            }
        }
    });

    let watcher_state = Arc::clone(state);
    let watcher_root = log_root.to_path_buf();
    thread::spawn(move || {
        if let Err(error) =
            watch_gvisor_seccomp_logs(&watcher_state, &watcher_root, log_poll_interval)
        {
            eprintln!("gVisor seccomp audit watcher failed: {error}");
            watcher_state.mark_sensor_degraded(SensorEngine::Gvisor);
        }
    });
    state
        .sensor(SensorEngine::Gvisor)
        .running
        .store(true, Ordering::SeqCst);
    Ok(())
}

fn handle_gvisor_client(
    mut connection: Socket,
    state: &Arc<SharedState>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut handshake_buffer = [0_u8; 1024];
    let handshake_size = connection.read(&mut handshake_buffer)?;
    if handshake_size == 0 || handshake_size == handshake_buffer.len() {
        return Err("gVisor remote sink handshake size is invalid".into());
    }
    let handshake = GvisorHandshake::decode(&handshake_buffer[..handshake_size])?;
    if handshake.version != GVISOR_WIRE_VERSION {
        return Err(format!(
            "gVisor remote sink wire version mismatch: expected {}, got {}",
            GVISOR_WIRE_VERSION, handshake.version
        )
        .into());
    }
    let response = GvisorHandshake {
        version: GVISOR_WIRE_VERSION,
    }
    .encode_to_vec();
    connection.write_all(&response)?;

    let mut packet_buffer = vec![0_u8; GVISOR_MAX_PACKET_BYTES + 1];
    loop {
        let packet_size = connection.read(&mut packet_buffer)?;
        if packet_size == 0 {
            return Ok(());
        }
        if packet_size > GVISOR_MAX_PACKET_BYTES {
            return Err("gVisor remote sink packet exceeded the accepted bound".into());
        }
        state
            .ingest_gvisor_packet(&packet_buffer[..packet_size])
            .map_err(|error| format!("gVisor remote sink event rejected: {error}"))?;
    }
}

fn watch_gvisor_seccomp_logs(
    state: &Arc<SharedState>,
    root: &Path,
    poll_interval: Duration,
) -> Result<(), String> {
    let mut cursors: HashMap<PathBuf, GvisorLogCursor> = HashMap::new();
    loop {
        let sandbox_directories = fs::read_dir(root)
            .map_err(|error| format!("cannot read gVisor audit root: {error}"))?;
        for sandbox_entry in sandbox_directories {
            let sandbox_entry = sandbox_entry
                .map_err(|error| format!("cannot inspect gVisor audit directory: {error}"))?;
            if !sandbox_entry
                .file_type()
                .map_err(|error| format!("cannot inspect gVisor audit entry type: {error}"))?
                .is_dir()
            {
                continue;
            }
            let Some(container_id) = sandbox_entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_lower_hex(&container_id, 64, 64)
                || !state.has_gvisor_container_registration(&container_id)
            {
                continue;
            }
            let files = fs::read_dir(sandbox_entry.path())
                .map_err(|error| format!("cannot read gVisor sandbox audit directory: {error}"))?;
            for file_entry in files {
                let file_entry = file_entry
                    .map_err(|error| format!("cannot inspect gVisor audit file: {error}"))?;
                if !file_entry
                    .file_type()
                    .map_err(|error| format!("cannot inspect gVisor audit file type: {error}"))?
                    .is_file()
                {
                    continue;
                }
                let file_name = file_entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };
                if file_name != "gvisor.boot.json" && !file_name.ends_with(".boot.json") {
                    continue;
                }
                let cursor = cursors.entry(file_entry.path()).or_default();
                read_gvisor_log_file(state, &container_id, &file_entry.path(), cursor)?;
            }
        }
        thread::sleep(poll_interval);
    }
}

fn read_gvisor_log_file(
    state: &Arc<SharedState>,
    container_id: &str,
    path: &Path,
    cursor: &mut GvisorLogCursor,
) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open gVisor seccomp audit log: {error}"))?;
    let file_len = file
        .metadata()
        .map_err(|error| format!("cannot stat gVisor seccomp audit log: {error}"))?
        .len();
    if file_len < cursor.offset {
        return Err("gVisor seccomp audit log was truncated".into());
    }
    if file_len == cursor.offset {
        return Ok(());
    }
    if file_len - cursor.offset > GVISOR_MAX_LOG_READ_BYTES {
        return Err("gVisor seccomp audit log advanced beyond the bounded reader window".into());
    }
    file.seek(SeekFrom::Start(cursor.offset))
        .map_err(|error| format!("cannot seek gVisor seccomp audit log: {error}"))?;
    let mut appended = Vec::new();
    file.read_to_end(&mut appended)
        .map_err(|error| format!("cannot read gVisor seccomp audit log: {error}"))?;
    cursor.offset +=
        u64::try_from(appended.len()).map_err(|_| "gVisor seccomp audit read length overflowed")?;
    cursor.remainder.extend_from_slice(&appended);
    while let Some(newline) = cursor.remainder.iter().position(|byte| *byte == b'\n') {
        if newline > GVISOR_MAX_PACKET_BYTES {
            return Err("gVisor seccomp audit line exceeded the accepted bound".into());
        }
        let mut raw_line: Vec<u8> = cursor.remainder.drain(..=newline).collect();
        raw_line.pop();
        if raw_line.last() == Some(&b'\r') {
            raw_line.pop();
        }
        if raw_line.is_empty() {
            continue;
        }
        let line =
            std::str::from_utf8(&raw_line).map_err(|_| "gVisor seccomp audit log is not UTF-8")?;
        state.ingest_gvisor_seccomp_log(container_id, line)?;
    }
    if cursor.remainder.len() > GVISOR_MAX_PACKET_BYTES {
        return Err("gVisor seccomp audit line exceeded the accepted bound".into());
    }
    Ok(())
}

fn falco_stderr_indicates_degraded_sensor(engine: SensorEngine, line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    match engine {
        SensorEngine::ModernEbpf => {
            (lower.contains("toctou")
                && (lower.contains("not available")
                    || lower.contains("failed")
                    || lower.contains("unable")))
                || (lower.contains("tracepoint")
                    && (lower.contains("not available") || lower.contains("failed to attach")))
                || lower.contains("unable to attach required")
        }
        SensorEngine::Gvisor => false,
    }
}

fn spawn_falco_modern(state: &Arc<SharedState>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let engine = SensorEngine::ModernEbpf;
    let falco_bin = env::var("ARGUS_S10_FALCO_BIN").unwrap_or_else(|_| DEFAULT_FALCO_BIN.into());
    let rules_path =
        env::var("ARGUS_S10_FALCO_RULES_PATH").unwrap_or_else(|_| DEFAULT_RULES_PATH.into());
    let mut command = Command::new(&falco_bin);
    command.args([
        "-U",
        "-o",
        "json_output=true",
        "-o",
        "stdout_output.enabled=true",
        "-o",
        "file_output.enabled=false",
        "-o",
        "syslog_output.enabled=false",
        "-r",
        &rules_path,
    ]);
    command.args(["-o", "engine.kind=modern_ebpf"]);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("Falco stdout was not captured")?;
    let stderr = child.stderr.take().ok_or("Falco stderr was not captured")?;
    let sensor = state.sensor(engine);
    *sensor.child.lock().expect("Falco child lock poisoned") = Some(child);
    sensor.running.store(true, Ordering::SeqCst);

    let stdout_state = Arc::clone(state);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(raw) if raw.trim().is_empty() => {}
                Ok(raw) => {
                    if let Err(error) = stdout_state.ingest_falco_line(engine, &raw) {
                        eprintln!(
                            "Security monitor rejected {} output: {error}",
                            engine.as_str()
                        );
                        stdout_state.mark_sensor_unhealthy(engine);
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("Failed reading Falco output: {error}");
                    stdout_state.mark_sensor_unhealthy(engine);
                    return;
                }
            }
        }
        stdout_state.mark_sensor_unhealthy(engine);
    });

    let stderr_state = Arc::clone(state);
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(raw) => {
                    eprintln!("{raw}");
                    if falco_stderr_indicates_degraded_sensor(engine, &raw) {
                        stderr_state.mark_sensor_degraded(engine);
                    }
                }
                Err(error) => {
                    eprintln!("Failed reading Falco diagnostics: {error}");
                    stderr_state.mark_sensor_unhealthy(engine);
                    return;
                }
            }
        }
    });
    Ok(())
}

fn run_healthcheck() -> Result<(), Box<dyn Error + Send + Sync>> {
    let port: u16 = env::var("ARGUS_S10_SECURITY_MONITOR_PORT")
        .unwrap_or_else(|_| "8765".into())
        .parse()?;
    let token = env::var("ARGUS_S10_SECURITY_MONITOR_AUTH_TOKEN")?;
    let address = ("127.0.0.1", port)
        .to_socket_addrs()?
        .next()
        .ok_or("security monitor healthcheck address did not resolve")?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("security monitor returned a malformed health response")?;
    if !headers.lines().next().unwrap_or_default().contains(" 200 ") {
        return Err("security monitor health endpoint did not return HTTP 200".into());
    }
    let payload: Value = serde_json::from_str(body)?;
    if payload.get("service").and_then(Value::as_str) != Some(SERVICE_NAME)
        || payload.get("status").and_then(Value::as_str) != Some("ok")
        || payload.get("engine").and_then(Value::as_str) != Some(BRIDGE_ENGINE_NAME)
        || payload.get("overflowed").and_then(Value::as_bool) != Some(false)
    {
        return Err("security monitor health payload is not healthy".into());
    }
    let sources = payload
        .get("sources")
        .and_then(Value::as_object)
        .ok_or("security monitor health payload omitted sources")?;
    if sources.len() != 2 {
        return Err("security monitor health payload has invalid sources".into());
    }
    for engine in [MODERN_EBPF_ENGINE_NAME, GVISOR_ENGINE_NAME] {
        let source = sources
            .get(engine)
            .and_then(Value::as_object)
            .ok_or("security monitor health payload omitted a source")?;
        let configured = source.get("configured").and_then(Value::as_bool);
        let running = source.get("running").and_then(Value::as_bool);
        let degraded = source.get("degraded").and_then(Value::as_bool);
        if configured.is_none() || running.is_none() || degraded.is_none() || source.len() != 3 {
            return Err("security monitor health source payload is invalid".into());
        }
        if configured == Some(true) && (running != Some(true) || degraded != Some(false)) {
            return Err("security monitor configured source is not healthy".into());
        }
    }
    Ok(())
}

fn run_server() -> Result<(), Box<dyn Error + Send + Sync>> {
    let auth_token = env::var("ARGUS_S10_SECURITY_MONITOR_AUTH_TOKEN")?;
    if auth_token.is_empty() {
        return Err("ARGUS_S10_SECURITY_MONITOR_AUTH_TOKEN cannot be empty".into());
    }
    let bind = env::var("ARGUS_S10_SECURITY_MONITOR_BIND").unwrap_or_else(|_| DEFAULT_BIND.into());
    let proc_root = PathBuf::from(
        env::var("ARGUS_S10_HOST_PROC_ROOT").unwrap_or_else(|_| DEFAULT_PROC_ROOT.into()),
    );
    let gvisor_socket_path = env::var("ARGUS_S10_GVISOR_SOCKET_PATH")
        .ok()
        .filter(|value| !value.is_empty());
    let gvisor_log_root = env::var("ARGUS_S10_GVISOR_LOG_ROOT")
        .ok()
        .filter(|value| !value.is_empty());
    let gvisor_configured = match (&gvisor_socket_path, &gvisor_log_root) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => return Err(
            "ARGUS_S10_GVISOR_SOCKET_PATH and ARGUS_S10_GVISOR_LOG_ROOT must be configured together"
                .into(),
        ),
    };
    let state = Arc::new(SharedState::new_with_gvisor(proc_root, gvisor_configured));
    spawn_falco_modern(&state)?;
    if let (Some(socket_path), Some(log_root)) = (&gvisor_socket_path, &gvisor_log_root) {
        let log_poll_ms: u64 = env::var("ARGUS_S10_GVISOR_LOG_POLL_MS")
            .unwrap_or_else(|_| "20".into())
            .parse()?;
        if !(1..=1000).contains(&log_poll_ms) {
            return Err("ARGUS_S10_GVISOR_LOG_POLL_MS must be between 1 and 1000".into());
        }
        start_gvisor_source(
            &state,
            Path::new(socket_path),
            Path::new(log_root),
            Duration::from_millis(log_poll_ms),
        )?;
    }
    let startup_grace_ms: u64 = env::var("ARGUS_S10_FALCO_STARTUP_GRACE_MS")
        .unwrap_or_else(|_| "1500".into())
        .parse()?;
    thread::sleep(Duration::from_millis(startup_grace_ms));
    let health = state.health();
    if health.status() != "ok" {
        return Err("configured host security sources did not become healthy".into());
    }
    let server = Server::http(&bind)?;
    eprintln!("{SERVICE_NAME} listening on {bind} with {BRIDGE_ENGINE_NAME}");
    for request in server.incoming_requests() {
        if let Err(error) = handle_request(request, &state, &auth_token) {
            eprintln!("Security monitor HTTP request failed: {error}");
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        None => run_server(),
        Some("healthcheck") if args.len() == 2 => run_healthcheck(),
        _ => Err("usage: argus-s10-security-monitor [healthcheck]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::fs::OpenOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    const CONTAINER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    #[cfg(target_arch = "x86_64")]
    const OPENAT_SYSNO: u64 = 257;
    #[cfg(target_arch = "aarch64")]
    const OPENAT_SYSNO: u64 = 56;
    #[cfg(target_arch = "x86_64")]
    const MOUNT_SYSNO: u64 = 165;
    #[cfg(target_arch = "aarch64")]
    const MOUNT_SYSNO: u64 = 40;
    #[cfg(target_arch = "x86_64")]
    const WRITE_SYSNO: u64 = 1;
    #[cfg(target_arch = "aarch64")]
    const WRITE_SYSNO: u64 = 64;
    #[cfg(target_arch = "x86_64")]
    const IOCTL_SYSNO: u64 = 16;
    #[cfg(target_arch = "aarch64")]
    const IOCTL_SYSNO: u64 = 29;

    fn container_request(trust_paths: Vec<String>) -> RegistrationRequest {
        RegistrationRequest {
            sandbox_id: "sandbox-security-1".into(),
            job_id: "job-security-1".into(),
            isolation_class: "docker".into(),
            runtime_kind: "container".into(),
            container_id: Some(CONTAINER_ID.into()),
            process_id: None,
            cgroup_v2_path: None,
            trust_paths,
        }
    }

    fn falco_alert(container_id: &str, path: &str) -> String {
        json!({
            "hostname": "argus-host",
            "output": "Argus trust path write attempt",
            "priority": "Critical",
            "rule": TRUSTWRITE_RULE,
            "source": "syscall",
            "tags": ["argus", "s10"],
            "time": "2026-07-15T00:00:00Z",
            "output_fields": {
                "container.id": container_id,
                "evt.rawres": "-30",
                "evt.type": "openat",
                "fd.name": path,
                "proc.pid": "4242"
            }
        })
        .to_string()
    }

    fn test_state() -> Arc<SharedState> {
        let state = Arc::new(SharedState::new(PathBuf::from("/nonexistent-proc")));
        state
            .sensor(SensorEngine::ModernEbpf)
            .running
            .store(true, Ordering::SeqCst);
        state
            .register(container_request(vec!["/opt/argus/trust".into()]))
            .expect("registration should pass");
        state
    }

    #[test]
    fn registration_rejects_short_container_and_non_normal_trust_path() {
        let mut short = container_request(vec!["/opt/argus/trust".into()]);
        short.container_id = Some("abc123".into());
        assert!(short.validate().is_err());

        let traversing = container_request(vec!["/opt/argus/../trust".into()]);
        assert!(traversing.validate().is_err());

        let duplicate_separator = container_request(vec!["/opt//argus/trust".into()]);
        assert!(duplicate_separator.validate().is_err());

        let mut cross_boundary = container_request(vec!["/opt/argus/trust".into()]);
        cross_boundary.isolation_class = "firecracker".into();
        assert!(cross_boundary.validate().is_err());
    }

    #[test]
    fn gvisor_registration_requires_gvisor_health_and_rejects_modern_events() {
        let unavailable = Arc::new(SharedState::new(PathBuf::from("/nonexistent-proc")));
        unavailable
            .sensor(SensorEngine::ModernEbpf)
            .running
            .store(true, Ordering::SeqCst);
        let mut request = container_request(vec!["/opt/argus/trust".into()]);
        request.isolation_class = "gvisor".into();
        assert_eq!(
            unavailable
                .register(request.clone())
                .expect_err("unconfigured gVisor source must fail")
                .status,
            503
        );

        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        for engine in [SensorEngine::ModernEbpf, SensorEngine::Gvisor] {
            state.sensor(engine).running.store(true, Ordering::SeqCst);
        }
        let registration = state
            .register(request)
            .expect("gVisor registration should pass");
        assert_eq!(registration.engine, SensorEngine::Gvisor);
        let alert = falco_alert(
            &CONTAINER_ID[..12],
            "/opt/argus/trust/verifier/profile.json",
        );
        assert!(state
            .ingest_falco_line(SensorEngine::ModernEbpf, &alert)
            .expect("modern event should parse")
            .is_none());
        let payload = GvisorOpen {
            context_data: Some(GvisorContextData {
                time_ns: 1_768_435_200_000_000_000,
                thread_id: 4242,
                thread_group_id: 4242,
                container_id: CONTAINER_ID.into(),
                cwd: "/".into(),
                process_name: "python3".into(),
            }),
            exit: Some(GvisorExit {
                result: -1,
                errorno: 30,
            }),
            sysno: OPENAT_SYSNO,
            fd: -100,
            fd_path: String::new(),
            pathname: "/opt/argus/trust/verifier/profile.json".into(),
            flags: 1,
            mode: 0,
        };
        let packet = encode_gvisor_packet(GVISOR_MESSAGE_SYSCALL_OPEN, 0, &payload.encode_to_vec());
        let event = state
            .ingest_gvisor_packet(&packet)
            .expect("gVisor packet should parse")
            .expect("gVisor packet should match");
        assert_eq!(event.engine, GVISOR_ENGINE_NAME);
        assert_eq!(event.isolation_class, "gvisor");
        assert_eq!(event.kind, "trustwrite");
        assert_eq!(event.result, -30);
        let poll = state
            .poll("sandbox-security-1", 0)
            .expect("gVisor poll should pass");
        assert!(poll.healthy);
        assert_eq!(poll.engine, GVISOR_ENGINE_NAME);
    }

    #[test]
    fn gvisor_non_path_write_and_unscoped_ioctl_do_not_false_positive() {
        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        for engine in [SensorEngine::ModernEbpf, SensorEngine::Gvisor] {
            state.sensor(engine).running.store(true, Ordering::SeqCst);
        }
        let mut request = container_request(vec!["/opt/argus/trust".into()]);
        request.isolation_class = "gvisor".into();
        state
            .register(request)
            .expect("gVisor registration should pass");
        let context = GvisorContextData {
            time_ns: 1_768_435_200_000_000_000,
            thread_id: 4242,
            thread_group_id: 4242,
            container_id: CONTAINER_ID.into(),
            cwd: "/".into(),
            process_name: "python3".into(),
        };
        let stdout_write = GvisorWrite {
            context_data: Some(context.clone()),
            exit: Some(GvisorExit {
                result: 16,
                errorno: 0,
            }),
            sysno: WRITE_SYSNO,
            fd: 1,
            fd_path: "pipe:[1234]".into(),
            count: 16,
            has_offset: false,
            offset: 0,
            flags: 0,
        };
        let ioctl = GvisorRawSyscall {
            context_data: Some(context),
            exit: Some(GvisorExit {
                result: -1,
                errorno: 25,
            }),
            sysno: IOCTL_SYSNO,
            arg1: 1,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            arg6: 0,
        };

        assert!(state.ingest_gvisor_write(stdout_write).is_ok());
        assert!(state
            .ingest_gvisor_raw_syscall(ioctl)
            .expect("unscoped ioctl should parse")
            .is_none());
        assert!(state
            .poll("sandbox-security-1", 0)
            .expect("clean gVisor poll should pass")
            .events
            .is_empty());
    }

    #[test]
    fn gvisor_seccomp_json_audit_maps_denied_syscall_to_registered_sandbox() {
        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        for engine in [SensorEngine::ModernEbpf, SensorEngine::Gvisor] {
            state.sensor(engine).running.store(true, Ordering::SeqCst);
        }
        let mut request = container_request(vec!["/opt/argus/trust".into()]);
        request.isolation_class = "gvisor".into();
        state
            .register(request)
            .expect("gVisor registration should pass");

        let log_line = format!(
            r#"{{"msg":"task_syscall.go:218] [   7:   7] Syscall {MOUNT_SYSNO}: denied by seccomp","level":"debug","time":"2026-07-15T00:00:00Z"}}"#
        );
        let event = state
            .ingest_gvisor_seccomp_log(CONTAINER_ID, &log_line)
            .expect("gVisor seccomp audit should parse")
            .expect("gVisor seccomp audit should match");

        assert_eq!(event.kind, "escape");
        assert_eq!(event.syscall, "mount");
        assert_eq!(event.process_id, 7);
        assert_eq!(event.result, -1);
        assert_eq!(event.engine, GVISOR_ENGINE_NAME);
    }

    #[test]
    fn gvisor_remote_drop_counter_degrades_source_fail_closed() {
        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        state
            .sensor(SensorEngine::Gvisor)
            .running
            .store(true, Ordering::SeqCst);
        let packet = encode_gvisor_packet(GVISOR_MESSAGE_SYSCALL_OPEN, 1, &[]);

        assert!(state.ingest_gvisor_packet(&packet).is_err());
        assert!(state
            .sensor(SensorEngine::Gvisor)
            .degraded
            .load(Ordering::SeqCst));
        assert!(!state
            .sensor(SensorEngine::Gvisor)
            .running
            .load(Ordering::SeqCst));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn gvisor_seqpacket_handshake_and_event_round_trip() {
        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        for engine in [SensorEngine::ModernEbpf, SensorEngine::Gvisor] {
            state.sensor(engine).running.store(true, Ordering::SeqCst);
        }
        let mut request = container_request(vec!["/opt/argus/trust".into()]);
        request.isolation_class = "gvisor".into();
        state
            .register(request)
            .expect("gVisor registration should pass");
        let (server, mut client) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None)
            .expect("seqpacket socket pair should be available");
        let server_state = Arc::clone(&state);
        let handler = thread::spawn(move || handle_gvisor_client(server, &server_state));

        client
            .write_all(
                &GvisorHandshake {
                    version: GVISOR_WIRE_VERSION,
                }
                .encode_to_vec(),
            )
            .expect("handshake should write");
        let mut handshake_response = [0_u8; 32];
        let response_size = client
            .read(&mut handshake_response)
            .expect("handshake response should read");
        let response = GvisorHandshake::decode(&handshake_response[..response_size])
            .expect("handshake response should decode");
        assert_eq!(response.version, GVISOR_WIRE_VERSION);

        let payload = GvisorOpen {
            context_data: Some(GvisorContextData {
                time_ns: 1_768_435_200_000_000_000,
                thread_id: 4242,
                thread_group_id: 4242,
                container_id: CONTAINER_ID.into(),
                cwd: "/".into(),
                process_name: "python3".into(),
            }),
            exit: Some(GvisorExit {
                result: -1,
                errorno: 30,
            }),
            sysno: OPENAT_SYSNO,
            fd: -100,
            fd_path: String::new(),
            pathname: "/opt/argus/trust/verifier/profile.json".into(),
            flags: OPEN_WRITE_ONLY,
            mode: 0,
        };
        client
            .write_all(&encode_gvisor_packet(
                GVISOR_MESSAGE_SYSCALL_OPEN,
                0,
                &payload.encode_to_vec(),
            ))
            .expect("event packet should write");
        drop(client);
        handler
            .join()
            .expect("gVisor client handler should join")
            .expect("gVisor client handler should succeed");

        let poll = state
            .poll("sandbox-security-1", 0)
            .expect("gVisor event should be available");
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].kind, "trustwrite");
    }

    #[test]
    fn gvisor_log_reader_waits_for_complete_json_line() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = env::temp_dir().join(format!("argus-s10-gvisor-log-{unique}"));
        fs::create_dir_all(&root).expect("log fixture root should exist");
        let path = root.join("gvisor.boot.json");
        let line = format!(
            r#"{{"msg":"task_syscall.go:218] [   7:   7] Syscall {MOUNT_SYSNO}: denied by seccomp","level":"debug","time":"2026-07-15T00:00:00Z"}}"#
        );
        let split = line.len() / 2;
        fs::write(&path, &line.as_bytes()[..split]).expect("partial log should write");

        let state = Arc::new(SharedState::new_with_gvisor(
            PathBuf::from("/nonexistent-proc"),
            true,
        ));
        for engine in [SensorEngine::ModernEbpf, SensorEngine::Gvisor] {
            state.sensor(engine).running.store(true, Ordering::SeqCst);
        }
        let mut request = container_request(vec!["/opt/argus/trust".into()]);
        request.isolation_class = "gvisor".into();
        state
            .register(request)
            .expect("gVisor registration should pass");
        let mut cursor = GvisorLogCursor::default();
        read_gvisor_log_file(&state, CONTAINER_ID, &path, &mut cursor)
            .expect("partial log should be retained");
        assert_eq!(
            state
                .poll("sandbox-security-1", 0)
                .expect("poll should pass")
                .cursor,
            0
        );

        let mut output = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("log fixture should reopen");
        output
            .write_all(&line.as_bytes()[split..])
            .expect("remaining log should write");
        output.write_all(b"\n").expect("newline should write");
        drop(output);
        read_gvisor_log_file(&state, CONTAINER_ID, &path, &mut cursor)
            .expect("complete log should parse");
        let poll = state
            .poll("sandbox-security-1", 0)
            .expect("poll should pass");
        assert_eq!(poll.events.len(), 1);
        assert_eq!(poll.events[0].syscall, "mount");
        fs::remove_dir_all(root).expect("log fixture should clean up");
    }

    #[test]
    fn falco_event_maps_to_full_identity_and_python_content_hash() {
        let state = test_state();
        let event = state
            .ingest_falco_line(
                SensorEngine::ModernEbpf,
                &falco_alert(
                    &CONTAINER_ID[..12],
                    "/opt/argus/trust/verifier/profile.json",
                ),
            )
            .expect("event should parse")
            .expect("event should match");

        assert_eq!(event.container_id.as_deref(), Some(CONTAINER_ID));
        assert_eq!(event.sequence, 1);
        assert_eq!(event.kind, "trustwrite");
        assert_eq!(
            event.event_id,
            "blake3:655a27de6d26b8fb054622952e5354373b0df4a0558bd9bba73b7f25384a108c"
        );
    }

    #[test]
    fn unknown_container_and_outside_trust_path_are_ignored_and_duplicates_are_deduplicated() {
        let state = test_state();
        assert!(state
            .ingest_falco_line(
                SensorEngine::ModernEbpf,
                &falco_alert("bbbbbbbbbbbb", "/opt/argus/trust/file"),
            )
            .expect("unknown event should parse")
            .is_none());
        assert!(state
            .ingest_falco_line(
                SensorEngine::ModernEbpf,
                &falco_alert(&CONTAINER_ID[..12], "/tmp/not-trusted"),
            )
            .expect("outside event should parse")
            .is_none());

        let alert = falco_alert(&CONTAINER_ID[..12], "/opt/argus/trust/file");
        assert!(state
            .ingest_falco_line(SensorEngine::ModernEbpf, &alert)
            .expect("first event should parse")
            .is_some());
        assert!(state
            .ingest_falco_line(SensorEngine::ModernEbpf, &alert)
            .expect("duplicate event should parse")
            .is_none());
    }

    #[test]
    fn host_process_matching_requires_both_ancestor_and_exact_cgroup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let root = env::temp_dir().join(format!("argus-s10-proc-{unique}"));
        fs::create_dir_all(root.join("9001")).expect("parent proc fixture should exist");
        fs::create_dir_all(root.join("9002")).expect("child proc fixture should exist");
        fs::write(root.join("9001/status"), "Name:\tjailer\nPPid:\t1\n")
            .expect("parent status should write");
        fs::write(
            root.join("9001/cgroup"),
            "0::/argus-firecracker/sandbox-firecracker-1\n",
        )
        .expect("parent cgroup should write");
        fs::write(
            root.join("9002/status"),
            "Name:\tfirecracker\nPPid:\t9001\n",
        )
        .expect("child status should write");
        fs::write(
            root.join("9002/cgroup"),
            "0::/argus-firecracker/sandbox-firecracker-1\n",
        )
        .expect("child cgroup should write");

        assert!(process_belongs_to_registration(
            9002,
            9001,
            "/argus-firecracker/sandbox-firecracker-1",
            &root,
        ));
        assert!(!process_belongs_to_registration(
            9002,
            9001,
            "/argus-firecracker/another-sandbox",
            &root,
        ));
        fs::remove_dir_all(root).expect("proc fixture should clean up");
    }

    #[test]
    fn degraded_tracepoint_diagnostics_fail_closed() {
        assert!(falco_stderr_indicates_degraded_sensor(
            SensorEngine::ModernEbpf,
            "TOCTOU mitigation tracepoint is not available"
        ));
        assert!(!falco_stderr_indicates_degraded_sensor(
            SensorEngine::ModernEbpf,
            "Falco initialized with modern eBPF probe"
        ));
    }

    #[test]
    fn bearer_comparison_is_constant_shape_and_exact() {
        assert!(constant_time_equal(b"monitor-secret", b"monitor-secret"));
        assert!(!constant_time_equal(b"monitor-secret", b"monitor-secreu"));
        assert!(!constant_time_equal(b"monitor-secret", b"short"));
    }
}
