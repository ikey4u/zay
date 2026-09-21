use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::{StreamExt as _, stream};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_stream::wrappers::WatchStream;
use tonic::{Request, Response, Status, codegen::BoxStream};

use super::{LogRing, locale::request_locale, proto};
use crate::{
    common::{network::SocksAddr, stun},
    outbound::{ConnectionSnapshot, SharedDialer, TrafficConnectionEvent},
};

/// Version of the daemon API implemented by the pinned upstream schema.
pub const DAEMON_API_VERSION: i32 = 4;

/// `time.Time{}.UnixMilli()` in Go.
pub const GO_ZERO_TIME_UNIX_MILLIS: i64 = -62_135_596_800_000;

const LOG_SUBSCRIBER_CAPACITY: usize = 128;

#[derive(Clone, Debug)]
pub struct StartedServiceOptions {
    pub version: String,
    pub log_max_lines: usize,
}

impl Default for StartedServiceOptions {
    fn default() -> Self {
        Self {
            version: crate::VERSION.to_owned(),
            log_max_lines: 0,
        }
    }
}

#[derive(Debug)]
struct ServiceState {
    default_log_level: Option<proto::LogLevel>,
    started_at_millis: i64,
}

#[derive(Debug)]
struct LogState {
    ring: LogRing,
    sender: broadcast::Sender<Option<proto::log::Message>>,
}

type StunOperation =
    Pin<Box<dyn Future<Output = io::Result<stun::Result>> + Send + 'static>>;

struct StunStreamState {
    progress: mpsc::UnboundedReceiver<stun::Progress>,
    operation: Option<StunOperation>,
    completion: Option<io::Result<stun::Result>>,
}

/// Native implementation of the lifecycle-independent StartedService RPCs.
///
/// The larger instance lifecycle calls remain generated as explicit
/// `Unimplemented` RPCs until their corresponding runtime modules are bound.
#[derive(Clone)]
pub struct StartedDaemonService {
    version: Arc<str>,
    status_sender: watch::Sender<proto::ServiceStatus>,
    state: Arc<Mutex<ServiceState>>,
    logs: Arc<Mutex<LogState>>,
    runtime: Arc<RwLock<Option<Arc<crate::Runtime>>>>,
}

impl StartedDaemonService {
    pub fn new(options: StartedServiceOptions) -> Self {
        let (status_sender, _) = watch::channel(proto::ServiceStatus {
            status: proto::service_status::Type::Idle.into(),
            error_message: String::new(),
        });
        let (log_sender, _) = broadcast::channel(LOG_SUBSCRIBER_CAPACITY);
        Self {
            version: options.version.into(),
            status_sender,
            state: Arc::new(Mutex::new(ServiceState {
                default_log_level: None,
                started_at_millis: GO_ZERO_TIME_UNIX_MILLIS,
            })),
            logs: Arc::new(Mutex::new(LogState {
                ring: LogRing::new(options.log_max_lines),
                sender: log_sender,
            })),
            runtime: Arc::new(RwLock::new(None)),
        }
    }

    /// Attach an already constructed Runtime to the daemon control plane.
    pub fn install_runtime(&self, runtime: Arc<crate::Runtime>) {
        *self.runtime.write().expect("daemon runtime lock poisoned") =
            Some(runtime);
    }

    pub fn detach_runtime(&self) -> Option<Arc<crate::Runtime>> {
        self.runtime
            .write()
            .expect("daemon runtime lock poisoned")
            .take()
    }

    pub fn runtime(&self) -> Option<Arc<crate::Runtime>> {
        self.runtime
            .read()
            .expect("daemon runtime lock poisoned")
            .clone()
    }

    pub fn service_status(&self) -> proto::ServiceStatus {
        self.status_sender.borrow().clone()
    }

    pub fn update_status(&self, status: proto::service_status::Type) {
        self.status_sender.send_replace(proto::ServiceStatus {
            status: status.into(),
            error_message: String::new(),
        });
    }

    pub fn update_status_error(&self, error: impl Into<String>) {
        let error = error.into();
        self.status_sender.send_replace(proto::ServiceStatus {
            status: proto::service_status::Type::Fatal.into(),
            error_message: error.clone(),
        });
        self.write_message(proto::LogLevel::Error, error);
    }

    pub fn mark_started(
        &self,
        started_at_millis: i64,
        default_log_level: proto::LogLevel,
    ) {
        let mut state = self.state.lock();
        state.started_at_millis = started_at_millis;
        state.default_log_level = Some(default_log_level);
        drop(state);
        self.update_status(proto::service_status::Type::Started);
    }

    pub fn mark_idle(&self) {
        self.detach_runtime();
        let mut state = self.state.lock();
        state.started_at_millis = GO_ZERO_TIME_UNIX_MILLIS;
        state.default_log_level = None;
        drop(state);
        self.update_status(proto::service_status::Type::Idle);
    }

    pub fn set_default_log_level(&self, level: Option<proto::LogLevel>) {
        self.state.lock().default_log_level = level;
    }

    pub fn set_started_at_millis(&self, started_at_millis: i64) {
        self.state.lock().started_at_millis = started_at_millis;
    }

    pub fn write_message(
        &self,
        level: proto::LogLevel,
        message: impl Into<String>,
    ) {
        let entry = proto::log::Message {
            level: level.into(),
            message: message.into(),
        };
        let mut logs = self.logs.lock();
        logs.ring.push(entry.clone());
        let _ = logs.sender.send(Some(entry));
    }

    pub fn saved_log(&self) -> Vec<proto::log::Message> {
        self.logs.lock().ring.snapshot()
    }

    pub fn clear_logs(&self) {
        let mut logs = self.logs.lock();
        logs.ring.reset();
        let _ = logs.sender.send(None);
    }

    fn runtime_or_invalid(&self) -> Result<Arc<crate::Runtime>, Status> {
        self.runtime()
            .ok_or_else(|| Status::unknown("invalid argument"))
    }

    async fn wait_for_started(&self) -> Result<(), Status> {
        let mut receiver = self.status_sender.subscribe();
        loop {
            let status = receiver.borrow().clone();
            match proto::service_status::Type::try_from(status.status) {
                Ok(proto::service_status::Type::Started) => return Ok(()),
                Ok(proto::service_status::Type::Starting) => {}
                Ok(proto::service_status::Type::Fatal) => {
                    return Err(Status::failed_precondition(
                        status.error_message,
                    ));
                }
                _ => return Err(Status::unknown("invalid argument")),
            }
            receiver
                .changed()
                .await
                .map_err(|_| Status::cancelled("service status closed"))?;
        }
    }

    fn status_snapshot(&self) -> proto::Status {
        let memory = current_process_memory();
        let Some(runtime) = self.runtime() else {
            return proto::Status {
                memory,
                ..proto::Status::default()
            };
        };
        let connections = runtime.outbounds().connections().len();
        let connections = i32::try_from(connections).unwrap_or(i32::MAX);
        let (uplink, downlink) = runtime.outbounds().traffic_totals();
        proto::Status {
            memory,
            goroutines: 0,
            connections_in: connections,
            connections_out: connections,
            traffic_available: true,
            uplink: 0,
            downlink: 0,
            uplink_total: unsigned_to_i64(uplink),
            downlink_total: unsigned_to_i64(downlink),
        }
    }

    fn status_subscription(
        &self,
        interval: Duration,
    ) -> BoxStream<proto::Status> {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let service = self.clone();
        let stream = stream::unfold(
            (service, ticker, None),
            |(service, mut ticker, previous)| async move {
                ticker.tick().await;
                let mut status = service.status_snapshot();
                if let Some((uplink, downlink)) = previous {
                    status.uplink = status.uplink_total.saturating_sub(uplink);
                    status.downlink =
                        status.downlink_total.saturating_sub(downlink);
                }
                let totals = (status.uplink_total, status.downlink_total);
                Some((Ok(status), (service, ticker, Some(totals))))
            },
        );
        Box::pin(stream)
    }

    fn groups_snapshot(&self) -> Result<proto::Groups, Status> {
        if proto::service_status::Type::try_from(self.service_status().status)
            != Ok(proto::service_status::Type::Started)
        {
            return Ok(proto::Groups::default());
        }
        let runtime = self.runtime_or_invalid()?;
        let outbounds = runtime.outbounds();
        let mut groups = Vec::new();
        for tag in outbounds.tags() {
            let Some(choices) = outbounds.group_choices(tag) else {
                continue;
            };
            let items = choices
                .into_iter()
                .filter_map(|item_tag| {
                    let kind = outbounds.kind(&item_tag)?;
                    let (url_test_time, url_test_delay) = outbounds
                        .urltest_history_entry(&item_tag)
                        .map(|(time, delay)| {
                            (unix_seconds(time), i32::from(delay))
                        })
                        .unwrap_or_default();
                    Some(proto::GroupItem {
                        tag: item_tag,
                        r#type: kind.to_owned(),
                        url_test_time,
                        url_test_delay,
                    })
                })
                .collect::<Vec<_>>();
            if items.is_empty() {
                continue;
            }
            groups.push(proto::Group {
                tag: tag.to_owned(),
                r#type: outbounds.kind(tag).unwrap_or_default().to_owned(),
                selectable: outbounds.selected_group(tag).is_some(),
                selected: outbounds.group_selected(tag).unwrap_or_default(),
                is_expand: outbounds
                    .group_expand(tag)
                    .map_err(|error| Status::internal(error.to_string()))?
                    .unwrap_or(false),
                items,
            });
        }
        Ok(proto::Groups { group: groups })
    }

    fn groups_subscription(&self) -> BoxStream<proto::Groups> {
        let service = self.clone();
        let status = self.status_sender.subscribe();
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let stream = stream::unfold(
            (service, status, ticker, None),
            |(service, mut status, mut ticker, previous)| async move {
                let mut previous = previous;
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        changed = status.changed() => {
                            if changed.is_err() {
                                return None;
                            }
                        }
                    }
                    let current = match service.groups_snapshot() {
                        Ok(current) => current,
                        Err(error) => {
                            return Some((
                                Err(error),
                                (service, status, ticker, previous),
                            ));
                        }
                    };
                    if previous.as_ref() != Some(&current) {
                        previous = Some(current.clone());
                        return Some((
                            Ok(current),
                            (service, status, ticker, previous),
                        ));
                    }
                }
            },
        );
        Box::pin(stream)
    }

    fn outbounds_snapshot(&self) -> Result<proto::OutboundList, Status> {
        if proto::service_status::Type::try_from(self.service_status().status)
            != Ok(proto::service_status::Type::Started)
        {
            return Ok(proto::OutboundList::default());
        }
        let runtime = self.runtime_or_invalid()?;
        let outbounds = runtime.outbounds();
        let outbounds = outbounds
            .outbound_items()
            .into_iter()
            .map(|(tag, r#type)| {
                let (url_test_time, url_test_delay) = outbounds
                    .urltest_history_entry(&tag)
                    .map(|(time, delay)| (unix_seconds(time), i32::from(delay)))
                    .unwrap_or_default();
                proto::GroupItem {
                    tag,
                    r#type,
                    url_test_time,
                    url_test_delay,
                }
            })
            .collect();
        Ok(proto::OutboundList { outbounds })
    }

    fn outbounds_subscription(&self) -> BoxStream<proto::OutboundList> {
        let service = self.clone();
        let status = self.status_sender.subscribe();
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let stream = stream::unfold(
            (service, status, ticker, None),
            |(service, mut status, mut ticker, previous)| async move {
                let mut previous = previous;
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        changed = status.changed() => {
                            if changed.is_err() {
                                return None;
                            }
                        }
                    }
                    let current = match service.outbounds_snapshot() {
                        Ok(current) => current,
                        Err(error) => {
                            return Some((
                                Err(error),
                                (service, status, ticker, previous),
                            ));
                        }
                    };
                    if previous.as_ref() != Some(&current) {
                        previous = Some(current.clone());
                        return Some((
                            Ok(current),
                            (service, status, ticker, previous),
                        ));
                    }
                }
            },
        );
        Box::pin(stream)
    }

    fn clash_mode_snapshot(&self) -> Result<proto::ClashMode, Status> {
        if proto::service_status::Type::try_from(self.service_status().status)
            != Ok(proto::service_status::Type::Started)
        {
            return Ok(proto::ClashMode::default());
        }
        let runtime = self.runtime_or_invalid()?;
        let mode = runtime
            .clash_mode()
            .ok_or_else(|| Status::not_found("clash mode not available"))?;
        Ok(proto::ClashMode { mode })
    }

    fn clash_mode_subscription(&self) -> BoxStream<proto::ClashMode> {
        let service = self.clone();
        let status = self.status_sender.subscribe();
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let stream = stream::unfold(
            (service, status, ticker, None),
            |(service, mut status, mut ticker, previous)| async move {
                let mut previous = previous;
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        changed = status.changed() => {
                            if changed.is_err() {
                                return None;
                            }
                        }
                    }
                    let current = match service.clash_mode_snapshot() {
                        Ok(current) => current,
                        Err(error) => {
                            return Some((
                                Err(error),
                                (service, status, ticker, previous),
                            ));
                        }
                    };
                    if previous.as_ref() != Some(&current) {
                        previous = Some(current.clone());
                        return Some((
                            Ok(current),
                            (service, status, ticker, previous),
                        ));
                    }
                }
            },
        );
        Box::pin(stream)
    }

    fn connection_subscription(
        &self,
        runtime: Arc<crate::Runtime>,
        interval: Duration,
    ) -> BoxStream<proto::ConnectionEvents> {
        let (connections, receiver) = runtime.outbounds().connection_state();
        let (initial, snapshots) =
            initial_connection_state(&runtime, connections);
        let initial = stream::once(async move {
            Ok(proto::ConnectionEvents {
                events: initial,
                reset: true,
            })
        });
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.reset();
        let live = stream::unfold(
            (runtime, receiver, ticker, snapshots),
            |(runtime, mut receiver, mut ticker, mut snapshots)| async move {
                loop {
                    tokio::select! {
                        event = receiver.recv() => {
                            match event {
                                Ok(event) => {
                                    let mut events = Vec::new();
                                    apply_connection_event(
                                        &runtime,
                                        event,
                                        &mut snapshots,
                                        &mut events,
                                    );
                                    let mut reset = false;
                                    loop {
                                        match receiver.try_recv() {
                                            Ok(event) => apply_connection_event(
                                                &runtime,
                                                event,
                                                &mut snapshots,
                                                &mut events,
                                            ),
                                            Err(broadcast::error::TryRecvError::Empty) => break,
                                            Err(broadcast::error::TryRecvError::Closed) => break,
                                            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                                                let state = reset_connection_state(&runtime);
                                                events = state.0;
                                                snapshots = state.1;
                                                reset = true;
                                                break;
                                            }
                                        }
                                    }
                                    if !events.is_empty() || reset {
                                        return Some((
                                            Ok(proto::ConnectionEvents { events, reset }),
                                            (runtime, receiver, ticker, snapshots),
                                        ));
                                    }
                                }
                                Err(broadcast::error::RecvError::Closed) => return None,
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    let (events, next_snapshots) =
                                        reset_connection_state(&runtime);
                                    snapshots = next_snapshots;
                                    return Some((
                                        Ok(proto::ConnectionEvents {
                                            events,
                                            reset: true,
                                        }),
                                        (runtime, receiver, ticker, snapshots),
                                    ));
                                }
                            }
                        }
                        _ = ticker.tick() => {
                            let events = traffic_updates(&runtime, &mut snapshots);
                            if !events.is_empty() {
                                return Some((
                                    Ok(proto::ConnectionEvents {
                                        events,
                                        reset: false,
                                    }),
                                    (runtime, receiver, ticker, snapshots),
                                ));
                            }
                        }
                    }
                }
            },
        );
        Box::pin(initial.chain(live))
    }

    fn log_subscription(&self) -> BoxStream<proto::Log> {
        let (saved, receiver) = {
            let logs = self.logs.lock();
            (logs.ring.snapshot(), logs.sender.subscribe())
        };
        let initial = stream::once(async move {
            Ok(proto::Log {
                messages: saved,
                reset: true,
            })
        });
        let logs = self.logs.clone();
        let live = stream::unfold(
            (receiver, logs),
            |(mut receiver, logs)| async move {
                let first = match receiver.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Closed) => return None,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let snapshot = logs.lock().ring.snapshot();
                        return Some((
                            Ok(proto::Log {
                                messages: snapshot,
                                reset: true,
                            }),
                            (receiver, logs),
                        ));
                    }
                };

                let mut message = proto::Log {
                    messages: Vec::new(),
                    reset: false,
                };
                apply_log_event(&mut message, first);
                loop {
                    match receiver.try_recv() {
                        Ok(event) => apply_log_event(&mut message, event),
                        Err(broadcast::error::TryRecvError::Empty)
                        | Err(broadcast::error::TryRecvError::Closed) => break,
                        Err(broadcast::error::TryRecvError::Lagged(_)) => {
                            message.messages = logs.lock().ring.snapshot();
                            message.reset = true;
                        }
                    }
                }
                Some((Ok(message), (receiver, logs)))
            },
        );
        Box::pin(initial.chain(live))
    }

    fn stun_subscription(
        server: String,
        dialer: SharedDialer,
    ) -> BoxStream<proto::StunTestProgress> {
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();
        let operation = Box::pin(async move {
            stun::run(&server, dialer.as_ref(), |progress| {
                let _ = progress_sender.send(progress);
            })
            .await
        });
        let state = StunStreamState {
            progress: progress_receiver,
            operation: Some(operation),
            completion: None,
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            loop {
                if let Some(completion) = state.completion.take() {
                    match state.progress.try_recv() {
                        Ok(progress) => {
                            state.completion = Some(completion);
                            return Some((
                                Ok(stun_progress_message(progress)),
                                state,
                            ));
                        }
                        Err(mpsc::error::TryRecvError::Empty)
                        | Err(mpsc::error::TryRecvError::Disconnected) => {
                            return Some((
                                Ok(stun_completion_message(completion)),
                                state,
                            ));
                        }
                    }
                }

                let operation = state.operation.as_mut()?;
                tokio::select! {
                    biased;
                    progress = state.progress.recv() => {
                        if let Some(progress) = progress {
                            return Some((Ok(stun_progress_message(progress)), state));
                        }
                    }
                    completion = operation => {
                        state.operation = None;
                        state.completion = Some(completion);
                    }
                }
            }
        }))
    }
}

fn unsigned_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

fn current_process_memory() -> u64 {
    let Ok(pid) = sysinfo::get_current_pid() else {
        return 0;
    };
    sysinfo::System::new_all()
        .process(pid)
        .map(sysinfo::Process::memory)
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
struct ConnectionTrackingSnapshot {
    uplink: u64,
    downlink: u64,
    had_traffic: bool,
}

fn initial_connection_state(
    runtime: &crate::Runtime,
    connections: Vec<ConnectionSnapshot>,
) -> (
    Vec<proto::ConnectionEvent>,
    HashMap<String, ConnectionTrackingSnapshot>,
) {
    let mut snapshots = HashMap::new();
    let events = connections
        .into_iter()
        .map(|connection| {
            snapshots.insert(
                connection.id.clone(),
                ConnectionTrackingSnapshot {
                    uplink: connection.upload,
                    downlink: connection.download,
                    had_traffic: false,
                },
            );
            new_connection_event(runtime, connection)
        })
        .collect();
    (events, snapshots)
}

fn reset_connection_state(
    runtime: &crate::Runtime,
) -> (
    Vec<proto::ConnectionEvent>,
    HashMap<String, ConnectionTrackingSnapshot>,
) {
    initial_connection_state(runtime, runtime.outbounds().connections())
}

fn apply_connection_event(
    runtime: &crate::Runtime,
    event: TrafficConnectionEvent,
    snapshots: &mut HashMap<String, ConnectionTrackingSnapshot>,
    events: &mut Vec<proto::ConnectionEvent>,
) {
    match event {
        TrafficConnectionEvent::New(connection) => {
            if snapshots.contains_key(&connection.id) {
                return;
            }
            snapshots.insert(
                connection.id.clone(),
                ConnectionTrackingSnapshot {
                    uplink: connection.upload,
                    downlink: connection.download,
                    had_traffic: false,
                },
            );
            events.push(new_connection_event(runtime, connection));
        }
        TrafficConnectionEvent::Closed {
            connection,
            closed_at,
        } => {
            if snapshots.remove(&connection.id).is_none() {
                return;
            }
            events
                .push(closed_connection_event(runtime, connection, closed_at));
        }
    }
}

fn traffic_updates(
    runtime: &crate::Runtime,
    snapshots: &mut HashMap<String, ConnectionTrackingSnapshot>,
) -> Vec<proto::ConnectionEvent> {
    let active = runtime.outbounds().connections();
    let active_ids = active
        .iter()
        .map(|connection| connection.id.clone())
        .collect::<std::collections::HashSet<_>>();
    let mut events = Vec::new();
    for connection in active {
        let Some(previous) = snapshots.get_mut(&connection.id) else {
            snapshots.insert(
                connection.id.clone(),
                ConnectionTrackingSnapshot {
                    uplink: connection.upload,
                    downlink: connection.download,
                    had_traffic: false,
                },
            );
            events.push(new_connection_event(runtime, connection));
            continue;
        };
        let uplink = connection.upload.saturating_sub(previous.uplink);
        let downlink = connection.download.saturating_sub(previous.downlink);
        if uplink > 0 || downlink > 0 {
            previous.uplink = connection.upload;
            previous.downlink = connection.download;
            previous.had_traffic = true;
            events.push(proto::ConnectionEvent {
                r#type: proto::ConnectionEventType::ConnectionEventUpdate
                    .into(),
                id: connection.id,
                uplink_delta: unsigned_to_i64(uplink),
                downlink_delta: unsigned_to_i64(downlink),
                ..proto::ConnectionEvent::default()
            });
        } else if previous.had_traffic {
            previous.had_traffic = false;
            events.push(proto::ConnectionEvent {
                r#type: proto::ConnectionEventType::ConnectionEventUpdate
                    .into(),
                id: connection.id,
                ..proto::ConnectionEvent::default()
            });
        }
    }
    let missing = snapshots
        .keys()
        .filter(|id| !active_ids.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    for id in missing {
        snapshots.remove(&id);
        events.push(proto::ConnectionEvent {
            r#type: proto::ConnectionEventType::ConnectionEventClosed.into(),
            id,
            closed_at: unix_millis(SystemTime::now()),
            ..proto::ConnectionEvent::default()
        });
    }
    events
}

fn new_connection_event(
    runtime: &crate::Runtime,
    connection: ConnectionSnapshot,
) -> proto::ConnectionEvent {
    proto::ConnectionEvent {
        r#type: proto::ConnectionEventType::ConnectionEventNew.into(),
        id: connection.id.clone(),
        connection: Some(connection_proto(runtime, connection, 0)),
        ..proto::ConnectionEvent::default()
    }
}

fn closed_connection_event(
    runtime: &crate::Runtime,
    connection: ConnectionSnapshot,
    closed_at: SystemTime,
) -> proto::ConnectionEvent {
    let closed_at = unix_millis(closed_at);
    proto::ConnectionEvent {
        r#type: proto::ConnectionEventType::ConnectionEventClosed.into(),
        id: connection.id.clone(),
        connection: Some(connection_proto(runtime, connection, closed_at)),
        closed_at,
        ..proto::ConnectionEvent::default()
    }
}

fn connection_proto(
    runtime: &crate::Runtime,
    connection: ConnectionSnapshot,
    closed_at: i64,
) -> proto::Connection {
    let (ip_version, domain) = match &connection.destination {
        SocksAddr::Ip(address) => {
            (if address.is_ipv4() { 4 } else { 6 }, String::new())
        }
        SocksAddr::Domain { host, .. } => (0, host.clone()),
    };
    proto::Connection {
        id: connection.id,
        ip_version,
        network: connection.network.into(),
        destination: connection.destination.to_string(),
        domain,
        created_at: unix_millis(connection.created_at),
        closed_at,
        uplink_total: unsigned_to_i64(connection.upload),
        downlink_total: unsigned_to_i64(connection.download),
        outbound_type: runtime
            .outbounds()
            .kind_owned(&connection.outbound)
            .unwrap_or_default(),
        outbound: connection.outbound,
        ..proto::Connection::default()
    }
}

fn unix_millis(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn stun_progress_message(progress: stun::Progress) -> proto::StunTestProgress {
    proto::StunTestProgress {
        phase: progress.phase as i32,
        external_addr: progress.external_addr,
        latency_ms: progress.latency_ms,
        nat_mapping: progress.nat_mapping as i32,
        nat_filtering: progress.nat_filtering as i32,
        ..proto::StunTestProgress::default()
    }
}

fn stun_completion_message(
    result: io::Result<stun::Result>,
) -> proto::StunTestProgress {
    match result {
        Ok(result) => proto::StunTestProgress {
            phase: stun::Phase::Done as i32,
            external_addr: result.external_addr,
            latency_ms: result.latency_ms,
            nat_mapping: result.nat_mapping as i32,
            nat_filtering: result.nat_filtering as i32,
            is_final: true,
            nat_type_supported: result.nat_type_supported,
            ..proto::StunTestProgress::default()
        },
        Err(error) => proto::StunTestProgress {
            is_final: true,
            error: error.to_string(),
            ..proto::StunTestProgress::default()
        },
    }
}

fn apply_log_event(
    message: &mut proto::Log,
    event: Option<proto::log::Message>,
) {
    match event {
        Some(entry) => message.messages.push(entry),
        None => {
            message.messages.clear();
            message.reset = true;
        }
    }
}

#[async_trait]
impl proto::started_service_server::StartedService for StartedDaemonService {
    async fn get_version(
        &self,
        _request: Request<()>,
    ) -> Result<Response<proto::Version>, Status> {
        Ok(Response::new(proto::Version {
            version: self.version.to_string(),
            api_version: DAEMON_API_VERSION,
        }))
    }

    async fn subscribe_service_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<BoxStream<proto::ServiceStatus>>, Status> {
        let stream = WatchStream::new(self.status_sender.subscribe()).map(Ok);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn subscribe_log(
        &self,
        _request: Request<()>,
    ) -> Result<Response<BoxStream<proto::Log>>, Status> {
        Ok(Response::new(self.log_subscription()))
    }

    async fn get_default_log_level(
        &self,
        _request: Request<()>,
    ) -> Result<Response<proto::DefaultLogLevel>, Status> {
        let level = self
            .state
            .lock()
            .default_log_level
            .ok_or_else(|| Status::unknown("invalid argument"))?;
        Ok(Response::new(proto::DefaultLogLevel {
            level: level.into(),
        }))
    }

    async fn clear_logs(
        &self,
        _request: Request<()>,
    ) -> Result<Response<()>, Status> {
        self.clear_logs();
        Ok(Response::new(()))
    }

    async fn subscribe_status(
        &self,
        request: Request<proto::SubscribeStatusRequest>,
    ) -> Result<Response<BoxStream<proto::Status>>, Status> {
        let interval = request.into_inner().interval;
        let interval = if interval <= 0 {
            Duration::from_secs(1)
        } else {
            Duration::from_nanos(u64::try_from(interval).unwrap_or(u64::MAX))
        };
        Ok(Response::new(self.status_subscription(interval)))
    }

    async fn subscribe_groups(
        &self,
        _request: Request<()>,
    ) -> Result<Response<BoxStream<proto::Groups>>, Status> {
        self.wait_for_started().await?;
        self.runtime_or_invalid()?;
        Ok(Response::new(self.groups_subscription()))
    }

    async fn get_clash_mode_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<proto::ClashModeStatus>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        let current_mode = runtime
            .clash_mode()
            .ok_or_else(|| Status::not_found("clash mode not available"))?;
        Ok(Response::new(proto::ClashModeStatus {
            mode_list: runtime.clash_modes().to_vec(),
            current_mode,
        }))
    }

    async fn subscribe_clash_mode(
        &self,
        _request: Request<()>,
    ) -> Result<Response<BoxStream<proto::ClashMode>>, Status> {
        self.wait_for_started().await?;
        self.clash_mode_snapshot()?;
        Ok(Response::new(self.clash_mode_subscription()))
    }

    async fn set_clash_mode(
        &self,
        request: Request<proto::ClashMode>,
    ) -> Result<Response<()>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        runtime.set_clash_mode(&request.into_inner().mode);
        Ok(Response::new(()))
    }

    async fn url_test(
        &self,
        request: Request<proto::UrlTestRequest>,
    ) -> Result<Response<()>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        let tag = request.into_inner().outbound_tag;
        let outbounds = runtime.outbounds();
        if outbounds.kind(&tag).is_none() {
            return Err(Status::not_found(format!(
                "outbound not found: {tag}"
            )));
        }
        let is_urltest = outbounds.urltest_history(&tag).is_some();
        let is_group = outbounds.group_choices(&tag).is_some();
        tokio::spawn(async move {
            if is_urltest {
                let _ = runtime.outbounds().refresh_urltest(&tag).await;
            } else if is_group {
                let _ = runtime
                    .outbounds()
                    .test_group_delay(&tag, "", Duration::from_secs(10))
                    .await;
            } else {
                let _ = runtime
                    .outbounds()
                    .test_outbound_delay(&tag, "", Duration::from_secs(10))
                    .await;
            }
        });
        Ok(Response::new(()))
    }

    async fn select_outbound(
        &self,
        request: Request<proto::SelectOutboundRequest>,
    ) -> Result<Response<()>, Status> {
        let runtime = self.runtime_or_invalid()?;
        let request = request.into_inner();
        let outbounds = runtime.outbounds();
        if outbounds.kind(&request.group_tag).is_none() {
            return Err(Status::not_found(format!(
                "selector not found: {}",
                request.group_tag
            )));
        }
        let Some(choices) = outbounds.group_choices(&request.group_tag) else {
            return Err(Status::invalid_argument(format!(
                "outbound is not a selector: {}",
                request.group_tag
            )));
        };
        if outbounds.selected_group(&request.group_tag).is_none() {
            return Err(Status::invalid_argument(format!(
                "outbound is not a selector: {}",
                request.group_tag
            )));
        }
        if !choices.iter().any(|tag| tag == &request.outbound_tag) {
            return Err(Status::not_found(format!(
                "outbound not found in selector: {}",
                request.outbound_tag
            )));
        }
        outbounds
            .select_group(&request.group_tag, &request.outbound_tag)
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(()))
    }

    async fn set_group_expand(
        &self,
        request: Request<proto::SetGroupExpandRequest>,
    ) -> Result<Response<()>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        let request = request.into_inner();
        runtime
            .outbounds()
            .set_group_expand(&request.group_tag, request.is_expand)
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(()))
    }

    async fn subscribe_connections(
        &self,
        request: Request<proto::SubscribeConnectionsRequest>,
    ) -> Result<Response<BoxStream<proto::ConnectionEvents>>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        let interval = request.into_inner().interval;
        let interval = if interval <= 0 {
            Duration::from_secs(1)
        } else {
            Duration::from_nanos(u64::try_from(interval).unwrap_or(u64::MAX))
        };
        Ok(Response::new(
            self.connection_subscription(runtime, interval),
        ))
    }

    async fn close_connection(
        &self,
        request: Request<proto::CloseConnectionRequest>,
    ) -> Result<Response<()>, Status> {
        let runtime = self.runtime_or_invalid()?;
        runtime
            .outbounds()
            .close_connection(&request.into_inner().id);
        Ok(Response::new(()))
    }

    async fn close_all_connections(
        &self,
        _request: Request<()>,
    ) -> Result<Response<()>, Status> {
        if let Some(runtime) = self.runtime() {
            runtime.outbounds().close_all_connections();
        }
        Ok(Response::new(()))
    }

    async fn get_deprecated_warnings(
        &self,
        request: Request<()>,
    ) -> Result<Response<proto::DeprecatedWarnings>, Status> {
        let locale = request_locale(&request);
        let runtime = self.runtime_or_invalid()?;
        let warnings = runtime
            .deprecated_warnings()
            .iter()
            .map(|note| proto::DeprecatedWarning {
                message: note.message_for_locale(locale),
                impending: note.impending(),
                migration_link: note.migration_link.into(),
                description: note.description.into(),
                deprecated_version: note.deprecated_version.into(),
                scheduled_version: note.scheduled_version.into(),
            })
            .collect();
        Ok(Response::new(proto::DeprecatedWarnings { warnings }))
    }

    async fn get_started_at(
        &self,
        _request: Request<()>,
    ) -> Result<Response<proto::StartedAt>, Status> {
        Ok(Response::new(proto::StartedAt {
            started_at: self.state.lock().started_at_millis,
        }))
    }

    async fn subscribe_outbounds(
        &self,
        _request: Request<()>,
    ) -> Result<Response<BoxStream<proto::OutboundList>>, Status> {
        self.wait_for_started().await?;
        self.runtime_or_invalid()?;
        Ok(Response::new(self.outbounds_subscription()))
    }

    async fn start_stun_test(
        &self,
        request: Request<proto::StunTestRequest>,
    ) -> Result<Response<BoxStream<proto::StunTestProgress>>, Status> {
        self.wait_for_started().await?;
        let runtime = self.runtime_or_invalid()?;
        let request = request.into_inner();
        let dialer = runtime
            .outbounds()
            .select(
                (!request.outbound_tag.is_empty())
                    .then_some(request.outbound_tag.as_str()),
            )
            .ok_or_else(|| {
                Status::not_found(format!(
                    "outbound not found: {}",
                    request.outbound_tag
                ))
            })?;
        Ok(Response::new(Self::stun_subscription(
            request.server,
            dialer,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, UdpSocket},
        sync::oneshot,
        time::timeout,
    };
    use tokio_stream::wrappers::TcpListenerStream;

    use super::{
        DAEMON_API_VERSION, GO_ZERO_TIME_UNIX_MILLIS, StartedDaemonService,
        StartedServiceOptions, proto,
    };
    use crate::{
        Options, Runtime,
        adapter::Dialer as _,
        common::{network::SocksAddr, stun},
        daemon::{
            RemoteClientOptions, ServerAuthInterceptor,
            proto::{
                started_service_client::StartedServiceClient,
                started_service_server::StartedServiceServer,
            },
        },
    };

    fn stun_binding_response(
        transaction_id: stun::TransactionId,
        address: std::net::SocketAddr,
    ) -> Vec<u8> {
        let std::net::IpAddr::V4(address_ip) = address.ip() else {
            panic!("test STUN server requires IPv4");
        };
        let mut response = vec![0_u8; 32];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        let encoded_port = address.port() ^ 0x2112;
        response[26..28].copy_from_slice(&encoded_port.to_be_bytes());
        let encoded_address = u32::from(address_ip) ^ 0x2112_a442;
        response[28..32].copy_from_slice(&encoded_address.to_be_bytes());
        response
    }

    async fn next_message<T>(stream: &mut tonic::Streaming<T>) -> T
    where
        T: prost::Message + Default,
    {
        timeout(Duration::from_secs(2), stream.message())
            .await
            .expect("stream timed out")
            .expect("stream failed")
            .expect("stream closed")
    }

    #[tokio::test]
    async fn started_service_core_rpcs_interoperate_over_grpc() {
        let service = StartedDaemonService::new(StartedServiceOptions {
            version: "1.12.0-rust-test".into(),
            log_max_lines: 2,
        });
        service.write_message(proto::LogLevel::Info, "discarded");
        service.write_message(proto::LogLevel::Warn, "saved one");
        service.write_message(proto::LogLevel::Error, "saved two");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(StartedServiceServer::with_interceptor(
                    server_service,
                    ServerAuthInterceptor::new("started secret"),
                ))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
        });

        let options = RemoteClientOptions {
            server_url: format!("http://{address}"),
            secret: "started secret".into(),
        };
        let mut client = StartedServiceClient::with_interceptor(
            options.channel().unwrap(),
            options.auth_interceptor().unwrap(),
        );

        let version = client.get_version(()).await.unwrap().into_inner();
        assert_eq!(version.version, "1.12.0-rust-test");
        assert_eq!(version.api_version, DAEMON_API_VERSION);

        let started_at = client.get_started_at(()).await.unwrap().into_inner();
        assert_eq!(started_at.started_at, GO_ZERO_TIME_UNIX_MILLIS);
        let error = client.get_default_log_level(()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unknown);
        assert_eq!(error.message(), "invalid argument");

        let mut status_stream = client
            .subscribe_service_status(())
            .await
            .unwrap()
            .into_inner();
        let initial_status = next_message(&mut status_stream).await;
        assert_eq!(
            initial_status.status,
            i32::from(proto::service_status::Type::Idle)
        );
        service.mark_started(1_789_000_000_123, proto::LogLevel::Debug);
        let started_status = next_message(&mut status_stream).await;
        assert_eq!(
            started_status.status,
            i32::from(proto::service_status::Type::Started)
        );
        assert_eq!(
            client
                .get_default_log_level(())
                .await
                .unwrap()
                .into_inner()
                .level,
            i32::from(proto::LogLevel::Debug)
        );
        assert_eq!(
            client
                .get_started_at(())
                .await
                .unwrap()
                .into_inner()
                .started_at,
            1_789_000_000_123
        );

        let mut log_stream =
            client.subscribe_log(()).await.unwrap().into_inner();
        let saved = next_message(&mut log_stream).await;
        assert!(saved.reset);
        assert_eq!(
            saved
                .messages
                .iter()
                .map(|message| message.message.as_str())
                .collect::<Vec<_>>(),
            ["saved one", "saved two"]
        );
        service.write_message(proto::LogLevel::Trace, "live");
        let live = next_message(&mut log_stream).await;
        assert!(!live.reset);
        assert_eq!(live.messages.len(), 1);
        assert_eq!(live.messages[0].message, "live");

        client.clear_logs(()).await.unwrap();
        let reset = next_message(&mut log_stream).await;
        assert!(reset.reset);
        assert!(reset.messages.is_empty());
        assert!(service.saved_log().is_empty());

        let error = client.get_deprecated_warnings(()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unknown);
        assert_eq!(error.message(), "invalid argument");

        drop(log_stream);
        drop(status_stream);
        drop(client);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn started_service_runtime_groups_clash_and_status_interoperate() {
        let directory = tempfile::tempdir().unwrap();
        let cache_path = directory.path().join("daemon-cache.db");
        let options: Options = serde_json::from_value(serde_json::json!({
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "path": cache_path,
                    "cache_id": "daemon-test",
                    "store_rdrc": true
                },
                "clash_api": {"default_mode": "Global"}
            },
            "dns": {
                "servers": [{"type": "hosts", "tag": "hosts"}],
                "independent_cache": true
            },
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "deny"},
                {
                    "type": "selector",
                    "tag": "choose",
                    "outbounds": ["direct", "deny"],
                    "default": "direct"
                }
            ],
            "route": {
                "rules": [
                    {"clash_mode": "Global", "outbound": "deny"},
                    {"clash_mode": "Rule", "outbound": "direct"}
                ],
                "final": "deny"
            }
        }))
        .unwrap();
        let runtime = Arc::new(Runtime::from_options(options).unwrap());
        let service =
            StartedDaemonService::new(StartedServiceOptions::default());
        service.install_runtime(runtime.clone());
        service.mark_started(1_789_000_000_456, proto::LogLevel::Info);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(StartedServiceServer::new(server_service))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
        });
        let mut client = StartedServiceClient::new(
            RemoteClientOptions {
                server_url: format!("http://{address}"),
                secret: String::new(),
            }
            .channel()
            .unwrap(),
        );

        let mut runtime_status = client
            .subscribe_status(proto::SubscribeStatusRequest {
                interval: 10_000_000,
            })
            .await
            .unwrap()
            .into_inner();
        let status = next_message(&mut runtime_status).await;
        assert!(status.memory > 0);
        assert!(status.traffic_available);
        assert_eq!(status.connections_in, 0);
        assert_eq!(status.connections_out, 0);
        assert_eq!(status.uplink, 0);
        assert_eq!(status.downlink, 0);

        let warnings = client
            .get_deprecated_warnings(())
            .await
            .unwrap()
            .into_inner()
            .warnings;
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].description, "`independent_cache` DNS option");
        assert_eq!(warnings[1].description, "`store_rdrc` cache file option");
        assert!(warnings.iter().all(|warning| !warning.impending));
        assert!(warnings.iter().all(|warning| {
            warning
                .message
                .contains("will be removed in sing-box 1.16.0")
        }));

        let mut outbound_stream =
            client.subscribe_outbounds(()).await.unwrap().into_inner();
        let outbounds = next_message(&mut outbound_stream).await;
        assert_eq!(
            outbounds
                .outbounds
                .iter()
                .map(|item| (item.tag.as_str(), item.r#type.as_str()))
                .collect::<Vec<_>>(),
            [
                ("direct", "direct"),
                ("deny", "block"),
                ("choose", "selector"),
            ]
        );

        let clash =
            client.get_clash_mode_status(()).await.unwrap().into_inner();
        assert_eq!(clash.mode_list, ["Rule", "Global"]);
        assert_eq!(clash.current_mode, "Global");
        let mut clash_stream =
            client.subscribe_clash_mode(()).await.unwrap().into_inner();
        assert_eq!(next_message(&mut clash_stream).await.mode, "Global");
        client
            .set_clash_mode(proto::ClashMode {
                mode: "rule".into(),
            })
            .await
            .unwrap();
        assert_eq!(next_message(&mut clash_stream).await.mode, "Rule");

        let mut groups_stream =
            client.subscribe_groups(()).await.unwrap().into_inner();
        let groups = next_message(&mut groups_stream).await;
        let choose = groups
            .group
            .iter()
            .find(|group| group.tag == "choose")
            .unwrap();
        assert!(choose.selectable);
        assert_eq!(choose.selected, "direct");
        assert_eq!(
            choose
                .items
                .iter()
                .map(|item| item.tag.as_str())
                .collect::<Vec<_>>(),
            ["direct", "deny"]
        );

        client
            .set_group_expand(proto::SetGroupExpandRequest {
                group_tag: "choose".into(),
                is_expand: true,
            })
            .await
            .unwrap();
        let groups = next_message(&mut groups_stream).await;
        assert!(groups.group[0].is_expand);

        client
            .select_outbound(proto::SelectOutboundRequest {
                group_tag: "choose".into(),
                outbound_tag: "deny".into(),
            })
            .await
            .unwrap();
        let groups = next_message(&mut groups_stream).await;
        assert_eq!(groups.group[0].selected, "deny");

        let error = client
            .select_outbound(proto::SelectOutboundRequest {
                group_tag: "choose".into(),
                outbound_tag: "missing".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        let error = client
            .url_test(proto::UrlTestRequest {
                outbound_tag: "missing".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);

        let mut connection_events = client
            .subscribe_connections(proto::SubscribeConnectionsRequest {
                interval: 10_000_000,
            })
            .await
            .unwrap()
            .into_inner();
        let initial = next_message(&mut connection_events).await;
        assert!(initial.reset);
        assert!(initial.events.is_empty());

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = SocksAddr::Ip(target.local_addr().unwrap());
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut request = [0_u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            socket.write_all(&request).await.unwrap();
        });
        let dialer = runtime.outbounds().outbound("direct").unwrap();
        let mut tracked = dialer.dial_tcp(&destination).await.unwrap();
        let created = next_message(&mut connection_events).await;
        assert!(!created.reset);
        assert_eq!(created.events.len(), 1);
        assert_eq!(
            created.events[0].r#type,
            i32::from(proto::ConnectionEventType::ConnectionEventNew)
        );
        let connection = created.events[0].connection.as_ref().unwrap();
        assert_eq!(connection.outbound, "direct");
        assert_eq!(connection.outbound_type, "direct");
        assert_eq!(connection.destination, destination.to_string());
        let connection_id = created.events[0].id.clone();

        tracked.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tracked.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        echo.await.unwrap();
        let mut uplink_delta = 0;
        let mut downlink_delta = 0;
        while uplink_delta < 4 || downlink_delta < 4 {
            let updated = next_message(&mut connection_events).await;
            for event in updated.events {
                assert_eq!(
                    event.r#type,
                    i32::from(
                        proto::ConnectionEventType::ConnectionEventUpdate
                    )
                );
                uplink_delta += event.uplink_delta;
                downlink_delta += event.downlink_delta;
            }
        }
        assert_eq!(uplink_delta, 4);
        assert_eq!(downlink_delta, 4);

        client
            .close_connection(proto::CloseConnectionRequest {
                id: connection_id.clone(),
            })
            .await
            .unwrap();
        let closed = loop {
            let message = next_message(&mut connection_events).await;
            if let Some(event) = message.events.into_iter().find(|event| {
                event.id == connection_id
                    && event.r#type
                        == i32::from(
                            proto::ConnectionEventType::ConnectionEventClosed,
                        )
            }) {
                break event;
            }
        };
        assert!(closed.closed_at > 0);
        assert_eq!(closed.connection.as_ref().unwrap().uplink_total, 4);
        client.close_all_connections(()).await.unwrap();
        drop(tracked);

        let missing = client
            .start_stun_test(proto::StunTestRequest {
                server: "127.0.0.1:3478".into(),
                outbound_tag: "missing".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
        assert_eq!(missing.message(), "outbound not found: missing");

        let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_address = stun_socket.local_addr().unwrap();
        let stun_server = tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            let (size, peer) =
                stun_socket.recv_from(&mut request).await.unwrap();
            let transaction_id =
                stun::transaction_id_from_message(&request[..size]).unwrap();
            stun_socket
                .send_to(&stun_binding_response(transaction_id, peer), peer)
                .await
                .unwrap();
        });
        let mut stun_stream = client
            .start_stun_test(proto::StunTestRequest {
                server: stun_address.to_string(),
                outbound_tag: "direct".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let binding_start = next_message(&mut stun_stream).await;
        assert_eq!(binding_start.phase, stun::Phase::Binding as i32);
        assert!(!binding_start.is_final);
        assert!(binding_start.external_addr.is_empty());
        let binding_result = next_message(&mut stun_stream).await;
        assert_eq!(binding_result.phase, stun::Phase::Binding as i32);
        assert!(!binding_result.is_final);
        assert!(!binding_result.external_addr.is_empty());
        let done = next_message(&mut stun_stream).await;
        assert_eq!(done.phase, stun::Phase::Done as i32);
        assert!(!done.is_final);
        let final_result = next_message(&mut stun_stream).await;
        assert_eq!(final_result.phase, stun::Phase::Done as i32);
        assert!(final_result.is_final);
        assert_eq!(final_result.external_addr, binding_result.external_addr);
        assert!(!final_result.nat_type_supported);
        assert!(final_result.error.is_empty());
        assert!(stun_stream.message().await.unwrap().is_none());
        stun_server.await.unwrap();

        let mut failed_stun = client
            .start_stun_test(proto::StunTestRequest {
                server: stun_address.to_string(),
                outbound_tag: "deny".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let failed_result = next_message(&mut failed_stun).await;
        assert!(failed_result.is_final);
        assert!(failed_result.error.contains("create UDP socket"));
        assert!(failed_stun.message().await.unwrap().is_none());

        service.mark_idle();
        assert!(next_message(&mut groups_stream).await.group.is_empty());
        assert!(
            next_message(&mut outbound_stream)
                .await
                .outbounds
                .is_empty()
        );
        assert_eq!(next_message(&mut clash_stream).await.mode, "");
        let error = client.get_clash_mode_status(()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unknown);

        drop(runtime_status);
        drop(groups_stream);
        drop(outbound_stream);
        drop(clash_stream);
        drop(connection_events);
        drop(client);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }
}
