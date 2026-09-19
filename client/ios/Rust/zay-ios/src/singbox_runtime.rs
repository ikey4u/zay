//! iOS host bridge for the embeddable Rust sing-box runtime.
//!
//! The Network Extension owns creation/configuration of the utun device.  The
//! callback below is invoked synchronously while the Rust runtime starts; the
//! returned descriptor must be a duplicate whose ownership is transferred to
//! this module.

use std::{
    ffi::{c_char, c_void},
    path::PathBuf,
};

use crate::error::{clear_error, cstr, set_error};

/// Swift callback used to configure the Network Extension and return an owned
/// duplicate of its utun file descriptor. `request_json` is valid only for the
/// duration of the callback.
pub type ZayIosOpenTunCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        request_json: *const c_char,
    ) -> i32,
>;

#[cfg(any(target_os = "ios", test))]
fn group_tags(config: &str) -> Vec<String> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(config) else {
        return Vec::new();
    };
    let Some(outbounds) =
        root.get("outbounds").and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    let mut tags = outbounds
        .iter()
        .filter(|outbound| {
            matches!(
                outbound.get("type").and_then(serde_json::Value::as_str),
                Some("selector" | "urltest")
            )
        })
        .filter_map(|outbound| {
            outbound.get("tag").and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    tags
}

#[cfg(target_os = "ios")]
mod platform {
    use std::{
        ffi::{CString, c_void},
        io, mem,
        os::fd::{FromRawFd as _, OwnedFd},
        path::{Path, PathBuf},
        sync::{Arc, Mutex, mpsc},
        thread,
        time::Duration,
    };

    use serde_json::json;
    use singbox::{
        Options, PlatformNetworkInterface, PlatformNetworkProvider,
        PlatformSocket, Runtime, TunDeviceRequest, TunFileDescriptorProvider,
        constant::InterfaceType,
    };

    use super::{ZayIosOpenTunCallback, group_tags};

    const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Clone, Copy)]
    pub(super) struct HostCallback {
        function:
            unsafe extern "C" fn(*mut c_void, *const std::ffi::c_char) -> i32,
        context: usize,
    }

    // The Swift owner guarantees that `context` remains alive until stop returns.
    unsafe impl Send for HostCallback {}
    unsafe impl Sync for HostCallback {}

    impl HostCallback {
        pub(super) fn new(
            callback: ZayIosOpenTunCallback,
            context: *mut c_void,
        ) -> Result<Self, String> {
            let function = callback.ok_or("open_tun callback is null")?;
            if context.is_null() {
                return Err("open_tun callback context is null".to_owned());
            }
            Ok(Self {
                function,
                context: context as usize,
            })
        }
    }

    struct CallbackTunProvider(HostCallback);

    impl TunFileDescriptorProvider for CallbackTunProvider {
        fn open_tun(&self, request: &TunDeviceRequest) -> io::Result<OwnedFd> {
            let payload = json!({
                "tag": request.tag,
                "mtu": request.mtu,
                "addresses": request.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "routes": request.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "dns_servers": request.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "platform": request.options.platform,
            });
            let payload = CString::new(payload.to_string()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TUN request contains NUL",
                )
            })?;
            let fd = unsafe {
                (self.0.function)(
                    self.0.context as *mut c_void,
                    payload.as_ptr(),
                )
            };
            if fd < 0 {
                return Err(io::Error::other(
                    "Network Extension failed to create the TUN descriptor",
                ));
            }
            // SAFETY: the callback contract transfers an independently owned
            // descriptor (Swift obtains it with dup(2)).
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    /// Native iOS underlay discovery and per-socket binding. This mirrors the
    /// former Go platform bridge without retaining borrowed socket handles.
    struct IosNetworkProvider;

    impl PlatformNetworkProvider for IosNetworkProvider {
        fn network_interfaces(
            &self,
        ) -> io::Result<Vec<PlatformNetworkInterface>> {
            let mut head = std::ptr::null_mut();
            if unsafe { libc::getifaddrs(&mut head) } != 0 {
                return Err(io::Error::last_os_error());
            }
            struct IfAddrs(*mut libc::ifaddrs);
            impl Drop for IfAddrs {
                fn drop(&mut self) {
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
            let _guard = IfAddrs(head);
            let mut names = std::collections::HashSet::new();
            let mut cursor = head;
            while !cursor.is_null() {
                let interface = unsafe { &*cursor };
                let flags = interface.ifa_flags as i32;
                if flags & libc::IFF_UP != 0 && flags & libc::IFF_LOOPBACK == 0
                {
                    let name =
                        unsafe { std::ffi::CStr::from_ptr(interface.ifa_name) }
                            .to_string_lossy()
                            .into_owned();
                    if !name.starts_with("utun")
                        && !name.starts_with("ipsec")
                        && !name.starts_with("awdl")
                        && !name.starts_with("llw")
                        && !name.starts_with("ap")
                    {
                        names.insert(name);
                    }
                }
                cursor = interface.ifa_next;
            }
            let mut interfaces = names
                .into_iter()
                .filter_map(|name| {
                    let c_name = CString::new(name.as_str()).ok()?;
                    let index =
                        unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                    (index != 0).then(|| {
                        let interface_type = if name.starts_with("en") {
                            InterfaceType::Wifi
                        } else if name.starts_with("pdp_ip")
                            || name.starts_with("pdp_")
                        {
                            InterfaceType::Cellular
                        } else {
                            InterfaceType::Other
                        };
                        PlatformNetworkInterface {
                            id: name.clone(),
                            name,
                            index,
                            interface_type,
                            is_default: false,
                            is_own: false,
                        }
                    })
                })
                .collect::<Vec<_>>();
            interfaces.sort_by(|left, right| {
                let priority =
                    |interface: &PlatformNetworkInterface| match interface
                        .interface_type
                    {
                        InterfaceType::Wifi => 0,
                        InterfaceType::Cellular => 1,
                        InterfaceType::Ethernet => 2,
                        InterfaceType::Other => 3,
                    };
                priority(left)
                    .cmp(&priority(right))
                    .then_with(|| left.name.cmp(&right.name))
            });
            if let Some(interface) = interfaces.first_mut() {
                interface.is_default = true;
            }
            Ok(interfaces)
        }

        fn bind_socket(
            &self,
            socket: PlatformSocket,
            interface: &PlatformNetworkInterface,
        ) -> io::Result<()> {
            const IP_BOUND_IF: libc::c_int = 25;
            const IPV6_BOUND_IF: libc::c_int = 125;
            let (level, option) = if socket.ipv6 {
                (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
            } else {
                (libc::IPPROTO_IP, IP_BOUND_IF)
            };
            let index = interface.index;
            let result = unsafe {
                libc::setsockopt(
                    socket.raw_handle as libc::c_int,
                    level,
                    option,
                    &index as *const _ as *const c_void,
                    mem::size_of_val(&index) as libc::socklen_t,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    enum Command {
        Stop(mpsc::SyncSender<Result<(), String>>),
        Preflight {
            config: String,
            base_path: PathBuf,
            response: mpsc::SyncSender<Result<(), String>>,
        },
        Groups(mpsc::SyncSender<String>),
        Select {
            group: String,
            outbound: String,
            response: mpsc::SyncSender<Result<(), String>>,
        },
        UrlTest {
            group: String,
            response: mpsc::SyncSender<Result<(), String>>,
        },
    }

    struct EngineHandle {
        commands: tokio::sync::mpsc::UnboundedSender<Command>,
        thread: thread::JoinHandle<()>,
        callback: HostCallback,
    }

    static ENGINE: Mutex<Option<EngineHandle>> = Mutex::new(None);

    fn configure_runtime(
        config: &str,
        base_path: &Path,
        provider: Arc<CallbackTunProvider>,
    ) -> Result<Runtime, String> {
        let options: Options = serde_json::from_str(config)
            .map_err(|error| format!("decode sing-box config: {error}"))?;
        Runtime::from_options_in_with_mobile_platform(
            options,
            base_path,
            None,
            provider,
            Arc::new(IosNetworkProvider),
        )
        .map_err(|error| format!("configure sing-box runtime: {error}"))
    }

    fn groups_json(runtime: &Runtime, tags: &[String]) -> String {
        let groups = tags
            .iter()
            .filter_map(|tag| {
                let choices = runtime.outbounds().group_choices(tag)?;
                let history = runtime.outbounds().urltest_history(tag).unwrap_or_default();
                let items = choices
                    .iter()
                    .map(|choice| {
                        json!({
                            "tag": choice,
                            "type": runtime.outbounds().kind_owned(choice).unwrap_or_default(),
                            "url_test_delay": history.get(choice).copied().unwrap_or_default(),
                            "url_test_time": 0,
                        })
                    })
                    .collect::<Vec<_>>();
                Some(json!({
                    "tag": tag,
                    "type": runtime.outbounds().kind_owned(tag).unwrap_or_default(),
                    "selectable": runtime.outbounds().kind(tag) == Some("selector"),
                    "selected": runtime.outbounds().group_selected(tag).unwrap_or_default(),
                    "items": items,
                }))
            })
            .collect::<Vec<_>>();
        json!({ "groups": groups }).to_string()
    }

    fn stop_handle(handle: EngineHandle) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let send_result = handle
            .commands
            .send(Command::Stop(response_tx))
            .map_err(|_| {
                "sing-box runtime thread stopped unexpectedly".to_owned()
            });
        let close_result = send_result.and_then(|()| {
            response_rx
                .recv_timeout(CONTROL_TIMEOUT)
                .map_err(|_| "timed out stopping sing-box runtime".to_owned())?
        });
        let join_result = handle
            .thread
            .join()
            .map_err(|_| "sing-box runtime thread panicked".to_owned());
        close_result.and(join_result)
    }

    pub(super) fn start(
        config: String,
        base_path: PathBuf,
        callback: HostCallback,
    ) -> Result<(), String> {
        stop()?;

        let group_tags = group_tags(&config);
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (command_tx, mut command_rx) =
            tokio::sync::mpsc::unbounded_channel();
        let provider = Arc::new(CallbackTunProvider(callback));
        let runtime_thread = thread::Builder::new()
            .name("zay-singbox".to_owned())
            .spawn(move || {
                let tokio_runtime =
                    match tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = startup_tx.send(Err(format!(
                                "create sing-box async runtime: {error}"
                            )));
                            return;
                        }
                    };
                tokio_runtime.block_on(async move {
                    let mut runtime = match configure_runtime(
                        &config,
                        Path::new(&base_path),
                        provider.clone(),
                    ) {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = startup_tx.send(Err(error));
                            return;
                        }
                    };
                    if let Err(error) = runtime.start().await {
                        let _ = startup_tx.send(Err(format!(
                            "start sing-box runtime: {error}"
                        )));
                        return;
                    }
                    if startup_tx.send(Ok(())).is_err() {
                        let _ = runtime.close().await;
                        return;
                    }

                    while let Some(command) = command_rx.recv().await {
                        match command {
                            Command::Stop(response) => {
                                let result = runtime
                                    .close()
                                    .await
                                    .map_err(|e| e.to_string());
                                let _ = response.send(result);
                                return;
                            }
                            Command::Preflight {
                                config,
                                base_path,
                                response,
                            } => {
                                let result = configure_runtime(
                                    &config,
                                    Path::new(&base_path),
                                    provider.clone(),
                                )
                                .map(drop);
                                let _ = response.send(result);
                            }
                            Command::Groups(response) => {
                                let _ = response
                                    .send(groups_json(&runtime, &group_tags));
                            }
                            Command::Select {
                                group,
                                outbound,
                                response,
                            } => {
                                let result = runtime
                                    .outbounds()
                                    .select_group(&group, &outbound)
                                    .map_err(|e| e.to_string());
                                let _ = response.send(result);
                            }
                            Command::UrlTest { group, response } => {
                                let result = runtime
                                    .outbounds()
                                    .test_group_delay(
                                        &group,
                                        "https://www.gstatic.com/generate_204",
                                        Duration::from_secs(10),
                                    )
                                    .await
                                    .map(|_| ())
                                    .map_err(|e| e.to_string());
                                let _ = response.send(result);
                            }
                        }
                    }
                    let _ = runtime.close().await;
                });
            })
            .map_err(|error| {
                format!("spawn sing-box runtime thread: {error}")
            })?;

        match startup_rx.recv_timeout(CONTROL_TIMEOUT) {
            Ok(Ok(())) => {
                *ENGINE.lock().map_err(|_| "sing-box state poisoned")? =
                    Some(EngineHandle {
                        commands: command_tx,
                        thread: runtime_thread,
                        callback,
                    });
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = runtime_thread.join();
                Err(error)
            }
            Err(_) => {
                let (response_tx, response_rx) = mpsc::sync_channel(1);
                let _ = command_tx.send(Command::Stop(response_tx));
                let _ = response_rx.recv_timeout(CONTROL_TIMEOUT);
                let _ = runtime_thread.join();
                Err("timed out starting sing-box runtime".to_owned())
            }
        }
    }

    pub(super) fn reload(
        config: String,
        base_path: PathBuf,
    ) -> Result<(), String> {
        let (callback, commands) = {
            let guard = ENGINE.lock().map_err(|_| "sing-box state poisoned")?;
            let engine =
                guard.as_ref().ok_or("sing-box runtime is not running")?;
            (engine.callback, engine.commands.clone())
        };
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        commands
            .send(Command::Preflight {
                config: config.clone(),
                base_path: base_path.clone(),
                response: response_tx,
            })
            .map_err(|_| {
                "sing-box runtime thread stopped unexpectedly".to_owned()
            })?;
        response_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| "timed out validating sing-box reload".to_owned())??;
        start(config, base_path, callback)
    }

    pub(super) fn stop() -> Result<(), String> {
        let handle =
            ENGINE.lock().map_err(|_| "sing-box state poisoned")?.take();
        match handle {
            Some(handle) => stop_handle(handle),
            None => Ok(()),
        }
    }

    pub(super) fn groups() -> Result<String, String> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let guard = ENGINE.lock().map_err(|_| "sing-box state poisoned")?;
        let engine = guard.as_ref().ok_or("sing-box runtime is not running")?;
        engine
            .commands
            .send(Command::Groups(response_tx))
            .map_err(|_| {
                "sing-box runtime thread stopped unexpectedly".to_owned()
            })?;
        response_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| "timed out reading sing-box groups".to_owned())
    }

    pub(super) fn select(
        group: String,
        outbound: String,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let guard = ENGINE.lock().map_err(|_| "sing-box state poisoned")?;
        let engine = guard.as_ref().ok_or("sing-box runtime is not running")?;
        engine
            .commands
            .send(Command::Select {
                group,
                outbound,
                response: response_tx,
            })
            .map_err(|_| {
                "sing-box runtime thread stopped unexpectedly".to_owned()
            })?;
        response_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| "timed out selecting sing-box outbound".to_owned())?
    }

    pub(super) fn url_test(group: String) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let guard = ENGINE.lock().map_err(|_| "sing-box state poisoned")?;
        let engine = guard.as_ref().ok_or("sing-box runtime is not running")?;
        engine
            .commands
            .send(Command::UrlTest {
                group,
                response: response_tx,
            })
            .map_err(|_| {
                "sing-box runtime thread stopped unexpectedly".to_owned()
            })?;
        response_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| "timed out testing sing-box outbound".to_owned())?
    }
}

#[cfg(not(target_os = "ios"))]
fn unsupported() -> Result<(), String> {
    Err("the embedded sing-box Network Extension runtime is only available on iOS".into())
}

/// Start the embedded sing-box runtime and transfer TUN creation to the host.
///
/// # Safety
///
/// Both string pointers must remain valid and NUL-terminated for this call.
/// `open_tun` and `context` must remain valid until the runtime is stopped.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_start_singbox(
    config_json: *const c_char,
    base_path: *const c_char,
    open_tun: ZayIosOpenTunCallback,
    context: *mut c_void,
) -> i32 {
    clear_error();
    let result = (|| {
        let config = unsafe { cstr(config_json) }?.to_owned();
        let base_path = PathBuf::from(unsafe { cstr(base_path) }?);
        #[cfg(target_os = "ios")]
        {
            let callback = platform::HostCallback::new(open_tun, context)?;
            platform::start(config, base_path, callback)
        }
        #[cfg(not(target_os = "ios"))]
        {
            let _ = (config, base_path, open_tun, context);
            unsupported()
        }
    })();
    return_code(result)
}

/// Reload the embedded sing-box runtime configuration.
///
/// # Safety
///
/// Both arguments must point to valid NUL-terminated strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_reload_singbox(
    config_json: *const c_char,
    base_path: *const c_char,
) -> i32 {
    clear_error();
    let result = (|| {
        let config = unsafe { cstr(config_json) }?.to_owned();
        let base_path = PathBuf::from(unsafe { cstr(base_path) }?);
        #[cfg(target_os = "ios")]
        {
            platform::reload(config, base_path)
        }
        #[cfg(not(target_os = "ios"))]
        {
            let _ = (config, base_path);
            unsupported()
        }
    })();
    return_code(result)
}

/// Stop the embedded sing-box runtime.
#[unsafe(no_mangle)]
pub extern "C" fn zay_ios_stop_singbox() -> i32 {
    clear_error();
    #[cfg(target_os = "ios")]
    let result = platform::stop();
    #[cfg(not(target_os = "ios"))]
    let result = unsupported();
    return_code(result)
}

/// Return a JSON snapshot of the running sing-box groups.
#[unsafe(no_mangle)]
pub extern "C" fn zay_ios_singbox_groups_json() -> *mut c_char {
    clear_error();
    #[cfg(target_os = "ios")]
    let result = platform::groups();
    #[cfg(not(target_os = "ios"))]
    let result: Result<String, String> = unsupported().map(|()| String::new());
    match result.and_then(crate::error::to_cstring) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            std::ptr::null_mut()
        }
    }
}

/// Select an outbound in a running sing-box group.
///
/// # Safety
///
/// Both arguments must point to valid NUL-terminated strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_select_singbox_outbound(
    group: *const c_char,
    outbound: *const c_char,
) -> i32 {
    clear_error();
    let result = (|| {
        let group = unsafe { cstr(group) }?.to_owned();
        let outbound = unsafe { cstr(outbound) }?.to_owned();
        #[cfg(target_os = "ios")]
        {
            platform::select(group, outbound)
        }
        #[cfg(not(target_os = "ios"))]
        {
            let _ = (group, outbound);
            unsupported()
        }
    })();
    return_code(result)
}

/// Trigger a URL test for a running sing-box group.
///
/// # Safety
///
/// `group` must point to a valid NUL-terminated string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zay_ios_url_test_singbox(group: *const c_char) -> i32 {
    clear_error();
    let result = (|| {
        let group = unsafe { cstr(group) }?.to_owned();
        #[cfg(target_os = "ios")]
        {
            platform::url_test(group)
        }
        #[cfg(not(target_os = "ios"))]
        {
            let _ = group;
            unsupported()
        }
    })();
    return_code(result)
}

fn return_code(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            set_error(error);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};

    use super::{group_tags, zay_ios_start_singbox};

    #[test]
    fn discovers_only_unique_proxy_groups_in_stable_order() {
        let tags = group_tags(
            r#"{
                "outbounds": [
                    {"type":"direct","tag":"direct"},
                    {"type":"urltest","tag":"Auto"},
                    {"type":"selector","tag":"Proxy"},
                    {"type":"selector","tag":"Proxy"}
                ]
            }"#,
        );
        assert_eq!(tags, ["Auto", "Proxy"]);
        assert!(group_tags("not json").is_empty());
    }

    #[cfg(not(target_os = "ios"))]
    #[test]
    fn host_stub_fails_closed_and_reports_an_owned_error() {
        let config = CString::new("{}").unwrap();
        let base = CString::new(".").unwrap();
        let result = unsafe {
            zay_ios_start_singbox(
                config.as_ptr(),
                base.as_ptr(),
                None,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, -1);
        let error = crate::error::zay_ios_last_error();
        assert!(!error.is_null());
        let message = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        unsafe { crate::error::zay_ios_free_string(error) };
        assert!(message.contains("only available on iOS"), "{message}");
    }
}
