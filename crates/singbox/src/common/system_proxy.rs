//! Platform system-proxy lease used by HTTP and mixed listeners.

use std::{io, net::SocketAddr};

/// An enabled system proxy. Closing the owning inbound disables the settings
/// before releasing its listener, matching sing-box's listener lifecycle.
pub(crate) struct SystemProxyLease {
    platform: platform::Lease,
}

impl SystemProxyLease {
    pub(crate) async fn enable(
        server: SocketAddr,
        support_socks: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Lease::enable(server, support_socks).await?,
        })
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        self.platform.close().await
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{env, ffi::OsString, io, net::SocketAddr, path::PathBuf};

    use tokio::process::Command;

    pub(super) struct Lease {
        runner: Runner,
        has_gsettings: bool,
        kwriteconfig: Option<&'static str>,
        enabled: bool,
    }

    #[derive(Clone)]
    struct Runner {
        sudo_user: Option<String>,
    }

    impl Runner {
        async fn run(&self, name: &str, args: &[String]) -> io::Result<()> {
            let status = if let Some(user) = &self.sudo_user {
                let command = std::iter::once(name)
                    .chain(args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ");
                Command::new("su")
                    .args(["-", user, "-c", &command])
                    .status()
                    .await?
            } else {
                Command::new(name).args(args).status().await?
            };
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("{name} exited with {status}")))
            }
        }
    }

    impl Lease {
        pub(super) async fn enable(
            server: SocketAddr,
            support_socks: bool,
        ) -> io::Result<Self> {
            let is_root = unsafe { libc::geteuid() } == 0;
            let sudo_user = is_root
                .then(|| env::var("SUDO_USER").ok())
                .flatten()
                .filter(|user| !user.is_empty());
            if is_root && sudo_user.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "set system proxy: unable to set as root",
                ));
            }
            let runner = Runner { sudo_user };
            let has_gsettings = find_command("gsettings").is_some();
            let kwriteconfig = ["kwriteconfig5", "kwriteconfig6"]
                .into_iter()
                .find(|command| find_command(command).is_some());
            if !has_gsettings && kwriteconfig.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported desktop environment",
                ));
            }
            let mut lease = Self {
                runner,
                has_gsettings,
                kwriteconfig,
                enabled: false,
            };
            lease.apply(server, support_socks).await?;
            lease.enabled = true;
            Ok(lease)
        }

        async fn apply(
            &self,
            server: SocketAddr,
            support_socks: bool,
        ) -> io::Result<()> {
            let host = server.ip().to_string();
            let port = server.port().to_string();
            if self.has_gsettings {
                self.runner
                    .run(
                        "gsettings",
                        &strings(&[
                            "set",
                            "org.gnome.system.proxy.http",
                            "enabled",
                            "true",
                        ]),
                    )
                    .await?;
                let types: &[&str] = if support_socks {
                    &["ftp", "http", "https", "socks"]
                } else {
                    &["http", "https"]
                };
                for proxy_type in types {
                    let schema = format!("org.gnome.system.proxy.{proxy_type}");
                    self.runner
                        .run(
                            "gsettings",
                            &[
                                "set".into(),
                                schema.clone(),
                                "host".into(),
                                host.clone(),
                            ],
                        )
                        .await?;
                    self.runner
                        .run(
                            "gsettings",
                            &[
                                "set".into(),
                                schema,
                                "port".into(),
                                port.clone(),
                            ],
                        )
                        .await?;
                }
                self.runner
                    .run(
                        "gsettings",
                        &strings(&[
                            "set",
                            "org.gnome.system.proxy",
                            "use-same-proxy",
                            if support_socks { "true" } else { "false" },
                        ]),
                    )
                    .await?;
                self.runner
                    .run(
                        "gsettings",
                        &strings(&[
                            "set",
                            "org.gnome.system.proxy",
                            "mode",
                            "manual",
                        ]),
                    )
                    .await?;
            }
            if let Some(command) = self.kwriteconfig {
                self.kde_set(command, "ProxyType", "1").await?;
                let types: &[&str] = if support_socks {
                    &["ftp", "http", "https", "socks"]
                } else {
                    &["http", "https"]
                };
                for proxy_type in types {
                    let scheme = if *proxy_type == "socks" {
                        "socks"
                    } else {
                        "http"
                    };
                    self.kde_set(
                        command,
                        &format!("{proxy_type}Proxy"),
                        &format!("{scheme}://{server}"),
                    )
                    .await?;
                }
                self.kde_set(command, "Authmode", "0").await?;
                self.kde_reload().await?;
            }
            Ok(())
        }

        async fn kde_set(
            &self,
            command: &str,
            key: &str,
            value: &str,
        ) -> io::Result<()> {
            self.runner
                .run(
                    command,
                    &strings(&[
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        key,
                        value,
                    ]),
                )
                .await
        }

        async fn kde_reload(&self) -> io::Result<()> {
            self.runner
                .run(
                    "dbus-send",
                    &strings(&[
                        "--type=signal",
                        "/KIO/Scheduler",
                        "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                        "string:''",
                    ]),
                )
                .await
        }

        pub(super) async fn close(&mut self) -> io::Result<()> {
            if !self.enabled {
                return Ok(());
            }
            if self.has_gsettings {
                self.runner
                    .run(
                        "gsettings",
                        &strings(&[
                            "set",
                            "org.gnome.system.proxy",
                            "mode",
                            "none",
                        ]),
                    )
                    .await?;
            }
            if let Some(command) = self.kwriteconfig {
                self.kde_set(command, "ProxyType", "0").await?;
                self.kde_reload().await?;
            }
            self.enabled = false;
            Ok(())
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn find_command(name: &str) -> Option<PathBuf> {
        let path: OsString = env::var_os("PATH")?;
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{io, net::SocketAddr, sync::Arc};

    use n0_watcher::Watcher as _;
    use tokio::{process::Command, sync::Mutex, task::JoinHandle};
    use tokio_util::sync::CancellationToken;

    pub(super) struct Lease {
        state: Arc<Mutex<State>>,
        cancellation: CancellationToken,
        task: Option<JoinHandle<()>>,
    }

    struct State {
        interface: String,
        server: SocketAddr,
        support_socks: bool,
        enabled: bool,
    }

    impl Lease {
        pub(super) async fn enable(
            server: SocketAddr,
            support_socks: bool,
        ) -> io::Result<Self> {
            let monitor =
                crate::common::network_monitor::NetworkMonitor::new().await?;
            let mut watcher = monitor.interface_state();
            let interface = watcher.get().default_route_interface.clone();
            let state = Arc::new(Mutex::new(State {
                interface: String::new(),
                server,
                support_socks,
                enabled: false,
            }));
            if let Some(interface) = interface {
                update(&state, &interface).await?;
            }
            let cancellation = CancellationToken::new();
            let task_state = state.clone();
            let task_cancellation = cancellation.clone();
            let task = tokio::spawn(async move {
                let _monitor = monitor;
                loop {
                    let current = tokio::select! {
                        _ = task_cancellation.cancelled() => return,
                        current = watcher.updated() => match current {
                            Ok(current) => current,
                            Err(_) => return,
                        },
                    };
                    if let Some(interface) = &current.default_route_interface {
                        let _ = update(&task_state, interface).await;
                    }
                }
            });
            Ok(Self {
                state,
                cancellation,
                task: Some(task),
            })
        }

        pub(super) async fn close(&mut self) -> io::Result<()> {
            self.cancellation.cancel();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            let mut state = self.state.lock().await;
            if state.enabled {
                disable(&state.interface, state.support_socks).await?;
                state.enabled = false;
            }
            Ok(())
        }
    }

    async fn update(
        state: &Arc<Mutex<State>>,
        interface: &str,
    ) -> io::Result<()> {
        let mut state = state.lock().await;
        if state.interface == interface {
            return Ok(());
        }
        if state.enabled {
            let _ = disable(&state.interface, state.support_socks).await;
            state.enabled = false;
        }
        state.interface = interface.to_owned();
        enable_interface(interface, state.server, state.support_socks).await?;
        state.enabled = true;
        Ok(())
    }

    async fn enable_interface(
        interface: &str,
        server: SocketAddr,
        support_socks: bool,
    ) -> io::Result<()> {
        let display = interface_display_name(interface).await?;
        let host = server.ip().to_string();
        let port = server.port().to_string();
        if support_socks {
            run(&["-setsocksfirewallproxy", &display, &host, &port]).await?;
        }
        run(&["-setwebproxy", &display, &host, &port]).await?;
        run(&["-setsecurewebproxy", &display, &host, &port]).await
    }

    async fn disable(interface: &str, support_socks: bool) -> io::Result<()> {
        let display = interface_display_name(interface).await?;
        if support_socks {
            run(&["-setsocksfirewallproxystate", &display, "off"]).await?;
        }
        run(&["-setwebproxystate", &display, "off"]).await?;
        run(&["-setsecurewebproxystate", &display, "off"]).await
    }

    async fn interface_display_name(interface: &str) -> io::Result<String> {
        let output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
            .await?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "networksetup exited with {}",
                output.status
            )));
        }
        parse_interface_display_name(
            &String::from_utf8_lossy(&output.stdout),
            interface,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{interface} not found in networksetup -listallhardwareports"
                ),
            )
        })
    }

    fn parse_interface_display_name(
        content: &str,
        interface: &str,
    ) -> Option<String> {
        for block in content.split("Ethernet Address") {
            if block.contains(&format!("Device: {interface}")) {
                let value = block.split_once("Hardware Port: ")?.1;
                return Some(value.lines().next()?.to_owned());
            }
        }
        None
    }

    async fn run(args: &[&str]) -> io::Result<()> {
        let status = Command::new("networksetup").args(args).status().await?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "networksetup exited with {status}"
            )))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse_interface_display_name;

        #[test]
        fn parses_networksetup_hardware_port_for_device() {
            let output = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb\n\
                          Hardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: cc:dd\n";
            assert_eq!(
                parse_interface_display_name(output, "en0").as_deref(),
                Some("Wi-Fi")
            );
            assert_eq!(
                parse_interface_display_name(output, "bridge0").as_deref(),
                Some("Thunderbolt Bridge")
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::{io, mem::size_of, net::SocketAddr, ptr};

    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_OPTION_PROXY_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH,
        INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_PROXY_SERVER,
        InternetSetOptionW, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };

    const PROXY_TYPE_AUTO_DETECT: u32 = 8;

    pub(super) struct Lease {
        enabled: bool,
    }

    impl Lease {
        pub(super) async fn enable(
            server: SocketAddr,
            _support_socks: bool,
        ) -> io::Result<Self> {
            let mut proxy = format!("http://{server}")
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>();
            set_options(&mut [
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_FLAGS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        dwValue: PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT,
                    },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: proxy.as_mut_ptr(),
                    },
                },
            ])?;
            Ok(Self { enabled: true })
        }

        pub(super) async fn close(&mut self) -> io::Result<()> {
            if self.enabled {
                set_options(&mut [INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_FLAGS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        dwValue: PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT,
                    },
                }])?;
                self.enabled = false;
            }
            Ok(())
        }
    }

    fn set_options(
        options: &mut [INTERNET_PER_CONN_OPTIONW],
    ) -> io::Result<()> {
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: ptr::null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        let size = list.dwSize;
        call(
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw mut list).cast(),
            size,
        )?;
        for option in [
            INTERNET_OPTION_SETTINGS_CHANGED,
            INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
            INTERNET_OPTION_REFRESH,
        ] {
            call(option, ptr::null_mut(), 0)?;
        }
        Ok(())
    }

    fn call(
        option: u32,
        buffer: *mut core::ffi::c_void,
        size: u32,
    ) -> io::Result<()> {
        if unsafe { InternetSetOptionW(ptr::null(), option, buffer, size) } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "android")]
mod platform {
    use std::{env, ffi::OsString, io, net::SocketAddr, path::PathBuf};

    use tokio::process::Command;

    pub(super) struct Lease {
        rish: Option<PathBuf>,
        enabled: bool,
    }

    impl Lease {
        pub(super) async fn enable(
            server: SocketAddr,
            _support_socks: bool,
        ) -> io::Result<Self> {
            let uid = unsafe { libc::getuid() };
            let rish = if matches!(uid, 0 | 1000 | 2000) {
                None
            } else {
                Some(find_command("rish").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "root or system (adb) permission is required for set system proxy",
                    )
                })?)
            };
            let mut lease = Self {
                rish,
                enabled: false,
            };
            lease.run(&server.to_string()).await?;
            lease.enabled = true;
            Ok(lease)
        }

        pub(super) async fn close(&mut self) -> io::Result<()> {
            if self.enabled {
                self.run(":0").await?;
                self.enabled = false;
            }
            Ok(())
        }

        async fn run(&self, value: &str) -> io::Result<()> {
            let status = if let Some(rish) = &self.rish {
                Command::new("sh")
                    .arg(rish)
                    .args([
                        "-c",
                        &format!("settings put global http_proxy {value}"),
                    ])
                    .status()
                    .await?
            } else {
                Command::new("settings")
                    .args(["put", "global", "http_proxy", value])
                    .status()
                    .await?
            };
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("settings exited with {status}")))
            }
        }
    }

    fn find_command(name: &str) -> Option<PathBuf> {
        let path: OsString = env::var_os("PATH")?;
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "android",
    windows
)))]
mod platform {
    use std::{io, net::SocketAddr};

    pub(super) struct Lease;

    impl Lease {
        pub(super) async fn enable(
            _server: SocketAddr,
            _support_socks: bool,
        ) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "system proxy is not supported on this platform",
            ))
        }

        pub(super) async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
