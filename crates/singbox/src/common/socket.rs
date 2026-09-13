//! Platform socket options shared by direct and underlay dialers.

use std::{io, net::SocketAddr};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    windows
))]
use std::num::NonZeroU32;

use socket2::{SockRef, Socket, TcpKeepalive};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

use crate::option::{AbstractDialerOptions, ListenOptions};

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct AutoRedirectMarkState {
    mark: u32,
    leases: usize,
}

#[cfg(target_os = "linux")]
static AUTO_REDIRECT_MARK: std::sync::Mutex<AutoRedirectMarkState> =
    std::sync::Mutex::new(AutoRedirectMarkState { mark: 0, leases: 0 });

/// Process-wide output mark registered by an active Linux TUN auto-redirect
/// instance. Explicit per-outbound `routing_mark` continues to take priority.
#[cfg(target_os = "linux")]
pub(crate) struct AutoRedirectMarkLease {
    mark: u32,
    active: bool,
}

#[cfg(target_os = "linux")]
impl AutoRedirectMarkLease {
    pub(crate) fn register(mark: u32) -> io::Result<Self> {
        if mark == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auto-redirect output mark must not be zero",
            ));
        }
        let mut state = AUTO_REDIRECT_MARK.lock().map_err(|_| {
            io::Error::other("auto-redirect mark lock poisoned")
        })?;
        if state.leases != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "only one auto-redirect can be configured (active mark {:#x})",
                    state.mark
                ),
            ));
        }
        state.mark = mark;
        state.leases += 1;
        Ok(Self { mark, active: true })
    }

    pub(crate) fn close(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut state) = AUTO_REDIRECT_MARK.lock()
            && state.mark == self.mark
            && state.leases > 0
        {
            state.leases -= 1;
            if state.leases == 0 {
                state.mark = 0;
            }
        }
        self.active = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for AutoRedirectMarkLease {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) async fn bind_tcp_listener(
    address: SocketAddr,
    options: &ListenOptions,
) -> io::Result<TcpListener> {
    let namespace = options.netns.clone();
    let options = options.clone();
    let listener = with_network_namespace(&namespace, move || {
        #[cfg(target_os = "linux")]
        if options.tcp_multi_path
            && let Ok(listener) = build_tcp_listener(
                address,
                &options,
                Some(socket2::Protocol::MPTCP),
            )
        {
            return Ok(listener);
        }
        build_tcp_listener(address, &options, Some(socket2::Protocol::TCP))
    })
    .await?;
    TcpListener::from_std(listener)
}

/// Bind a UDP listener while applying the same platform socket controls used
/// by inbound TCP listeners and outbound packet sockets.
pub(crate) async fn bind_udp_listener(
    address: SocketAddr,
    options: &ListenOptions,
) -> io::Result<UdpSocket> {
    let namespace = options.netns.clone();
    let options = options.clone();
    let socket = with_network_namespace(&namespace, move || {
        let domain = if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(options.reuse_addr)?;
        let socket_ref = SockRef::from(&socket);
        apply_bind_interface(&socket_ref, address, &options.bind_interface)?;
        apply_routing_mark(&socket_ref, options.routing_mark.0)?;
        apply_udp_fragmentation(&socket_ref, address, options.udp_fragment)?;
        socket.bind(&address.into())?;
        socket.set_nonblocking(true)?;
        Ok::<_, io::Error>(socket.into())
    })
    .await?;
    UdpSocket::from_std(socket)
}

/// Create a socket inside a Linux network namespace without leaking the
/// namespace switch to Tokio's reusable worker thread.  A relative value is
/// interpreted exactly like `ip netns`: `/run/netns/<name>`.
pub(crate) async fn with_network_namespace<T, F>(
    namespace: &str,
    operation: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    if namespace.is_empty() {
        return operation();
    }
    #[cfg(target_os = "linux")]
    {
        let namespace = namespace.to_owned();
        return tokio::task::spawn_blocking(move || {
            let _guard = NetworkNamespaceGuard::enter(&namespace)?;
            operation()
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = operation;
        Err(unsupported(
            "network namespaces are only available on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
struct NetworkNamespaceGuard {
    original: std::fs::File,
}

#[cfg(target_os = "linux")]
impl NetworkNamespaceGuard {
    fn enter(namespace: &str) -> io::Result<Self> {
        use std::os::fd::AsRawFd as _;

        let original = std::fs::File::open("/proc/thread-self/ns/net")
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("open current network namespace: {error}"),
                )
            })?;
        let path = if namespace.starts_with('/') {
            std::path::PathBuf::from(namespace)
        } else {
            std::path::Path::new("/run/netns").join(namespace)
        };
        let target = std::fs::File::open(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("open network namespace {}: {error}", path.display()),
            )
        })?;
        if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("enter network namespace {}: {error}", path.display()),
            ));
        }
        Ok(Self { original })
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetworkNamespaceGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        if unsafe { libc::setns(self.original.as_raw_fd(), libc::CLONE_NEWNET) }
            != 0
        {
            // A failed restore would poison a reusable Tokio blocking thread.
            // Abort instead of silently creating later sockets in the wrong
            // namespace.
            std::process::abort();
        }
    }
}

fn build_tcp_listener(
    address: SocketAddr,
    options: &ListenOptions,
    protocol: Option<socket2::Protocol>,
) -> io::Result<std::net::TcpListener> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let context = |operation: &str, error: io::Error| {
        io::Error::new(
            error.kind(),
            format!("{operation} for TCP listener {address}: {error}"),
        )
    };
    let socket = Socket::new(domain, socket2::Type::STREAM, protocol)
        .map_err(|error| context("create socket", error))?;
    socket
        .set_reuse_address(options.reuse_addr)
        .map_err(|error| context("set SO_REUSEADDR", error))?;
    let socket_ref = SockRef::from(&socket);
    apply_bind_interface(&socket_ref, address, &options.bind_interface)
        .map_err(|error| context("bind interface", error))?;
    apply_routing_mark(&socket_ref, options.routing_mark.0)
        .map_err(|error| context("set routing mark", error))?;
    if options.disable_tcp_keep_alive {
        socket_ref
            .set_keepalive(false)
            .map_err(|error| context("disable keepalive", error))?;
    } else {
        socket_ref
            .set_keepalive(true)
            .map_err(|error| context("enable keepalive", error))?;
        let keepalive = TcpKeepalive::new()
            .with_time(
                options
                    .tcp_keep_alive
                    .as_std()
                    .unwrap_or(std::time::Duration::from_secs(5 * 60)),
            )
            .with_interval(
                options
                    .tcp_keep_alive_interval
                    .as_std()
                    .unwrap_or(std::time::Duration::from_secs(75)),
            );
        socket_ref
            .set_tcp_keepalive(&keepalive)
            .map_err(|error| context("configure keepalive", error))?;
    }
    apply_tcp_fast_open_listener(&socket_ref, options.tcp_fast_open)
        .map_err(|error| context("configure TCP fast open", error))?;
    socket
        .bind(&address.into())
        .map_err(|error| context("bind socket", error))?;
    socket
        .listen(1024)
        .map_err(|error| context("listen", error))?;
    apply_tcp_fast_open_listener_post_listen(
        &socket_ref,
        options.tcp_fast_open,
    )?;
    socket
        .set_nonblocking(true)
        .map_err(|error| context("set nonblocking", error))?;
    Ok(socket.into())
}

pub(crate) fn apply_tcp_dialer_options(
    socket: &TcpSocket,
    remote: SocketAddr,
    options: &AbstractDialerOptions,
) -> io::Result<()> {
    validate_supported_options(options)?;
    let socket = SockRef::from(socket);
    apply_common_options(&socket, remote, options)?;
    if options.disable_tcp_keep_alive {
        socket.set_keepalive(false)?;
    } else {
        socket.set_keepalive(true)?;
        let keepalive = TcpKeepalive::new()
            .with_time(
                options
                    .tcp_keep_alive
                    .as_std()
                    .unwrap_or(std::time::Duration::from_secs(5 * 60)),
            )
            .with_interval(
                options
                    .tcp_keep_alive_interval
                    .as_std()
                    .unwrap_or(std::time::Duration::from_secs(75)),
            );
        socket.set_tcp_keepalive(&keepalive)?;
    }
    apply_tcp_fast_open(&socket, options.tcp_fast_open)?;
    apply_bind_address_no_port(&socket, remote, options.bind_address_no_port)
}

pub(crate) fn apply_udp_dialer_options(
    socket: &Socket,
    remote: SocketAddr,
    options: &AbstractDialerOptions,
) -> io::Result<()> {
    validate_supported_options(options)?;
    let socket = SockRef::from(socket);
    apply_common_options(&socket, remote, options)?;
    if options.reuse_addr {
        socket.set_reuse_address(true)?;
    }
    apply_bind_address_no_port(&socket, remote, options.bind_address_no_port)?;
    apply_udp_fragmentation(&socket, remote, options.udp_fragment)
}

/// Apply the controls shared by direct TCP/UDP/ICMP sockets. ICMP has no
/// transport port and does not use UDP fragmentation or bind-no-port flags.
pub(crate) fn apply_icmp_dialer_options(
    socket: &Socket,
    remote: SocketAddr,
    options: &AbstractDialerOptions,
) -> io::Result<()> {
    validate_supported_options(options)?;
    apply_common_options(&SockRef::from(socket), remote, options)
}

fn validate_supported_options(
    options: &AbstractDialerOptions,
) -> io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    if !options.netns.is_empty() {
        return Err(unsupported(
            "network namespaces are only available on Linux",
        ));
    }
    #[cfg(not(unix))]
    if !options.protect_path.is_empty() {
        return Err(unsupported(
            "protect_path requires Unix file-descriptor passing",
        ));
    }
    Ok(())
}

fn apply_common_options(
    socket: &SockRef<'_>,
    remote: SocketAddr,
    options: &AbstractDialerOptions,
) -> io::Result<()> {
    apply_bind_interface(socket, remote, &options.bind_interface)?;
    #[cfg(target_os = "linux")]
    let mark = {
        let auto_redirect_mark = AUTO_REDIRECT_MARK
            .lock()
            .map_err(|_| io::Error::other("auto-redirect mark lock poisoned"))?
            .mark;
        if auto_redirect_mark != 0 {
            auto_redirect_mark
        } else {
            options.routing_mark.0
        }
    };
    #[cfg(not(target_os = "linux"))]
    let mark = options.routing_mark.0;
    apply_routing_mark(socket, mark)?;
    apply_protect_path(socket, &options.protect_path)
}

/// Ask an Android-style VPN service to exempt this socket from its TUN by
/// passing the descriptor over the configured Unix stream. This follows
/// sing/common's `ProtectPath` protocol: one data byte plus one SCM_RIGHTS
/// descriptor, followed by a one-byte acknowledgement.
#[cfg(unix)]
fn apply_protect_path(
    socket: &SockRef<'_>,
    protect_path: &str,
) -> io::Result<()> {
    use std::{io::Read as _, os::fd::AsRawFd as _};

    if protect_path.is_empty() {
        return Ok(());
    }

    let mut control = connect_protect_path(protect_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("connect protect path {protect_path}: {error}"),
        )
    })?;
    let descriptor = socket.as_raw_fd();
    let mut dummy = [1_u8];
    let mut iovec = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: dummy.len(),
    };
    let control_length = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize
    };
    let mut ancillary = vec![0_u8; control_length];
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = std::ptr::from_mut(&mut iovec);
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary.len() as _;

    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(io::Error::other(
            "failed to allocate protect_path ancillary message",
        ));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
        std::ptr::write(libc::CMSG_DATA(header).cast(), descriptor);
    }

    let sent = unsafe { libc::sendmsg(control.as_raw_fd(), &message, 0) };
    if sent != 1 {
        let error = if sent < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!("protect_path sent {sent} bytes instead of 1"),
            )
        };
        return Err(io::Error::new(
            error.kind(),
            format!("send socket to protect path {protect_path}: {error}"),
        ));
    }

    let mut acknowledgement = [0_u8; 1];
    control.read_exact(&mut acknowledgement).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "read protect acknowledgement from {protect_path}: {error}"
            ),
        )
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn connect_protect_path(
    protect_path: &str,
) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::net::{SocketAddr, UnixStream};

    let path = protect_path.as_bytes();
    if path.first().is_some_and(|byte| *byte == b'@' || *byte == 0) {
        #[cfg(target_os = "android")]
        use std::os::android::net::SocketAddrExt as _;
        #[cfg(target_os = "linux")]
        use std::os::linux::net::SocketAddrExt as _;

        let address = SocketAddr::from_abstract_name(&path[1..])?;
        UnixStream::connect_addr(&address)
    } else {
        UnixStream::connect(protect_path)
    }
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "linux"))))]
fn connect_protect_path(
    protect_path: &str,
) -> io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(protect_path)
}

#[cfg(not(unix))]
fn apply_protect_path(
    _socket: &SockRef<'_>,
    protect_path: &str,
) -> io::Result<()> {
    if protect_path.is_empty() {
        Ok(())
    } else {
        Err(unsupported(
            "protect_path requires Unix file-descriptor passing",
        ))
    }
}

fn apply_bind_interface(
    socket: &SockRef<'_>,
    remote: SocketAddr,
    interface: &str,
) -> io::Result<()> {
    if interface.is_empty() {
        return Ok(());
    }
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    {
        let name = std::ffi::CString::new(interface).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name contains NUL",
            )
        })?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        let index = NonZeroU32::new(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("network interface not found: {interface}"),
            )
        })?;
        if remote.is_ipv4() {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;

        use network_interface::{
            NetworkInterface, NetworkInterfaceConfig as _,
        };
        use windows_sys::Win32::Networking::WinSock::{
            SOCKET_ERROR, WSAGetLastError, setsockopt,
        };

        let index = NetworkInterface::show()
            .map_err(io::Error::other)?
            .into_iter()
            .find(|candidate| candidate.name == interface)
            .and_then(|candidate| NonZeroU32::new(candidate.index))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("network interface not found: {interface}"),
                )
            })?;
        let (level, option, value) =
            windows_interface_option(remote.is_ipv4(), index.get());
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                level,
                option,
                (&value as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(unsafe {
                WSAGetLastError()
            }));
        }
        Ok(())
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        windows
    )))]
    {
        let _ = (socket, remote);
        Err(unsupported(
            "binding an outbound socket to an interface is unsupported on this platform",
        ))
    }
}

#[cfg(any(windows, test))]
fn windows_interface_option(ipv4: bool, index: u32) -> (i32, i32, u32) {
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    }
}

fn apply_routing_mark(socket: &SockRef<'_>, mark: u32) -> io::Result<()> {
    if mark == 0 {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        socket.set_mark(mark)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = socket;
        Err(unsupported(
            "routing_mark is only supported on Linux and Android",
        ))
    }
}

fn apply_bind_address_no_port(
    socket: &SockRef<'_>,
    remote: SocketAddr,
    enabled: bool,
) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _ = remote;
        use std::os::fd::AsRawFd as _;
        let value: libc::c_int = 1;
        // Linux exposes this option at SOL_IP for both IPv4 and IPv6
        // sockets, matching sing/common's BindAddressNoPort control.
        let (level, name) = (libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT);
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                std::ptr::from_ref(&value).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (socket, remote);
        Err(unsupported(
            "bind_address_no_port is only supported on Linux and Android",
        ))
    }
}

fn apply_tcp_fast_open(socket: &SockRef<'_>, enabled: bool) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd as _;
        set_integer_option(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            1,
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = socket;
        Err(unsupported(
            "client TCP Fast Open is unsupported on this platform",
        ))
    }
}

fn apply_tcp_fast_open_listener(
    socket: &SockRef<'_>,
    enabled: bool,
) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd as _;
        set_integer_option(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            1024,
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = socket;
        Ok(())
    }
}

fn apply_tcp_fast_open_listener_post_listen(
    socket: &SockRef<'_>,
    enabled: bool,
) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    {
        use std::os::fd::AsRawFd as _;
        set_integer_option(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            1,
        )
    }
    #[cfg(not(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    )))]
    {
        let _ = socket;
        Ok(())
    }
}

fn apply_udp_fragmentation(
    socket: &SockRef<'_>,
    remote: SocketAddr,
    enabled: Option<bool>,
) -> io::Result<()> {
    let Some(enabled) = enabled else {
        return Ok(());
    };
    // Fragmentation is the operating-system default. Upstream only installs a
    // socket control callback when fragmentation has been disabled.
    if enabled {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd as _;
        let (level, name, value) = if remote.is_ipv4() {
            (
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            )
        } else {
            (
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_DO,
            )
        };
        set_integer_option(socket.as_raw_fd(), level, name, value)
    }
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd as _;
        let (level, name) = if remote.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_DONTFRAG)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
        };
        match set_integer_option(socket.as_raw_fd(), level, name, 1) {
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    code == libc::ENOPROTOOPT || code == libc::EOPNOTSUPP
                }) =>
            {
                Ok(())
            }
            result => result,
        }
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos"
    )))]
    {
        let _ = (socket, remote, enabled);
        Err(unsupported(
            "explicit UDP fragmentation control is unsupported on this platform",
        ))
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
fn set_integer_option(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use socket2::{Domain, Protocol, SockRef, Socket, Type};
    use tokio::net::TcpSocket;

    use super::{
        apply_tcp_dialer_options, apply_udp_dialer_options, bind_tcp_listener,
        windows_interface_option,
    };
    use crate::option::{AbstractDialerOptions, Addr, ListenOptions};

    const REMOTE: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

    #[test]
    fn windows_interface_binding_matches_sing_network_byte_order() {
        assert_eq!(
            windows_interface_option(true, 0x0102_0304),
            (0, 31, 0x0102_0304_u32.to_be())
        );
        assert_eq!(
            windows_interface_option(false, 0x0102_0304),
            (41, 31, 0x0102_0304)
        );
    }

    #[tokio::test]
    async fn applies_default_and_disabled_tcp_keepalive() {
        let socket = TcpSocket::new_v4().unwrap();
        apply_tcp_dialer_options(
            &socket,
            REMOTE,
            &AbstractDialerOptions::default(),
        )
        .unwrap();
        assert!(SockRef::from(&socket).keepalive().unwrap());

        let socket = TcpSocket::new_v4().unwrap();
        let options = AbstractDialerOptions {
            disable_tcp_keep_alive: true,
            ..Default::default()
        };
        apply_tcp_dialer_options(&socket, REMOTE, &options).unwrap();
        assert!(!SockRef::from(&socket).keepalive().unwrap());
    }

    #[test]
    fn applies_udp_reuse_address() {
        let socket =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .unwrap();
        let options = AbstractDialerOptions {
            reuse_addr: true,
            ..Default::default()
        };
        apply_udp_dialer_options(&socket, REMOTE, &options).unwrap();
        assert!(socket.reuse_address().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn passes_socket_descriptor_to_protect_path() {
        use std::{
            io::Write as _, os::fd::AsRawFd as _, os::unix::net::UnixListener,
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("protect.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0_u8; 1];
            let mut iovec = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: byte.len(),
            };
            let control_length = unsafe {
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _)
                    as usize
            };
            let mut ancillary = vec![0_u8; control_length];
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = std::ptr::from_mut(&mut iovec);
            message.msg_iovlen = 1;
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = ancillary.len() as _;

            assert_eq!(
                unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) },
                1
            );
            let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            assert!(!header.is_null());
            assert_eq!(unsafe { (*header).cmsg_level }, libc::SOL_SOCKET);
            assert_eq!(unsafe { (*header).cmsg_type }, libc::SCM_RIGHTS);
            let descriptor = unsafe {
                std::ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>())
            };
            assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
            assert_eq!(unsafe { libc::close(descriptor) }, 0);
            stream.write_all(&[1]).unwrap();
        });

        let socket = TcpSocket::new_v4().unwrap();
        let options = AbstractDialerOptions {
            protect_path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        apply_tcp_dialer_options(&socket, REMOTE, &options).unwrap();
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reports_missing_protect_path() {
        let socket = TcpSocket::new_v4().unwrap();
        let options = AbstractDialerOptions {
            protect_path: "/definitely/missing/sing-box-protect.sock".into(),
            ..Default::default()
        };
        let error =
            apply_tcp_dialer_options(&socket, REMOTE, &options).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("connect protect path"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn rejects_unported_network_namespace() {
        let socket = TcpSocket::new_v4().unwrap();
        let options = AbstractDialerOptions {
            netns: "isolated".into(),
            ..Default::default()
        };
        let error =
            apply_tcp_dialer_options(&socket, REMOTE, &options).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("network namespaces"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn missing_network_namespace_fails_before_socket_creation() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let called = Arc::new(AtomicBool::new(false));
        let operation_called = called.clone();
        let error = super::with_network_namespace(
            "/definitely/missing/sing-box-test-netns",
            move || {
                operation_called.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!called.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn listener_applies_multipath_with_tcp_fallback() {
        let options = ListenOptions {
            listen: Some(Addr(Ipv4Addr::LOCALHOST.into())),
            reuse_addr: true,
            tcp_multi_path: true,
            ..Default::default()
        };
        let listener = bind_tcp_listener(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            &options,
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address);
        let (accepted, connected) = tokio::join!(listener.accept(), client);
        accepted.unwrap();
        connected.unwrap();
    }
}
