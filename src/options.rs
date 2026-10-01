/// Options for `zay x run proxy`.
#[derive(clap::Args, Debug, Default)]
pub struct ProxyOpts {
    /// Remote proxy subscription URL (repeatable)
    #[clap(
        short = 's',
        long = "proxy",
        value_name = "URL",
        action = clap::ArgAction::Append
    )]
    pub subscriptions: Vec<String>,

    /// Internal persistent-service data directory.
    #[clap(skip)]
    pub data_dir: Option<std::path::PathBuf>,

    /// Internal persistent-service configuration path.
    #[clap(skip)]
    pub config: Option<std::path::PathBuf>,

    /// Local HTTP/SOCKS proxy port (default: 7890)
    #[clap(long, value_name = "PORT")]
    pub mixed_port: Option<u16>,

    /// Subscription provider update interval in seconds (default: 3600)
    #[clap(long, value_name = "SECS")]
    pub update_interval: Option<u64>,

    /// URL used for provider health checks
    #[clap(long, value_name = "URL")]
    pub health_check_url: Option<String>,

    /// Log level: debug, info, warning, error (default: info)
    #[clap(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Disable system TUN (default: TUN on for `zay x run proxy`)
    #[clap(long = "no-tun", action = clap::ArgAction::SetTrue)]
    pub no_tun: bool,

    /// Extra CIDR excluded from proxy TUN auto-route (repeatable; mesh/SSH excludes are automatic)
    #[clap(long = "tun-exclude", value_name = "CIDR", action = clap::ArgAction::Append)]
    pub tun_exclude_routes: Vec<String>,

    /// Internal persistent-service bootstrap proxy configuration.
    #[clap(skip)]
    pub bootstrap_proxy: Option<std::path::PathBuf>,
}
