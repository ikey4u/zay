use std::{borrow::Cow, path::PathBuf};

use ely_gpui_component::{
    data_display::{Badge, Tone},
    theme::{Mode as ElyMode, Theme as ElyTheme},
};
use gpui_kit::{
    base::{Disableable, Selectable},
    component::{
        ActiveTheme, Theme, ThemeMode,
        button::*,
        input::{Input, InputState},
        switch::Switch,
    },
    *,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{
        Menu as TrayMenu, MenuEvent, MenuItem as TrayItem, PredefinedMenuItem,
    },
};
use zay::settings::{MeshConfig, MeshRole, PersistentProxyFile};

use crate::backend::{self, Command, Update};

gpui_kit::actions!(
    zay_desktop,
    [
        ShowWindow,
        Preferences,
        Hide,
        Quit,
        CloseWindow,
        StartServices,
        StopServices
    ]
);
/// Both libraries load icons through the one GPUI application asset source.
struct Assets;
impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = gpui_kit::assets::Assets.load(path)? {
            return Ok(Some(bytes));
        }
        ely_gpui_component::Assets.load(path)
    }
    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(ely_gpui_component::Assets.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Proxy,
    Mesh,
    Preferences,
}

struct Fields {
    port: Entity<InputState>,
    subscriptions: Entity<InputState>,
    network: Entity<InputState>,
    secret: Entity<InputState>,
    peers: Entity<InputState>,
    address: Entity<InputState>,
    password: Entity<InputState>,
}
struct Desktop {
    page: Page,
    fields: Fields,
    config: PersistentProxyFile,
    loaded: bool,
    dark: bool,
}
struct Session {
    window: Option<AnyWindowHandle>,
    view: Option<Entity<Desktop>>,
    _tray: TrayIcon,
    sender: async_channel::Sender<Command>,
    snapshot: Option<Update>,
    busy: bool,
    quitting: bool,
    error: Option<String>,
    dark: bool,
    data_dir: PathBuf,
}
impl Global for Session {}

fn input(
    value: &str,
    secret: bool,
    window: &mut Window,
    cx: &mut App,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .default_value(value.to_owned())
            .masked(secret)
    })
}

fn open_page(page: Page, cx: &mut App) {
    if let Some(handle) = cx.global::<Session>().window {
        if handle
            .update(cx, |_, window, cx| {
                if let Some(view) = cx.global::<Session>().view.clone() {
                    view.update(cx, |view, cx| {
                        view.page = page;
                        cx.notify();
                    });
                }
                window.activate_window();
            })
            .is_ok()
        {
            cx.activate(true);
            return;
        }
    }
    let dark = cx.global::<Session>().dark;
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(1100.), px(780.)),
            cx,
        ))),
        window_min_size: Some(size(px(860.), px(620.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Zay".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    match gpui_kit::open_window(options, cx, |window, cx| {
        let fields = Fields {
            port: input("7890", false, window, cx),
            subscriptions: input("", false, window, cx),
            network: input("", false, window, cx),
            secret: input("", true, window, cx),
            peers: input("", false, window, cx),
            address: input("", false, window, cx),
            password: input("", true, window, cx),
        };
        cx.new(|_| Desktop {
            page,
            fields,
            config: PersistentProxyFile::default(),
            loaded: false,
            dark,
        })
    }) {
        Ok((window, view)) => {
            let session = cx.global_mut::<Session>();
            session.window = Some(window);
            session.view = Some(view);
            cx.activate(true);
        }
        Err(e) => eprintln!("Cannot open Zay: {e:#}"),
    }
}

fn send(command: Command, cx: &mut App) {
    let state = cx.global_mut::<Session>();
    if state.busy {
        return;
    }
    state.busy = true;
    state.error = None;
    if state.sender.try_send(command).is_err() {
        state.busy = false;
        state.error = Some(
            "The networking worker is unavailable. Quit and reopen Zay.".into(),
        );
    }
    if let Some(view) = state.view.clone() {
        // A button listener may already be updating this entity.
        cx.notify(view.entity_id());
    }
}

fn start_services(cx: &mut App) {
    let session = cx.global::<Session>();
    if session.busy
        || session.quitting
        || session.snapshot.as_ref().is_some_and(|s| s.running)
    {
        return;
    }
    open_page(Page::Proxy, cx);
    if let Some(window) = cx.global::<Session>().window {
        let _ = window.update(cx, |_, window, cx| {
            if let Some(view) = cx.global::<Session>().view.clone() {
                view.update(cx, |view, cx| {
                    view.load_fields(window, cx);
                    if view.loaded {
                        view.submit(true, window, cx);
                    }
                });
            }
        });
    }
}
fn quit(cx: &mut App) {
    let state = cx.global_mut::<Session>();
    if state.quitting {
        return;
    }
    state.quitting = true;
    state.busy = true;
    if state.sender.try_send(Command::Shutdown).is_err() {
        cx.quit();
    }
}

impl Desktop {
    fn load_fields(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.loaded {
            return;
        }
        let Some(config) = cx
            .global::<Session>()
            .snapshot
            .as_ref()
            .and_then(|s| s.config.clone())
        else {
            return;
        };
        let mesh = config.mesh.as_ref();
        for (field, value) in [
            (
                &self.fields.port,
                config.mixed_port.unwrap_or(7890).to_string(),
            ),
            (&self.fields.subscriptions, config.subscriptions.join(" ")),
            (
                &self.fields.network,
                mesh.map(|m| m.network_name.clone()).unwrap_or_default(),
            ),
            (
                &self.fields.secret,
                mesh.map(|m| m.network_secret.clone()).unwrap_or_default(),
            ),
            (
                &self.fields.peers,
                mesh.and_then(|m| m.peers.clone())
                    .unwrap_or_default()
                    .join(" "),
            ),
            (
                &self.fields.address,
                mesh.and_then(|m| m.ipv4.clone()).unwrap_or_default(),
            ),
        ] {
            field.update(cx, |s, cx| s.set_value(value, window, cx));
        }
        self.config = config;
        self.loaded = true;
    }
    fn read_config(&self, cx: &App) -> anyhow::Result<PersistentProxyFile> {
        let mut config = self.config.clone();
        let port =
            self.fields
                .port
                .read(cx)
                .value()
                .parse::<u16>()
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Proxy port must be a number from 1 to 65535."
                    )
                })?;
        anyhow::ensure!(
            port > 0,
            "Proxy port must be a number from 1 to 65535."
        );
        config.mixed_port = Some(port);
        config.subscriptions = self
            .fields
            .subscriptions
            .read(cx)
            .value()
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if let Some(mesh) = config.mesh.as_mut() {
            mesh.network_name =
                self.fields.network.read(cx).value().trim().to_string();
            mesh.network_secret =
                self.fields.secret.read(cx).value().to_string();
            mesh.peers = Some(
                self.fields
                    .peers
                    .read(cx)
                    .value()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
            );
            let address =
                self.fields.address.read(cx).value().trim().to_string();
            // Recompute automatically derived routes after changing the IP;
            // retain explicitly configured route lists.
            let derived_routes = mesh
                .ipv4
                .as_deref()
                .and_then(|ip| zay::settings::ipv4_network_cidr(ip).ok())
                .map(|route| vec![route]);
            if derived_routes.is_some() && mesh.mesh_routes == derived_routes {
                mesh.mesh_routes = None;
            }
            mesh.ipv4 = (!address.is_empty()).then_some(address);
            mesh.dhcp =
                Some(mesh.role == MeshRole::Node && mesh.ipv4.is_none());
            if mesh.role == MeshRole::Relay {
                mesh.peers = Some(vec![]);
                mesh.mesh_routes = None;
            }
            if mesh.enabled {
                anyhow::ensure!(
                    !mesh.network_name.is_empty()
                        && !mesh.network_secret.is_empty(),
                    "Mesh network name and secret are required."
                );
            }
        }
        Ok(config)
    }
    fn submit(
        &mut self,
        start: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let config = match self.read_config(cx) {
            Ok(c) => c,
            Err(e) => {
                cx.global_mut::<Session>().error = Some(e.to_string());
                cx.notify();
                return;
            }
        };
        let password = self.fields.password.read(cx).value().to_string();
        self.fields
            .password
            .update(cx, |s, cx| s.set_value("", window, cx));
        let password = (!password.is_empty()).then_some(password);
        self.config = config.clone();
        send(
            if start {
                Command::Start(Some(Box::new(config)), password)
            } else {
                Command::Save(Box::new(config), password)
            },
            cx,
        );
    }
    fn nav(
        &self,
        label: &'static str,
        page: Page,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        Button::new(label)
            .label(label)
            .ghost()
            .selected(self.page == page)
            .on_click(cx.listener(move |view, _, _, cx| {
                view.page = page;
                cx.notify();
            }))
    }
    fn field(label: &'static str, field: &Entity<InputState>) -> Div {
        div()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(label))
            .child(Input::new(field))
    }
    fn card(
        title: &'static str,
        body: impl Into<SharedString>,
        cx: &App,
    ) -> Div {
        div()
            .min_w_0()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .rounded_xl()
            .border_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(body.into()),
            )
    }
}
fn default_mesh() -> MeshConfig {
    serde_json::from_value(serde_json::json!({"enabled":false,"role":"node","network_name":"","network_secret":"","dhcp":true})).expect("default Mesh configuration")
}
impl Render for Desktop {
    fn render(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        self.load_fields(window, cx);
        let state = cx.global::<Session>();
        let busy = state.busy;
        let running = state.snapshot.as_ref().is_some_and(|s| s.running);
        let status = if state.quitting {
            "Stopping before exit…".into()
        } else if busy {
            "Applying changes…".into()
        } else {
            state
                .snapshot
                .as_ref()
                .map(|s| s.status.clone())
                .unwrap_or("Loading…".into())
        };
        let proxy_ready =
            state.snapshot.as_ref().is_some_and(|s| s.proxy_ready);
        let mesh = state
            .snapshot
            .as_ref()
            .map(|s| s.mesh.clone())
            .unwrap_or(serde_json::json!([]));
        let error = state.error.clone();
        let data_dir = state.data_dir.display().to_string();
        let muted = cx.theme().muted_foreground;
        let border = cx.theme().border;
        let foreground = cx.theme().foreground;
        let background = cx.theme().background;
        let side = div()
            .w(px(196.))
            .flex_shrink_0()
            .h_full()
            .p_5()
            .border_r_1()
            .border_color(border)
            .flex()
            .flex_col()
            .justify_between()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_6()
                    .child(
                        div()
                            .text_3xl()
                            .font_weight(FontWeight::BOLD)
                            .child("Zay"),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(self.nav("Overview", Page::Overview, cx))
                            .child(self.nav("Proxy", Page::Proxy, cx))
                            .child(self.nav("Mesh", Page::Mesh, cx))
                            .child(self.nav(
                                "Preferences",
                                Page::Preferences,
                                cx,
                            )),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_start()
                    .gap_2()
                    .child(
                        Badge::new(status.clone())
                            .tone(if error.is_some() {
                                Tone::Danger
                            } else if running {
                                Tone::Success
                            } else {
                                Tone::Neutral
                            })
                            .dot(),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(muted)
                            .child("Native networking"),
                    ),
            );
        let title = match self.page {
            Page::Overview => "Your network, within reach.",
            Page::Proxy => "Proxy",
            Page::Mesh => "Mesh network",
            Page::Preferences => "Preferences",
        };
        let mesh_enabled = self.config.mesh.as_ref().is_some_and(|m| m.enabled);
        let relay = self
            .config
            .mesh
            .as_ref()
            .is_some_and(|m| m.role == MeshRole::Relay);
        let content=match self.page {
            Page::Overview=>{
                let peers=mesh.as_array().map(|items|items.iter().filter_map(|m|m["connected_peers"].as_u64()).sum::<u64>()).unwrap_or(0);
                let mut view=div().flex().flex_col().gap_4()
                    .child(Self::card("Proxy",if proxy_ready {format!("Listening on 127.0.0.1:{} · HTTP and SOCKS5",self.config.mixed_port.unwrap_or(7890))} else {"Not running".into()},cx))
                    .child(Self::card("Mesh",format!("{} active instance(s) · {peers} connected peer(s)",mesh.as_array().map(Vec::len).unwrap_or(0)),cx));
                if let Some(instances)=mesh.as_array() {for instance in instances {if let Some(peers)=instance["peers"].as_array(){for peer in peers {
                    view=view.child(Self::card("Peer",format!("{} · {} · {}",peer["hostname"].as_str().unwrap_or("Unknown"),peer["virtual_ipv4"].as_str().unwrap_or("No address"),peer["path"].as_str().unwrap_or("Connecting")),cx));
                }}}}
                view.child(Self::card("Runs with you", "Closing this window keeps proxy and Mesh running. Reopen Zay from the menu bar. Quit stops the services owned by this desktop app.",cx))
            }
            Page::Proxy=>div().flex().flex_col().gap_5()
                .child(Switch::new("proxy-enabled").label("Enable proxy").checked(self.config.enabled).on_click(cx.listener(|v,on,_,cx|{v.config.enabled=*on;cx.notify();})))
                .child(Self::field("HTTP / SOCKS5 port",&self.fields.port))
                .child(Self::field("Subscription URLs (space-separated)",&self.fields.subscriptions))
                .child(div().text_sm().text_color(muted).child("Leave subscriptions empty for direct routing. Existing routing rules and advanced settings are preserved."))
                .child(Switch::new("tun-enabled").label("Route system traffic through TUN").checked(self.config.tun.enabled).on_click(cx.listener(|v,on,_,cx|{v.config.tun.enabled=*on;cx.notify();})))
                .child(div().text_sm().text_color(muted).child("TUN requires administrator authorization. With TUN off, configure applications to use the local proxy port.")),
            Page::Mesh=>div().flex().flex_col().gap_5()
                .child(Switch::new("mesh-enabled").label("Enable Mesh").checked(mesh_enabled).on_click(cx.listener(|v,on,_,cx|{v.config.mesh.get_or_insert_with(default_mesh).enabled=*on;cx.notify();})))
                .child(div().flex().gap_3().child(Button::new("node").label("Node").selected(!relay).on_click(cx.listener(|v,_,_,cx|{v.config.mesh.get_or_insert_with(default_mesh).role=MeshRole::Node;cx.notify();}))).child(Button::new("relay").label("Relay").selected(relay).on_click(cx.listener(|v,_,_,cx|{v.config.mesh.get_or_insert_with(default_mesh).role=MeshRole::Relay;cx.notify();}))))
                .child(Self::field("Network name",&self.fields.network))
                .child(Self::field("Network secret",&self.fields.secret))
                .child(Self::field("Peer URLs (space-separated)",&self.fields.peers))
                .child(Self::field("Virtual IPv4 / prefix (empty for DHCP)",&self.fields.address))
                .child(div().text_sm().text_color(muted).child("Nodes join the virtual network and require administrator authorization. Relays connect peers without a local Mesh TUN.")),
            Page::Preferences=>div().flex().flex_col().gap_5()
                .child(Self::card("Appearance","Choose an appearance for this session.",cx).child(div().flex().gap_3().child(Button::new("light").label("Light").selected(!self.dark).on_click(cx.listener(|v,_,w,cx|{v.dark=false;set_dark(false,w,cx);cx.notify();}))).child(Button::new("dark").label("Dark").selected(self.dark).on_click(cx.listener(|v,_,w,cx|{v.dark=true;set_dark(true,w,cx);cx.notify();})))))
                .child(Self::card("Configuration",format!("{data_dir}/zay.toml\nDesktop configuration is separate from the CLI. Advanced Zay routing settings can also be edited in this file while services are stopped; reopen the app to reload the forms."),cx))
                .child(Self::card("Zay Desktop 0.1.0","GPUI Kit + Ely components, powered directly by the Zay Rust library. Proxy and Mesh run without a browser or WebUI server.",cx)),
        };
        let mut main = div()
            .id("main")
            .min_w_0()
            .flex_1()
            .h_full()
            .overflow_y_scroll()
            .p_8()
            .flex()
            .flex_col()
            .gap_6()
            .child(
                div()
                    .text_xs()
                    .text_color(muted)
                    .child("ZAY DESKTOP / MACOS"),
            )
            .child(div().text_3xl().font_weight(FontWeight::BOLD).child(title))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(
                        Button::new("start")
                            .primary()
                            .label(if running {
                                "Running"
                            } else {
                                "Start services"
                            })
                            .disabled(busy || running || !self.loaded)
                            .on_click(
                                cx.listener(|v, _, w, cx| {
                                    v.submit(true, w, cx)
                                }),
                            ),
                    )
                    .child(
                        Button::new("stop")
                            .outline()
                            .label("Stop services")
                            .disabled(busy || !running)
                            .on_click(|_, _, cx| send(Command::Stop, cx)),
                    )
                    .child(
                        Button::new("save")
                            .outline()
                            .label("Save and apply")
                            .disabled(busy || !self.loaded)
                            .on_click(cx.listener(|v, _, w, cx| {
                                v.submit(false, w, cx)
                            })),
                    ),
            )
            .child(content);
        if matches!(self.page, Page::Proxy | Page::Mesh) {
            main=main.child(Self::field("Administrator password (only for TUN / Mesh node)",&self.fields.password)).child(div().text_xs().text_color(muted).child("Used once to authorize the Zay worker. Never written to configuration. Authorization lasts for this desktop session."));
        }
        if let Some(error) = error {
            main = main.child(
                div()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(0x51282b))
                    .text_color(rgb(0xffdddd))
                    .child(error),
            );
        }
        div()
            .size_full()
            .flex()
            .whitespace_normal()
            .bg(background)
            .text_color(foreground)
            .child(side)
            .child(main)
    }
}
fn set_dark(dark: bool, window: &mut Window, cx: &mut App) {
    Theme::change(
        if dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        },
        Some(window),
        cx,
    );
    ElyTheme::set_mode_now(
        if dark { ElyMode::Dark } else { ElyMode::Light },
        cx,
    );
    cx.global_mut::<Session>().dark = dark;
}

pub fn run() {
    let application = gpui_kit::application()
        .with_assets(Assets)
        .with_quit_mode(QuitMode::Explicit);
    application.on_reopen(|cx| open_page(Page::Overview, cx));
    application.run(|cx| {
        ely_gpui_component::init(cx);
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Light, None, cx);
        ElyTheme::set_mode_now(ElyMode::Light, cx);
        let menu = TrayMenu::new();
        let show = TrayItem::new("Open Zay", true, None);
        let start = TrayItem::new("Start services", true, None);
        let stop = TrayItem::new("Stop services", true, None);
        let preferences = TrayItem::new("Preferences…", true, None);
        let quit_item = TrayItem::new("Quit Zay", true, None);
        menu.append_items(&[
            &show,
            &start,
            &stop,
            &preferences,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ])
        .expect("create menu");
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_title("Zay")
            .with_tooltip("Zay · Proxy and Mesh")
            .build()
            .expect("create menu-bar item");
        let data_dir = std::env::var_os("ZAY_DESKTOP_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(
                    std::env::var_os("HOME").expect("HOME is required"),
                )
                .join("Library/Application Support/Zay Desktop")
            });
        let (sender, events, stopped) = backend::launch(data_dir.clone());
        cx.set_global(Session {
            window: None,
            view: None,
            _tray: tray,
            sender,
            snapshot: None,
            busy: false,
            quitting: false,
            error: None,
            dark: false,
            data_dir,
        });
        cx.on_action(|_: &ShowWindow, cx| open_page(Page::Overview, cx));
        cx.on_action(|_: &Preferences, cx| open_page(Page::Preferences, cx));
        // Native menu actions can run while their window is being updated.
        // Access the form after dispatch releases that window.
        cx.on_action(|_: &StartServices, cx| cx.defer(start_services));
        cx.on_action(|_: &StopServices, cx| send(Command::Stop, cx));
        cx.on_action(|_: &Hide, cx| cx.hide());
        cx.on_action(|_: &Quit, cx| quit(cx));
        cx.on_action(|_: &CloseWindow, cx| {
            if let Some(w) = cx.global::<Session>().window {
                let _ = w.update(cx, |_, w, _| w.remove_window());
            }
        });
        cx.bind_keys([
            KeyBinding::new("cmd-q", Quit, None),
            KeyBinding::new("cmd-h", Hide, None),
            KeyBinding::new("cmd-w", CloseWindow, None),
            KeyBinding::new("cmd-,", Preferences, None),
            KeyBinding::new("cmd-1", ShowWindow, None),
        ]);
        cx.set_menus([
            Menu::new("Zay").items([
                MenuItem::action("Preferences…", Preferences),
                MenuItem::separator(),
                MenuItem::action("Hide Zay", Hide),
                MenuItem::action("Quit Zay", Quit),
            ]),
            Menu::new("Window").items([
                MenuItem::action("Open Zay", ShowWindow),
                MenuItem::action("Close Window", CloseWindow),
            ]),
            Menu::new("Network").items([
                MenuItem::action("Start services", StartServices),
                MenuItem::action("Stop services", StopServices),
            ]),
        ]);
        let (tx, rx) = async_channel::unbounded();
        MenuEvent::set_event_handler(Some(move |e| {
            let _ = tx.try_send(e);
        }));
        cx.spawn(async move |cx| {
            while let Ok(event) = rx.recv().await {
                let _ = cx.update(|cx| {
                    if event.id == show.id() {
                        open_page(Page::Overview, cx);
                    } else if event.id == preferences.id() {
                        open_page(Page::Preferences, cx);
                    } else if event.id == start.id() {
                        start_services(cx);
                    } else if event.id == stop.id() {
                        send(Command::Stop, cx);
                    } else if event.id == quit_item.id() {
                        quit(cx);
                    }
                });
            }
        })
        .detach();
        cx.spawn(async move |cx| {
            while let Ok(update) = events.recv().await {
                let done = update.quit;
                let _ = cx.update(|cx| {
                    let state = cx.global_mut::<Session>();
                    if update.finished {
                        state.busy = false;
                        state.error = update.error.clone();
                    } else if update.error.is_some() {
                        state.error = update.error.clone();
                    }
                    state.snapshot = Some(update);
                    if let Some(view) = state.view.clone() {
                        view.update(cx, |_, cx| cx.notify());
                    }
                    if done {
                        cx.quit();
                    }
                });
            }
        })
        .detach();
        cx.on_app_quit(move |cx| {
            let sender = cx.global::<Session>().sender.clone();
            let _ = sender.try_send(Command::Shutdown);
            // GPUI gives async quit observers only 200ms. Native termination
            // must wait here for the independent networking thread instead.
            // Bound the wait in case a networking operation never completes.
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                stopped.recv_timeout(std::time::Duration::from_secs(60))
            {
                eprintln!("Timed out waiting for networking shutdown");
            }
            async {}
        })
        .detach();
        open_page(Page::Overview, cx);
    });
}
