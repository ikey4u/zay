use std::{borrow::Cow, path::PathBuf};

use ely_gpui_component::theme::{Mode as ElyMode, Theme as ElyTheme};
use gpui_kit::{
    assets::IconName,
    base::{Disableable, Selectable},
    component::{
        ActiveTheme, Icon, Theme, ThemeMode, TitleBar,
        button::*,
        checkbox::Checkbox,
        input::{Input, InputEvent, InputState},
        menu::{ContextMenuExt, DropdownMenu, PopupMenuItem},
        popover::Popover,
        switch::Switch,
    },
    prelude::FluentBuilder,
    *,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{
        Menu as TrayMenu, MenuEvent, MenuItem as TrayItem, PredefinedMenuItem,
    },
};
use zay::settings::{MeshConfig, MeshRole, PersistentProxyFile};

use crate::backend::{self, Command, Service, ServiceAction, Update};

gpui_kit::actions!(
    zay_desktop,
    [ShowWindow, Preferences, Hide, Quit, CloseWindow]
);
/// Both libraries load icons through the one GPUI application asset source.
struct Assets;
impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = gpui_kit::assets::AllAssets.load(path)? {
            return Ok(Some(bytes));
        }
        ely_gpui_component::Assets.load(path)
    }
    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::AllAssets.list(path)?;
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
    Rules,
    Logs,
}

struct Fields {
    port: Entity<InputState>,
    subscriptions: Entity<InputState>,
    network: Entity<InputState>,
    secret: Entity<InputState>,
    peers: Entity<InputState>,
    address: Entity<InputState>,
    search: Entity<InputState>,
    connection_search: Entity<InputState>,
    application_search: Entity<InputState>,
    log_search: Entity<InputState>,
    listeners: Entity<InputState>,
    rule_name: Entity<InputState>,
    rule_match: Entity<InputState>,
    route_target: Entity<InputState>,
}
struct Desktop {
    page: Page,
    fields: Fields,
    config: PersistentProxyFile,
    loaded: bool,
    dark: bool,
    rule_kind: usize,
    rule_target: String,
    editing_rule: Option<String>,
    connection_activity: usize,
    connection_protocol: usize,
    application_sort: usize,
    confirm_usage_reset: bool,
    log_level: usize,
    selected_subscription: Option<usize>,
    adding_subscription: bool,
    mesh_draft: MeshConfig,
    mesh_test: Option<String>,
    route_test: Option<zay::desktop::RouteTest>,
    _subscriptions: Vec<Subscription>,
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
        ..TitleBar::window_options()
    };
    match gpui_kit::open_window(options, cx, |window, cx| {
        let fields = Fields {
            port: input("7890", false, window, cx),
            subscriptions: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("https://example.com/subscription")
            }),
            network: cx.new(|cx| {
                InputState::new(window, cx).placeholder("Network name")
            }),
            secret: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Shared secret")
                    .masked(true)
            }),
            peers: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("tcp://relay.example.com:11010")
            }),
            address: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Automatic, or 10.10.0.2/24")
            }),
            listeners: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("tcp://0.0.0.0:11010 udp://0.0.0.0:11010")
            }),
            log_search: cx.new(|cx| {
                InputState::new(window, cx).placeholder("Search logs…")
            }),
            search: cx.new(|cx| {
                InputState::new(window, cx).placeholder("Search proxies…")
            }),
            application_search: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Search applications...")
            }),
            connection_search: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Search host, IP, process or route…")
            }),
            route_target: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("URL, domain or IP address")
            }),
            rule_name: cx
                .new(|cx| InputState::new(window, cx).placeholder("Rule name")),
            rule_match: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Matches, separated by spaces")
            }),
        };
        cx.new(|cx| {
            let mut subscriptions = vec![cx.subscribe_in(
                &fields.port,
                window,
                |view: &mut Desktop, _, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        view.submit(false, window, cx);
                    }
                },
            )];
            subscriptions.push(cx.subscribe_in(
                &fields.subscriptions,
                window,
                |view: &mut Desktop, _, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        view.add_subscription(window, cx);
                    }
                },
            ));
            for field in [
                &fields.network,
                &fields.secret,
                &fields.peers,
                &fields.address,
                &fields.listeners,
            ] {
                subscriptions.push(cx.subscribe_in(
                    field,
                    window,
                    |view: &mut Desktop, _, _: &InputEvent, _, cx| {
                        view.mesh_test = None;
                        cx.notify();
                    },
                ));
            }
            subscriptions.push(cx.subscribe_in(
                &fields.log_search,
                window,
                |_: &mut Desktop, _, _: &InputEvent, _, cx| cx.notify(),
            ));
            subscriptions.push(cx.subscribe_in(
                &fields.search,
                window,
                |_: &mut Desktop, _, _: &InputEvent, _, cx| cx.notify(),
            ));
            subscriptions.push(cx.subscribe_in(
                &fields.application_search,
                window,
                |_: &mut Desktop, _, _: &InputEvent, _, cx| cx.notify(),
            ));
            subscriptions.push(cx.subscribe_in(
                &fields.connection_search,
                window,
                |_: &mut Desktop, _, _: &InputEvent, _, cx| cx.notify(),
            ));
            subscriptions.push(cx.subscribe_in(
                &fields.route_target,
                window,
                |view: &mut Desktop, _, event: &InputEvent, _, cx| match event {
                    InputEvent::PressEnter { .. } => view.test_route(cx),
                    InputEvent::Change => {
                        view.route_test = None;
                        cx.notify();
                    }
                    _ => {}
                },
            ));
            for field in [&fields.rule_name, &fields.rule_match] {
                subscriptions.push(cx.subscribe_in(
                    field,
                    window,
                    |view: &mut Desktop, _, event: &InputEvent, window, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            view.commit_rule(window, cx);
                        }
                    },
                ));
            }
            Desktop {
                rule_kind: 0,
                rule_target: "Proxy".into(),
                editing_rule: None,
                connection_activity: 0,
                connection_protocol: 0,
                application_sort: 0,
                confirm_usage_reset: false,
                log_level: 0,
                selected_subscription: None,
                adding_subscription: false,
                mesh_draft: default_mesh(),
                mesh_test: None,
                route_test: None,
                page,
                fields,
                config: PersistentProxyFile::default(),
                loaded: false,
                dark,
                _subscriptions: subscriptions,
            }
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
            (
                &self.fields.listeners,
                mesh.and_then(|m| m.listeners.clone())
                    .unwrap_or_default()
                    .join(" "),
            ),
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
        self.mesh_draft = config.mesh.clone().unwrap_or_else(default_mesh);
        self.mesh_draft.enabled |= config.mesh_paused;
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
        Ok(config)
    }
    fn read_mesh_config(
        &self,
        cx: &App,
    ) -> anyhow::Result<PersistentProxyFile> {
        let mut config = self.config.clone();
        config.mesh = Some(self.mesh_draft.clone());
        if let Some(mesh) = config.mesh.as_mut() {
            mesh.listeners = Some(
                self.fields
                    .listeners
                    .read(cx)
                    .value()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
            );
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
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if !self.loaded || cx.global::<Session>().busy {
            return false;
        }
        let config = match self.read_config(cx) {
            Ok(c) => c,
            Err(e) => {
                cx.global_mut::<Session>().error = Some(e.to_string());
                cx.notify();
                return false;
            }
        };
        self.config = config.clone();
        send(
            if start {
                Command::Start(Some(Box::new(config)))
            } else {
                Command::Save(Box::new(config))
            },
            cx,
        );
        true
    }
    fn change_option(
        &mut self,
        enable: bool,
        change: impl FnOnce(&mut PersistentProxyFile),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.loaded || cx.global::<Session>().busy {
            return;
        }
        let previous = self.config.clone();
        change(&mut self.config);
        if self.config.enabled {
            self.config.paused = false;
        }
        if self.config.mesh.as_ref().is_some_and(|m| m.enabled) {
            self.config.mesh_paused = false;
        }
        let running = cx
            .global::<Session>()
            .snapshot
            .as_ref()
            .is_some_and(|s| s.running);
        if !self.submit(enable && !running, window, cx) {
            self.config = previous;
        }
        cx.notify();
    }
    fn proxy_list(&self, cx: &Context<Self>) -> Div {
        let state = cx.global::<Session>();
        let snapshot = state.snapshot.as_ref();
        let nodes = snapshot.map(|s| s.proxies.as_slice()).unwrap_or_default();
        let selected = snapshot
            .and_then(|s| s.config.as_ref())
            .map(|c| c.active_nodes.clone())
            .unwrap_or_default();
        let disabled = state.busy || !self.loaded;
        let query = self.fields.search.read(cx).value().to_lowercase();
        let nodes: Vec<_> = nodes
            .iter()
            .filter(|node| {
                self.selected_subscription.is_none_or(|index| {
                    node.id.starts_with(&format!("sub{index}-"))
                })
            })
            .collect();
        let mut list = Self::section("Proxies", "Check one proxy to pin it. Check several to use the fastest available. Automatic uses every node.", cx)
            .child(div().flex().items_center().gap_3()
                .child(div().flex_1().child(Input::new(&self.fields.search).aria_label("Search proxies")))
                .child(Button::new("refresh-proxies").label("Refresh").icon(IconName::RefreshCw).outline().disabled(disabled || self.config.subscriptions.is_empty())
                    .on_click(|_, _, cx| send(Command::RefreshProxies, cx))))
            .child(div().flex().items_center().justify_between()
                .child(Checkbox::new("proxy-auto").label("Automatic · all proxies").checked(selected.is_empty()).disabled(disabled)
                    .on_click(|_, _, cx| send(Command::SelectProxies(vec![]), cx)))
                .child(Self::hint(format!("{} nodes · {} selected", nodes.len(), selected.len()), cx)));
        if nodes.is_empty() {
            return list.child(div().py_4().child(Self::hint(
                if self.config.subscriptions.is_empty() {
                    "Add a subscription to find your proxies."
                } else {
                    "No nodes fetched. Refresh the subscription to try again."
                },
                cx,
            )));
        }
        for node in nodes.iter().filter(|node| {
            query.is_empty()
                || node.name.to_lowercase().contains(&query)
                || node.protocol.contains(&query)
        }) {
            let id = node.id.clone();
            let checked = selected.contains(&id);
            let mut next = selected.clone();
            if checked {
                next.retain(|tag| tag != &id);
            } else {
                next.push(id.clone());
            }
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .py_3()
                    .px_3()
                    .rounded_md()
                    .bg(if checked {
                        cx.theme().accent
                    } else {
                        cx.theme().background
                    })
                    .child(
                        Checkbox::new(SharedString::from(format!("node-{id}")))
                            .label(node.name.clone())
                            .checked(checked)
                            .disabled(disabled)
                            .on_click(move |_, _, cx| {
                                send(Command::SelectProxies(next.clone()), cx)
                            }),
                    )
                    .child(div().flex_1())
                    .child(Self::hint(node.protocol.to_uppercase(), cx)),
            );
        }
        list
    }

    fn add_subscription(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let url = self.fields.subscriptions.read(cx).value().trim().to_owned();
        match url::Url::parse(&url) {
            Ok(parsed)
                if matches!(parsed.scheme(), "http" | "https")
                    && parsed.host_str().is_some() => {}
            _ => {
                cx.global_mut::<Session>().error = Some(
                    "Enter a valid HTTP or HTTPS subscription URL.".into(),
                );
                cx.notify();
                return;
            }
        }
        if self.config.subscriptions.contains(&url) {
            cx.global_mut::<Session>().error =
                Some("This subscription is already added.".into());
            cx.notify();
            return;
        }
        self.selected_subscription = Some(self.config.subscriptions.len());
        send(Command::AddSubscription(url), cx);
        self.adding_subscription = false;
        self.fields
            .subscriptions
            .update(cx, |s, cx| s.set_value("", window, cx));
    }

    fn subscription_cards(&self, cx: &Context<Self>) -> Div {
        let busy = cx.global::<Session>().busy;
        let nodes = cx
            .global::<Session>()
            .snapshot
            .as_ref()
            .map(|s| s.proxies.as_slice())
            .unwrap_or_default();
        let mut cards = div().flex().flex_wrap().gap_3();
        for (index, subscription) in
            self.config.subscriptions.iter().enumerate()
        {
            let count = nodes
                .iter()
                .filter(|node| node.id.starts_with(&format!("sub{index}-")))
                .count();
            let label = subscription_label(subscription);
            cards = cards.child(
                div()
                    .id(SharedString::from(format!("subscription-{index}")))
                    .w(px(240.))
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(
                        if self.selected_subscription == Some(index) {
                            cx.theme().primary
                        } else {
                            cx.theme().border
                        },
                    )
                    .bg(cx.theme().background)
                    .cursor_pointer()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.selected_subscription = Some(index);
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(Icon::new(IconName::Globe))
                            .child(div().min_w_0().text_sm().child(label)),
                    )
                    .child(Self::hint(
                        format!("Subscription {} · {count} proxies", index + 1),
                        cx,
                    )),
            );
        }
        cards = cards.child(
            Button::new("add-subscription-card")
                .label("Add subscription")
                .icon(IconName::Plus)
                .outline()
                .h(px(100.))
                .w(px(240.))
                .disabled(busy)
                .on_click(cx.listener(|v, _, _, cx| {
                    v.adding_subscription = true;
                    cx.notify();
                })),
        );
        let mut view = Self::section("Subscriptions", "", cx).child(cards);
        if self.adding_subscription {
            view = view.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div().flex_1().child(
                            Input::new(&self.fields.subscriptions)
                                .aria_label("Subscription URL")
                                .disabled(busy),
                        ),
                    )
                    .child(
                        Button::new("confirm-subscription")
                            .label("Add")
                            .disabled(busy)
                            .on_click(cx.listener(|v, _, w, cx| {
                                v.add_subscription(w, cx)
                            })),
                    )
                    .child(
                        Button::new("cancel-subscription")
                            .label("Cancel")
                            .ghost()
                            .on_click(cx.listener(|v, _, _, cx| {
                                v.adding_subscription = false;
                                cx.notify();
                            })),
                    ),
            );
        }
        if let Some(index) = self
            .selected_subscription
            .filter(|i| *i < self.config.subscriptions.len())
        {
            view = view.child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(Self::hint(
                        format!("Viewing subscription {}", index + 1),
                        cx,
                    ))
                    .child(
                        Button::new("remove-subscription")
                            .label("Remove")
                            .ghost()
                            .disabled(busy)
                            .on_click(cx.listener(move |v, _, _, cx| {
                                v.selected_subscription = None;
                                send(Command::RemoveSubscription(index), cx);
                            })),
                    ),
            );
        }
        view
    }

    fn mesh_view(&self, cx: &Context<Self>) -> Div {
        let busy = cx.global::<Session>().busy || !self.loaded;
        let enabled = self.mesh_draft.enabled;
        let relay = self.mesh_draft.role == MeshRole::Relay;
        let mut view = Self::section("Mesh", "", cx).child(Self::setting(
            "Enable Mesh",
            "Connect your devices in a private network",
            Switch::new("mesh-enabled")
                .checked(enabled)
                .disabled(busy)
                .on_click(cx.listener(|v, on, _, cx| {
                    if *on {
                        v.mesh_draft.enabled = true;
                        v.mesh_test = None;
                        cx.notify();
                    } else {
                        v.control_service(
                            Service::Mesh,
                            ServiceAction::Stop,
                            cx,
                        );
                    }
                })),
            cx,
        ));
        if !enabled {
            return view;
        }
        view = view.child(self.service_controls(Service::Mesh, cx));
        let mut tabs =
            div().flex().gap_1().p_1().rounded_md().bg(cx.theme().muted);
        for (label, role) in
            [("Node", MeshRole::Node), ("Relay", MeshRole::Relay)]
        {
            tabs = tabs.child(
                Button::new(label)
                    .label(label)
                    .ghost()
                    .selected(self.mesh_draft.role == role)
                    .disabled(busy)
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.mesh_draft.role = role;
                        v.mesh_test = None;
                        cx.notify();
                    })),
            );
        }
        view = view.child(tabs)
            .child(Self::inline_field("Network", "Use the same network name on every device.", &self.fields.network, busy, cx))
            .child(Self::inline_field("Secret", "Shared authentication secret; use the same secret on every device.", &self.fields.secret, busy, cx));
        if !relay {
            view = view.child(Self::inline_field("Peers", "Peer or relay URLs, separated by spaces. Test connects without creating an interface.", &self.fields.peers, busy, cx));
        }
        view = view.child(Self::inline_field("Virtual IPv4", if relay { "Optional hub address with prefix, such as 10.10.0.1/24." } else { "Leave empty for DHCP, or enter an address with prefix such as 10.10.0.2/24. Saving Node mode creates the Mesh virtual interface using the networking helper." }, &self.fields.address, busy, cx))
            .child(Self::inline_field("Listeners", "Transport listener URLs, separated by spaces. Leave empty for the default TCP and UDP listeners on port 11010.", &self.fields.listeners, busy, cx))
            .child(div().flex().justify_end().gap_2()
                .child(Button::new("mesh-test").label("Test connection").outline().disabled(busy)
                    .on_click(cx.listener(|v, _, _, cx| {
                        match v.read_mesh_config(cx) {
                            Ok(config) => { v.mesh_test = None; send(Command::TestMesh(Box::new(config.mesh.expect("mesh draft"))), cx); }
                            Err(e) => { cx.global_mut::<Session>().error = Some(e.to_string()); cx.notify(); }
                        }
                    })))
                .child(Button::new("mesh-save").label("Save").disabled(busy)
                    .on_click(cx.listener(|v, _, _, cx| {
                        match v.read_mesh_config(cx) {
                            Ok(mut config) => { backend::set_service_state(&mut config, Service::Mesh, ServiceAction::Start); send(Command::Save(Box::new(config)), cx); }
                            Err(e) => { cx.global_mut::<Session>().error = Some(e.to_string()); cx.notify(); }
                        }
                    }))));
        if let Some(result) = &self.mesh_test {
            view = view.child(Self::hint(result.clone(), cx));
        }
        view
    }

    fn control_service(
        &mut self,
        service: Service,
        action: ServiceAction,
        cx: &mut Context<Self>,
    ) {
        if !self.loaded || cx.global::<Session>().busy {
            return;
        }
        // Mesh startup commits its visible draft. Pause/Stop use applied settings
        // so incomplete edits cannot prevent an immediate suspension.
        if matches!(service, Service::Mesh)
            && matches!(action, ServiceAction::Start)
        {
            self.mesh_draft.enabled = true;
            if self.fields.network.read(cx).value().trim().is_empty()
                || self.fields.secret.read(cx).value().is_empty()
            {
                cx.notify();
                return;
            }
        }
        let config = match (service, action) {
            (Service::Mesh, ServiceAction::Start) => self.read_mesh_config(cx),
            (Service::Proxy, ServiceAction::Start) => self.read_config(cx),
            _ => Ok(self.config.clone()),
        };
        match config {
            Ok(mut config) => {
                backend::set_service_state(&mut config, service, action);
                if matches!(service, Service::Mesh) {
                    self.mesh_draft.enabled =
                        !matches!(action, ServiceAction::Stop);
                    self.mesh_test = None;
                }
                send(Command::ControlService(Box::new(config), action), cx);
            }
            Err(error) => {
                cx.global_mut::<Session>().error = Some(error.to_string());
                cx.notify();
            }
        }
    }

    fn service_controls(&self, service: Service, cx: &Context<Self>) -> Div {
        let session = cx.global::<Session>();
        let busy = session.busy || !self.loaded;
        let enabled = match service {
            Service::Proxy => self.config.enabled,
            Service::Mesh => {
                self.config.mesh.as_ref().is_some_and(|m| m.enabled)
            }
        };
        let paused = match service {
            Service::Proxy => self.config.paused,
            Service::Mesh => self.config.mesh_paused,
        };
        let running =
            session.snapshot.as_ref().is_some_and(|s| s.running) && enabled;
        let label = if paused {
            "Paused"
        } else if running {
            "Running"
        } else if enabled {
            "Needs attention"
        } else {
            "Stopped"
        };
        let name = match service {
            Service::Proxy => "proxy",
            Service::Mesh => "mesh",
        };
        div().flex().items_center().justify_between().gap_3()
            .child(div().flex().items_center().gap_2()
                .child(Icon::new(if paused { IconName::Pause } else if running { IconName::CircleCheck } else { IconName::Circle }).size(px(16.)))
                .child(Self::hint(label, cx)))
            .child(div().flex().items_center().gap_2()
                .child(Button::new(SharedString::from(format!("{name}-start")))
                    .label(if paused { "Resume" } else { "Start" }).icon(IconName::Play).primary()
                    .disabled(busy || running)
                    .tooltip(match service { Service::Proxy => "Start the proxy using your saved routing settings", Service::Mesh => "Start Mesh using the configuration below" })
                    .on_click(cx.listener(move |v, _, _, cx| v.control_service(service, ServiceAction::Start, cx))))
                .child(Button::new(SharedString::from(format!("{name}-pause")))
                    .label("Pause").icon(IconName::Pause).ghost().disabled(busy || !running)
                    .tooltip("Suspend traffic and keep the configuration for Resume")
                    .on_click(cx.listener(move |v, _, _, cx| v.control_service(service, ServiceAction::Pause, cx))))
                .child(Button::new(SharedString::from(format!("{name}-stop")))
                    .label("Stop").icon(IconName::Square).ghost().disabled(busy || (!enabled && !paused))
                    .tooltip("Turn off this service and retain its configuration")
                    .on_click(cx.listener(move |v, _, _, cx| v.control_service(service, ServiceAction::Stop, cx)))))
    }

    fn inline_field(
        label: &'static str,
        help: &'static str,
        field: &Entity<InputState>,
        disabled: bool,
        _cx: &App,
    ) -> Div {
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(div().w(px(100.)).text_sm().child(label))
            .child(
                div().flex_1().min_w_0().child(
                    Input::new(field).aria_label(label).disabled(disabled),
                ),
            )
            .child(
                Popover::new(SharedString::from(format!("help-popup-{label}")))
                    .anchor(Anchor::TopRight)
                    .trigger(
                        Button::new(SharedString::from(format!(
                            "help-{label}"
                        )))
                        .accessibility_label(format!("Help for {label}"))
                        .icon(IconName::Info)
                        .ghost()
                        .tooltip(format!("About {label}")),
                    )
                    .content(move |_, _, _| {
                        div()
                            .w(px(300.))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(label),
                            )
                            .child(
                                div().text_sm().whitespace_normal().child(help),
                            )
                    }),
            )
    }

    fn commit_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if cx.global::<Session>().busy {
            return;
        }
        let name = self.fields.rule_name.read(cx).value().trim().to_owned();
        let matches = self
            .fields
            .rule_match
            .read(cx)
            .value()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if name.is_empty() || matches.is_empty() {
            cx.global_mut::<Session>().error =
                Some("Give the rule a name and at least one match.".into());
            cx.notify();
            return;
        }
        let mut rule = self
            .config
            .domain_rule
            .iter()
            .find(|r| Some(&r.name) == self.editing_rule.as_ref())
            .cloned()
            .unwrap_or_default();
        rule.enabled = true;
        rule.name = name;
        rule.host.clear();
        rule.by_suffix.clear();
        rule.process.clear();
        rule.source.clear();
        rule.destination.clear();
        match self.rule_kind {
            0 => rule.host = matches,
            1 => rule.process = matches,
            2 => rule.source = matches,
            _ => rule.destination = matches,
        }
        rule.outbounds = vec![self.rule_target.clone()];
        // Names identify rules; renaming an edited rule is handled by the backend.
        if let Some(previous) = self.editing_rule.as_ref() {
            rule.name = previous.clone();
        }
        send(Command::UpsertRule(rule), cx);
        self.editing_rule = None;
        self.fields
            .rule_name
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.fields
            .rule_match
            .update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }

    fn test_route(&mut self, cx: &mut Context<Self>) {
        if cx.global::<Session>().busy {
            return;
        }
        self.route_test = None;
        send(
            Command::TestRoute(
                self.fields.route_target.read(cx).value().to_string(),
            ),
            cx,
        );
        cx.notify();
    }

    fn route_test_view(&self, cx: &Context<Self>) -> Div {
        let busy = cx.global::<Session>().busy;
        let mut card = Self::section(
            "Test routing",
            "Check a destination against your saved rules and routing mode.",
            cx,
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div().flex_1().min_w_0().child(
                        Input::new(&self.fields.route_target)
                            .aria_label("Routing test destination")
                            .disabled(busy),
                    ),
                )
                .child(
                    Button::new("test-route")
                        .label("Test route")
                        .primary()
                        .disabled(
                            busy || self
                                .fields
                                .route_target
                                .read(cx)
                                .value()
                                .trim()
                                .is_empty(),
                        )
                        .on_click(cx.listener(|v, _, _, cx| v.test_route(cx))),
                ),
        );
        if let Some(result) = &self.route_test {
            card = card.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_3()
                    .rounded_md()
                    .bg(cx.theme().muted)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(result.route.clone()),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .child(result.destination.clone()),
                            ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .child(format!("Matched: {}", result.matched_rule)),
                    )
                    .child(Self::hint(result.detail.clone(), cx))
                    .child(Self::hint(result.note.clone(), cx)),
            );
        }
        card
    }

    fn rules_view(&self, cx: &Context<Self>) -> Div {
        let busy = cx.global::<Session>().busy;
        let mut kinds = div().flex().gap_2();
        for (index, label) in ["Host", "Process", "Source", "Destination"]
            .iter()
            .enumerate()
        {
            kinds = kinds.child(
                Button::new(*label)
                    .label(*label)
                    .ghost()
                    .selected(self.rule_kind == index)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.rule_kind = index;
                        cx.notify();
                    })),
            );
        }
        let nodes = cx
            .global::<Session>()
            .snapshot
            .as_ref()
            .map(|s| s.proxies.clone())
            .unwrap_or_default();
        let target = self.rule_target.clone();
        let view = cx.entity().downgrade();
        let chooser = Button::new("rule-route")
            .label(format!(
                "Route: {}",
                if target == "Proxy" {
                    "Selected pool"
                } else if target == "direct" {
                    "Direct"
                } else {
                    &target
                }
            ))
            .outline()
            .dropdown_menu(move |mut menu, _, _| {
                for (id, name) in [
                    ("Proxy".to_string(), "Selected pool".to_string()),
                    ("direct".to_string(), "Direct".to_string()),
                ]
                .into_iter()
                .chain(nodes.iter().map(|n| (n.id.clone(), n.name.clone())))
                {
                    let view = view.clone();
                    menu = menu.item(
                        PopupMenuItem::new(name)
                            .checked(id == target)
                            .on_click(move |_, _, cx| {
                                let _ = view.update(cx, |v, cx| {
                                    v.rule_target = id.clone();
                                    cx.notify();
                                });
                            }),
                    );
                }
                menu
            });
        let mut list = Self::section(
            "Your routing rules",
            "First match wins. Custom rules run before the routing mode. Changes reconnect proxy traffic.",
            cx,
        );
        for rule in &self.config.domain_rule {
            let mut toggled = rule.clone();
            toggled.enabled = !rule.enabled;
            let name = rule.name.clone();
            let edit = rule.clone();
            let matches = rule
                .host
                .iter()
                .chain(rule.by_suffix.iter())
                .chain(rule.process.iter())
                .chain(rule.source.iter())
                .chain(rule.destination.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .py_3()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(
                        Switch::new(SharedString::from(format!(
                            "rule-toggle-{name}"
                        )))
                        .checked(rule.enabled)
                        .disabled(busy)
                        .on_click(move |_, _, cx| {
                            send(Command::UpsertRule(toggled.clone()), cx)
                        }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::MEDIUM)
                                    .child(rule.name.clone()),
                            )
                            .child(Self::hint(matches, cx)),
                    )
                    .child(Self::hint(rule.outbounds.join(", "), cx))
                    .child(
                        Button::new(SharedString::from(format!("edit-{name}")))
                            .label("Edit")
                            .ghost()
                            .disabled(busy)
                            .on_click(cx.listener(move |v, _, w, cx| {
                                v.editing_rule = Some(edit.name.clone());
                                v.rule_kind = if !edit.process.is_empty() {
                                    1
                                } else if !edit.source.is_empty() {
                                    2
                                } else if !edit.destination.is_empty() {
                                    3
                                } else {
                                    0
                                };
                                v.rule_target = edit
                                    .outbounds
                                    .first()
                                    .cloned()
                                    .unwrap_or("Proxy".into());
                                v.fields.rule_name.update(cx, |s, cx| {
                                    s.set_value(edit.name.clone(), w, cx)
                                });
                                let values = match v.rule_kind {
                                    1 => edit.process.clone(),
                                    2 => edit.source.clone(),
                                    3 => edit.destination.clone(),
                                    _ => edit
                                        .host
                                        .iter()
                                        .cloned()
                                        .chain(
                                            edit.by_suffix
                                                .iter()
                                                .map(|v| format!("*.{v}")),
                                        )
                                        .collect(),
                                };
                                v.fields.rule_match.update(cx, |s, cx| {
                                    s.set_value(values.join(" "), w, cx)
                                });
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new(SharedString::from(format!(
                            "remove-{name}"
                        )))
                        .label("Remove")
                        .ghost()
                        .disabled(busy)
                        .on_click(move |_, _, cx| {
                            send(Command::DeleteRule(name.clone()), cx)
                        }),
                    ),
            );
        }
        if self.config.domain_rule.is_empty() {
            list = list.child(Self::hint("No custom rules. Add a match below, or route a destination from Overview.", cx));
        }
        div().flex().flex_col().gap_4().child(self.route_test_view(cx)).child(list.child(Self::section(if self.editing_rule.is_some() { "Edit rule" } else { "New rule" }, "Use *.example.com for a domain group, a process name, or an IP/CIDR. Enter applies the rule.", cx)
            .child(kinds)
            .child(Input::new(&self.fields.rule_name).aria_label("Rule name").disabled(busy || self.editing_rule.is_some()))
            .child(Input::new(&self.fields.rule_match).aria_label("Rule matches").disabled(busy))
            .child(chooser)))
    }

    fn application_traffic_view(&self, cx: &Context<Self>) -> Div {
        let state = cx.global::<Session>();
        let snapshot = state.snapshot.as_ref();
        let value = snapshot
            .map(|s| s.process_traffic.clone())
            .unwrap_or_default();
        let enabled = value["enabled"].as_bool().unwrap_or(false);
        let available = value["available"].as_bool().unwrap_or(false);
        let unavailable = state.busy || !available;
        let mut rows = value["records"].as_array().cloned().unwrap_or_default();
        let count = |record: &serde_json::Value, key: &str| {
            record[key].as_u64().unwrap_or(0)
        };
        let mut totals = [0u64; 4];
        for row in &rows {
            for (index, amount) in [
                count(row, "upload"),
                count(row, "download"),
                count(row, "direct_upload")
                    .saturating_add(count(row, "direct_download")),
                count(row, "proxy_upload")
                    .saturating_add(count(row, "proxy_download")),
            ]
            .into_iter()
            .enumerate()
            {
                totals[index] = totals[index].saturating_add(amount);
            }
        }
        let mut list = Self::section(
            "Application usage",
            "Includes direct and proxied traffic handled by Zay. Saved across restarts until reset.",
            cx,
        );
        let mut summary = div().flex().flex_wrap().gap_3();
        for (label, amount) in ["Uploaded", "Downloaded", "Direct", "Proxied"]
            .into_iter()
            .zip(totals)
        {
            summary = summary.child(
                div()
                    .flex_1()
                    .min_w(px(110.))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(Self::hint(label, cx))
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(bytes(amount)),
                    ),
            );
        }
        list = list.child(summary).child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(Self::hint(
                    if !available {
                        "Saved usage · start the proxy to record or reset"
                    } else if enabled {
                        "Recording · updates every second"
                    } else {
                        "Recording paused · saved usage retained"
                    },
                    cx,
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            Button::new("reset-application-usage")
                                .label("Reset usage")
                                .ghost()
                                .disabled(unavailable || rows.is_empty())
                                .on_click(cx.listener(|v, _, _, cx| {
                                    v.confirm_usage_reset = true;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Switch::new("record-application-usage")
                                .checked(enabled)
                                .disabled(unavailable)
                                .on_click(cx.listener(|_, on, _, cx| {
                                    send(
                                        Command::ProcessTraffic(if *on {
                                            "enable"
                                        } else {
                                            "disable"
                                        }),
                                        cx,
                                    )
                                })),
                        ),
                ),
        );
        if self.confirm_usage_reset {
            list = list.child(div().p_3().rounded_md().bg(cx.theme().muted).flex().flex_col().gap_2()
                .child(Self::hint("Clear all saved application usage? Active connections will continue counting from zero.", cx))
                .child(div().flex().gap_2()
                    .child(Button::new("cancel-usage-reset").label("Cancel").ghost().on_click(cx.listener(|v, _, _, cx| { v.confirm_usage_reset = false; cx.notify(); })))
                    .child(Button::new("confirm-usage-reset").label("Reset all usage").disabled(unavailable).on_click(cx.listener(|v, _, _, cx| { v.confirm_usage_reset = false; send(Command::ProcessTraffic("reset"), cx); })))));
        }
        let tun = snapshot.is_some_and(|s| s.tun_active);
        list = list.child(Self::hint(if tun { "TUN traffic is included; excluded routes are outside these totals. App helpers are grouped under their macOS application." } else { "Only traffic sent to Zay's proxy is included. Enable TUN to capture more applications." }, cx));
        let mut sorting = div().flex().gap_1();
        for (index, label) in
            ["Total", "Direct", "Proxied"].into_iter().enumerate()
        {
            sorting = sorting.child(
                Button::new(SharedString::from(format!("usage-sort-{index}")))
                    .label(label)
                    .ghost()
                    .selected(self.application_sort == index)
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.application_sort = index;
                        cx.notify();
                    })),
            );
        }
        list = list
            .child(
                Input::new(&self.fields.application_search)
                    .aria_label("Search application usage"),
            )
            .child(sorting);
        let query = self
            .fields
            .application_search
            .read(cx)
            .value()
            .to_lowercase();
        rows.retain(|row| {
            format!(
                "{} {}",
                row["process_name"].as_str().unwrap_or(""),
                row["process_path"].as_str().unwrap_or("")
            )
            .to_lowercase()
            .contains(query.as_str())
        });
        let amount = |row: &serde_json::Value| match self.application_sort {
            1 => count(row, "direct_upload")
                .saturating_add(count(row, "direct_download")),
            2 => count(row, "proxy_upload")
                .saturating_add(count(row, "proxy_download")),
            _ => count(row, "upload").saturating_add(count(row, "download")),
        };
        rows.sort_by_key(|row| std::cmp::Reverse(amount(row)));
        if rows.is_empty() {
            list = list.child(Self::hint("No matching application usage. Send traffic through Zay to start recording.", cx));
        }
        for row in rows {
            let mut details = div().flex().flex_wrap().gap_4();
            for (label, amount) in [
                (
                    "Direct",
                    count(&row, "direct_upload")
                        .saturating_add(count(&row, "direct_download")),
                ),
                (
                    "Proxied",
                    count(&row, "proxy_upload")
                        .saturating_add(count(&row, "proxy_download")),
                ),
                ("Uploaded", count(&row, "upload")),
                ("Downloaded", count(&row, "download")),
            ] {
                details = details.child(div().flex_1().min_w(px(100.)).child(
                    Self::hint(format!("{label} · {}", bytes(amount)), cx),
                ));
            }
            list = list.child(
                div()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(FontWeight::MEDIUM)
                                            .child(
                                                row["process_name"]
                                                    .as_str()
                                                    .unwrap_or("Unattributed")
                                                    .to_owned(),
                                            ),
                                    )
                                    .child(
                                        div().truncate().child(Self::hint(
                                            row["process_path"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_owned(),
                                            cx,
                                        )),
                                    ),
                            )
                            .child(div().text_sm().child(format!(
                                "{} · {} connections",
                                bytes(
                                    count(&row, "upload").saturating_add(
                                        count(&row, "download")
                                    )
                                ),
                                count(&row, "connections")
                            ))),
                    )
                    .child(details),
            );
        }
        list
    }

    fn connections_view(&self, cx: &Context<Self>) -> Div {
        let state = cx.global::<Session>();
        let snapshot = state.snapshot.as_ref();
        let value = snapshot.map(|s| s.connections.clone()).unwrap_or_default();
        let nodes = snapshot.map(|s| s.proxies.clone()).unwrap_or_default();
        let busy = state.busy;
        let mut list = Self::section(
            "Live connections",
            format!(
                "↑ {}  ·  ↓ {}  ·  updates every second",
                bytes(value["uploadTotal"].as_u64().unwrap_or(0)),
                bytes(value["downloadTotal"].as_u64().unwrap_or(0))
            ),
            cx,
        );
        let mut activity = div().flex().gap_1();
        for (index, label) in
            ["All", "Active", "Closed"].into_iter().enumerate()
        {
            activity = activity.child(
                Button::new(SharedString::from(format!("activity-{index}")))
                    .label(label)
                    .ghost()
                    .selected(self.connection_activity == index)
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.connection_activity = index;
                        cx.notify();
                    })),
            );
        }
        let mut protocol = div().flex().gap_1();
        for (index, label) in
            ["Any protocol", "TCP", "UDP"].into_iter().enumerate()
        {
            protocol = protocol.child(
                Button::new(SharedString::from(format!("protocol-{index}")))
                    .label(label)
                    .ghost()
                    .selected(self.connection_protocol == index)
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.connection_protocol = index;
                        cx.notify();
                    })),
            );
        }
        list = list
            .child(
                Input::new(&self.fields.connection_search)
                    .aria_label("Search connections"),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(activity)
                    .child(protocol),
            );
        let query = self
            .fields
            .connection_search
            .read(cx)
            .value()
            .trim()
            .to_lowercase();
        let mut rows =
            value["connections"].as_array().cloned().unwrap_or_default();
        let active_count = rows.len();
        if let Some(recent) = value["recentConnections"].as_array() {
            rows.extend(recent.iter().take(100).cloned().map(|mut c| {
                c["closed"] = true.into();
                c
            }));
        }
        rows.retain(|connection| {
            let closed = connection["closed"] == true;
            if (self.connection_activity == 1 && closed)
                || (self.connection_activity == 2 && !closed)
            {
                return false;
            }
            let metadata = &connection["metadata"];
            let network = metadata["network"].as_str().unwrap_or("");
            if (self.connection_protocol == 1 && network != "tcp")
                || (self.connection_protocol == 2 && network != "udp")
            {
                return false;
            }
            let mut terms = [
                "host",
                "destinationIP",
                "destinationPort",
                "sourceIP",
                "process",
                "processPath",
            ]
            .iter()
            .filter_map(|key| metadata[*key].as_str())
            .collect::<Vec<_>>();
            if let Some(chains) = connection["chains"].as_array() {
                terms.extend(chains.iter().filter_map(|chain| chain.as_str()));
            }
            terms.join(" ").to_lowercase().contains(&query)
        });
        list = list.child(Self::hint(format!("{active_count} active · recent completed attempts are kept for inspection"), cx));
        {
            for connection in &rows {
                let m = &connection["metadata"];
                let host = m["host"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| {
                        m["destinationIP"].as_str().unwrap_or("Unknown")
                    });
                let process = m["process"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("Unknown process");
                let outbound = connection["chains"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" → ")
                    })
                    .unwrap_or_default();
                let current = connection.clone();
                let choices = nodes.clone();
                let route_menu =
                    move |mut menu: gpui_kit::component::menu::PopupMenu,
                          _: &mut Window,
                          _: &mut Context<
                        gpui_kit::component::menu::PopupMenu,
                    >| {
                        menu = menu.item(PopupMenuItem::label(
                            "Route destination & reconnect",
                        ));
                        for (target, label) in [
                            (
                                Some("Proxy".to_string()),
                                "Selected proxy pool".to_string(),
                            ),
                            (None, "Default TUN route".to_string()),
                            (Some("direct".to_string()), "Direct".to_string()),
                        ]
                        .into_iter()
                        .chain(
                            choices
                                .iter()
                                .map(|n| (Some(n.id.clone()), n.name.clone())),
                        ) {
                            let current = current.clone();
                            menu = menu.item(
                                PopupMenuItem::new(label)
                                    .disabled(busy)
                                    .on_click(move |_, _, cx| {
                                        send(
                                            Command::RouteConnection(
                                                current.clone(),
                                                target.clone(),
                                            ),
                                            cx,
                                        )
                                    }),
                            );
                        }
                        menu
                    };
                list = list.child(
                    div()
                        .id(SharedString::from(format!(
                            "connection-{}",
                            connection["id"].as_str().unwrap_or("")
                        )))
                        .flex()
                        .items_center()
                        .gap_3()
                        .py_3()
                        .border_t_1()
                        .border_color(cx.theme().border)
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(format!(
                                            "{host}:{}",
                                            m["destinationPort"]
                                                .as_str()
                                                .unwrap_or("")
                                        )),
                                )
                                .child(Self::hint(
                                    format!(
                                        "{process} · {} · {}",
                                        m["network"].as_str().unwrap_or(""),
                                        connection["rule"]
                                            .as_str()
                                            .unwrap_or("")
                                    ),
                                    cx,
                                )),
                        )
                        .child(div().text_sm().child(format!(
                            "{}{}",
                            outbound,
                            if connection["closed"] == true {
                                " · Closed"
                            } else {
                                " · Active / connecting"
                            }
                        )))
                        .child(Self::hint(
                            format!(
                                "↑ {}  ↓ {}",
                                bytes(
                                    connection["upload"].as_u64().unwrap_or(0)
                                ),
                                bytes(
                                    connection["download"]
                                        .as_u64()
                                        .unwrap_or(0)
                                )
                            ),
                            cx,
                        ))
                        .child(
                            Button::new(SharedString::from(format!(
                                "route-{}",
                                connection["id"].as_str().unwrap_or("")
                            )))
                            .label("Route")
                            .ghost()
                            .dropdown_menu(route_menu.clone()),
                        )
                        .context_menu(route_menu),
                );
            }
        }
        if rows.is_empty() {
            list = list.child(Self::hint("No matching connections.", cx));
        }
        list
    }

    fn logs_view(&self, cx: &Context<Self>) -> Div {
        let query = self
            .fields
            .log_search
            .read(cx)
            .value()
            .trim()
            .to_lowercase();
        let lines = cx
            .global::<Session>()
            .snapshot
            .as_ref()
            .map(|s| s.logs.clone())
            .unwrap_or_default();
        let mut filters = div().flex().gap_2();
        for (index, label) in ["All levels", "Error", "Warn", "Info", "Debug"]
            .into_iter()
            .enumerate()
        {
            filters = filters.child(
                Button::new(SharedString::from(format!("log-level-{index}")))
                    .label(label)
                    .ghost()
                    .selected(self.log_level == index)
                    .on_click(cx.listener(move |v, _, _, cx| {
                        v.log_level = index;
                        cx.notify();
                    })),
            );
        }
        let mut view = Self::section("Activity log", "", cx)
            .child(
                Input::new(&self.fields.log_search).aria_label("Search logs"),
            )
            .child(filters);
        let lines = lines
            .into_iter()
            .filter(|line| log_matches(line, &query, self.log_level))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            view = view.child(Self::hint("No matching log entries.", cx));
        }
        for line in lines.iter().rev() {
            let error = line.to_lowercase().contains("error");
            view = view.child(
                div()
                    .text_xs()
                    .py_2()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .text_color(if error {
                        cx.theme().danger
                    } else {
                        cx.theme().muted_foreground
                    })
                    .child(line.clone()),
            );
        }
        view
    }
    fn nav(
        &self,
        label: &'static str,
        icon: IconName,
        page: Page,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        Button::new(label)
            .accessibility_label(label)
            .icon(Icon::new(icon).size_4())
            .tooltip(label)
            .ghost()
            .w_full()
            .h(px(40.))
            .selected(self.page == page)
            .on_click(cx.listener(move |view, _, _, cx| {
                view.page = page;
                cx.notify();
            }))
    }
    fn hint(text: impl Into<SharedString>, cx: &App) -> Div {
        div()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(text.into())
    }
    fn section(
        title: &'static str,
        description: impl Into<SharedString>,
        cx: &App,
    ) -> Div {
        let description: SharedString = description.into();
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .bg(cx.theme().background)
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_base()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .when(!description.is_empty(), |v| {
                        v.child(Self::hint(description, cx))
                    }),
            )
    }
    fn setting(
        title: &'static str,
        description: &'static str,
        control: impl IntoElement,
        cx: &App,
    ) -> Div {
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap_5()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::MEDIUM)
                            .child(title),
                    )
                    .child(Self::hint(description, cx)),
            )
            .child(control)
    }
    fn detail(
        label: &'static str,
        value: impl Into<SharedString>,
        cx: &App,
    ) -> Div {
        div()
            .flex()
            .justify_between()
            .items_center()
            .gap_4()
            .text_sm()
            .child(Self::hint(label, cx))
            .child(div().min_w_0().child(value.into()))
    }
}
fn bytes(value: u64) -> String {
    if value >= 1_099_511_627_776 {
        format!("{:.1} TB", value as f64 / 1_099_511_627_776.)
    } else if value >= 1_073_741_824 {
        format!("{:.1} GB", value as f64 / 1_073_741_824.)
    } else if value >= 1_048_576 {
        format!("{:.1} MB", value as f64 / 1_048_576.)
    } else if value >= 1024 {
        format!("{:.1} KB", value as f64 / 1024.)
    } else {
        format!("{value} B")
    }
}

fn subscription_label(raw: &str) -> String {
    url::Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "Subscription".into())
}

fn log_matches(line: &str, query: &str, level: usize) -> bool {
    let lower = line.to_lowercase();
    if !lower.contains(query) {
        return false;
    }
    if level == 0 {
        return true;
    }
    // Structured desktop lines have timestamp followed by their severity.
    let severity = lower.split_whitespace().nth(1).unwrap_or("");
    let requested = ["", "error", "warn", "info", "debug"][level.min(4)];
    severity == requested || (requested == "warn" && severity == "warning")
}

fn menu_bar_icon() -> tray_icon::Icon {
    let size = 36u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let segments = [
        ((8., 9.), (28., 9.)),
        ((28., 9.), (8., 27.)),
        ((8., 27.), (28., 27.)),
    ];
    for y in 0..size {
        for x in 0..size {
            let on = segments.iter().any(|&((ax, ay), (bx, by))| {
                let dx = bx - ax;
                let dy = by - ay;
                let t = (((x as f32 - ax) * dx + (y as f32 - ay) * dy)
                    / (dx * dx + dy * dy))
                    .clamp(0., 1.);
                (x as f32 - ax - t * dx).powi(2)
                    + (y as f32 - ay - t * dy).powi(2)
                    <= 2.3f32.powi(2)
            });
            if on {
                rgba[((y * size + x) * 4 + 3) as usize] = 255;
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, size, size).expect("valid menu-bar icon")
}

fn set_application_icon() {
    use objc2::{AnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;
    let main =
        MainThreadMarker::new().expect("desktop runs on the main thread");
    let data = NSData::with_bytes(include_bytes!("../assets/app-icon.png"));
    if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
        // Updating an existing bundle can leave Launch Services' icon cache stale.
        // Set the running app's icon too, including direct development launches.
        unsafe {
            NSApplication::sharedApplication(main)
                .setApplicationIconImage(Some(&image));
        }
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
        let proxy_ready =
            state.snapshot.as_ref().is_some_and(|s| s.proxy_ready);
        let mesh = state
            .snapshot
            .as_ref()
            .map(|s| s.mesh.clone())
            .unwrap_or(serde_json::json!([]));
        // Report the saved configuration rather than unsaved form values.
        let applied = state.snapshot.as_ref().and_then(|s| s.config.as_ref());
        let port = applied.and_then(|c| c.mixed_port).unwrap_or(7890);
        let network = applied
            .and_then(|c| c.mesh.as_ref())
            .map(|m| m.network_name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or("Not configured".into());
        let mut errors = state.error.iter().cloned().collect::<Vec<_>>();
        if let Some(snapshot) = &state.snapshot {
            for error in [
                &snapshot.error,
                &snapshot.proxy_error,
                &snapshot.telemetry_error,
                &snapshot.process_traffic_error,
            ]
            .into_iter()
            .flatten()
            {
                if !errors.contains(error) {
                    errors.push(error.clone());
                }
            }
        }
        let error = (!errors.is_empty()).then(|| errors.join("\n"));
        let data_dir = state.data_dir.display().to_string();
        let needs_attention = error.is_some()
            || state.snapshot.as_ref().is_some_and(|s| {
                matches!(s.status.as_str(), "Degraded" | "Failed")
            });
        let status = if state.quitting {
            "Stopping…"
        } else if busy {
            "Applying changes…"
        } else if needs_attention {
            "Needs attention"
        } else if !self.loaded {
            "Loading…"
        } else if running {
            "Connected"
        } else {
            "Disconnected"
        };
        let border = cx.theme().border;
        let background = cx.theme().background;
        let foreground = cx.theme().foreground;
        let unavailable = busy || !self.loaded;

        let mut navigation = div().flex().flex_col().gap_1();
        for (label, icon, page) in [
            ("Overview", IconName::LayoutDashboard, Page::Overview),
            ("Proxy", IconName::Globe, Page::Proxy),
            ("Mesh", IconName::Network, Page::Mesh),
            ("Rules", IconName::ListFilter, Page::Rules),
            ("Logs", IconName::ScrollText, Page::Logs),
        ] {
            navigation = navigation.child(self.nav(label, icon, page, cx));
        }
        let side = div()
            .w(px(56.))
            .flex_shrink_0()
            .h_full()
            .p_2()
            .bg(cx.theme().sidebar)
            .border_r_1()
            .border_color(border)
            .flex()
            .flex_col()
            .justify_between()
            .child(navigation)
            .child(self.nav(
                "Preferences",
                IconName::Settings,
                Page::Preferences,
                cx,
            ));
        let content = match self.page {
            Page::Overview => {
                let selected = applied.map(|c| c.active_nodes.len()).unwrap_or(0);
                let pool_size = state.snapshot.as_ref().map(|s| s.proxies.len()).unwrap_or(0);
                let peers = mesh.as_array().map(|items| items.iter().filter_map(|m| m["connected_peers"].as_u64()).sum::<u64>()).unwrap_or(0);
                let tun_active = state.snapshot.as_ref().is_some_and(|s| s.tun_active);
                let mut stats = div().flex().gap_3();
                for (label, value, detail) in [
                    ("Proxy pool", format!("{}", if selected == 0 { pool_size } else { selected }), if selected == 1 { "Pinned node" } else { "Automatic selection" }.to_owned()),
                    ("System traffic", if tun_active { "TUN active" } else if proxy_ready { "App proxy" } else { "Off" }.to_owned(), if tun_active { "Device traffic captured".into() } else if proxy_ready { format!("127.0.0.1:{port}") } else { "No traffic captured".into() }),
                    ("Mesh peers", peers.to_string(), network.clone()),
                ] {
                    stats = stats.child(div().flex_1().p_4().rounded_lg().border_1().border_color(border).bg(background).flex().flex_col().gap_2()
                        .child(Self::hint(label, cx)).child(div().text_xl().font_weight(FontWeight::SEMIBOLD).child(value)).child(Self::hint(detail, cx)));
                }
                div().flex().flex_col().gap_4().child(stats)
                    .child(self.application_traffic_view(cx))
                    .child(self.connections_view(cx))
            }
            Page::Rules => self.rules_view(cx),
            Page::Logs => self.logs_view(cx),
            Page::Proxy => {
                let mut modes = div().flex().gap_2();
                for (mode, label) in [("global", "Global"), ("rules", "Rules"), ("direct", "Direct")] {
                    modes = modes.child(Button::new(mode).label(label).selected(self.config.routing_mode == mode).disabled(unavailable)
                        .on_click(cx.listener(move |v, _, w, cx| v.change_option(false, |c| c.routing_mode = mode.into(), w, cx))));
                }
                div().flex().flex_col().gap_4()
                    .child(Self::section("Routing", "", cx)
                        .child(self.service_controls(Service::Proxy, cx))
                        .child(div().flex().items_center().justify_between().child(Self::hint("Routing mode", cx)).child(modes))
                        .child(Self::inline_field("Listening port", "HTTP / SOCKS5 port; press Enter to apply.", &self.fields.port, unavailable, cx)))
                    .child(self.subscription_cards(cx))
                    .when(self.selected_subscription.is_some(), |view| view.child(self.proxy_list(cx)))
            },
            Page::Mesh => self.mesh_view(cx),
            Page::Preferences => div().flex().flex_col().gap_5()
                .child(Self::section("Network", "", cx)
                    .child(Self::setting("TUN", "Route device traffic through the proxy when it is running",
                        Switch::new("tun-enabled").checked(self.config.tun.enabled).disabled(unavailable)
                            .on_click(cx.listener(|v, on, w, cx| v.change_option(false, |c| c.tun.enabled = *on, w, cx))), cx)))
                .child(Self::section("Appearance", "Choose a theme for this session.", cx)
                    .child(div().flex().gap_3()
                        .child(Button::new("light").label("Light").icon(IconName::Sun).selected(!self.dark)
                            .on_click(cx.listener(|v, _, w, cx| { v.dark = false; set_dark(false, w, cx); cx.notify(); })))
                        .child(Button::new("dark").label("Dark").icon(IconName::Moon).selected(self.dark)
                            .on_click(cx.listener(|v, _, w, cx| { v.dark = true; set_dark(true, w, cx); cx.notify(); })))))
                .child(Self::section("Configuration", "Desktop settings are stored separately from your CLI configuration.", cx)
                    .child(div().p_3().rounded_md().bg(cx.theme().muted).text_sm().child(format!("{data_dir}/zay.toml")))
                    .child(Self::hint("Use Rules to edit routing without opening the configuration file.", cx)))
                .child(Self::section("About Zay", "A home for your proxy and private network.", cx)
                    .child(Self::detail("Version", env!("CARGO_PKG_VERSION"), cx))
                    .child(Self::hint("Services continue when the window closes. Quit Zay to stop them.", cx))),
        };
        let details = format!(
            "Status: {status}\nProxy: {}\nTUN: {}\nMesh peers: {}\nController: {}\nData folder: {data_dir}{}",
            if applied.is_some_and(|c| c.paused) {
                "Paused"
            } else if applied.is_some_and(|c| !c.enabled) {
                "Stopped"
            } else if proxy_ready {
                "Ready"
            } else {
                "Not ready"
            },
            if state.snapshot.as_ref().is_some_and(|s| s.tun_active) {
                "Active"
            } else {
                "Off"
            },
            mesh.as_array()
                .map(|a| a
                    .iter()
                    .filter_map(|m| m["connected_peers"].as_u64())
                    .sum::<u64>())
                .unwrap_or(0),
            state
                .snapshot
                .as_ref()
                .and_then(|s| s.telemetry_error.as_deref())
                .unwrap_or(if running { "Connected" } else { "Stopped" }),
            error
                .as_ref()
                .map(|e| format!("\nError: {e}"))
                .unwrap_or_default()
        );
        let retry =
            state.snapshot.as_ref().and_then(|s| s.retry_config.clone());
        let title_bar = TitleBar::new().child(
            div()
                .flex_1()
                .h_full()
                .flex()
                .items_center()
                .justify_end()
                .pr_3()
                .child(
                    Popover::new("connection-status-popover")
                        .anchor(Anchor::TopRight)
                        .trigger(
                            Button::new("connection-status")
                                .accessibility_label("Connection status")
                                .ghost()
                                .w(px(24.))
                                .h(px(24.))
                                .icon(
                                    Icon::new(if needs_attention {
                                        IconName::CircleAlert
                                    } else {
                                        IconName::Info
                                    })
                                    .size_4()
                                    .text_color(if needs_attention {
                                        cx.theme().danger
                                    } else if running {
                                        cx.theme().success
                                    } else {
                                        cx.theme().muted_foreground
                                    }),
                                )
                                .tooltip(format!(
                                    "{status} · click for details"
                                )),
                        )
                        .content(move |_, _, _| {
                            let copy = details.clone();
                            let retry = retry.clone();
                            div()
                                .w(px(340.))
                                .flex()
                                .flex_col()
                                .gap_3()
                                .child(
                                    div()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .child("Connection status"),
                                )
                                .child(
                                    details.lines().fold(
                                        div()
                                            .id("status-details")
                                            .w_full()
                                            .max_h(px(320.))
                                            .overflow_y_scroll()
                                            .flex()
                                            .flex_col()
                                            .gap_2()
                                            .text_sm()
                                            .whitespace_normal(),
                                        |view, line| {
                                            view.child(
                                                div().child(line.to_owned()),
                                            )
                                        },
                                    ),
                                )
                                .child(
                                    Button::new("copy-status")
                                        .label("Copy details")
                                        .ghost()
                                        .on_click(move |_, _, cx| {
                                            cx.write_to_clipboard(
                                                ClipboardItem::new_string(
                                                    copy.clone(),
                                                ),
                                            )
                                        }),
                                )
                                .when_some(retry, |view, config| {
                                    view.child(
                                        Button::new("retry-connection")
                                            .label("Retry")
                                            .outline()
                                            .disabled(unavailable)
                                            .on_click(move |_, _, cx| {
                                                send(
                                                    Command::Start(Some(
                                                        Box::new(
                                                            config.clone(),
                                                        ),
                                                    )),
                                                    cx,
                                                )
                                            }),
                                    )
                                })
                        }),
                ),
        );
        let body = div()
            .w_full()
            .max_w(px(920.))
            .mx_auto()
            .flex()
            .flex_col()
            .gap_5()
            .child(content);
        let mut main = div().min_w_0().flex_1().h_full().flex().flex_col();
        main = main.child(
            div()
                .id("main-scroll")
                .min_h_0()
                .flex_1()
                .overflow_y_scroll()
                .p_5()
                .bg(cx.theme().muted)
                .child(body),
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .whitespace_normal()
            .bg(background)
            .text_color(foreground)
            .child(title_bar)
            .child(div().flex().flex_1().min_h_0().child(side).child(main))
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
        set_application_icon();
        ely_gpui_component::init(cx);
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Light, None, cx);
        ElyTheme::set_mode_now(ElyMode::Light, cx);
        let menu = TrayMenu::new();
        let show = TrayItem::new("Open Zay", true, None);
        let preferences = TrayItem::new("Preferences…", true, None);
        let quit_item = TrayItem::new("Quit Zay", true, None);
        menu.append_items(&[
            &show,
            &preferences,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ])
        .expect("create menu");
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(menu_bar_icon())
            .with_icon_as_template(true)
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
                let mesh_test = update.mesh_test.clone();
                let route_test = update.route_test.clone();
                let _ = cx.update(|cx| {
                    let state = cx.global_mut::<Session>();
                    if update.finished {
                        state.busy = false;
                        state.error = update.action_error.clone();
                    }
                    let completed_config = update
                        .finished
                        .then(|| update.config.clone())
                        .flatten();
                    state.snapshot = Some(update);
                    if let Some(view) = state.view.clone() {
                        view.update(cx, |view, cx| {
                            if let Some(result) = route_test {
                                view.route_test = Some(result);
                            }
                            if let Some(config) = &completed_config {
                                if toml::to_string(&view.config).ok()
                                    != toml::to_string(config).ok()
                                {
                                    view.route_test = None;
                                }
                            }
                            if let Some(result) = mesh_test {
                                view.mesh_test = Some(result);
                            }
                            if let Some(config) = completed_config {
                                view.config = config;
                            }
                            cx.notify();
                        });
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

#[cfg(test)]
mod view_tests {
    use super::{log_matches, subscription_label};

    #[::core::prelude::v1::test]
    fn log_filter_uses_severity_and_search_together() {
        let info = "2026-10-06T00:00:00Z  info · proxy\nNo error in connection to lab.test";
        let error =
            "2026-10-06T00:00:01Z  error · proxy\nTLS failed for lab.test";
        assert!(!log_matches(info, "", 1));
        assert!(log_matches(error, "lab.test", 1));
        assert!(!log_matches(error, "other.test", 1));
        assert!(log_matches(info, "connection", 3));
        assert!(log_matches(error, "tls", 0));
    }

    #[::core::prelude::v1::test]
    fn subscription_cards_hide_url_credentials_and_tokens() {
        assert_eq!(
            subscription_label(
                "https://name:secret@example.com/feed?token=private"
            ),
            "example.com"
        );
        assert_eq!(subscription_label("invalid-secret"), "Subscription");
    }
}
