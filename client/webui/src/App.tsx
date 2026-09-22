import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  Activity, ArrowLeft, ArrowRight, Cable, Check, CheckCircle2, CircleStop,
  Database, FileJson, Globe2, Info, KeyRound, List, LoaderCircle, Network,
  Pencil, Play, Plus, Power, Radio, RefreshCw, RotateCw, Save, ScrollText,
  Search, Server, Settings2, ShieldCheck, TerminalSquare, Trash2,
  TriangleAlert, Upload, Users,
} from "lucide-react"
import {
  ApiError, api, setToken, type ConfigPayload, type EventRecord, type EventsResponse,
  type DomainRule, type MeshInstance, type NodeTestResult, type ProcessTrafficResponse, type ProxyNode, type RuleSetContent, type RuleSetEntry,
  type StateResponse, uploadRuleSet,
} from "@/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"

type Page = "proxy" | "mesh" | "connections" | "logs"
type Notice = { kind: "ok" | "error" | "warning"; text: string } | null

const emptyForm: ConfigPayload = {
  proxy: {
    enabled: true, subscriptions: [], active_nodes: [], gateway: false, mixed_port: 7890,
    update_interval: 3600, health_check_url: "https://www.gstatic.com/generate_204",
    log_level: "info", tun_enabled: true, tun_exclude_routes: [], domain_rules: [],
  },
  mesh: {
    enabled: false, role: "node", name: "", network_name: "", network_secret: "",
    ipv4: "", listeners: [], peers: [], proxy_networks: [], mesh_routes: [],
    wireguard_listen: "", wireguard_client_cidr: "", wireguard_client_address: "",
  },
}

const navItems = [
  { id: "proxy" as const, label: "代理", icon: ShieldCheck },
  { id: "mesh" as const, label: "Mesh 组网", icon: Network },
  { id: "connections" as const, label: "网络连接", icon: Globe2 },
  { id: "logs" as const, label: "运行日志", icon: ScrollText },
]

function configToForm(state: StateResponse): ConfigPayload {
  const proxy = state.config.proxy ?? {}
  const mesh = proxy.mesh ?? {}
  return {
    proxy: {
      enabled: proxy.enabled ?? false,
      subscriptions: proxy.subscriptions ?? [],
      active_nodes: proxy.active_nodes ?? [],
      gateway: proxy.gateway ?? false,
      mixed_port: proxy.mixed_port ?? 7890,
      update_interval: proxy.update_interval ?? 3600,
      health_check_url: proxy.health_check_url ?? "https://www.gstatic.com/generate_204",
      log_level: proxy.log_level ?? "info",
      tun_enabled: proxy.tun?.enabled ?? true,
      tun_exclude_routes: proxy.tun?.exclude_routes ?? [],
      domain_rules: (proxy.domain_rule ?? []).map((rule) => ({
        enabled: rule.enabled ?? true,
        name: rule.name ?? "",
        by_suffix: rule.by_suffix ?? [],
        host: rule.host ?? [],
        process: rule.process ?? [],
        source: rule.source ?? [],
        destination: rule.destination ?? [],
        outbounds: rule.outbounds ?? [],
        health_check_url: rule.health_check_url ?? null,
        interval: rule.interval ?? null,
        tolerance: rule.tolerance ?? null,
      })),
    },
    mesh: {
      enabled: mesh.enabled ?? false, role: mesh.role ?? "node", name: mesh.name ?? "",
      network_name: mesh.network_name ?? "", network_secret: mesh.network_secret ?? "",
      ipv4: mesh.ipv4 ?? "", listeners: mesh.listeners ?? [], peers: mesh.peers ?? [],
      proxy_networks: mesh.proxy_networks ?? [], mesh_routes: mesh.mesh_routes ?? [],
      wireguard_listen: mesh.wireguard_listen ?? "",
      wireguard_client_cidr: mesh.wireguard_client_cidr ?? "",
      wireguard_client_address: mesh.wireguard_client_address ?? "",
    },
  }
}

const splitLines = (value: string) => value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)

export default function App() {
  const [page, setPage] = useState<Page>("proxy")
  const [state, setState] = useState<StateResponse | null>(null)
  const [form, setForm] = useState<ConfigPayload>(emptyForm)
  const [savedForm, setSavedForm] = useState<ConfigPayload | null>(null)
  const [events, setEvents] = useState<EventRecord[]>([])
  const [eventsPath, setEventsPath] = useState("")
  const [processTraffic, setProcessTraffic] = useState<ProcessTrafficResponse>({ enabled: false, records: [] })
  const [processTrafficBusy, setProcessTrafficBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [restartRequired, setRestartRequired] = useState(false)
  const [notice, setNotice] = useState<Notice>(null)
  const [needsToken, setNeedsToken] = useState(false)
  const [tokenInput, setTokenInput] = useState("")
  const [actionMenuOpen, setActionMenuOpen] = useState(false)
  const [aboutOpen, setAboutOpen] = useState(false)
  const initialized = useRef(false)
  const contentRef = useRef<HTMLDivElement>(null)

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    try {
      const next = await api<StateResponse>("/api/v1/state")
      setState(next); setNeedsToken(false)
      if (!initialized.current) {
        const nextForm = configToForm(next)
        setForm(nextForm); setSavedForm(nextForm); initialized.current = true
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) setNeedsToken(true)
      else if (!quiet) setNotice({ kind: "error", text: error instanceof Error ? error.message : String(error) })
    } finally { if (!quiet) setLoading(false) }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(true), 3000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    if (page !== "logs" && page !== "connections") return
    const load = async () => {
      try {
        const result = await api<EventsResponse>("/api/v1/events")
        setEvents(result.events); setEventsPath(result.path)
      } catch { /* state polling reports authorization and availability */ }
      if (page === "connections") {
        try { setProcessTraffic(await api<ProcessTrafficResponse>("/api/v1/process-traffic")) }
        catch { /* process traffic requires a running proxy core */ }
      }
    }
    void load()
    const timer = window.setInterval(() => void load(), 2500)
    return () => window.clearInterval(timer)
  }, [page])

  useEffect(() => { contentRef.current?.scrollTo({ top: 0 }) }, [page])

  const dirty = useMemo(
    () => savedForm != null && JSON.stringify(form) !== JSON.stringify(savedForm),
    [form, savedForm],
  )

  const updateProxy = <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => {
    setForm((current) => ({ ...current, proxy: { ...current.proxy, [key]: value } }))
  }
  const updateMesh = <K extends keyof ConfigPayload["mesh"]>(key: K, value: ConfigPayload["mesh"][K]) => {
    setForm((current) => ({ ...current, mesh: { ...current.mesh, [key]: value } }))
  }
  const persistConfig = async (submitted: ConfigPayload, restartAfter = false) => {
    setBusy(true); setNotice(null)
    try {
      await api("/api/v1/config", { method: "PUT", body: JSON.stringify(submitted) })
      setForm(submitted); setSavedForm(submitted)
      if (restartAfter && running) {
        const next = await api<StateResponse>("/api/v1/core/restart", { method: "POST" })
        setState(next); setRestartRequired(false)
        setNotice({ kind: "ok", text: "配置已保存并已生效。" })
      } else {
        setRestartRequired(running)
        setNotice({ kind: "ok", text: running ? "配置已保存，重启后生效。" : "配置已保存，下次启动后生效。" })
      }
      await refresh(true)
      return true
    } catch (error) { setNotice({ kind: "error", text: error instanceof Error ? error.message : String(error) }); return false }
    finally { setBusy(false) }
  }
  const save = async () => persistConfig(form)
  const testNodes = async (nodes: string[]) => {
    setBusy(true); setNotice(null)
    try {
      const result = await api<{ results: NodeTestResult[] }>("/api/v1/proxy/nodes/test", { method: "POST", body: JSON.stringify({ nodes }) })
      const ok = result.results.filter((item) => item.latency_ms != null).length
      setNotice({ kind: ok > 0 ? "ok" : "warning", text: `测速完成：${ok}/${result.results.length} 个节点可用。` })
      await refresh(true)
    } catch (error) { setNotice({ kind: "error", text: error instanceof Error ? error.message : String(error) }) }
    finally { setBusy(false) }
  }
  const createConnectionRule = async (rule: DomainRule) => {
    const next = { ...form, proxy: { ...form.proxy, domain_rules: [...form.proxy.domain_rules, rule] } }
    return persistConfig(next, true)
  }
  const toggleProcessTraffic = async (enabled: boolean) => {
    setProcessTrafficBusy(true); setNotice(null)
    try {
      const next = await api<ProcessTrafficResponse>(`/api/v1/process-traffic/${enabled ? "enable" : "disable"}`, { method: "POST" })
      setProcessTraffic(next)
      setNotice({ kind: "ok", text: enabled ? "已开始记录按进程流量；关闭或重启后会清空。" : "已停止记录并清空按进程流量。" })
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : String(error) })
    } finally { setProcessTrafficBusy(false) }
  }
  const coreAction = async (action: "start" | "stop" | "restart") => {
    setBusy(true); setNotice(null)
    try {
      const next = await api<StateResponse>(`/api/v1/core/${action}`, { method: "POST" })
      setState(next); setRestartRequired(false)
      const health = next.core.health
      if (health === "failed") setNotice({ kind: "error", text: next.core.error ?? "启动失败" })
      else if (health === "degraded") setNotice({ kind: "warning", text: next.core.error ?? "部分可用" })
      else setNotice({ kind: "ok", text: action === "stop" ? "已停止" : action === "start" ? "已启动" : "已重启" })
    } catch (error) {
      const text = error instanceof ApiError && error.code === "terminal_authorization_required"
        ? "sudo 授权已失效，请回到终端重新启动 zay webui。"
        : error instanceof Error ? error.message : String(error)
      setNotice({ kind: "error", text })
    } finally { setBusy(false) }
  }
  const exitWebui = async () => {
    if (!window.confirm("退出 WebUI 会同时停止，确定继续吗？")) return
    setBusy(true)
    try {
      await api("/api/v1/exit", { method: "POST" })
      setNotice({ kind: "ok", text: "Zay 已退出，可以关闭此页面。" })
    } catch (error) { setNotice({ kind: "error", text: error instanceof Error ? error.message : String(error) }); setBusy(false) }
  }

  const submitToken = () => { setToken(tokenInput); initialized.current = false; void refresh() }
  const running = state?.core.running ?? false
  const stackState = state?.core.stack?.state ?? (running ? "running" : "stopped")
  const coreHealth = state?.core.health ?? (stackState === "failed" ? "failed" : running ? "healthy" : "stopped")
  const coreFailed = coreHealth === "failed"
  const coreDegraded = coreHealth === "degraded"
  const coreError = state?.core.error ?? state?.core.stack?.error ?? null
  const meshInstances = Array.isArray(state?.mesh) ? state.mesh : []
  const pageLabel = navItems.find((item) => item.id === page)?.label ?? "Zay"
  const hasWorkspaceSidebar = page === "proxy" || page === "mesh"

  return <div className="relative h-screen overflow-hidden bg-background text-foreground">
    <div className="ambient" />
    <aside className="primary-sidebar">
      <nav className="flex w-full flex-col items-center gap-2">{navItems.map(({ id, label, icon: Icon }) => <button key={id} aria-label={label} title={label} onClick={() => setPage(id)} className={cn("primary-nav-item", page === id && "primary-nav-item-active")}><Icon className="h-5 w-5" />{id === "mesh" && form.mesh.enabled && <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-primary" />}</button>)}</nav>
      <button className="relative mt-auto rounded-xl transition hover:brightness-110" aria-label="打开 Zay 菜单" title="Zay 菜单" onClick={() => setActionMenuOpen((open) => !open)}><img src="/logo.svg" alt="" className="brand-mark h-10 w-10" /><span className={cn("absolute -right-0.5 -top-0.5 h-3 w-3 rounded-full border-2 border-card bg-muted", running && !coreFailed && !coreDegraded && "bg-emerald-400 pulse-dot", coreDegraded && "bg-amber-400", coreFailed && "bg-red-400")} /></button>
    </aside>

    {actionMenuOpen && <ActionMenu running={running} loading={loading} busy={busy} onClose={() => setActionMenuOpen(false)} onRefresh={() => void refresh()} onCoreAction={(action) => void coreAction(action)} onAbout={() => setAboutOpen(true)} onExit={() => void exitWebui()} />}

    <main className={cn("relative flex h-full min-w-0 flex-col", hasWorkspaceSidebar ? "lg:ml-[292px]" : "lg:ml-[72px]")}>
      <header className="z-20 shrink-0 border-b border-white/5 bg-background/80 px-4 py-3 backdrop-blur-xl md:px-8">
        <div className="mx-auto flex max-w-[1500px] items-center gap-4">
          <button className="lg:hidden" aria-label="打开 Zay 菜单" onClick={() => setActionMenuOpen((open) => !open)}><img src="/logo.svg" alt="" className="brand-mark h-8 w-8" /></button>
          <div className="min-w-0"><div className="text-base font-semibold">{pageLabel}</div><div className="hidden text-xs text-muted-foreground sm:block">Zay 网络控制台</div></div>
          <div className="ml-auto flex items-center gap-1.5">
            <Badge variant="outline" className={cn("mr-1 hidden gap-1.5 border-white/10 bg-card/60 sm:flex", running && !coreFailed && !coreDegraded && "text-emerald-400", coreDegraded && "text-amber-300", coreFailed && "text-red-300")}><span className={cn("h-1.5 w-1.5 rounded-full bg-muted", running && !coreFailed && !coreDegraded && "bg-emerald-400 pulse-dot", coreDegraded && "bg-amber-400", coreFailed && "bg-red-400")} />{coreFailed ? "异常" : coreDegraded ? "部分可用" : running ? "运行中" : "已停止"}</Badge>
          </div>
        </div>
        <div className="mx-auto mt-3 flex max-w-[1500px] justify-between gap-1 lg:hidden">{navItems.map(({ id, label, icon: Icon }) => <Button key={id} size="icon" variant={page === id ? "secondary" : "ghost"} title={label} aria-label={label} onClick={() => setPage(id)}><Icon className="h-4 w-4" /></Button>)}</div>
      </header>

      <div ref={contentRef} id="main-scroll" className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
        <div className="mx-auto max-w-[1500px] p-4 md:p-8">
          {notice && <NoticeBar notice={notice} onClose={() => setNotice(null)} />}
          {restartRequired && <RestartBar busy={busy} onRestart={() => void coreAction("restart")} />}
          {coreFailed && coreError && <CoreAlert kind="error" error={coreError} busy={busy} onRestart={() => void coreAction("restart")} onLogs={() => setPage("logs")} />}
          {coreDegraded && coreError && <CoreAlert kind="warning" error={coreError} busy={busy} onRestart={() => void coreAction("restart")} onLogs={() => setPage("logs")} />}
          {loading && !state ? <Loading /> : page === "proxy" ? <ProxyWorkspace form={form} update={updateProxy} nodes={state?.proxy_nodes ?? []} ruleSets={state?.rule_sets ?? { builtin: [], external: [] }} busy={busy} onTestNodes={(nodes) => void testNodes(nodes)} onApplyProvider={() => void persistConfig(form, true)} onSectionChange={() => contentRef.current?.scrollTo({ top: 0 })} onRulesChanged={() => { setRestartRequired(running); void refresh(true) }} onApply={() => void persistConfig(form, true)} />
            : page === "mesh" ? <MeshWorkspace form={form} update={updateMesh} instances={meshInstances} onSectionChange={() => contentRef.current?.scrollTo({ top: 0 })} />
            : page === "connections" ? <Connections events={events} nodes={state?.proxy_nodes ?? []} subscriptions={form.proxy.subscriptions} busy={busy} processTraffic={processTraffic} processTrafficBusy={processTrafficBusy} onToggleProcessTraffic={(enabled) => void toggleProcessTraffic(enabled)} onCreateRule={createConnectionRule} />
            : <RuntimeLogs events={events} path={eventsPath} />}
        </div>
      </div>
      {hasWorkspaceSidebar && <SaveBar dirty={dirty} busy={busy} restartRequired={restartRequired} onSave={() => void save()} />}
    </main>

    {needsToken && <TokenGate value={tokenInput} setValue={setTokenInput} submit={submitToken} />}
    {aboutOpen && <AboutDialog state={state} onClose={() => setAboutOpen(false)} />}
  </div>
}

function ActionMenu({ running, loading, busy, onClose, onRefresh, onCoreAction, onAbout, onExit }: { running: boolean; loading: boolean; busy: boolean; onClose: () => void; onRefresh: () => void; onCoreAction: (action: "start" | "stop" | "restart") => void; onAbout: () => void; onExit: () => void }) {
  const run = (action: () => void) => { onClose(); action() }
  return <><button className="fixed inset-0 z-40 cursor-default bg-black/10" aria-label="关闭 Zay 菜单" onClick={onClose} /><div className="fixed bottom-4 left-4 z-50 w-60 rounded-xl border border-border bg-card/95 p-2 shadow-2xl backdrop-blur-xl lg:left-[60px]">
    <div className="mb-1 px-3 py-2"><div className="text-sm font-semibold">Zay</div><div className="text-[11px] text-muted-foreground">{running ? "已启动" : "未启动"}</div></div>
    <MenuAction icon={RefreshCw} label="刷新状态" disabled={loading} spin={loading} onClick={() => run(onRefresh)} />
    <MenuAction icon={running ? CircleStop : Play} label={running ? "停止" : "启动"} danger={running} disabled={busy} onClick={() => run(() => onCoreAction(running ? "stop" : "start"))} />
    <MenuAction icon={RotateCw} label="重启" disabled={busy || !running} onClick={() => run(() => onCoreAction("restart"))} />
    <div className="my-1 h-px bg-border" />
    <MenuAction icon={Info} label="关于 Zay" onClick={() => run(onAbout)} />
    <MenuAction icon={Power} label="退出 Zay" danger disabled={busy} onClick={() => run(onExit)} />
  </div></>
}

function MenuAction({ icon: Icon, label, disabled, danger, spin, onClick }: { icon: typeof Activity; label: string; disabled?: boolean; danger?: boolean; spin?: boolean; onClick: () => void }) { return <button className={cn("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-muted-foreground transition hover:bg-white/5 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40", danger && "hover:bg-red-500/10 hover:text-red-300")} disabled={disabled} onClick={onClick}><Icon className={cn("h-4 w-4", spin && "animate-spin")} /><span>{label}</span></button> }

function AboutDialog({ state, onClose }: { state: StateResponse | null; onClose: () => void }) { return <div className="fixed inset-0 z-[70] grid place-items-center bg-black/70 p-4 backdrop-blur-md" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><Card className="w-full max-w-lg shadow-glow"><CardHeader><div className="flex items-start gap-4"><img src="/logo.svg" alt="" className="brand-mark h-12 w-12" /><div><CardTitle>关于 Zay</CardTitle><CardDescription className="mt-1">统一管理代理、Mesh 与网络诊断。</CardDescription></div></div></CardHeader><CardContent className="space-y-4"><div className="grid gap-3 rounded-lg border border-border bg-background/40 p-4 text-sm"><AboutRow label="版本" value={state?.version ?? "—"} /><AboutRow label="平台" value={state ? `${state.platform.os} / ${state.platform.arch}` : "—"} mono /><AboutRow label="进程识别" value={state?.platform.process_attribution ?? "—"} mono /><AboutRow label="配置" value={state?.paths.config ?? "—"} mono /><AboutRow label="数据" value={state?.paths.data_dir ?? "—"} mono /><AboutRow label="日志策略" value="滚动保留，目录总量最多 200 MB" /></div><p className="text-xs leading-5 text-muted-foreground">WebUI 随当前前台进程运行，不创建守护进程或系统服务。</p><Button className="w-full" variant="outline" onClick={onClose}>关闭</Button></CardContent></Card></div> }
function AboutRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div className="grid grid-cols-[68px_1fr] gap-3"><span className="text-muted-foreground">{label}</span><span className={cn("min-w-0 break-all", mono && "font-mono text-xs")}>{value}</span></div> }

function SaveBar({ dirty, busy, restartRequired, onSave }: { dirty: boolean; busy: boolean; restartRequired: boolean; onSave: () => void }) { const status = dirty ? "有尚未保存的修改" : restartRequired ? "配置已保存，等待重启生效" : "配置已同步"; return <div className="z-20 shrink-0 border-t border-white/5 bg-background/90 px-4 py-3 backdrop-blur-xl md:px-8"><div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4"><div className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground"><span className={cn("h-2 w-2 shrink-0 rounded-full", dirty ? "bg-amber-400" : "bg-emerald-400")} /><span className="truncate">{status}</span></div><Button onClick={onSave} disabled={!dirty || busy}><Save className="h-4 w-4" />{busy ? "保存中…" : dirty ? "保存配置" : "已保存"}</Button></div></div> }
function NoticeBar({ notice, onClose }: { notice: Exclude<Notice, null>; onClose: () => void }) { const Icon = notice.kind === "ok" ? CheckCircle2 : TriangleAlert; return <div className={cn("mb-5 flex items-start gap-3 rounded-xl border p-3 text-sm", notice.kind === "ok" ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : notice.kind === "warning" ? "border-amber-500/25 bg-amber-500/10 text-amber-200" : "border-destructive/30 bg-destructive/10 text-red-300")}><Icon className="mt-0.5 h-4 w-4 shrink-0" /><span className="flex-1">{notice.text}</span><button onClick={onClose} className="opacity-60 hover:opacity-100">×</button></div> }
function RestartBar({ busy, onRestart }: { busy: boolean; onRestart: () => void }) { return <div className="mb-5 flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/10 p-4"><TriangleAlert className="h-5 w-5 text-amber-400" /><div className="flex-1"><div className="text-sm font-medium">配置变更等待应用</div><div className="text-xs text-muted-foreground">重启后新配置生效，页面保持打开。</div></div><Button size="sm" variant="outline" onClick={onRestart} disabled={busy}><RotateCw className="h-4 w-4" />重启</Button></div> }
function CoreAlert({ kind, error, busy, onRestart, onLogs }: { kind: "error" | "warning"; error: string; busy: boolean; onRestart: () => void; onLogs: () => void }) { return <div className={cn("mb-5 rounded-xl border p-4", kind === "error" ? "border-red-500/30 bg-red-500/10" : "border-amber-500/30 bg-amber-500/10")}><div className="flex items-start gap-3"><TriangleAlert className={cn("mt-0.5 h-5 w-5", kind === "error" ? "text-red-300" : "text-amber-300")} /><div className="min-w-0 flex-1"><div className="font-medium">{kind === "error" ? "启动失败" : "部分可用"}</div><pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-black/20 p-3 font-mono text-xs text-foreground/75">{friendlyCoreError(error)}</pre><div className="mt-3 flex gap-2"><Button size="sm" variant="outline" onClick={onRestart} disabled={busy}><RotateCw className="h-4 w-4" />重试</Button><Button size="sm" variant="ghost" onClick={onLogs}><ScrollText className="h-4 w-4" />日志</Button></div></div></div></div> }
function friendlyCoreError(error: string) { const lower = error.toLowerCase(); if (lower.includes("proxy health check failed") && lower.includes("timed out")) return `代理真实连通性检查超时。请检查激活节点、订阅和物理网络。\n\n${error}`; if (lower.includes("address already in use")) return `监听端口已被占用。${error}`; if (error.includes("another full-route TUN")) return "检测到另一个全局 TUN。请关闭 Clash Verge 等其他 TUN 后重试。"; return error }
function Loading() { return <div className="grid min-h-[55vh] place-items-center text-muted-foreground"><div className="text-center"><LoaderCircle className="mx-auto mb-3 h-7 w-7 animate-spin text-primary" />正在连接 Zay…</div></div> }

function Metric({ icon: Icon, label, value, detail, active, failed }: { icon: typeof Activity; label: string; value: string; detail: string; active?: boolean; failed?: boolean }) { return <Card className={cn("metric-card", failed && "border-red-500/25")}><CardContent className="p-5"><div className="flex items-center justify-between"><div className={cn("icon-tile", failed && "border-red-500/25 bg-red-500/10 text-red-300")}><Icon className="h-4 w-4" /></div><span className={cn("h-2 w-2 rounded-full bg-muted", active && "bg-primary", failed && "bg-red-400")} /></div><div className="mt-5 text-xs uppercase tracking-widest text-muted-foreground">{label}</div><div className="mt-1 text-2xl font-semibold">{value}</div><div className="mt-1 truncate text-xs text-muted-foreground" title={detail}>{detail}</div></CardContent></Card> }
type ProxySection = "providers" | "nodes" | "rules" | "settings"
function ProxyWorkspace({ form, update, nodes, ruleSets, busy, onTestNodes, onApplyProvider, onSectionChange, onRulesChanged, onApply }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; nodes: ProxyNode[]; ruleSets: { builtin: RuleSetEntry[]; external: RuleSetEntry[] }; busy: boolean; onTestNodes: (nodes: string[]) => void; onApplyProvider: () => void; onSectionChange: () => void; onRulesChanged: () => void; onApply: () => void }) { const [section, setSection] = useState<ProxySection>("providers"); return <Workspace title="代理" description="订阅、节点池、规则与系统流量设置" icon={ShieldCheck} nav={[{ id: "providers", label: "代理商", icon: Users, count: form.proxy.subscriptions.length }, { id: "nodes", label: "节点列表", icon: List, count: nodes.length }, { id: "rules", label: "规则集", icon: FileJson, count: ruleSets.builtin.length + ruleSets.external.length + form.proxy.domain_rules.length }, { id: "settings", label: "设置", icon: Settings2 }]} section={section} setSection={(value) => setSection(value as ProxySection)} onSectionChange={onSectionChange}>{section === "providers" ? <Providers form={form} update={update} nodes={nodes} busy={busy} onApply={onApplyProvider} onQuickApply={onApply} /> : section === "nodes" ? <ProxyNodes form={form} update={update} nodes={nodes} busy={busy} onTestNodes={onTestNodes} /> : section === "rules" ? <RulesPanel form={form} update={update} ruleSets={ruleSets} onRulesChanged={onRulesChanged} /> : <ProxySettings form={form} update={update} />}</Workspace> }
function Providers({ form, update, nodes, busy, onApply, onQuickApply }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; nodes: ProxyNode[]; busy: boolean; onApply: () => void; onQuickApply: () => void }) {
  const [candidate, setCandidate] = useState("")
  const [selected, setSelected] = useState<number | null>(null)
  const add = () => { const value = candidate.trim(); if (!value || form.proxy.subscriptions.includes(value)) return; update("subscriptions", [...form.proxy.subscriptions, value]); setCandidate(""); setSelected(form.proxy.subscriptions.length) }
  const remove = (index: number) => { if (!window.confirm(`删除 ${providerName(form.proxy.subscriptions[index], index)}？`)) return; update("subscriptions", form.proxy.subscriptions.filter((_, item) => item !== index)); update("active_nodes", form.proxy.active_nodes.flatMap((tag) => { const match = /^sub(\d+)-(.*)$/.exec(tag); if (!match) return [tag]; const provider = Number(match[1]); if (provider === index) return []; return [provider > index ? `sub${provider - 1}-${match[2]}` : tag] })); setSelected(null) }
  if (selected != null && form.proxy.subscriptions[selected] != null) {
    const providerNodes = nodes.filter((node) => node.provider_index === selected)
    const protocols = [...new Set(providerNodes.map((node) => node.protocol.toUpperCase()))]
    const setUrl = (url: string) => update("subscriptions", form.proxy.subscriptions.map((item, index) => index === selected ? url : item))
    return <div className="space-y-5"><BackTitle title={providerName(form.proxy.subscriptions[selected], selected)} description="代理商详情、订阅地址与节点清单" onBack={() => setSelected(null)} /><Card><CardHeader><CardTitle className="text-base">订阅配置</CardTitle><CardDescription>修改后点击“更新代理商”，会保存配置、重启并重新拉取订阅。</CardDescription></CardHeader><CardContent className="space-y-4"><Field label="订阅 URL"><Input value={form.proxy.subscriptions[selected]} onChange={(event) => setUrl(event.target.value)} /></Field><div className="grid gap-3 sm:grid-cols-3"><ProviderStat label="节点" value={String(providerNodes.length)} /><ProviderStat label="协议" value={protocols.join(" / ") || "—"} /><ProviderStat label="已测速" value={String(providerNodes.filter((node) => node.latency_ms != null).length)} /></div><div className="flex flex-wrap gap-2"><Button onClick={onApply} disabled={busy || !form.proxy.subscriptions[selected].trim()}><RefreshCw className={cn("h-4 w-4", busy && "animate-spin")} />更新代理商</Button><Button variant="outline" onClick={() => remove(selected)} disabled={busy}><Trash2 className="h-4 w-4" />删除</Button></div></CardContent></Card><DataTable headers={["节点", "协议", "服务器", "延迟"]}>{providerNodes.map((node) => <tr key={node.id} className="table-row"><td className="max-w-72 truncate font-medium">{node.name}</td><td><Badge variant="outline">{node.protocol.toUpperCase()}</Badge></td><td className="font-mono text-xs">{node.server ? `${node.server}:${node.port ?? ""}` : "—"}</td><td>{node.latency_ms == null ? "—" : <Latency value={node.latency_ms} />}</td></tr>)}</DataTable>{providerNodes.length === 0 && <Empty icon={Radio} title="尚无节点" text="保存并更新代理商后会载入订阅节点。" />}</div>
  }
  return <div className="space-y-5"><QuickSettings form={form} update={update} busy={busy} onApply={onQuickApply} /><PageTitle title="代理商" description="不添加订阅时流量走直连。添加后，规则命中的流量才走代理。" /><Card><CardContent className="flex gap-2 p-4"><Input value={candidate} onChange={(event) => setCandidate(event.target.value)} onKeyDown={(event) => event.key === "Enter" && add()} placeholder="https://provider.example/subscription" /><Button onClick={add} disabled={!candidate.trim()}><Plus className="h-4 w-4" />添加</Button></CardContent></Card><div className="grid gap-3 xl:grid-cols-2">{form.proxy.subscriptions.map((url, index) => { const count = nodes.filter((node) => node.provider_index === index).length; return <Card key={`${index}-${url}`} className="cursor-pointer transition hover:border-primary/30" onClick={() => setSelected(index)}><CardContent className="flex items-center gap-4 p-5"><div className="icon-tile"><Radio className="h-4 w-4" /></div><div className="min-w-0 flex-1"><div className="font-medium">{providerName(url, index)}</div><div className="mt-1 truncate text-xs text-muted-foreground" title={redactedProviderUrl(url)}>{redactedProviderUrl(url)}</div><div className="mt-2 text-xs text-primary">{count} 个可用节点</div></div><div className="flex gap-1"><Button size="icon" variant="ghost" title="编辑" onClick={(event) => { event.stopPropagation(); setSelected(index) }}><Pencil className="h-4 w-4" /></Button><Button size="icon" variant="ghost" title="更新" disabled={busy} onClick={(event) => { event.stopPropagation(); onApply() }}><RefreshCw className={cn("h-4 w-4", busy && "animate-spin")} /></Button><Button size="icon" variant="ghost" className="text-muted-foreground hover:text-red-300" onClick={(event) => { event.stopPropagation(); remove(index) }} title="删除代理商"><Trash2 className="h-4 w-4" /></Button></div></CardContent></Card> })}</div>{form.proxy.subscriptions.length === 0 && <Empty icon={Users} title="当前为直连" text="没有订阅时，系统流量直接访问目标。需要代理时再添加订阅地址。" />}</div>
}
function QuickSettings({ form, update, busy, onApply }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; busy: boolean; onApply: () => void }) {
  const direct = form.proxy.subscriptions.length === 0
  const p = form.proxy
  return <Card><CardHeader><CardTitle>快捷设置</CardTitle><CardDescription>{direct ? "未配置代理，流量走直连。" : "已配置订阅，按规则分流；未命中的流量走直连。"} 修改后点应用即可保存；已启动时会立即生效。</CardDescription></CardHeader><CardContent className="space-y-5"><div className="grid gap-4 md:grid-cols-2"><ToggleRow title="TUN 模式" description="接管系统流量，需要终端 sudo 授权" checked={p.tun_enabled} onChecked={(value) => update("tun_enabled", value)} /><ToggleRow title="局域网网关" description="允许其他设备使用本机出口" checked={p.gateway} onChecked={(value) => update("gateway", value)} /></div><div className="flex flex-wrap items-end gap-3"><Field label={p.tun_enabled ? "Mixed 端口（TUN 下不监听）" : "Mixed 端口"}><Input type="number" min={1} max={65535} value={p.mixed_port} disabled={p.tun_enabled} onChange={(event) => update("mixed_port", Number(event.target.value))} /></Field><Button onClick={onApply} disabled={busy}><Save className="h-4 w-4" />应用</Button></div></CardContent></Card>
}
function ProviderStat({ label, value }: { label: string; value: string }) { return <div className="rounded-lg border border-border bg-background/40 p-3"><div className="text-[11px] text-muted-foreground">{label}</div><div className="mt-1 truncate text-sm font-medium" title={value}>{value}</div></div> }
function ProxyNodes({ form, update, nodes, busy, onTestNodes }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; nodes: ProxyNode[]; busy: boolean; onTestNodes: (nodes: string[]) => void }) { const [query, setQuery] = useState(""); const allActive = form.proxy.active_nodes.length === 0; const activeSet = useMemo(() => new Set(allActive ? nodes.map((node) => node.id) : form.proxy.active_nodes), [allActive, form.proxy.active_nodes, nodes]); const activeNodes = nodes.filter((node) => activeSet.has(node.id)); const filtered = nodes.filter((node) => `${node.name} ${node.protocol} ${node.server ?? ""} ${providerName(form.proxy.subscriptions[node.provider_index], node.provider_index)}`.toLowerCase().includes(query.toLowerCase())); const toggle = (id: string) => { const next = new Set(activeSet); if (next.has(id)) next.delete(id); else next.add(id); update("active_nodes", nodes.filter((node) => next.has(node.id)).map((node) => node.id)) }; return <div className="space-y-5"><PageTitle title="节点列表" description="激活节点构成实际流量候选池；测速请求由运行中的 sing-box 出站直接执行。" /><Card className="border-primary/20"><CardHeader><div className="flex items-center justify-between"><div><CardTitle className="text-base">激活节点</CardTitle><CardDescription>{allActive ? "当前兼容模式：全部节点均可参与流量选择" : `${activeNodes.length} 个节点参与流量选择`}</CardDescription></div><Badge>{activeNodes.length}</Badge></div></CardHeader><CardContent className="flex gap-2 overflow-x-auto pb-5">{activeNodes.slice(0, 12).map((node) => <div key={node.id} className="min-w-52 rounded-lg border border-primary/20 bg-primary/5 p-3"><div className="truncate text-sm font-medium">{node.name}</div><div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground"><span>{providerName(form.proxy.subscriptions[node.provider_index], node.provider_index)}</span><span>·</span><span>{node.protocol.toUpperCase()}</span></div></div>)}{activeNodes.length === 0 && <span className="text-sm text-muted-foreground">尚未选择节点</span>}</CardContent></Card><div className="flex flex-wrap items-center gap-3"><div className="relative min-w-64 max-w-md flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索节点、协议、地址或代理商" /></div><Button variant="outline" onClick={() => update("active_nodes", [])}>全部激活</Button><Button variant="outline" disabled={busy || filtered.length === 0} onClick={() => onTestNodes(filtered.map((node) => node.id))}><Activity className={cn("h-4 w-4", busy && "animate-pulse")} />{query ? "测速筛选结果" : "全部测速"}</Button></div><DataTable headers={["", "代理商", "节点名称", "协议", "服务器", "TLS", "延迟", "操作"]}>{filtered.map((node) => { const active = activeSet.has(node.id); return <tr key={node.id} className={cn("table-row", active && "bg-primary/[.035]")}><td><button onClick={() => toggle(node.id)} className={cn("grid h-5 w-5 place-items-center rounded border", active ? "border-primary bg-primary text-primary-foreground" : "border-border")} aria-label={active ? "取消激活" : "激活"}>{active && <Check className="h-3.5 w-3.5" />}</button></td><td>{providerName(form.proxy.subscriptions[node.provider_index], node.provider_index)}</td><td className="max-w-72 truncate font-medium" title={node.name}>{node.name}</td><td><Badge variant="outline">{node.protocol.toUpperCase()}</Badge></td><td className="font-mono text-xs">{node.server ? `${node.server}:${node.port ?? ""}` : "—"}</td><td>{node.tls ? "是" : "—"}</td><td title={node.latency_error ?? node.latency_checked_at ?? ""}>{node.latency_ms == null ? <span className={cn("text-muted-foreground", node.latency_error && "text-red-300")}>{node.latency_error ? "失败" : "待测速"}</span> : <Latency value={node.latency_ms} />}</td><td><div className="flex items-center gap-2"><span className={cn("status-pill", active && "status-pill-active")}>{active ? "激活" : "可用"}</span><Button size="sm" variant="ghost" disabled={busy} onClick={() => onTestNodes([node.id])}>测速</Button></div></td></tr> })}</DataTable>{nodes.length === 0 && <Empty icon={List} title="没有载入节点" text="请先添加代理商并保存，然后重启。" />}</div> }

type RuleGroup = "builtin" | "external" | "custom"
function RulesPanel({ form, update, ruleSets, onRulesChanged }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; ruleSets: { builtin: RuleSetEntry[]; external: RuleSetEntry[] }; onRulesChanged: () => void }) {
  const [group, setGroup] = useState<RuleGroup | null>(null)
  if (group === "builtin") return <RuleFileGroup title="内置规则集" description="随 Zay 发布，只读并在版本升级时更新。" group="builtin" entries={ruleSets.builtin} onBack={() => setGroup(null)} onChanged={onRulesChanged} />
  if (group === "external") return <RuleFileGroup title="外部规则集" description="运行时下载的规则；JSON 可直接编辑，所有格式均可上传替换。" group="external" entries={ruleSets.external} onBack={() => setGroup(null)} onChanged={onRulesChanged} />
  if (group === "custom") return <CustomRules form={form} update={update} onBack={() => setGroup(null)} />
  return <div className="space-y-5"><PageTitle title="规则集" description="内置、外部与自定义规则分组管理。" /><div className="grid gap-4 md:grid-cols-3"><RuleGroupCard icon={ShieldCheck} title="内置规则集" description="Zay 内置的基础分流规则，只读。" count={ruleSets.builtin.length} onClick={() => setGroup("builtin")} /><RuleGroupCard icon={Database} title="外部规则集" description="在线下载或手动替换的规则文件。" count={ruleSets.external.length} onClick={() => setGroup("external")} /><RuleGroupCard icon={Pencil} title="自定义规则" description="按域名后缀指定代理候选节点。" count={form.proxy.domain_rules.length} onClick={() => setGroup("custom")} /></div></div>
}
function RuleGroupCard({ icon: Icon, title, description, count, onClick }: { icon: typeof Activity; title: string; description: string; count: number; onClick: () => void }) { return <button onClick={onClick} className="group rounded-xl border border-border bg-card/65 p-5 text-left transition hover:-translate-y-0.5 hover:border-primary/35"><div className="flex items-center gap-3"><div className="icon-tile"><Icon className="h-4 w-4" /></div><div className="font-medium">{title}</div><Badge variant="secondary" className="ml-auto">{count}</Badge></div><p className="mt-4 text-sm leading-6 text-muted-foreground">{description}</p><div className="mt-4 flex items-center gap-1 text-xs text-primary">进入分组 <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-1" /></div></button> }

function RuleFileGroup({ title, description, group, entries, onBack, onChanged }: { title: string; description: string; group: "builtin" | "external"; entries: RuleSetEntry[]; onBack: () => void; onChanged: () => void }) {
  const [selected, setSelected] = useState<RuleSetContent | null>(null)
  const [draft, setDraft] = useState("")
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const open = async (entry: RuleSetEntry) => { setBusy(true); setMessage(""); try { const value = await api<RuleSetContent>(`/api/v1/rules/${group}/${encodeURIComponent(entry.name)}`); setSelected(value); setDraft(value.content ?? "") } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } finally { setBusy(false) } }
  const saveText = async () => { if (!selected) return; setBusy(true); setMessage(""); try { await uploadRuleSet(`/api/v1/rules/external/${encodeURIComponent(selected.name)}`, draft); setMessage("规则集已保存，重启后生效。"); onChanged() } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } finally { setBusy(false) } }
  const upload = async (file: File, name?: string) => { setBusy(true); setMessage(""); try { const target = name ?? file.name; await uploadRuleSet(`/api/v1/rules/external/${encodeURIComponent(target)}`, file); setMessage("规则文件已替换，重启后生效。"); onChanged(); if (selected) await open({ ...selected, name: target }) } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } finally { setBusy(false) } }
  if (selected) return <div className="space-y-5"><BackTitle title={selected.name} description={`${title} · ${formatBytes(selected.bytes)} · ${selected.format.toUpperCase()}`} onBack={() => setSelected(null)} />{message && <InlineMessage text={message} />}{selected.binary ? <Card><CardHeader><CardTitle>二进制规则</CardTitle><CardDescription>SRS 不能作为文本编辑，可上传新的同格式文件进行替换。</CardDescription></CardHeader><CardContent>{group === "external" ? <FileButton label="上传替换文件" disabled={busy} onFile={(file) => void upload(file, selected.name)} /> : <p className="text-sm text-muted-foreground">内置规则不可修改。</p>}</CardContent></Card> : <Card><CardHeader><CardTitle>规则内容</CardTitle><CardDescription>{group === "builtin" ? "内置规则为只读。" : "保存时会校验 sing-box JSON 规则结构。"}</CardDescription></CardHeader><CardContent className="space-y-4"><textarea value={draft} readOnly={group === "builtin"} onChange={(event) => setDraft(event.target.value)} rows={22} className="flex w-full resize-y rounded-md border border-input bg-background/70 px-3 py-3 font-mono text-xs leading-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" />{group === "external" && <div className="flex flex-wrap gap-2"><Button onClick={() => void saveText()} disabled={busy}><Save className="h-4 w-4" />保存规则</Button><FileButton label="上传替换" disabled={busy} onFile={(file) => void upload(file, selected.name)} /></div>}</CardContent></Card>}</div>
  return <div className="space-y-5"><BackTitle title={title} description={description} onBack={onBack} />{message && <InlineMessage text={message} />}<div className="grid gap-3">{entries.map((entry) => <button key={entry.name} onClick={() => void open(entry)} className="flex items-center gap-4 rounded-xl border border-border bg-card/55 p-4 text-left transition hover:border-primary/30"><div className="icon-tile"><FileJson className="h-4 w-4" /></div><div className="min-w-0 flex-1"><div className="truncate font-medium">{entry.id}</div><div className="mt-1 text-xs text-muted-foreground">{entry.name} · {formatBytes(entry.bytes)}</div></div><Badge variant="outline">{entry.format.toUpperCase()}</Badge><ArrowRight className="h-4 w-4 text-muted-foreground" /></button>)}</div>{entries.length === 0 && <Empty icon={FileJson} title="没有规则文件" text={group === "external" ? "下载完成后会显示在这里。" : "启动后会解压内置规则。"} />}{group === "external" && <Card><CardHeader><CardTitle className="text-base">导入外部规则</CardTitle><CardDescription>上传名称以 .json 或 .srs 结尾的 sing-box 规则集。</CardDescription></CardHeader><CardContent><FileButton label="选择规则文件" disabled={busy} onFile={(file) => void upload(file)} /></CardContent></Card>}</div>
}

function CustomRules({ form, update, onBack }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void; onBack: () => void }) {
  type Rule = ConfigPayload["proxy"]["domain_rules"][number]
  const [editing, setEditing] = useState<number | "new" | null>(null)
  const blankRule = (): Rule => ({ enabled: true, name: "", by_suffix: [], host: [], process: [], source: [], destination: [], outbounds: ["Proxy"], health_check_url: null, interval: null, tolerance: null })
  const [draft, setDraft] = useState<Rule>(blankRule)
  const edit = (index: number) => { setEditing(index); const rule = form.proxy.domain_rules[index]; setDraft({ ...rule, by_suffix: [...rule.by_suffix], host: [...rule.host], process: [...rule.process], source: [...rule.source], destination: [...rule.destination], outbounds: [...rule.outbounds] }) }
  const create = () => { setEditing("new"); setDraft(blankRule()) }
  const valid = draft.name.trim() && ruleHasMatcher(draft) && draft.outbounds.length > 0
  const commit = () => { if (!valid) return; const next = [...form.proxy.domain_rules]; if (editing === "new") next.push(draft); else if (typeof editing === "number") next[editing] = draft; update("domain_rules", next); setEditing(null) }
  const remove = (index: number) => update("domain_rules", form.proxy.domain_rules.filter((_, item) => item !== index))
  if (editing != null) return <div className="space-y-5"><BackTitle title={editing === "new" ? "新增自定义规则" : `编辑 ${draft.name}`} description="Host、Process、Source、Destination 条件可单独或组合使用。" onBack={() => setEditing(null)} /><Card><CardContent className="space-y-4 pt-6"><ToggleRow title="启用规则" description="关闭后保留配置但不参与路由" checked={draft.enabled} onChecked={(enabled) => setDraft({ ...draft, enabled })} /><Field label="规则名称"><Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="github-fast" /></Field><div className="grid gap-4 lg:grid-cols-2"><TextArea label="Host（每行一个，支持 *.example.com）" value={[...draft.host, ...draft.by_suffix.map((value) => `*.${value}`)].join("\n")} onChange={(value) => setDraft({ ...draft, host: splitLines(value), by_suffix: [] })} placeholder="github.com\n*.githubusercontent.com" /><TextArea label="Process（名称或完整路径）" value={draft.process.join("\n")} onChange={(value) => setDraft({ ...draft, process: splitLines(value) })} placeholder="/Applications/Cursor.app/Contents/MacOS/Cursor" /><TextArea label="Source（IP、CIDR 或 IP:端口）" value={draft.source.join("\n")} onChange={(value) => setDraft({ ...draft, source: splitLines(value) })} placeholder="10.14.14.1" /><TextArea label="Destination（域名、IP、CIDR 或 IP:端口）" value={draft.destination.join("\n")} onChange={(value) => setDraft({ ...draft, destination: splitLines(value) })} placeholder="140.82.112.4:443" /></div><TextArea label="出站节点标签（每行一个）" value={draft.outbounds.join("\n")} onChange={(value) => setDraft({ ...draft, outbounds: splitLines(value) })} placeholder="sub0-节点名称\nProxy" /><div className="form-grid"><Field label="健康检查 URL"><Input value={draft.health_check_url ?? ""} onChange={(event) => setDraft({ ...draft, health_check_url: event.target.value || null })} placeholder="留空使用全局设置" /></Field><Field label="检查间隔（秒）"><Input type="number" min={1} value={draft.interval ?? ""} onChange={(event) => setDraft({ ...draft, interval: event.target.value ? Number(event.target.value) : null })} /></Field><Field label="切换容差（毫秒）"><Input type="number" min={0} value={draft.tolerance ?? ""} onChange={(event) => setDraft({ ...draft, tolerance: event.target.value ? Number(event.target.value) : null })} /></Field></div><Button onClick={commit} disabled={!valid}><Save className="h-4 w-4" />保存到配置</Button></CardContent></Card></div>
  const toggleEnabled = (index: number, enabled: boolean) => update("domain_rules", form.proxy.domain_rules.map((rule, item) => item === index ? { ...rule, enabled } : rule))
  return <div className="space-y-5"><BackTitle title="自定义规则" description="支持 Host 通配符、进程、源地址和目标地址匹配。" onBack={onBack} /><div className="flex justify-end"><Button onClick={create}><Plus className="h-4 w-4" />新增规则</Button></div><div className="grid gap-3">{form.proxy.domain_rules.map((rule, index) => <div key={`${rule.name}-${index}`} className={cn("flex items-center gap-4 rounded-xl border border-border bg-card/55 p-4", !rule.enabled && "opacity-60")}><div className="icon-tile"><Pencil className="h-4 w-4" /></div><button className="min-w-0 flex-1 text-left" onClick={() => edit(index)}><div className="flex items-center gap-2"><span className="font-medium">{rule.name}</span><span className={cn("status-pill", rule.enabled && "status-pill-active")}>{rule.enabled ? "启用" : "停用"}</span></div><div className="mt-1 truncate text-xs text-muted-foreground">{ruleMatchSummary(rule)} → {rule.outbounds.join("、")}</div></button><Switch checked={rule.enabled} onCheckedChange={(enabled) => toggleEnabled(index, enabled)} /><Button size="icon" variant="ghost" title="编辑" onClick={() => edit(index)}><Pencil className="h-4 w-4" /></Button><Button size="icon" variant="ghost" className="text-muted-foreground hover:text-red-300" title="删除" onClick={() => remove(index)}><Trash2 className="h-4 w-4" /></Button></div>)}</div>{form.proxy.domain_rules.length === 0 && <Empty icon={Pencil} title="没有自定义规则" text="新增规则后可为特定连接单独指定节点候选池。" />}</div>
}
function ruleHasMatcher(rule: DomainRule) { return rule.by_suffix.length + rule.host.length + rule.process.length + rule.source.length + rule.destination.length > 0 }
function ruleMatchSummary(rule: DomainRule) { const items = [...rule.host, ...rule.by_suffix.map((value) => `*.${value}`), ...rule.process, ...rule.source, ...rule.destination]; return items.join("、") || "无匹配条件" }
function BackTitle({ title, description, onBack }: { title: string; description: string; onBack: () => void }) { return <div className="flex items-start gap-3"><Button size="icon" variant="ghost" onClick={onBack} title="返回规则分组"><ArrowLeft className="h-4 w-4" /></Button><PageTitle title={title} description={description} /></div> }
function FileButton({ label, disabled, onFile }: { label: string; disabled?: boolean; onFile: (file: File) => void }) { return <label className={cn("inline-flex h-10 cursor-pointer items-center justify-center gap-2 rounded-md border border-input bg-background px-4 py-2 text-sm font-medium transition hover:bg-accent hover:text-accent-foreground", disabled && "pointer-events-none opacity-50")}><Upload className="h-4 w-4" />{label}<input type="file" className="hidden" accept=".json,.srs,application/json" disabled={disabled} onChange={(event) => { const file = event.target.files?.[0]; if (file) onFile(file); event.currentTarget.value = "" }} /></label> }
function InlineMessage({ text }: { text: string }) { return <div className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-muted-foreground">{text}</div> }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`; return `${(value / 1024 / 1024).toFixed(1)} MB` }

function ProxySettings({ form, update }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["proxy"]>(key: K, value: ConfigPayload["proxy"][K]) => void }) { const p = form.proxy; return <div className="space-y-5"><PageTitle title="代理设置" description="设置 TUN、监听方式、健康检查和路由排除。" /><Card><CardHeader><CardTitle>运行方式</CardTitle></CardHeader><CardContent className="space-y-5"><ToggleRow title="TUN 模式" description="接管系统流量，需要终端 sudo 授权" checked={p.tun_enabled} onChecked={(value) => update("tun_enabled", value)} /><ToggleRow title="局域网网关" description="允许其他设备使用本机代理" checked={p.gateway} onChecked={(value) => update("gateway", value)} /></CardContent></Card><Card><CardHeader><CardTitle>连接参数</CardTitle></CardHeader><CardContent className="form-grid"><Field label={p.tun_enabled ? "Mixed 端口（TUN 下不监听）" : "Mixed 端口"}><Input type="number" min={1} max={65535} value={p.mixed_port} disabled={p.tun_enabled} onChange={(event) => update("mixed_port", Number(event.target.value))} /></Field><Field label="订阅刷新（秒）"><Input type="number" min={60} value={p.update_interval} onChange={(event) => update("update_interval", Number(event.target.value))} /></Field><Field label="健康检查 URL" wide><Input value={p.health_check_url} onChange={(event) => update("health_check_url", event.target.value)} /></Field><Field label="日志级别"><Select value={p.log_level} onValueChange={(value) => update("log_level", value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["debug", "info", "warning", "error"].map((level) => <SelectItem key={level} value={level}>{level}</SelectItem>)}</SelectContent></Select></Field></CardContent></Card><Card><CardHeader><CardTitle>路由排除</CardTitle><CardDescription>每行一个不应进入代理 TUN 的 CIDR。</CardDescription></CardHeader><CardContent><TextArea label="TUN 排除 CIDR" value={p.tun_exclude_routes.join("\n")} onChange={(value) => update("tun_exclude_routes", splitLines(value))} placeholder="192.0.2.0/24" /></CardContent></Card></div> }

type MeshSection = "nodes" | "settings"
function MeshWorkspace({ form, update, instances, onSectionChange }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["mesh"]>(key: K, value: ConfigPayload["mesh"][K]) => void; instances: MeshInstance[]; onSectionChange: () => void }) { const [section, setSection] = useState<MeshSection>("nodes"); const peers = instances.flatMap((instance) => instance.peers); return <Workspace title="Mesh 组网" description="EasyTier 节点与虚拟网络" icon={Network} nav={[{ id: "nodes", label: "节点列表", icon: List, count: peers.length }, { id: "settings", label: "设置", icon: Settings2 }]} section={section} setSection={(value) => setSection(value as MeshSection)} onSectionChange={onSectionChange}>{section === "nodes" ? <MeshNodes instances={instances} /> : <MeshSettings form={form} update={update} />}</Workspace> }
function MeshNodes({ instances }: { instances: MeshInstance[] }) { const peers = instances.flatMap((instance) => instance.peers); return <div className="space-y-5"><PageTitle title="Mesh 节点" description="当前实例、远端节点、路径和延迟。" /><div className="grid gap-4 md:grid-cols-3">{instances.map((instance) => <Metric key={instance.instance_id} icon={Radio} label="本地实例" value={instance.virtual_ipv4 ?? "—"} detail={`${instance.connected_peers} 个对端 · ${instance.routes} 条路由`} active={instance.connected_peers > 0} />)}</div><DataTable headers={["状态", "节点", "虚拟地址", "路径", "隧道", "延迟"]}>{peers.map((peer) => <tr key={peer.peer_id} className="table-row"><td><span className="status-pill status-pill-active">在线</span></td><td><div className="font-medium">{peer.hostname ?? peer.peer_id}</div><div className="text-xs text-muted-foreground">{peer.peer_id}</div></td><td className="font-mono text-xs">{peer.virtual_ipv4 ?? "—"}</td><td>{peer.path ?? "—"}</td><td>{peer.tunnel ?? "—"}</td><td>{peer.latency_ms == null ? "—" : <Latency value={peer.latency_ms} />}</td></tr>)}</DataTable>{instances.length === 0 && <Empty icon={Network} title="Mesh 尚未运行" text="在设置中启用 Mesh 并配置网络身份。" />}</div> }
function MeshSettings({ form, update }: { form: ConfigPayload; update: <K extends keyof ConfigPayload["mesh"]>(key: K, value: ConfigPayload["mesh"][K]) => void }) { const m = form.mesh; return <div className="space-y-5"><PageTitle title="Mesh 设置" description="配置节点角色、网络身份、监听器和路由。" /><Card><CardHeader><CardTitle>节点角色</CardTitle></CardHeader><CardContent className="space-y-5"><ToggleRow title="启用 Mesh" description="开启后随当前启动一起运行" checked={m.enabled} onChecked={(value) => update("enabled", value)} /><div className="grid gap-3 sm:grid-cols-2">{(["node", "relay"] as const).map((role) => <button key={role} onClick={() => update("role", role)} className={cn("role-card", m.role === role && "role-card-active")}><div className="flex items-center gap-3"><div className="icon-tile">{role === "node" ? <Cable className="h-4 w-4" /> : <Server className="h-4 w-4" />}</div><div className="text-left"><div className="font-medium">{role === "node" ? "Node" : "Relay"}</div><div className="text-xs text-muted-foreground">{role === "node" ? "完整网络成员" : "公网中继节点"}</div></div></div></button>)}</div></CardContent></Card><Card><CardHeader><CardTitle>网络身份</CardTitle></CardHeader><CardContent className="form-grid"><Field label="节点名称"><Input value={m.name} onChange={(event) => update("name", event.target.value)} placeholder="macbook-pro" /></Field><Field label="虚拟 IPv4"><Input value={m.ipv4} onChange={(event) => update("ipv4", event.target.value)} placeholder="10.126.126.2/24" /></Field><Field label="网络名"><Input value={m.network_name} onChange={(event) => update("network_name", event.target.value)} /></Field><Field label="网络密钥"><Input type="password" value={m.network_secret} onChange={(event) => update("network_secret", event.target.value)} /></Field></CardContent></Card><Card><CardHeader><CardTitle>连接与路由</CardTitle></CardHeader><CardContent className="grid gap-4 md:grid-cols-2"><TextArea label="Peers" value={m.peers.join("\n")} onChange={(value) => update("peers", splitLines(value))} placeholder="tcp://relay.example.com:11010" /><TextArea label="Listeners" value={m.listeners.join("\n")} onChange={(value) => update("listeners", splitLines(value))} placeholder="tcp://0.0.0.0:11010" /><TextArea label="Mesh 路由" value={m.mesh_routes.join("\n")} onChange={(value) => update("mesh_routes", splitLines(value))} /><TextArea label="代理网段" value={m.proxy_networks.join("\n")} onChange={(value) => update("proxy_networks", splitLines(value))} /></CardContent></Card></div> }

type ConnectionMatcher = "host" | "process" | "source" | "destination"
function Connections({ events, nodes, subscriptions, busy, processTraffic, processTrafficBusy, onToggleProcessTraffic, onCreateRule }: { events: EventRecord[]; nodes: ProxyNode[]; subscriptions: string[]; busy: boolean; processTraffic: ProcessTrafficResponse; processTrafficBusy: boolean; onToggleProcessTraffic: (enabled: boolean) => void; onCreateRule: (rule: DomainRule) => Promise<boolean> }) {
  const [query, setQuery] = useState("")
  const [evidence, setEvidence] = useState("all")
  const [selected, setSelected] = useState<EventRecord | null>(null)
  const rows = useMemo(() => events.filter((event) => event.component === "proxy" && event.event === "connection").reverse().filter((event) => {
    const fields = event.fields ?? {}
    const haystack = `${fields.domain ?? ""} ${fields.source ?? ""} ${fields.destination ?? ""} ${fields.process_name ?? ""} ${fields.process_path ?? ""} ${fields.app ?? ""} ${fields.process_lookup ?? ""} ${fields.node ?? ""}`.toLowerCase()
    return haystack.includes(query.toLowerCase()) && (evidence === "all" || fields.domain_confidence === evidence)
  }), [events, evidence, query])
  return <div className="space-y-5"><PageTitle title="网络连接" description="选择任意连接，可按 Host、Process、Source 或 Destination 为它创建定向代理规则。" /><ProcessTrafficPanel value={processTraffic} busy={processTrafficBusy} onToggle={onToggleProcessTraffic} /><FilterBar query={query} setQuery={setQuery} placeholder="筛选域名、IP、应用或节点"><Select value={evidence} onValueChange={setEvidence}><SelectTrigger className="w-40"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">全部域名证据</SelectItem><SelectItem value="exact">精确证据</SelectItem><SelectItem value="correlated">DNS 关联</SelectItem><SelectItem value="none">未识别</SelectItem></SelectContent></Select></FilterBar><div className="rounded-xl border border-border bg-card/65 p-3 text-xs text-muted-foreground"><span className="text-emerald-300">精确</span>来自 FakeIP、SNI、HTTP Host 或 QUIC；<span className="ml-2 text-amber-300">关联</span>来自有 TTL 的 DNS IP 映射；没有证据的连接保持“未识别”。</div><DataTable headers={["时间", "进程", "域名", "目标地址", "网络 / 协议", "规则", "节点", "证据", ""]}>{rows.slice(0, 300).map((event, index) => { const f = event.fields ?? {}; return <tr key={`${event.timestamp}-${index}`} className="table-row cursor-pointer" onClick={() => setSelected(event)}><td className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTime(event.timestamp)}</td><td className="max-w-72"><ProcessIdentity name={f.process_name} path={f.process_path ?? f.app} lookup={f.process_lookup} /></td><td className="max-w-64 truncate font-medium" title={f.domain}>{f.domain || <span className="text-muted-foreground">未识别</span>}</td><td className="font-mono text-xs">{f.destination ?? "—"}</td><td>{[f.network, f.protocol].filter(Boolean).join(" / ") || "—"}</td><td className="font-mono text-xs">{f.rule ?? "—"}</td><td>{f.node ?? f.outbound ?? "—"}</td><td><Evidence source={f.domain_source} confidence={f.domain_confidence} /></td><td><Button size="sm" variant="ghost" onClick={(click) => { click.stopPropagation(); setSelected(event) }}>定向代理</Button></td></tr> })}</DataTable>{rows.length === 0 && <Empty icon={Globe2} title="没有匹配的连接" text="产生网络流量后，连接记录会在这里出现。" />}{selected && <ConnectionRuleDialog event={selected} nodes={nodes} subscriptions={subscriptions} busy={busy} onClose={() => setSelected(null)} onSubmit={async (rule) => { if (await onCreateRule(rule)) setSelected(null) }} />}</div>
}

function ProcessTrafficPanel({ value, busy, onToggle }: { value: ProcessTrafficResponse; busy: boolean; onToggle: (enabled: boolean) => void }) {
  return <Card><CardHeader><div className="flex items-start justify-between gap-5"><div><CardTitle>按进程流量记录</CardTitle><CardDescription className="mt-1">默认关闭。开启后只在内存中累计，不写入磁盘；关闭或重启即清空。</CardDescription></div><Switch checked={value.enabled} disabled={busy} onCheckedChange={onToggle} aria-label="按进程流量记录" /></div></CardHeader>{value.enabled && <CardContent><div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground"><Database className="h-3.5 w-3.5" />{value.started_at ? `自 ${formatTime(value.started_at)} 开始` : "正在记录"} · {value.records.length} 个进程</div><DataTable headers={["进程", "连接数", "上传", "下载", "总计", "最近活动"]}>{value.records.slice(0, 200).map((record) => <tr key={record.process_path || record.process_name} className="table-row"><td className="max-w-md"><ProcessIdentity name={record.process_name} path={record.process_path} lookup={record.process_lookup} /></td><td>{record.connections}</td><td className="font-mono text-xs">{formatBytes(record.upload)}</td><td className="font-mono text-xs">{formatBytes(record.download)}</td><td className="font-mono text-xs font-medium">{formatBytes(record.upload + record.download)}</td><td className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTime(record.last_seen)}</td></tr>)}</DataTable>{value.records.length === 0 && <div className="rounded-b-xl border border-t-0 border-border p-5 text-center text-sm text-muted-foreground">正在等待可归属到进程的流量。</div>}</CardContent>}</Card>
}

function ConnectionRuleDialog({ event, nodes, subscriptions, busy, onClose, onSubmit }: { event: EventRecord; nodes: ProxyNode[]; subscriptions: string[]; busy: boolean; onClose: () => void; onSubmit: (rule: DomainRule) => Promise<void> }) {
  const fields = event.fields ?? {}
  const processValue = fields.process_path ?? fields.process_name ?? fields.app ?? ""
  const defaultMatcher: ConnectionMatcher = fields.domain ? "host" : processValue ? "process" : fields.source ? "source" : "destination"
  const initialValue = (matcher: ConnectionMatcher) => matcher === "host" ? fields.domain ?? "" : matcher === "process" ? processValue : matcher === "source" ? fields.source ?? "" : fields.destination ?? ""
  const [matcher, setMatcher] = useState<ConnectionMatcher>(defaultMatcher)
  const [pattern, setPattern] = useState(initialValue(defaultMatcher))
  const [name, setName] = useState(() => `连接规则-${(fields.domain || fields.process_name || shortApp(processValue) || fields.destination || "custom").replace(/[^\p{L}\p{N}._-]+/gu, "-").slice(0, 48)}`)
  const [nodeQuery, setNodeQuery] = useState("")
  const [selectedNodes, setSelectedNodes] = useState<string[]>(() => fields.node && nodes.some((node) => node.id === fields.node) ? [fields.node] : [])
  const filtered = nodes.filter((node) => `${node.name} ${node.protocol} ${node.server ?? ""} ${providerName(subscriptions[node.provider_index], node.provider_index)}`.toLowerCase().includes(nodeQuery.toLowerCase()))
  const selectMatcher = (value: ConnectionMatcher) => { setMatcher(value); setPattern(initialValue(value)) }
  const toggleNode = (id: string) => setSelectedNodes((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  const valid = name.trim().length > 0 && pattern.trim().length > 0 && selectedNodes.length > 0
  const submit = async () => {
    if (!valid) return
    const rule: DomainRule = { enabled: true, name: name.trim(), by_suffix: [], host: [], process: [], source: [], destination: [], outbounds: selectedNodes, health_check_url: null, interval: null, tolerance: null }
    rule[matcher] = [pattern.trim()]
    await onSubmit(rule)
  }
  return <div className="fixed inset-0 z-[70] grid place-items-center overflow-y-auto bg-black/70 p-4 backdrop-blur-md" onMouseDown={(mouse) => mouse.target === mouse.currentTarget && !busy && onClose()}><Card className="my-8 w-full max-w-3xl shadow-glow"><CardHeader><CardTitle>为连接创建定向代理规则</CardTitle><CardDescription>规则保存后会立即重启并启用。可在“代理 → 规则集 → 自定义规则”中继续编辑。</CardDescription></CardHeader><CardContent className="space-y-5"><Field label="规则名称"><Input value={name} onChange={(change) => setName(change.target.value)} /></Field><div className="space-y-2"><Label>判断规则</Label><div className="grid gap-2 sm:grid-cols-4">{(["host", "process", "source", "destination"] as ConnectionMatcher[]).map((item) => <button key={item} onClick={() => selectMatcher(item)} className={cn("rounded-lg border px-3 py-2 text-left text-sm transition", matcher === item ? "border-primary bg-primary/10 text-primary" : "border-border bg-background/40 text-muted-foreground hover:text-foreground")}><div className="font-medium capitalize">{item}</div><div className="mt-1 truncate text-[10px]" title={initialValue(item)}>{initialValue(item) || "当前记录无该字段"}</div></button>)}</div></div><Field label={matcher === "host" ? "Host（支持 *.example.com 通配符）" : matcher === "process" ? "Process（进程名或完整路径）" : matcher === "source" ? "Source（IP、CIDR 或 IP:端口）" : "Destination（域名、IP、CIDR 或 IP:端口）"}><Input value={pattern} onChange={(change) => setPattern(change.target.value)} placeholder={matcher === "host" ? "*.example.com" : undefined} /></Field><div className="space-y-3"><div className="flex items-end justify-between gap-3"><div><Label>所用代理节点</Label><div className="mt-1 text-xs text-muted-foreground">已选择 {selectedNodes.length} 个；多个节点将组成自动测速候选池。</div></div>{selectedNodes.length > 0 && <Button size="sm" variant="ghost" onClick={() => setSelectedNodes([])}>清空</Button>}</div><div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input className="pl-9" value={nodeQuery} onChange={(change) => setNodeQuery(change.target.value)} placeholder="搜索节点、代理商、协议或服务器" /></div><div className="max-h-64 space-y-1 overflow-y-auto rounded-lg border border-border bg-background/35 p-2">{filtered.map((node) => { const checked = selectedNodes.includes(node.id); return <button key={node.id} className={cn("flex w-full items-center gap-3 rounded-md px-3 py-2 text-left transition hover:bg-white/5", checked && "bg-primary/10")} onClick={() => toggleNode(node.id)}><span className={cn("grid h-5 w-5 shrink-0 place-items-center rounded border", checked ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{checked && <Check className="h-3.5 w-3.5" />}</span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{node.name}</span><span className="block truncate text-[11px] text-muted-foreground">{providerName(subscriptions[node.provider_index], node.provider_index)} · {node.protocol.toUpperCase()} · {node.server ?? "—"}</span></span>{node.latency_ms != null && <Latency value={node.latency_ms} />}</button> })}{filtered.length === 0 && <div className="p-6 text-center text-sm text-muted-foreground">没有匹配的节点</div>}</div></div><div className="flex justify-end gap-2"><Button variant="ghost" disabled={busy} onClick={onClose}>取消</Button><Button disabled={!valid || busy} onClick={() => void submit()}>{busy ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}保存并应用</Button></div></CardContent></Card></div>
}
function RuntimeLogs({ events, path }: { events: EventRecord[]; path: string }) {
  const [query, setQuery] = useState("")
  const [level, setLevel] = useState("all")
  const rows = useMemo(() => [...events].reverse().filter((event) => {
    const f = event.fields ?? {}
    const haystack = `${event.component} ${event.event} ${event.message} ${event.error ?? ""} ${f.source ?? ""} ${f.destination ?? ""} ${f.domain ?? ""} ${f.rule ?? ""} ${f.process_name ?? ""} ${f.process_path ?? ""} ${f.app ?? ""}`.toLowerCase()
    return haystack.includes(query.toLowerCase()) && (level === "all" || event.level === level)
  }), [events, level, query])
  return <div className="space-y-5"><div className="flex flex-wrap items-start justify-between gap-3"><PageTitle title="运行日志" description={path || "运行事件"} /><div className="status-pill status-pill-active gap-2 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400 pulse-dot" />每 2.5 秒更新 · 最多 200 MB</div></div><FilterBar query={query} setQuery={setQuery} placeholder="筛选进程、来源、目标、域名、规则或消息"><Select value={level} onValueChange={setLevel}><SelectTrigger className="w-32"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">全部级别</SelectItem>{["error", "warn", "info", "debug"].map((item) => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent></Select></FilterBar><DataTable headers={["时间", "级别", "事件", "进程", "源地址", "协议", "目标地址", "规则 / 节点", "详情"]}>{rows.slice(0, 400).map((event, index) => { const f = event.fields ?? {}; return <tr key={`${event.timestamp}-${index}`} className="table-row align-top"><td className="whitespace-nowrap font-mono text-xs text-muted-foreground">{formatTime(event.timestamp)}</td><td><Level value={event.level} /></td><td><div className="font-medium">{event.component}.{event.event}</div><div className="text-xs text-muted-foreground">{event.source}</div></td><td className="max-w-72"><ProcessIdentity name={f.process_name} path={f.process_path ?? f.app} lookup={f.process_lookup} /></td><td className="font-mono text-xs">{f.source ?? "—"}</td><td>{[f.network, f.protocol].filter(Boolean).join(" / ") || "—"}</td><td className="font-mono text-xs">{f.destination ?? "—"}</td><td><div>{f.rule ?? "—"}</div><div className="text-xs text-muted-foreground">{f.node ?? f.outbound}</div></td><td className="max-w-md"><div className="line-clamp-2 break-all text-xs text-muted-foreground" title={event.error ?? event.message}>{event.error ?? event.message}</div></td></tr> })}</DataTable>{rows.length === 0 && <Empty icon={TerminalSquare} title="没有匹配的日志" text="调整筛选条件或等待新的事件。" />}</div>
}

function Workspace({ title, description, icon: Icon, nav, section, setSection, onSectionChange, children }: { title: string; description: string; icon: typeof Activity; nav: { id: string; label: string; icon: typeof Activity; count?: number }[]; section: string; setSection: (value: string) => void; onSectionChange: () => void; children: React.ReactNode }) { const select = (value: string) => { setSection(value); onSectionChange() }; return <><aside className="workspace-sidebar"><div className="border-b border-white/5 px-5 py-[18px]"><div className="flex items-center gap-3"><div className="icon-tile h-9 w-9"><Icon className="h-4 w-4" /></div><div className="min-w-0"><div className="font-semibold">{title}</div><div className="truncate text-[11px] text-muted-foreground">{description}</div></div></div></div><nav className="min-h-0 flex-1 overflow-y-auto p-3">{nav.map(({ id, label, icon: NavIcon, count }) => <button key={id} onClick={() => select(id)} className={cn("secondary-nav", section === id && "secondary-nav-active")}><NavIcon className="h-4 w-4" /><span>{label}</span>{count != null && <span className="ml-auto rounded-full bg-background/70 px-2 py-0.5 text-[10px]">{count}</span>}</button>)}</nav></aside><div className="mb-5 lg:hidden"><div className="mb-4 flex items-center gap-3"><div className="icon-tile"><Icon className="h-4 w-4" /></div><div><h1 className="text-xl font-semibold">{title}</h1><p className="text-xs text-muted-foreground">{description}</p></div></div><div className="flex gap-1 overflow-x-auto border-b border-border pb-2">{nav.map(({ id, label, icon: NavIcon, count }) => <button key={id} onClick={() => select(id)} className={cn("secondary-nav w-auto shrink-0", section === id && "secondary-nav-active")}><NavIcon className="h-4 w-4" /><span>{label}</span>{count != null && <span className="rounded-full bg-background/70 px-2 py-0.5 text-[10px]">{count}</span>}</button>)}</div></div><section className="min-w-0">{children}</section></> }
function PageTitle({ title, description }: { title: string; description: string }) { return <div><h2 className="text-xl font-semibold">{title}</h2><p className="mt-1 text-sm text-muted-foreground">{description}</p></div> }
function FilterBar({ query, setQuery, placeholder, children }: { query: string; setQuery: (value: string) => void; placeholder: string; children?: React.ReactNode }) { return <div className="flex flex-col gap-3 sm:flex-row"><div className="relative max-w-xl flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={placeholder} /></div>{children}</div> }
function DataTable({ headers, children }: { headers: string[]; children: React.ReactNode }) { return <div className="overflow-x-auto rounded-xl border border-border bg-card/55"><table className="w-full min-w-[900px] text-left text-sm"><thead className="border-b border-border bg-background/35 text-xs text-muted-foreground"><tr>{headers.map((header, index) => <th key={`${header}-${index}`} className="px-4 py-3 font-medium">{header}</th>)}</tr></thead><tbody>{children}</tbody></table></div> }
function ProcessIdentity({ name, path, lookup }: { name?: string; path?: string; lookup?: string }) {
  if (name || path) {
    const displayName = name || shortApp(path)
    const lookupHint = lookup === "udp_cache" ? "UDP 缓存归属" : lookup === "platform_monitor" ? "系统网络扩展归属" : ""
    return <div className="min-w-0" title={[name, path, lookupHint].filter(Boolean).join(" · ")}><div className="truncate font-medium"><span>{displayName}</span>{lookup === "udp_cache" && <span className="ml-1 text-[10px] text-sky-300">缓存</span>}{lookup === "platform_monitor" && <span className="ml-1 text-[10px] text-emerald-300">系统</span>}</div>{path && <div className="truncate font-mono text-[10px] text-muted-foreground">{path}</div>}</div>
  }
  const labels: Record<string, string> = { socket_snapshot_miss: "快照未命中", kernel_socket: "系统 / 内核", process_exited: "进程已退出", permission_denied: "权限不足", resolver_error: "查询失败" }
  return <span className="status-pill" title={lookup || "没有进程归属信息"}>{labels[lookup ?? ""] ?? "未识别"}</span>
}
function Evidence({ source, confidence }: { source?: string; confidence?: string }) { if (confidence === "exact") return <span className="status-pill status-pill-active">{source ?? "精确"}</span>; if (confidence === "correlated") return <span className="status-pill border-amber-500/20 bg-amber-500/10 text-amber-300">DNS 关联</span>; return <span className="status-pill">未识别</span> }
function Level({ value }: { value: string }) { return <span className={cn("status-pill uppercase", value === "error" && "border-red-500/20 bg-red-500/10 text-red-300", value === "warn" && "border-amber-500/20 bg-amber-500/10 text-amber-300", value === "info" && "border-sky-500/20 bg-sky-500/10 text-sky-300")}>{value}</span> }
function Latency({ value }: { value: number }) { return <span className={cn("font-mono text-xs", value < 150 ? "text-emerald-300" : value < 400 ? "text-amber-300" : "text-red-300")}>{value} ms</span> }
function Empty({ icon: Icon, title, text }: { icon: typeof Activity; title: string; text: string }) { return <div className="grid min-h-56 place-items-center rounded-xl border border-dashed border-border bg-card/25 p-8 text-center"><div><Icon className="mx-auto h-7 w-7 text-muted-foreground" /><div className="mt-3 font-medium">{title}</div><div className="mt-1 text-sm text-muted-foreground">{text}</div></div></div> }
function ToggleRow({ title, description, checked, onChecked }: { title: string; description: string; checked: boolean; onChecked: (value: boolean) => void }) { return <div className="flex items-center justify-between gap-4"><div><div className="text-sm font-medium">{title}</div><div className="mt-1 text-xs text-muted-foreground">{description}</div></div><Switch checked={checked} onCheckedChange={onChecked} /></div> }
function Field({ label, wide = false, children }: { label: string; wide?: boolean; children: React.ReactNode }) { return <div className={cn("space-y-2", wide && "md:col-span-2")}><Label>{label}</Label>{children}</div> }
function TextArea({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) { return <div className="space-y-2"><Label>{label}</Label><textarea value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} rows={4} className="flex w-full resize-y rounded-md border border-input bg-background/70 px-3 py-2 font-mono text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" /></div> }
function TokenGate({ value, setValue, submit }: { value: string; setValue: (value: string) => void; submit: () => void }) { return <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-md"><Card className="w-full max-w-md shadow-glow"><CardHeader><div className="icon-tile mb-3 h-11 w-11"><KeyRound className="h-5 w-5" /></div><CardTitle>连接远程 WebUI</CardTitle><CardDescription>令牌只保存在当前浏览器标签页。</CardDescription></CardHeader><CardContent className="space-y-4"><Input type="password" autoFocus value={value} onChange={(event) => setValue(event.target.value)} onKeyDown={(event) => event.key === "Enter" && submit()} placeholder="ZAY_WEBUI_TOKEN" /><Button className="w-full" onClick={submit}>连接 <ArrowRight className="h-4 w-4" /></Button></CardContent></Card></div> }
function providerName(url: string | undefined, index: number) { if (!url) return `代理商 ${index + 1}`; try { const host = new URL(url).hostname.replace(/^www\./, ""); return host || `代理商 ${index + 1}` } catch { return `代理商 ${index + 1}` } }
function redactedProviderUrl(value: string) { try { const url = new URL(value); return `${url.origin}${url.pathname}` } catch { return value.split("?")[0] } }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }) }
function shortApp(value?: string) { if (!value) return "—"; const parts = value.split("/"); return parts.at(-1) || value }
