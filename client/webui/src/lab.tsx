import { useEffect, useState } from "react"
import { ArrowLeft, ArrowRight, Globe2, RotateCw, TerminalSquare, FlaskConical, LoaderCircle } from "lucide-react"
import { api, type LabBrowser, type LabProbe, type LabProfile } from "@/api"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

import { LabTerminal } from "@/lab-terminal"

type Row = LabProbe & { label: string; expect_via?: string | null }

export function LabPage() {
  const [profile, setProfile] = useState<LabProfile | null>(null)
  const [url, setUrl] = useState("https://baidu.com")
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [rows, setRows] = useState<Row[]>([])

  const [tab, setTab] = useState<"browser" | "terminal">("browser")
  const [page, setPage] = useState<LabBrowser | null>(null)
  const [history, setHistory] = useState<string[]>([])
  const [position, setPosition] = useState(-1)

  const navigate = async (target: string, index?: number) => {
    const address = /^https?:\/\//i.test(target.trim()) ? target.trim() : `https://${target.trim()}`
    setBusy("browser")
    setError(null)
    setPage(null)
    setUrl(address)
    try {
      const result = await api<LabBrowser>("/api/v1/lab/browser", { method: "POST", body: JSON.stringify({ url: address }) })
      setPage(result)
      if (index == null) {
        const next = [...history.slice(0, position + 1), address]
        setHistory(next)
        setPosition(next.length - 1)
      } else setPosition(index)
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(null) }
  }

  useEffect(() => {
    void api<LabProfile>("/api/v1/lab")
      .then(setProfile)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : String(reason)))
  }, [])

  const run = async (id: string, label: string, target: { url?: string | null; tcp?: string | null }, expectVia?: string | null) => {
    setBusy(id)
    setError(null)
    try {
      const body = target.tcp ? { tcp: target.tcp } : { url: target.url }
      const result = await api<LabProbe>("/api/v1/lab/probe", { method: "POST", body: JSON.stringify(body) })
      setRows((current) => [{ ...result, label, expect_via: expectVia }, ...current].slice(0, 20))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-semibold">Lab</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {profile?.hint ?? "Probes run on the machine that hosts Zay, to check TUN, the subscription proxy, and Mesh."}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><FlaskConical className="h-4 w-4" />Lab</CardTitle>
          <CardDescription>
            {profile?.active
              ? `${profile.platform} · ${profile.name}. The browser only opens this page; probes stay in the Zay network.`
              : "devpane is not detected. A manual probe still uses this machine's egress."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {(profile?.presets ?? []).map((preset) => (
            <Button
              key={preset.id}
              variant="outline"
              disabled={busy != null}
              onClick={() => void run(preset.id, preset.label, preset, preset.expect_via)}
            >
              {busy === preset.id ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
              {preset.label}
            </Button>
          ))}
          {!profile?.active && <span className="text-sm text-muted-foreground">Presets appear after `mise devpane`.</span>}
        </CardContent>
      </Card>

      {profile?.interactive && <>
        <div className="flex gap-2" role="tablist" aria-label="Lab tools">
          <Button role="tab" aria-selected={tab === "browser"} variant={tab === "browser" ? "secondary" : "ghost"} onClick={() => setTab("browser")}><Globe2 className="h-4 w-4" />Browser</Button>
          <Button role="tab" aria-selected={tab === "terminal"} variant={tab === "terminal" ? "secondary" : "ghost"} onClick={() => setTab("terminal")}><TerminalSquare className="h-4 w-4" />{profile?.platform} terminal</Button>
        </div>
        <div hidden={tab !== "browser"} className="overflow-hidden rounded-xl border border-border bg-card">
          <div className="flex items-center gap-2 border-b border-border bg-background/50 p-3">
            <Button size="icon" variant="ghost" aria-label="Back" disabled={busy != null || position <= 0} onClick={() => void navigate(history[position - 1], position - 1)}><ArrowLeft className="h-4 w-4" /></Button>
            <Button size="icon" variant="ghost" aria-label="Forward" disabled={busy != null || position >= history.length - 1} onClick={() => void navigate(history[position + 1], position + 1)}><ArrowRight className="h-4 w-4" /></Button>
            <Button size="icon" variant="ghost" aria-label="Reload" disabled={busy != null || !page} onClick={() => void navigate(page!.url, position)}><RotateCw className="h-4 w-4" /></Button>
            <form className="flex min-w-0 flex-1 gap-2" onSubmit={(event) => { event.preventDefault(); if (!busy && url.trim()) void navigate(url) }}>
              <Input aria-label="Browser URL" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" className="font-mono text-xs" />
              <Button type="submit" disabled={busy != null || !url.trim()}>{busy === "browser" ? <LoaderCircle className="h-4 w-4 animate-spin" /> : "Go"}</Button>
            </form>
          </div>
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2 text-xs text-muted-foreground"><span className="h-2 w-2 rounded-full bg-emerald-400" />Browser inside {profile?.platform} · 1280 × 800 · Rendered snapshot</div>
          <div className="min-h-[300px] bg-white">
            {busy === "browser" ? <div className="flex h-[300px] items-center justify-center gap-2 text-slate-500"><LoaderCircle className="h-5 w-5 animate-spin" />Loading page through the lab network…</div>
              : page?.image ? <img src={page.image} alt={`Rendered page: ${page.url}`} className="block h-auto w-full" />
              : <div className="flex min-h-[300px] flex-col items-center justify-center gap-3 overflow-hidden px-6 py-8 text-center text-sm text-slate-500"><Globe2 className="h-10 w-10" /><p className="max-w-full break-words">{page?.error ?? "Enter a URL to render a page from inside the lab."}</p><p className="text-xs">JavaScript, styles, and images load in the lab. Enter another URL to navigate.</p></div>}
          </div>
          {page?.error && page.diagnostics && <details className="border-t border-border p-4 text-xs"><summary className="cursor-pointer">Browser diagnostics</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all">{page.diagnostics}</pre></details>}
          {page && <div className="space-y-3 border-t border-border p-4"><div className="text-xs text-muted-foreground">Connection check · separate curl request through the same lab network</div><ProbeRow row={{ ...page.connection, label: "Connection" }} />{page.connection.headers && <details className="text-xs"><summary className="cursor-pointer text-muted-foreground">Response headers</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap font-mono">{page.connection.headers}</pre></details>}</div>}
        </div>
        <div hidden={tab !== "terminal"}><LabTerminal platform={profile?.platform ?? "Lab"} /></div>
      </>}
      {!profile?.interactive && <Card><CardHeader><CardTitle>Custom URL</CardTitle></CardHeader><CardContent className="flex gap-2"><Input aria-label="Probe URL" value={url} onChange={(event) => setUrl(event.target.value)} /><Button disabled={busy != null || !url.trim()} onClick={() => void run("custom", url, { url })}>Probe</Button></CardContent></Card>}

      {error && <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-red-300">{error}</div>}

      <div className="space-y-3">
        {rows.map((row, index) => <ProbeRow key={`${row.target}-${index}`} row={row} />)}
      </div>
    </div>
  )
}

function ProbeRow({ row }: { row: Row }) {
  const mismatch = Boolean(row.expect_via && row.via !== row.expect_via)
  const ok = row.ok && !mismatch
  return (
    <Card className={cn(ok ? "border-emerald-500/20" : "border-amber-500/25")}>
      <CardContent className="space-y-2 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className={cn("rounded-full px-2 py-0.5 text-xs", ok ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-200")}>
            {ok ? "Pass" : mismatch ? "Wrong path" : "Failed"}
          </span>
          <span className="font-medium">{row.label}</span>
          <span className="text-muted-foreground">{row.elapsed_ms} ms</span>
          {row.status != null && <span className="font-mono text-xs">HTTP {row.status}</span>}
          {row.remote_ip && <span className="font-mono text-xs">IP {row.remote_ip}</span>}
          {row.dns_ms != null && <span className="text-xs">DNS {row.dns_ms.toFixed(1)} ms</span>}
          {row.connect_ms != null && <span className="text-xs">Connect {row.connect_ms.toFixed(1)} ms</span>}
          {row.via && <span className="font-mono text-xs">via {row.via}</span>}
          {row.expect_via && <span className="font-mono text-xs text-muted-foreground">expected {row.expect_via}</span>}
        </div>
        <div className="break-all font-mono text-xs text-muted-foreground">{row.target}</div>
        {row.error && <div className="text-red-300">{row.error}</div>}
        {row.body && <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-black/20 p-3 font-mono text-xs">{row.body}</pre>}
      </CardContent>
    </Card>
  )
}
