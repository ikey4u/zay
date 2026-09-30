import { useEffect, useState } from "react"
import { FlaskConical, LoaderCircle } from "lucide-react"
import { api, type LabProbe, type LabProfile } from "@/api"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

type Row = LabProbe & { label: string; expect_via?: string | null }

export function LabPage() {
  const [profile, setProfile] = useState<LabProfile | null>(null)
  const [url, setUrl] = useState("https://www.gstatic.com/generate_204")
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [rows, setRows] = useState<Row[]>([])

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
              ? `Environment ${profile.name}. The browser only opens this page; probes stay in the Zay network.`
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

      <Card>
        <CardHeader>
          <CardTitle>Custom URL</CardTitle>
          <CardDescription>http and https only. curl runs on the Zay machine and ignores proxy environment variables.</CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" />
          <Button disabled={busy != null || !url.trim()} onClick={() => void run("custom", url.trim(), { url: url.trim() }, null)}>
            {busy === "custom" ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            Probe
          </Button>
        </CardContent>
      </Card>

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
