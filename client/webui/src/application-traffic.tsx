import { useState } from "react"
import { Database, Search } from "lucide-react"
import type { ProcessTrafficRecord, ProcessTrafficResponse } from "@/api"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"

function bytes(value: number) {
  const units = ["B", "KB", "MB", "GB", "TB"]
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
  return `${unit ? value.toFixed(1) : value} ${units[unit]}`
}

type Props = {
  value: ProcessTrafficResponse
  busy: boolean
  error: string | null
  tun: boolean
  onAction: (action: "enable" | "disable" | "reset") => void
}

export function ApplicationTrafficOverview({ value, busy, error, tun, onAction }: Props) {
  const [query, setQuery] = useState("")
  const [sort, setSort] = useState("total")
  const [confirmReset, setConfirmReset] = useState(false)
  const totals = value.records.reduce((sum, record) => ({
    upload: sum.upload + record.upload,
    download: sum.download + record.download,
    direct: sum.direct + record.direct_upload + record.direct_download,
    proxy: sum.proxy + record.proxy_upload + record.proxy_download,
  }), { upload: 0, download: 0, direct: 0, proxy: 0 })
  const amount = (record: ProcessTrafficRecord) => sort === "direct"
    ? record.direct_upload + record.direct_download
    : sort === "proxy" ? record.proxy_upload + record.proxy_download : record.upload + record.download
  const rows = value.records
    .filter((record) => `${record.process_name} ${record.process_path}`.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => amount(b) - amount(a))
  const unavailable = value.available === false || !!error
  const stats: [string, number][] = [["Total uploaded", totals.upload], ["Total downloaded", totals.download], ["Direct traffic", totals.direct], ["Proxied traffic", totals.proxy]]

  return <div className="space-y-5">
    <div><h1 className="text-2xl font-semibold tracking-tight">Overview</h1><p className="mt-1 text-sm text-muted-foreground">Application traffic handled by Zay, including direct and proxied routes.</p></div>
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{stats.map(([label, amount]) =>
      <Card key={label}><CardContent className="p-5"><div className="text-xs text-muted-foreground">{label}</div><div className="mt-2 text-2xl font-semibold tabular-nums">{bytes(amount)}</div></CardContent></Card>
    )}</div>
    <Card>
      <CardHeader><div className="flex flex-wrap items-start justify-between gap-5">
        <div><CardTitle>Application usage</CardTitle><CardDescription className="mt-1">Usage is saved across restarts until reset. Pausing keeps existing totals.</CardDescription></div>
        <div className="flex items-center gap-3">
          <Button size="sm" variant="outline" disabled={busy || unavailable || value.records.length === 0} onClick={() => setConfirmReset(true)}>Reset usage</Button>
          <Label htmlFor="application-traffic-enabled">Record traffic</Label>
          <Switch id="application-traffic-enabled" checked={value.enabled} disabled={busy || unavailable} onCheckedChange={(enabled) => onAction(enabled ? "enable" : "disable")} />
        </div>
      </div></CardHeader>
      <CardContent>
        <div className="mb-4 space-y-2 text-xs text-muted-foreground">
          <div className="flex items-center gap-2"><Database className="h-3.5 w-3.5" />{value.started_at ? `Since ${new Date(value.started_at).toLocaleString("en-US")}` : "No usage recorded"} · {value.records.length} {value.records.length === 1 ? "application" : "applications"} · {unavailable ? "Saved usage" : value.enabled ? "Recording" : "Recording paused"}</div>
          <p>{tun ? "Includes direct and proxied traffic entering Zay's TUN. Excluded routes are outside these totals." : "Includes traffic sent to Zay's proxy listeners. Enable TUN to capture more applications."} Unidentified processes are grouped separately.</p>
          {unavailable && <p className="text-amber-300">{error ?? "The proxy core is stopped. Saved usage is shown; start the proxy to resume recording or reset."}</p>}
        </div>
        <div className="mb-4 flex flex-wrap gap-3">
          <div className="relative min-w-48 flex-1"><Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" /><Input className="pl-9" aria-label="Search applications" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search application name or path" /></div>
          <Select value={sort} onValueChange={setSort}><SelectTrigger className="w-40" aria-label="Sort usage"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="total">Total traffic</SelectItem><SelectItem value="direct">Direct traffic</SelectItem><SelectItem value="proxy">Proxied traffic</SelectItem></SelectContent></Select>
        </div>
        <div className="overflow-x-auto rounded-xl border border-border"><table className="w-full text-sm">
          <thead className="bg-white/[0.03] text-xs text-muted-foreground"><tr>{["Application", "Direct", "Proxied", "Upload", "Download", "Total", "Connections"].map((title) => <th className="whitespace-nowrap px-4 py-3 text-left font-medium" key={title}>{title}</th>)}</tr></thead>
          <tbody>{rows.map((record) => <tr key={record.process_path || record.process_name} className="table-row">
            <td className="max-w-md px-4 py-3"><div className="font-medium">{record.process_name}</div><div className="truncate text-xs text-muted-foreground" title={record.process_path}>{record.process_path || "Process path unavailable"}</div></td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs" title={`↑ ${bytes(record.direct_upload)} · ↓ ${bytes(record.direct_download)}`}>{bytes(record.direct_upload + record.direct_download)}</td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs" title={`↑ ${bytes(record.proxy_upload)} · ↓ ${bytes(record.proxy_download)}`}>{bytes(record.proxy_upload + record.proxy_download)}</td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{bytes(record.upload)}</td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{bytes(record.download)}</td>
            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs font-medium">{bytes(record.upload + record.download)}</td>
            <td className="px-4 py-3">{record.connections}</td>
          </tr>)}</tbody>
        </table>{rows.length === 0 && <div className="border-t border-border p-5 text-center text-sm text-muted-foreground">{query ? "No matching applications." : "Send traffic through Zay to start recording usage."}</div>}</div>
      </CardContent>
    </Card>
    {confirmReset && <div role="alertdialog" aria-modal="true" aria-labelledby="reset-usage-title" className="fixed inset-0 z-[70] grid place-items-center bg-black/70 p-4">
      <Card className="w-full max-w-md"><CardHeader><CardTitle id="reset-usage-title">Reset application usage?</CardTitle><CardDescription>This clears all saved usage. Active connections will continue counting from zero.</CardDescription></CardHeader><CardContent className="flex justify-end gap-3"><Button variant="outline" onClick={() => setConfirmReset(false)}>Cancel</Button><Button disabled={busy || unavailable} onClick={() => { setConfirmReset(false); onAction("reset") }}>Reset usage</Button></CardContent></Card>
    </div>}
  </div>
}
