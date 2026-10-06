import { useEffect, useRef, useState } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import "@xterm/xterm/css/xterm.css"
import { Button } from "@/components/ui/button"
import { terminalSocket } from "@/api"

export function LabTerminal({ platform }: { platform: string }) {
  const element = useRef<HTMLDivElement>(null)
  const connection = useRef<WebSocket | null>(null)
  const [session, setSession] = useState(0)
  const [status, setStatus] = useState("Disconnected")

  useEffect(() => {
    if (!session || !element.current) return
    const terminal = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: "monospace", scrollback: 5000, theme: { background: "#090f1a", foreground: "#dbeafe" } })
    const fit = new FitAddon()
    terminal.loadAddon(fit)
    terminal.open(element.current)
    fit.fit()
    const socket = terminalSocket()
    connection.current = socket
    setStatus("Connecting")
    socket.binaryType = "arraybuffer"
    const send = (value: object) => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value)) }
    const resize = () => { fit.fit(); send({ type: "resize", cols: terminal.cols, rows: terminal.rows }) }
    socket.addEventListener("open", () => { setStatus("Connected"); resize(); terminal.focus() })
    socket.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) terminal.write(new Uint8Array(event.data))
    }
    socket.onerror = () => setStatus("Connection failed")
    socket.onclose = () => { setStatus("Disconnected"); terminal.writeln("\r\n[Session closed. Connect to start a new shell.]") }
    const input = terminal.onData((data) => send({ type: "input", data }))
    const observer = new ResizeObserver(resize)
    observer.observe(element.current)
    return () => {
      observer.disconnect()
      input.dispose()
      socket.onclose = null
      socket.onerror = null
      socket.onmessage = null
      socket.close()
      connection.current = null
      terminal.dispose()
    }
  }, [session])

  return <section className="overflow-hidden rounded-xl border border-border bg-[#090f1a]">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
      <div><div className="font-mono text-sm text-blue-100">{platform} / bash</div><div className="mt-1 text-xs text-slate-400">{status} · Shell inside {platform}. Ctrl+C interrupts commands.</div></div>
      <div className="flex gap-2"><Button variant="outline" size="sm" onClick={() => { connection.current?.close(); setSession((value) => value + 1) }}>Connect / reconnect</Button><Button variant="ghost" size="sm" disabled={status !== "Connected"} onClick={() => connection.current?.close()}>Disconnect</Button></div>
    </div>
    {!session && <div className="px-4 pt-4 font-mono text-xs text-slate-400">Connect to run curl, ping, dig, ip, traceroute, or any shell command. Shell state persists during the session.</div>}
    <div ref={element} className="h-[440px] overflow-hidden p-3" />
  </section>
}
