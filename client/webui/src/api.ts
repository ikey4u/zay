export type StackStatus = {
  state: "stopped" | "starting" | "running" | "degraded" | "failed" | "stopping"
  pid?: number | null
  mixed_port?: number | null
  tun_enabled: boolean
  mesh_enabled: boolean
  gateway: boolean
  proxy_ready: boolean
  proxy_error?: string | null
  error?: string | null
}

export type MeshPeer = {
  peer_id: string
  hostname?: string | null
  virtual_ipv4?: string | null
  path?: string | null
  latency_ms?: number | null
  tunnel?: string | null
}

export type MeshInstance = {
  instance_id: string
  virtual_ipv4?: string | null
  connected_peers: number
  routes: number
  peers: MeshPeer[]
}

export type ZayConfig = {
  proxy?: {
    enabled?: boolean
    subscriptions?: string[]
    active_nodes?: string[]
    gateway?: boolean
    mixed_port?: number
    update_interval?: number
    health_check_url?: string
    log_level?: string
    domain_rule?: DomainRule[]
    tun?: { enabled?: boolean; exclude_routes?: string[] }
    mesh?: {
      enabled?: boolean
      role?: "node" | "relay"
      name?: string
      network_name?: string
      network_secret?: string
      ipv4?: string
      listeners?: string[]
      peers?: string[]
      proxy_networks?: string[]
      mesh_routes?: string[]
      wireguard_listen?: string
      wireguard_client_cidr?: string
      wireguard_client_address?: string
    }
  }
}

export type StateResponse = {
  version: string
  core: {
    running: boolean
    health: "stopped" | "starting" | "healthy" | "degraded" | "failed" | "stopping"
    error?: string | null
    stack?: StackStatus | null
  }
  mesh: MeshInstance[] | { error: string }
  proxy_nodes: ProxyNode[]
  rule_sets: RuleSetInventory
  config: ZayConfig
  paths: { data_dir: string; config: string; log: string }
}

export type ConfigPayload = {
  proxy: {
    enabled: boolean
    subscriptions: string[]
    active_nodes: string[]
    gateway: boolean
    mixed_port: number
    update_interval: number
    health_check_url: string
    log_level: string
    tun_enabled: boolean
    tun_exclude_routes: string[]
    domain_rules: DomainRule[]
  }
  mesh: {
    enabled: boolean
    role: "node" | "relay"
    name: string
    network_name: string
    network_secret: string
    ipv4: string
    listeners: string[]
    peers: string[]
    proxy_networks: string[]
    mesh_routes: string[]
    wireguard_listen: string
    wireguard_client_cidr: string
    wireguard_client_address: string
  }
}

export type DomainRule = {
  enabled: boolean
  name: string
  by_suffix: string[]
  host: string[]
  process: string[]
  source: string[]
  destination: string[]
  outbounds: string[]
  health_check_url?: string | null
  interval?: number | null
  tolerance?: number | null
}

export type RuleSetEntry = {
  id: string
  name: string
  format: "json" | "srs"
  bytes: number
  editable: boolean
}

export type RuleSetInventory = {
  builtin: RuleSetEntry[]
  external: RuleSetEntry[]
}

export type RuleSetContent = RuleSetEntry & {
  group: "builtin" | "external"
  binary: boolean
  content?: string | null
}

export type ProxyNode = {
  id: string
  provider_id: string
  provider_index: number
  name: string
  protocol: string
  server?: string | null
  port?: number | null
  tls: boolean
  latency_ms?: number | null
  latency_error?: string | null
  latency_checked_at?: string | null
}

export type NodeTestResult = {
  id: string
  latency_ms?: number | null
  error?: string | null
  checked_at: string
}

export type EventRecord = {
  timestamp: string
  source: string
  level: string
  component: string
  event: string
  message: string
  error?: string | null
  fields?: Record<string, string>
}

export type EventsResponse = { path: string; events: EventRecord[] }

export type ProcessTrafficRecord = {
  process_name: string
  process_path: string
  process_lookup: string
  upload: number
  download: number
  connections: number
  first_seen: string
  last_seen: string
}

export type ProcessTrafficResponse = {
  enabled: boolean
  started_at?: string | null
  records: ProcessTrafficRecord[]
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

let token = sessionStorage.getItem("zay-token") ?? ""

export function setToken(value: string) {
  token = value.trim()
  if (token) sessionStorage.setItem("zay-token", token)
  else sessionStorage.removeItem("zay-token")
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  if (token) headers.set("Authorization", `Bearer ${token}`)
  if (init?.body) headers.set("Content-Type", "application/json")
  const response = await fetch(path, { ...init, headers })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new ApiError(response.status, data.error ?? "request_failed", data.message ?? response.statusText)
  }
  return data as T
}

export async function uploadRuleSet(path: string, body: BodyInit): Promise<{ ok: boolean; restart_required: boolean }> {
  const headers = new Headers()
  if (token) headers.set("Authorization", `Bearer ${token}`)
  const response = await fetch(path, { method: "PUT", headers, body })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new ApiError(response.status, data.error ?? "request_failed", data.message ?? response.statusText)
  }
  return data
}
