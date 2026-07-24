import { ensureAuthenticated, handleUnauthorized } from '@/composables/auth'
import { getApiToken } from '@/api/tokens'

export { clearApiToken, getApiToken, hasApiToken, setApiToken } from '@/api/tokens'

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

const PUBLIC_PATHS = new Set(['/api/v1/meta'])

function isPublicPath(path: string): boolean {
  return PUBLIC_PATHS.has(path)
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json()
    if (body?.error?.message) return body.error.message
    return JSON.stringify(body)
  } catch {
    return (await res.text()) || `HTTP ${res.status}`
  }
}

async function fetchWithAuth(path: string, init: RequestInit, token: string): Promise<Response> {
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  return fetch(path, { ...init, headers })
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const publicPath = isPublicPath(path)
  let token = publicPath ? getApiToken() : await ensureAuthenticated()

  let res = await fetchWithAuth(path, init, token)
  if (res.status === 401 && !publicPath) {
    handleUnauthorized()
    token = await ensureAuthenticated()
    res = await fetchWithAuth(path, init, token)
  }

  if (!res.ok) throw new ApiError(await parseError(res), res.status)
  const ct = res.headers.get('content-type') ?? ''
  if (ct.includes('application/json')) return res.json() as Promise<T>
  return res.text() as Promise<T>
}

export interface MetaResponse {
  version: string
  singbox_version: string
  webui_version?: string
  data_dir: string
  features?: string[]
  embedded_ui: boolean
}

export interface JobSummary {
  id: string
  kind: string
  state: string
  created_at: string
  spec: Record<string, unknown>
  error?: string
  exit_code?: number
}

export interface StackStatus {
  state: string
  pid?: number
  mixed_port?: number
  tun_enabled: boolean
  mesh_enabled: boolean
  gateway: boolean
  error?: string
}

export interface StackStartBody {
  subscriptions?: string[]
  mixed_port?: number
  api_port?: number
  update_interval?: number
  health_check_url?: string
  log_level?: string
  no_tun?: boolean
  tun_exclude_routes?: string[]
  bootstrap_proxy?: string
  mesh?: string
  gateway?: boolean
  no_rules?: boolean
  mesh_auth?: string
  mesh_ip?: string
  sudo_password?: string
}

export const api = {
  meta: () => apiFetch<MetaResponse>('/api/v1/meta'),
  health: () => apiFetch<{ status: string }>('/api/v1/health'),
  getConfig: () => apiFetch<string>('/api/v1/config'),
  putConfig: (content: string) =>
    apiFetch<{ ok: boolean }>('/api/v1/config', {
      method: 'PUT',
      body: JSON.stringify({ content }),
    }),
  validateConfig: () => apiFetch<{ ok: boolean }>('/api/v1/config/validate', { method: 'POST' }),
  stackStatus: () => apiFetch<StackStatus>('/api/v1/stack/status'),
  stackStart: (body: StackStartBody) =>
    apiFetch<StackStatus>('/api/v1/stack/start', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  stackStop: () => apiFetch<{ ok: boolean }>('/api/v1/stack/stop', { method: 'POST' }),
  stackConfig: () => apiFetch<string>('/api/v1/stack/config'),
  listJobs: () => apiFetch<JobSummary[]>('/api/v1/jobs'),
  getJob: (id: string) => apiFetch<{ job: JobSummary; logs: string[] }>(`/api/v1/jobs/${id}`),
  stopJob: (id: string) => apiFetch<{ ok: boolean }>(`/api/v1/jobs/${id}`, { method: 'DELETE' }),
  createSshJob: (spec: Record<string, unknown>) =>
    apiFetch<JobSummary>('/api/v1/jobs/ssh', {
      method: 'POST',
      body: JSON.stringify(spec),
    }),
  createFwdJob: (spec: Record<string, unknown>) =>
    apiFetch<JobSummary>('/api/v1/jobs/fwd', {
      method: 'POST',
      body: JSON.stringify(spec),
    }),
  createHttpJob: (spec: Record<string, unknown>) =>
    apiFetch<JobSummary>('/api/v1/jobs/http', {
      method: 'POST',
      body: JSON.stringify(spec),
    }),
  clashProxies: () => apiFetch<Record<string, unknown>>('/api/v1/stack/clash/proxies'),
}

export function connectJobEvents(onJob: (job: JobSummary) => void): WebSocket | null {
  const token = getApiToken()
  if (!token) return null
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(
    `${proto}://${location.host}/api/v1/ws/events?token=${encodeURIComponent(token)}`
  )
  ws.onmessage = (ev) => {
    try {
      onJob(JSON.parse(ev.data) as JobSummary)
    } catch {
      /* ignore */
    }
  }
  return ws
}

export function connectStackLogs(onText: (text: string) => void): EventSource | null {
  const token = getApiToken()
  if (!token) return null
  const es = new EventSource(`/api/v1/stack/logs?token=${encodeURIComponent(token)}`)
  es.onmessage = (ev) => onText(ev.data)
  return es
}

export const fetchMeta = api.meta
export const fetchHealth = () => api.health()
