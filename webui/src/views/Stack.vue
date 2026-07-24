<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api, connectStackLogs, type StackStartBody, type StackStatus } from '@/api/client'
import { authenticated } from '@/composables/auth'

const status = ref<StackStatus | null>(null)
const proxies = ref<Record<string, unknown> | null>(null)
const logs = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const optionsOpen = ref(true)
const logsOpen = ref(true)
const proxiesOpen = ref(false)
const showPasswordModal = ref(false)
const adminPassword = ref('')

const form = ref({
  subscriptions: '',
  mixed_port: '',
  api_port: '',
  update_interval: '',
  health_check_url: '',
  log_level: '',
  bootstrap_proxy: '',
  no_tun: false,
  tun_exclude_routes: '',
  gateway: false,
  no_rules: false,
  mesh: '',
  mesh_auth: '',
  mesh_ip: '',
})

const isActive = computed(() => {
  const s = status.value?.state
  return s === 'running' || s === 'starting' || s === 'stopping'
})

const canStart = computed(() => !busy.value && !isActive.value)
const canStop = computed(() => !busy.value && isActive.value)

const stateLabel: Record<string, string> = {
  stopped: '已停止',
  starting: '启动中',
  running: '运行中',
  failed: '失败',
  stopping: '停止中',
}

const stateClass: Record<string, string> = {
  stopped: 'bg-zinc-800 text-zinc-300',
  starting: 'bg-amber-900/50 text-amber-200',
  running: 'bg-emerald-900/50 text-emerald-200',
  failed: 'bg-red-900/50 text-red-200',
  stopping: 'bg-amber-900/50 text-amber-200',
}

const meshEnabled = computed(() => form.value.mesh === 'node' || form.value.mesh === 'relay')

function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

function parseOptionalNumber(raw: string): number | undefined {
  const n = Number(raw.trim())
  return raw.trim() && Number.isFinite(n) ? n : undefined
}

function buildStartBody(sudoPassword?: string): StackStartBody {
  const body: StackStartBody = {
    gateway: form.value.gateway,
    no_tun: form.value.no_tun,
    no_rules: form.value.no_rules,
  }

  const subs = lines(form.value.subscriptions)
  if (subs.length) body.subscriptions = subs

  const mixedPort = parseOptionalNumber(form.value.mixed_port)
  if (mixedPort !== undefined) body.mixed_port = mixedPort

  const apiPort = parseOptionalNumber(form.value.api_port)
  if (apiPort !== undefined) body.api_port = apiPort

  const updateInterval = parseOptionalNumber(form.value.update_interval)
  if (updateInterval !== undefined) body.update_interval = updateInterval

  const healthUrl = form.value.health_check_url.trim()
  if (healthUrl) body.health_check_url = healthUrl

  const logLevel = form.value.log_level.trim()
  if (logLevel) body.log_level = logLevel

  const bootstrap = form.value.bootstrap_proxy.trim()
  if (bootstrap) body.bootstrap_proxy = bootstrap

  const tunExclude = lines(form.value.tun_exclude_routes)
  if (tunExclude.length) body.tun_exclude_routes = tunExclude

  if (form.value.mesh) body.mesh = form.value.mesh

  const meshAuth = form.value.mesh_auth.trim()
  if (meshAuth) body.mesh_auth = meshAuth

  const meshIp = form.value.mesh_ip.trim()
  if (meshIp) body.mesh_ip = meshIp

  if (sudoPassword) body.sudo_password = sudoPassword

  return body
}

function needsAdminPassword(): boolean {
  return !form.value.no_tun
}

async function refresh() {
  if (!authenticated.value) return
  error.value = null
  try {
    status.value = await api.stackStatus()
    try {
      proxies.value = await api.clashProxies()
    } catch {
      proxies.value = null
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function requestStart() {
  if (needsAdminPassword()) {
    adminPassword.value = ''
    showPasswordModal.value = true
    return
  }
  void doStart()
}

function cancelPasswordModal() {
  showPasswordModal.value = false
  adminPassword.value = ''
}

async function confirmPasswordAndStart() {
  if (!adminPassword.value) {
    error.value = 'TUN 模式需要输入管理员密码'
    return
  }
  showPasswordModal.value = false
  const password = adminPassword.value
  adminPassword.value = ''
  await doStart(password)
}

async function doStart(sudoPassword?: string) {
  busy.value = true
  error.value = null
  try {
    status.value = await api.stackStart(buildStartBody(sudoPassword))
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
    await refresh()
  }
}

async function stop() {
  busy.value = true
  error.value = null
  try {
    await api.stackStop()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
    await refresh()
  }
}

async function restart() {
  if (isActive.value) {
    await stop()
  }
  requestStart()
}

let logSource: EventSource | null = null

function connectLogs() {
  logSource?.close()
  if (!authenticated.value) return
  logSource = connectStackLogs((text) => {
    logs.value = text
  })
}

watch(authenticated, (ok) => {
  if (ok) {
    refresh()
    connectLogs()
  } else {
    logSource?.close()
    logSource = null
    logs.value = ''
    status.value = null
    proxies.value = null
  }
})

onMounted(() => {
  if (authenticated.value) {
    refresh()
    connectLogs()
  }
})

onUnmounted(() => logSource?.close())
</script>

<template>
  <div class="space-y-5">
    <div>
      <h1 class="text-2xl font-semibold text-zinc-50">Stack</h1>
      <p class="mt-1 text-sm text-zinc-400">sing-box 代理栈 · 对应 <code>zay stack</code></p>
    </div>

    <div
      v-if="error"
      class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-if="showPasswordModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      @keydown.esc="cancelPasswordModal"
    >
      <div
        class="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-900 p-5 shadow-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="admin-password-title"
      >
        <h2 id="admin-password-title" class="text-lg font-medium text-zinc-100">管理员密码</h2>
        <p class="mt-2 text-sm text-zinc-400">
          TUN 模式需要 sudo 启动 sing-box，请输入本机 macOS / Linux 管理员密码。
        </p>
        <input
          v-model="adminPassword"
          type="password"
          autocomplete="current-password"
          class="mt-4 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
          placeholder="密码"
          @keyup.enter="confirmPasswordAndStart"
        >
        <div class="mt-4 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
            @click="cancelPasswordModal"
          >
            取消
          </button>
          <button
            type="button"
            class="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500"
            @click="confirmPasswordAndStart"
          >
            确认启动
          </button>
        </div>
      </div>
    </div>

    <!-- 1. 启动选项（可折叠） -->
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50">
      <button
        type="button"
        class="flex w-full items-center justify-between px-4 py-3 text-left"
        @click="optionsOpen = !optionsOpen"
      >
        <div>
          <h2 class="text-sm font-medium text-zinc-200">启动选项</h2>
          <p class="mt-0.5 text-xs text-zinc-500">与 CLI 参数一致，启动时生效</p>
        </div>
        <span class="text-zinc-500">{{ optionsOpen ? '▾' : '▸' }}</span>
      </button>

      <div v-show="optionsOpen" class="border-t border-zinc-800 px-4 pb-4 pt-3">
        <div class="space-y-5">
          <div>
            <h3 class="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">
              代理 / 端口
            </h3>
            <div class="grid gap-3 sm:grid-cols-2">
              <label class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2">
                <span>订阅 URL <code class="text-xs">--proxy / -s</code>（每行一个）</span>
                <textarea
                  v-model="form.subscriptions"
                  rows="3"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="https://example/sub?token=..."
                />
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400">
                <span>混合端口 <code class="text-xs">--mixed-port</code></span>
                <input
                  v-model="form.mixed_port"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                  placeholder="7890"
                >
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400">
                <span>API 端口 <code class="text-xs">--api-port</code></span>
                <input
                  v-model="form.api_port"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                  placeholder="8787"
                >
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2">
                <span>引导代理 <code class="text-xs">--bootstrap-proxy</code></span>
                <input
                  v-model="form.bootstrap_proxy"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="/path/to/bootstrap.yaml"
                >
              </label>
            </div>
          </div>

          <div>
            <h3 class="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">运行时</h3>
            <div class="grid gap-3 sm:grid-cols-2">
              <label class="flex flex-col gap-1 text-sm text-zinc-400">
                <span>更新间隔（秒） <code class="text-xs">--update-interval</code></span>
                <input
                  v-model="form.update_interval"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                  placeholder="3600"
                >
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400">
                <span>日志级别 <code class="text-xs">--log-level</code></span>
                <select
                  v-model="form.log_level"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                >
                  <option value="">默认 (info)</option>
                  <option value="debug">debug</option>
                  <option value="info">info</option>
                  <option value="warning">warning</option>
                  <option value="error">error</option>
                </select>
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2">
                <span>健康检查 URL <code class="text-xs">--health-check-url</code></span>
                <input
                  v-model="form.health_check_url"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="https://..."
                >
              </label>
            </div>
          </div>

          <div>
            <h3 class="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">
              TUN / 路由
            </h3>
            <div class="grid gap-3 sm:grid-cols-2">
              <label class="flex items-center gap-2 text-sm text-zinc-300">
                <input v-model="form.no_tun" type="checkbox">
                禁用 TUN <code class="text-xs text-zinc-500">--no-tun</code>
              </label>
              <label class="flex items-center gap-2 text-sm text-zinc-300">
                <input v-model="form.gateway" type="checkbox">
                LAN 网关 <code class="text-xs text-zinc-500">--gateway</code>
              </label>
              <label class="flex items-center gap-2 text-sm text-zinc-300">
                <input v-model="form.no_rules" type="checkbox">
                跳过规则下载 <code class="text-xs text-zinc-500">--no-rules</code>
              </label>
              <label class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2">
                <span
                  >TUN 排除路由 <code class="text-xs">--tun-exclude</code>（每行一个 CIDR）</span
                >
                <textarea
                  v-model="form.tun_exclude_routes"
                  rows="2"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="10.0.0.0/8"
                />
              </label>
            </div>
          </div>

          <div>
            <h3 class="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Mesh</h3>
            <div class="grid gap-3 sm:grid-cols-2">
              <label class="flex flex-col gap-1 text-sm text-zinc-400">
                <span>角色 <code class="text-xs">--mesh</code></span>
                <select
                  v-model="form.mesh"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                >
                  <option value="">关闭</option>
                  <option value="node">node</option>
                  <option value="relay">relay</option>
                </select>
              </label>
              <label
                v-if="meshEnabled"
                class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2"
              >
                <span>认证 <code class="text-xs">--mesh-auth</code></span>
                <input
                  v-model="form.mesh_auth"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="user:pass 或 user:pass@tcp://host:11010"
                >
              </label>
              <label
                v-if="meshEnabled"
                class="flex flex-col gap-1 text-sm text-zinc-400 sm:col-span-2"
              >
                <span>虚拟 IP <code class="text-xs">--mesh-ip</code></span>
                <input
                  v-model="form.mesh_ip"
                  class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
                  placeholder="10.126.126.10/24"
                >
              </label>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- 2. 控制按钮 -->
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <h2 class="text-sm font-medium text-zinc-400">控制</h2>
      <div class="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40"
          :disabled="!canStart"
          @click="requestStart"
        >
          启动
        </button>
        <button
          type="button"
          class="rounded-lg border border-red-800/80 bg-red-950/30 px-4 py-2 text-sm text-red-200 hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
          :disabled="!canStop"
          @click="stop"
        >
          停止
        </button>
        <button
          type="button"
          class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40"
          :disabled="busy"
          @click="restart"
        >
          重启
        </button>
        <button
          type="button"
          class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
          :disabled="busy"
          @click="refresh"
        >
          刷新
        </button>
      </div>
    </section>

    <!-- 3. 运行状态 -->
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <h2 class="text-sm font-medium text-zinc-400">运行状态</h2>
      <div v-if="status" class="mt-3 space-y-3">
        <div class="flex flex-wrap items-center gap-3">
          <span
            class="rounded-full px-3 py-1 text-sm font-medium"
            :class="stateClass[status.state] ?? stateClass.stopped"
          >
            {{ stateLabel[status.state] ?? status.state }}
          </span>
          <span v-if="status.pid" class="font-mono text-sm text-zinc-400"
            >PID {{ status.pid }}</span
          >
          <span v-if="status.mixed_port" class="font-mono text-sm text-zinc-400">
            端口 {{ status.mixed_port }}
          </span>
        </div>
        <dl class="grid gap-2 text-sm sm:grid-cols-2">
          <div class="flex justify-between rounded-lg bg-zinc-950/60 px-3 py-2">
            <dt class="text-zinc-500">TUN</dt>
            <dd :class="status.tun_enabled ? 'text-emerald-400' : 'text-zinc-400'">
              {{ status.tun_enabled ? '开启' : '关闭' }}
            </dd>
          </div>
          <div class="flex justify-between rounded-lg bg-zinc-950/60 px-3 py-2">
            <dt class="text-zinc-500">Mesh</dt>
            <dd :class="status.mesh_enabled ? 'text-emerald-400' : 'text-zinc-400'">
              {{ status.mesh_enabled ? '开启' : '关闭' }}
            </dd>
          </div>
          <div class="flex justify-between rounded-lg bg-zinc-950/60 px-3 py-2">
            <dt class="text-zinc-500">Gateway</dt>
            <dd :class="status.gateway ? 'text-emerald-400' : 'text-zinc-400'">
              {{ status.gateway ? '开启' : '关闭' }}
            </dd>
          </div>
        </dl>
        <p
          v-if="status.error"
          class="rounded-lg border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-200"
        >
          {{ status.error }}
        </p>
      </div>
      <p v-else class="mt-3 text-sm text-zinc-500">尚未获取状态</p>
    </section>

    <!-- 4. 日志 -->
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50">
      <button
        type="button"
        class="flex w-full items-center justify-between px-4 py-3 text-left"
        @click="logsOpen = !logsOpen"
      >
        <h2 class="text-sm font-medium text-zinc-200">运行日志</h2>
        <span class="text-zinc-500">{{ logsOpen ? '▾' : '▸' }}</span>
      </button>
      <div v-show="logsOpen" class="border-t border-zinc-800 px-4 pb-4">
        <pre
          class="mt-3 max-h-80 overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-300 whitespace-pre-wrap"
        >{{ logs || '（暂无日志，启动 stack 后此处会显示）' }}</pre>
      </div>
    </section>

    <!-- 5. Clash 代理（可选） -->
    <section v-if="proxies" class="rounded-xl border border-zinc-800 bg-zinc-900/50">
      <button
        type="button"
        class="flex w-full items-center justify-between px-4 py-3 text-left"
        @click="proxiesOpen = !proxiesOpen"
      >
        <h2 class="text-sm font-medium text-zinc-200">Clash 代理</h2>
        <span class="text-zinc-500">{{ proxiesOpen ? '▾' : '▸' }}</span>
      </button>
      <div v-show="proxiesOpen" class="border-t border-zinc-800 px-4 pb-4">
        <pre
          class="mt-3 max-h-96 overflow-auto rounded-lg bg-zinc-950 p-3 text-xs text-zinc-300"
        >{{ JSON.stringify(proxies, null, 2) }}</pre>
      </div>
    </section>
  </div>
</template>
