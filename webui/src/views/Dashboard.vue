<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { api, connectJobEvents, type JobSummary, type MetaResponse } from '@/api/client'
import { authenticated } from '@/composables/auth'

const meta = ref<MetaResponse | null>(null)
const healthStatus = ref<string | null>(null)
const jobs = ref<JobSummary[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
let ws: WebSocket | null = null

async function refresh() {
  if (!authenticated.value) return
  loading.value = true
  error.value = null
  try {
    meta.value = await api.meta()
    healthStatus.value = (await api.health()).status
    jobs.value = await api.listJobs()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function connectWs() {
  ws?.close()
  ws = connectJobEvents(() => refresh())
}

async function stopJob(id: string) {
  await api.stopJob(id)
  await refresh()
}

watch(authenticated, (ok) => {
  if (ok) {
    refresh()
    connectWs()
  } else {
    ws?.close()
    ws = null
    healthStatus.value = null
    jobs.value = []
  }
})

onMounted(() => {
  if (authenticated.value) {
    refresh()
    connectWs()
  }
})

onUnmounted(() => ws?.close())
</script>

<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-semibold text-zinc-50">Dashboard</h1>
    <p class="text-sm text-zinc-400">Control plane overview</p>
    <div
      v-if="error"
      class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>
    <div class="grid gap-4 sm:grid-cols-2">
      <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <h2 class="text-sm font-medium text-zinc-400">Meta</h2>
        <dl v-if="meta" class="mt-3 space-y-2 text-sm">
          <div class="flex justify-between">
            <dt class="text-zinc-500">zay</dt>
            <dd class="font-mono text-zinc-200">{{ meta.version }}</dd>
          </div>
          <div class="flex justify-between">
            <dt class="text-zinc-500">sing-box</dt>
            <dd class="font-mono text-zinc-200">{{ meta.singbox_version }}</dd>
          </div>
          <div class="flex justify-between gap-2">
            <dt class="text-zinc-500">data_dir</dt>
            <dd class="truncate font-mono text-xs text-zinc-300">{{ meta.data_dir }}</dd>
          </div>
        </dl>
      </section>
      <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <h2 class="text-sm font-medium text-zinc-400">Health</h2>
        <p v-if="healthStatus" class="mt-3 text-3xl font-semibold text-emerald-400">
          {{ healthStatus }}
        </p>
        <button
          type="button"
          class="mt-4 rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800"
          :disabled="loading"
          @click="refresh"
        >
          Refresh
        </button>
      </section>
    </div>
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <h2 class="text-sm font-medium text-zinc-400">Jobs</h2>
      <ul class="mt-3 divide-y divide-zinc-800 text-sm">
        <li v-for="j in jobs" :key="j.id" class="flex justify-between py-2">
          <span
            ><span class="font-mono text-xs text-zinc-500">{{ j.id.slice(0,8) }}</span> {{ j.kind }}
            <span class="rounded bg-zinc-800 px-2 py-0.5 text-xs">{{ j.state }}</span></span
          >
          <button
            v-if="j.state==='running'||j.state==='starting'"
            type="button"
            class="rounded border border-zinc-700 px-2 py-0.5 text-xs hover:bg-zinc-800"
            @click="stopJob(j.id)"
          >
            Stop
          </button>
        </li>
      </ul>
    </section>
  </div>
</template>
