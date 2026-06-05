<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type JobSummary } from '@/api/client'

const jobs = ref<JobSummary[]>([])
const error = ref<string | null>(null)
const busy = ref(false)
const form = ref({ to: '', from: '', token: '' })

async function refresh() {
  const all = await api.listJobs()
  jobs.value = all.filter((j) => j.kind === 'fwd')
}

async function start() {
  busy.value = true
  error.value = null
  try {
    await api.createFwdJob({
      to: form.value.to,
      from: form.value.from,
      token: form.value.token || undefined,
    })
    await refresh()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

async function stop(id: string) {
  await api.stopJob(id)
  await refresh()
}

onMounted(async () => {
  try {
    await refresh()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
})
</script>

<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-semibold">TCP / WS forward</h1>
    <div
      v-if="error"
      class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <h2 class="text-sm font-medium text-zinc-400">New job</h2>
      <div class="mt-3 grid gap-3">
        <label class="flex flex-col gap-1 text-sm text-zinc-400"
          ><span>--to</span>
          <input
            v-model="form.to"
            class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
            placeholder="tcp://0.0.0.0:8080"
          ></label
        >
        <label class="flex flex-col gap-1 text-sm text-zinc-400"
          ><span>--from</span>
          <input
            v-model="form.from"
            class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
            placeholder="tcp://127.0.0.1:80"
          ></label
        >
        <label class="flex flex-col gap-1 text-sm text-zinc-400"
          ><span>--token</span>
          <input
            v-model="form.token"
            class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
          ></label
        >
      </div>
      <button
        type="button"
        class="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500"
        :disabled="busy"
        @click="start"
      >
        Start
      </button>
    </section>
    <section class="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <h2 class="text-sm font-medium text-zinc-400">Running</h2>
      <ul class="mt-2 divide-y divide-zinc-800 text-sm">
        <li v-for="j in jobs" :key="j.id" class="flex justify-between py-2">
          <span class="font-mono text-xs">{{ j.id.slice(0, 8) }} · {{ j.state }}</span>
          <button
            v-if="j.state === 'running'"
            type="button"
            class="rounded border border-zinc-700 px-2 py-0.5 text-xs hover:bg-zinc-800"
            @click="stop(j.id)"
          >
            Stop
          </button>
        </li>
      </ul>
    </section>
  </div>
</template>
