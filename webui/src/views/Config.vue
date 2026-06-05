<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api/client'

const content = ref('')
const error = ref<string | null>(null)
const message = ref<string | null>(null)
const busy = ref(false)

async function load() {
  error.value = null
  try {
    content.value = await api.getConfig()
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
}

async function save() {
  busy.value = true
  message.value = null
  error.value = null
  try {
    await api.putConfig(content.value)
    message.value = 'Saved'
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

async function validate() {
  busy.value = true
  message.value = null
  error.value = null
  try {
    await api.validateConfig()
    message.value = 'Valid TOML'
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-semibold text-zinc-50">Config</h1>
    <p class="text-sm text-zinc-400">Edit <code>zay.toml</code></p>
    <div
      v-if="error"
      class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>
    <div
      v-if="message"
      class="rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-200"
    >
      {{ message }}
    </div>
    <textarea
      v-model="content"
      class="min-h-[24rem] w-full rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-sm text-zinc-100 focus:border-emerald-700 focus:outline-none"
      spellcheck="false"
    />
    <div class="flex gap-2">
      <button
        type="button"
        class="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500 disabled:opacity-50"
        :disabled="busy"
        @click="save"
      >
        Save
      </button>
      <button
        type="button"
        class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
        :disabled="busy"
        @click="validate"
      >
        Validate
      </button>
      <button
        type="button"
        class="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
        @click="load"
      >
        Reload
      </button>
    </div>
  </div>
</template>
