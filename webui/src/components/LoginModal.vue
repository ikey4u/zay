<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { loginError, showLoginModal, submitLogin } from '@/composables/auth'

const tokenInput = ref('')
const loading = ref(false)
const inputRef = ref<HTMLInputElement | null>(null)

watch(showLoginModal, async (open) => {
  if (!open) return
  tokenInput.value = ''
  loginError.value = null
  await nextTick()
  inputRef.value?.focus()
})

async function onSubmit() {
  if (loading.value) return
  loading.value = true
  try {
    await submitLogin(tokenInput.value)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <Teleport to="body">
    <div
      v-if="showLoginModal"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-zinc-950/90 p-4 backdrop-blur-sm"
    >
      <form
        class="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="login-title"
        @submit.prevent="onSubmit"
      >
        <div class="mb-6 text-center">
          <p class="text-xs font-medium uppercase tracking-widest text-emerald-500">Zay</p>
          <h1 id="login-title" class="mt-2 text-xl font-semibold text-zinc-50">登录控制平面</h1>
          <p class="mt-2 text-sm text-zinc-400">
            输入启动 <code>zay serve</code> 时设置的 Bearer Token
          </p>
        </div>

        <label class="block text-sm text-zinc-400">
          API Token
          <input
            ref="inputRef"
            v-model="tokenInput"
            type="password"
            autocomplete="current-password"
            class="mt-2 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-zinc-100 outline-none ring-emerald-500/0 focus:border-emerald-600 focus:ring-2 focus:ring-emerald-500/30"
            placeholder="your-secret"
            :disabled="loading"
          >
        </label>

        <p v-if="loginError" class="mt-3 text-sm text-red-300">{{ loginError }}</p>

        <button
          type="submit"
          class="mt-5 w-full rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          :disabled="loading"
        >
          {{ loading ? '验证中…' : '登录' }}
        </button>
      </form>
    </div>
  </Teleport>
</template>
