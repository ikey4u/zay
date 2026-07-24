<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import LoginModal from '@/components/LoginModal.vue'
import { authenticated, initAuth, logout } from '@/composables/auth'

initAuth()
</script>

<template>
  <LoginModal />
  <div
    class="flex min-h-screen flex-col transition-[filter,opacity]"
    :class="authenticated ? '' : 'pointer-events-none select-none opacity-40 blur-[1px]'"
  >
    <header class="border-b border-zinc-800 bg-zinc-900/90 px-4 py-3 backdrop-blur">
      <div class="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4">
        <div class="flex flex-wrap items-center gap-6">
          <span class="text-lg font-semibold tracking-tight text-zinc-50">Zay</span>
          <nav class="flex flex-wrap gap-4 text-sm text-zinc-400">
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/"
              >Dashboard</RouterLink
            >
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/stack"
              >Stack</RouterLink
            >
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/config"
              >Config</RouterLink
            >
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/ssh"
              >SSH</RouterLink
            >
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/fwd"
              >Fwd</RouterLink
            >
            <RouterLink
              class="hover:text-zinc-100 [&.router-link-active]:font-medium [&.router-link-active]:text-emerald-400"
              to="/http"
              >HTTP</RouterLink
            >
          </nav>
        </div>
        <div v-if="authenticated" class="flex items-center gap-3 text-xs text-zinc-400">
          <span class="inline-flex items-center gap-1.5">
            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            已登录
          </span>
          <button
            type="button"
            class="rounded-lg border border-zinc-700 px-3 py-1.5 text-zinc-300 hover:bg-zinc-800"
            @click="logout"
          >
            退出
          </button>
        </div>
      </div>
    </header>
    <main class="mx-auto w-full max-w-6xl flex-1 px-4 py-8"><RouterView /></main>
  </div>
</template>
