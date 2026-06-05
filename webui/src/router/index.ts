import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '@/views/Dashboard.vue'
import Stack from '@/views/Stack.vue'
import Config from '@/views/Config.vue'
import Ssh from '@/views/Ssh.vue'
import Fwd from '@/views/Fwd.vue'
import Http from '@/views/Http.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: Dashboard },
    { path: '/stack', name: 'stack', component: Stack },
    { path: '/config', name: 'config', component: Config },
    { path: '/ssh', name: 'ssh', component: Ssh },
    { path: '/fwd', name: 'fwd', component: Fwd },
    { path: '/http', name: 'http', component: Http },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

export default router
