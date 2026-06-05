import { ref } from 'vue'
import { clearApiToken, getApiToken, setApiToken } from '@/api/tokens'

export const showLoginModal = ref(false)
export const loginError = ref<string | null>(null)
export const authenticated = ref(hasInitialToken())

function hasInitialToken(): boolean {
  return getApiToken().length > 0
}

let pendingLogin: Promise<string> | null = null
let resolveLogin: ((token: string) => void) | null = null
let rejectLogin: ((err: Error) => void) | null = null

function openLoginModal() {
  showLoginModal.value = true
  loginError.value = null
}

function closeLoginModal() {
  showLoginModal.value = false
  loginError.value = null
}

export function initAuth() {
  authenticated.value = hasInitialToken()
  if (!authenticated.value) {
    openLoginModal()
  }
}

export function logout() {
  clearApiToken()
  authenticated.value = false
  pendingLogin = null
  resolveLogin = null
  rejectLogin = null
  openLoginModal()
}

export function ensureAuthenticated(): Promise<string> {
  const token = getApiToken()
  if (token) return Promise.resolve(token)

  if (!pendingLogin) {
    openLoginModal()
    pendingLogin = new Promise<string>((resolve, reject) => {
      resolveLogin = resolve
      rejectLogin = reject
    })
  }
  return pendingLogin
}

function finishLogin(token: string) {
  authenticated.value = true
  closeLoginModal()
  resolveLogin?.(token)
  resolveLogin = null
  rejectLogin = null
  pendingLogin = null
}

function failLogin(message: string) {
  clearApiToken()
  authenticated.value = false
  loginError.value = message
}

async function validateToken(token: string): Promise<boolean> {
  const res = await fetch('/api/v1/health', {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (res.ok) return true

  if (res.status === 401) {
    failLogin('Token 无效，请检查后重试')
    return false
  }

  let message = `验证失败 (HTTP ${res.status})`
  try {
    const body = await res.json()
    if (body?.error?.message) message = body.error.message
  } catch {
    /* ignore */
  }
  failLogin(message)
  return false
}

export async function submitLogin(tokenInput: string): Promise<boolean> {
  loginError.value = null
  const token = tokenInput.trim()
  if (!token) {
    loginError.value = '请输入 API Token'
    return false
  }

  setApiToken(token)
  try {
    if (!(await validateToken(token))) {
      return false
    }
    finishLogin(token)
    return true
  } catch (e) {
    clearApiToken()
    authenticated.value = false
    loginError.value = e instanceof Error ? e.message : '无法连接服务'
    return false
  }
}

export function handleUnauthorized() {
  clearApiToken()
  authenticated.value = false
  if (pendingLogin) {
    rejectLogin?.(new Error('unauthorized'))
    pendingLogin = null
    resolveLogin = null
    rejectLogin = null
  }
  openLoginModal()
}
