const TOKEN_KEY = 'zay.serve.token'

export function getApiToken(): string {
  const fromStorage = sessionStorage.getItem(TOKEN_KEY)
  if (fromStorage) return fromStorage
  const fromEnv = import.meta.env.VITE_API_TOKEN
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    sessionStorage.setItem(TOKEN_KEY, fromEnv)
    return fromEnv
  }
  return ''
}

export function setApiToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token.trim())
}

export function clearApiToken() {
  sessionStorage.removeItem(TOKEN_KEY)
}

export function hasApiToken(): boolean {
  return getApiToken().length > 0
}
