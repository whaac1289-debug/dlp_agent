import axios from 'axios'

const client = axios.create({
  baseURL: '/api/v1',
  timeout: 8000,
  withCredentials: true
})

client.interceptors.request.use((config) => {
  const csrfCookie = document.cookie
    .split('; ')
    .find((row) => row.startsWith('dlp_csrf='))
  if (csrfCookie) {
    config.headers['X-CSRF-Token'] = csrfCookie.split('=')[1]
  }
  return config
})

export default client
