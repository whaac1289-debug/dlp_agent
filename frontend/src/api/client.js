import axios from 'axios'

const client = axios.create({
  baseURL: '/api/v1',
  timeout: 8000
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('dlp_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export default client
