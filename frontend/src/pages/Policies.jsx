import React, { useState } from 'react'
import client from '../api/client'

export default function Policies() {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [message, setMessage] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    try {
      await client.post('/admin/policies', {
        name,
        description,
        rules: []
      })
      setMessage('Policy created')
      setName('')
      setDescription('')
    } catch (error) {
      setMessage('Failed to create policy')
    }
  }

  return (
    <div className="bg-slate-900 p-6 rounded-lg">
      <h2 className="text-xl font-semibold mb-4">Policies</h2>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="block text-sm text-slate-400">Name</label>
          <input
            className="w-full bg-slate-800 rounded px-3 py-2"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-sm text-slate-400">Description</label>
          <input
            className="w-full bg-slate-800 rounded px-3 py-2"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <button className="bg-sky-500 px-4 py-2 rounded text-white" type="submit">
          Create Policy
        </button>
        {message && <p className="text-sm text-slate-400">{message}</p>}
      </form>
    </div>
  )
}
