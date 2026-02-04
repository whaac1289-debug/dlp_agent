import React, { useEffect, useState } from 'react'
import client from '../api/client'

export default function Agents() {
  const [agents, setAgents] = useState([])

  useEffect(() => {
    client.get('/admin/agents').then((res) => setAgents(res.data)).catch(() => {})
  }, [])

  return (
    <div className="bg-slate-900 p-6 rounded-lg">
      <h2 className="text-xl font-semibold mb-4">Agents</h2>
      <table className="w-full text-left">
        <thead>
          <tr className="text-slate-400">
            <th className="py-2">Agent ID</th>
            <th>Hostname</th>
            <th>Status</th>
            <th>Last heartbeat</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.id} className="border-t border-slate-800">
              <td className="py-2">{agent.agent_uuid}</td>
              <td>{agent.hostname}</td>
              <td>{agent.status}</td>
              <td>{agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'N/A'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
