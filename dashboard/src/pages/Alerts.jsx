import React, { useEffect, useState } from 'react'
import client from '../api/client'

export default function Alerts() {
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    client.get('/admin/alerts').then((res) => setAlerts(res.data)).catch(() => {})
  }, [])

  return (
    <div className="bg-slate-900 p-6 rounded-lg">
      <h2 className="text-xl font-semibold mb-4">Alerts</h2>
      <table className="w-full text-left">
        <thead>
          <tr className="text-slate-400">
            <th className="py-2">ID</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-t border-slate-800">
              <td className="py-2">{alert.id}</td>
              <td>{alert.severity}</td>
              <td>{alert.status}</td>
              <td>{new Date(alert.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
