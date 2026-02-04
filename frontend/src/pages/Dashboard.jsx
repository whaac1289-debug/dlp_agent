import React, { useEffect, useState } from 'react'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend
} from 'chart.js'
import client from '../api/client'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

export default function Dashboard() {
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    client.get('/admin/events').then((res) => setEvents(res.data)).catch(() => {})
    client.get('/admin/alerts').then((res) => setAlerts(res.data)).catch(() => {})
  }, [])

  const labels = events.slice(0, 10).map((e) => new Date(e.created_at).toLocaleTimeString())
  const data = {
    labels,
    datasets: [
      {
        label: 'Recent Events',
        data: events.slice(0, 10).map((_, idx) => idx + 1),
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.3)'
      }
    ]
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900 p-4 rounded-lg">
          <p className="text-slate-400">Events</p>
          <p className="text-2xl font-semibold">{events.length}</p>
        </div>
        <div className="bg-slate-900 p-4 rounded-lg">
          <p className="text-slate-400">Alerts</p>
          <p className="text-2xl font-semibold">{alerts.length}</p>
        </div>
        <div className="bg-slate-900 p-4 rounded-lg">
          <p className="text-slate-400">Open Alerts</p>
          <p className="text-2xl font-semibold">
            {alerts.filter((a) => a.status === 'open').length}
          </p>
        </div>
      </div>
      <div className="bg-slate-900 p-6 rounded-lg">
        <Line data={data} />
      </div>
    </div>
  )
}
