import React from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Alerts from './pages/Alerts'
import Policies from './pages/Policies'

const NavItem = ({ to, label }) => (
  <NavLink
    to={to}
    className={({ isActive }) =>
      `px-3 py-2 rounded-md ${isActive ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800'}`
    }
  >
    {label}
  </NavLink>
)

export default function App() {
  return (
    <div className="min-h-screen flex">
      <aside className="w-64 bg-slate-900 p-6">
        <h1 className="text-xl font-semibold mb-6">DLP Admin</h1>
        <nav className="flex flex-col gap-2">
          <NavItem to="/" label="Dashboard" />
          <NavItem to="/agents" label="Agents" />
          <NavItem to="/alerts" label="Alerts" />
          <NavItem to="/policies" label="Policies" />
        </nav>
      </aside>
      <main className="flex-1 p-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/policies" element={<Policies />} />
        </Routes>
      </main>
    </div>
  )
}
