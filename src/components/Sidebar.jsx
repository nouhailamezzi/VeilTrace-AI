import {
  Activity,
  FileBarChart2,
  FileInput,
  Fingerprint,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'
import BrandMark from './BrandMark'

const NAV_ITEMS = [
  { label: 'Overview', path: '/', icon: Activity, end: true },
  { label: 'Import Logs', path: '/import-logs', icon: FileInput },
  { label: 'Incidents', path: '/incidents', icon: ShieldAlert },
  { label: 'AI Investigator', path: '/investigator', icon: Search },
  { label: 'Privacy Firewall', path: '/privacy-firewall', icon: Fingerprint },
  { label: 'Threat Intelligence', path: '/threat-intelligence', icon: ShieldCheck },
  { label: 'Reports', path: '/reports', icon: FileBarChart2 },
]

function Sidebar({ isOpen, onNavigate }) {
  return (
    <>
      {isOpen && (
        <button
          className="sidebar-scrim"
          type="button"
          aria-label="Close navigation menu"
          onClick={onNavigate}
        />
      )}
      <aside
        className={`app-sidebar${isOpen ? ' app-sidebar-open' : ''}`}
        aria-label="Main sidebar"
      >
        <div className="sidebar-brand flex items-center">
          <BrandMark className="brand-mark" />
          <div className="brand-copy">
            <span className="brand-name">VeilTrace AI</span>
            <span className="brand-product">SECURITY WORKSPACE</span>
          </div>
        </div>

        <div className="sidebar-section-label">Workspace</div>
        <nav
          className="sidebar-nav"
          id="primary-navigation"
          aria-label="Primary navigation"
        >
          {NAV_ITEMS.map(({ label, path, icon: Icon, end }) => (
            <NavLink
              key={path}
              to={path}
              end={end}
              onClick={onNavigate}
              className={({ isActive }) =>
                `sidebar-link${isActive ? ' sidebar-link-active' : ''}`
              }
            >
              <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="sidebar-footer-icon" aria-hidden="true">
            <ShieldCheck size={17} />
          </span>
          <div>
            <strong>Privacy first</strong>
            <p>Cloud analysis requires explicit approval.</p>
          </div>
        </div>
      </aside>
    </>
  )
}

export default Sidebar
