import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Header from './Header'
import Sidebar from './Sidebar'

const PAGE_TITLES = {
  '/': 'Overview',
  '/import-logs': 'Import Logs',
  '/incidents': 'Incidents',
  '/investigator': 'AI Investigator',
  '/privacy-firewall': 'Privacy Firewall',
  '/threat-intelligence': 'Threat Intelligence',
  '/reports': 'Reports',
}

function AppLayout() {
  const [isNavOpen, setIsNavOpen] = useState(false)
  const { pathname } = useLocation()
  const title = PAGE_TITLES[pathname] ?? 'Overview'

  useEffect(() => {
    if (!isNavOpen) {
      return undefined
    }
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        setIsNavOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isNavOpen])

  return (
    <div className="app-shell min-h-screen">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <Sidebar
        isOpen={isNavOpen}
        onNavigate={() => setIsNavOpen(false)}
      />
      <div className="app-main">
        <Header
          title={title}
          isNavOpen={isNavOpen}
          onMenuClick={() => setIsNavOpen((open) => !open)}
        />
        <main className="page-content" id="main-content" tabIndex="-1">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

export default AppLayout
