import { Menu, Moon, ShieldCheck, Sun } from 'lucide-react'
import useTheme from '../context/useTheme'

function Header({ title, onMenuClick, isNavOpen }) {
  const { theme, toggleTheme } = useTheme()
  const ThemeIcon = theme === 'dark' ? Sun : Moon
  const nextTheme = theme === 'dark' ? 'light' : 'dark'

  return (
    <header className="app-header">
      <div className="header-heading">
        <button
          className="mobile-menu-button"
          type="button"
          aria-label={isNavOpen ? 'Close navigation' : 'Open navigation'}
          aria-expanded={isNavOpen}
          aria-controls="primary-navigation"
          onClick={onMenuClick}
        >
          <Menu size={20} aria-hidden="true" />
        </button>
        <div>
          <p className="header-eyebrow">SECURITY WORKSPACE</p>
          <h1>{title}</h1>
        </div>
      </div>
      <div className="header-actions">
        <button
          className="theme-toggle"
          type="button"
          aria-label={`Switch to ${nextTheme} theme`}
          aria-pressed={theme === 'light'}
          title={`Switch to ${nextTheme} theme`}
          onClick={toggleTheme}
        >
          <ThemeIcon size={17} aria-hidden="true" />
          <span className="theme-toggle-label">
            {theme === 'dark' ? 'Light' : 'Dark'}
          </span>
        </button>
        <div className="header-status" aria-label="Workspace status">
          <span className="header-status-icon" aria-hidden="true">
            <ShieldCheck size={16} />
          </span>
          <span>Monitoring not configured</span>
        </div>
      </div>
    </header>
  )
}

export default Header
