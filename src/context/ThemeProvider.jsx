import { useCallback, useEffect, useState } from 'react'
import ThemeContext from './themeContext'

const STORAGE_KEY = 'veiltrace-theme'
const THEMES = ['dark', 'light']

function getInitialTheme() {
  if (typeof document !== 'undefined') {
    const documentTheme = document.documentElement.dataset.theme
    if (THEMES.includes(documentTheme)) {
      return documentTheme
    }
  }

  try {
    return localStorage.getItem(STORAGE_KEY) === 'light' ? 'light' : 'dark'
  } catch (error) {
    console.warn('Unable to restore the saved theme preference.', error)
    return 'dark'
  }
}

function updateDocumentTheme(theme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
  document.querySelector('meta[name="theme-color"]')?.setAttribute(
    'content',
    theme === 'light' ? '#F8FAFC' : '#080F1C',
  )
}

function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(getInitialTheme)

  const setTheme = useCallback((nextTheme) => {
    if (!THEMES.includes(nextTheme)) {
      return
    }

    updateDocumentTheme(nextTheme)
    setThemeState(nextTheme)

    try {
      localStorage.setItem(STORAGE_KEY, nextTheme)
    } catch (error) {
      console.warn('Unable to save the theme preference.', error)
    }
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }, [setTheme, theme])

  useEffect(() => {
    updateDocumentTheme(theme)
  }, [theme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export default ThemeProvider
