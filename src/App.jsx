import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppLayout from './components/AppLayout'
import OverviewPage from './pages/OverviewPage'
import PlaceholderPage from './pages/PlaceholderPage'
import ThemeProvider from './context/ThemeProvider'

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route index element={<OverviewPage />} />
            <Route
              path="import-logs"
              element={
                <PlaceholderPage
                  title="Import logs"
                  description="Connect or import incident evidence when log ingestion is available."
                  iconName="import"
                />
              }
            />
            <Route
              path="incidents"
              element={
                <PlaceholderPage
                  title="Incidents"
                  description="Validated incident records will appear here when an evidence source is connected."
                  iconName="incidents"
                />
              }
            />
            <Route
              path="investigator"
              element={
                <PlaceholderPage
                  title="AI Investigator"
                  description="Investigation workflows are not connected to this interface yet. No AI request has been made."
                  iconName="investigator"
                />
              }
            />
            <Route
              path="privacy-firewall"
              element={
                <PlaceholderPage
                  title="Privacy Firewall"
                  description="Firewall status has not been checked in this dashboard."
                  iconName="privacy"
                />
              }
            />
            <Route
              path="threat-intelligence"
              element={
                <PlaceholderPage
                  title="Threat Intelligence"
                  description="No vulnerability lookups have been requested from this dashboard."
                  iconName="threats"
                />
              }
            />
            <Route
              path="reports"
              element={
                <PlaceholderPage
                  title="Reports"
                  description="Investigation reports will be listed here once real analysis results are available."
                  iconName="reports"
                />
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  )
}

export default App
