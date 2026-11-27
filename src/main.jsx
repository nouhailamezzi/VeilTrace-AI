import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './ai/appCheck'
import './index.css'
import App from './App.jsx'

if (import.meta.env.DEV && !import.meta.env.PROD) {
  void import('./ai/appCheckDevTest')
  void import('./ai/cloudAIDevTest')
  void import('./ai/localAIDevTest')
  void import('./ai/hybridRouterDevTest')
  void import('./ai/threatIntelligenceDevTest')
  void import('./ai/promptsDevTest')
  void import('./ai/investigationServiceDevTest')
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
