import {
  Activity,
  FileBarChart2,
  FileInput,
  Fingerprint,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import EmptyState from '../components/EmptyState'

const PAGE_ICONS = {
  import: FileInput,
  incidents: ShieldAlert,
  investigator: Search,
  privacy: Fingerprint,
  threats: ShieldCheck,
  reports: FileBarChart2,
}

function PlaceholderPage({ title, description, iconName }) {
  const Icon = PAGE_ICONS[iconName] ?? Activity

  return (
    <section className="placeholder-page">
      <div className="placeholder-heading">
        <p className="section-eyebrow">WORKSPACE</p>
        <h2>{title}</h2>
        <span className="placeholder-label">Placeholder</span>
      </div>
      <div className="panel placeholder-panel">
        <EmptyState
          icon={Icon}
          title={`${title} is not connected yet`}
          description={description}
        />
      </div>
    </section>
  )
}

export default PlaceholderPage
