import { lazy, Suspense } from 'react'
import {
  Activity,
  ArrowUpRight,
  FileInput,
  Fingerprint,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import AIStatusBadge from '../components/AIStatusBadge'
import EmptyState from '../components/EmptyState'
import StatCard from '../components/StatCard'

const ThreatActivityChart = lazy(
  () => import('../components/ThreatActivityChart')
)

function CapabilityRow({ icon: Icon, title, detail }) {
  return (
    <div className="capability-row">
      <span className="capability-icon" aria-hidden="true">
        <Icon size={17} strokeWidth={1.8} />
      </span>
      <span className="capability-copy">
        <strong>{title}</strong>
        <span>{detail}</span>
      </span>
      <AIStatusBadge status="not-checked" />
    </div>
  )
}

function OverviewPage({ activityData = [] }) {
  const navigate = useNavigate()

  return (
    <div className="overview-page">
      <section className="overview-intro">
        <div>
          <p className="section-eyebrow">THREAT MONITORING</p>
          <h2>Uncover threats. Keep secrets.</h2>
          <p className="overview-description">
            A clear view of your security posture starts with trusted evidence.
            No data source is connected yet.
          </p>
        </div>
        <button
          className="button button-primary"
          type="button"
          onClick={() => navigate('/import-logs')}
        >
          <FileInput size={17} aria-hidden="true" />
          <span>Import logs</span>
          <ArrowUpRight size={16} aria-hidden="true" />
        </button>
      </section>

      <section className="stats-grid" aria-label="Security overview metrics">
        <StatCard
          icon={Activity}
          label="Logs analyzed"
          value="—"
          detail="Waiting for a data source"
          context="No source"
          tone="emerald"
        />
        <StatCard
          icon={ShieldAlert}
          label="Detected incidents"
          value="—"
          detail="No incident data available"
          context="No records"
          tone="amber"
        />
        <StatCard
          icon={Fingerprint}
          label="Sensitive fields"
          value="—"
          detail="No scan has been run"
          context="Not scanned"
          tone="cyan"
        />
        <StatCard
          icon={ShieldCheck}
          label="Privacy protection"
          value="Not checked"
          detail="Firewall status not queried"
          context="Not checked"
          tone="emerald"
        />
      </section>

      <div className="overview-grid">
        <section className="panel threat-panel" aria-labelledby="threat-title">
          <div className="panel-heading">
            <div>
              <p className="section-eyebrow">ACTIVITY</p>
              <h2 id="threat-title">Threat activity</h2>
            </div>
            <span className="panel-state">
              <span className="state-dot state-dot-muted" />
              No telemetry
            </span>
          </div>
          <div
            className="chart-container"
            role="img"
            aria-label={
              activityData.length > 0
                ? 'Threat activity chart'
                : 'Threat activity chart. No data is available yet.'
            }
          >
            <div className="chart-grid-lines" aria-hidden="true" />
            {activityData.length > 0 && (
              <Suspense fallback={null}>
                <ThreatActivityChart data={activityData} />
              </Suspense>
            )}
            <div className="chart-empty-overlay">
              {activityData.length > 0 ? null : (
                <EmptyState
                  icon={Activity}
                  title="No activity to chart"
                  description="Import logs to see verified threat activity here."
                  compact
                />
              )}
            </div>
          </div>
        </section>

        <section
          className="panel capabilities-panel"
          aria-labelledby="capabilities-title"
        >
          <div className="panel-heading">
            <div>
              <p className="section-eyebrow">RUNTIME</p>
              <h2 id="capabilities-title">Hybrid AI capabilities</h2>
            </div>
            <span className="panel-heading-mark" aria-hidden="true">
              <Sparkles size={17} />
            </span>
          </div>
          <p className="panel-description">
            Status checks have not been run. No AI inference has been requested.
          </p>
          <div className="capability-list">
            <CapabilityRow
              icon={ShieldCheck}
              title="Private AI"
              detail="On-device inference"
            />
            <CapabilityRow
              icon={Activity}
              title="Cloud-assisted AI"
              detail="Requires firewall and consent"
            />
            <CapabilityRow
              icon={Fingerprint}
              title="Privacy firewall"
              detail="Runtime validation"
            />
          </div>
          <div className="capability-note">
            <ShieldCheck size={15} aria-hidden="true" />
            <span>Private and cloud routes remain separately controlled.</span>
          </div>
        </section>
      </div>

      <section className="panel recent-panel" aria-labelledby="recent-title">
        <div className="panel-heading recent-heading">
          <div>
            <p className="section-eyebrow">INVESTIGATION QUEUE</p>
            <h2 id="recent-title">Recent incidents</h2>
          </div>
          <button
            className="button button-secondary"
            type="button"
            onClick={() => navigate('/incidents')}
          >
            View incidents
            <ArrowUpRight size={15} aria-hidden="true" />
          </button>
        </div>
        <EmptyState
          icon={ShieldAlert}
          title="No incidents yet"
          description="Incidents will appear after real evidence has been imported and analyzed."
          action={
            <button
              className="text-button"
              type="button"
              onClick={() => navigate('/import-logs')}
            >
              Import logs to get started
              <ArrowUpRight size={14} aria-hidden="true" />
            </button>
          }
          compact
        />
      </section>
    </div>
  )
}

export default OverviewPage
