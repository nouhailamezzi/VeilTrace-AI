import { CircleHelp, CircleCheck, CircleX } from 'lucide-react'

const STATUS_ICONS = {
  'not-checked': CircleHelp,
  available: CircleCheck,
  unavailable: CircleX,
}

const STATUS_LABELS = {
  'not-checked': 'Not checked',
  available: 'Available',
  unavailable: 'Unavailable',
}

function AIStatusBadge({ status = 'not-checked', label }) {
  const Icon = STATUS_ICONS[status] ?? CircleHelp
  const visibleLabel = label ?? STATUS_LABELS[status] ?? STATUS_LABELS['not-checked']

  return (
    <span className={`ai-status-badge ai-status-${status}`}>
      <Icon aria-hidden="true" size={14} strokeWidth={1.8} />
      <span>{visibleLabel}</span>
    </span>
  )
}

export default AIStatusBadge
