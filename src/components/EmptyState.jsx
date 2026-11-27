import { FileSearch } from 'lucide-react'

function EmptyState({
  icon: Icon = FileSearch,
  title,
  description,
  action,
  compact = false,
}) {
  return (
    <div className={`empty-state${compact ? ' empty-state-compact' : ''}`}>
      <span className="empty-state-icon" aria-hidden="true">
        <Icon size={20} strokeWidth={1.7} />
      </span>
      <div className="empty-state-copy">
        <h3>{title}</h3>
        <p>{description}</p>
        {action}
      </div>
    </div>
  )
}

export default EmptyState
