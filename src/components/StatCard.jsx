function StatCard({
  icon: Icon,
  label,
  value,
  detail,
  context,
  tone = 'emerald',
}) {
  return (
    <article className={`stat-card stat-card-${tone}`}>
      <div className="stat-card-top flex items-center justify-between">
        <span className="stat-card-icon" aria-hidden="true">
          <Icon size={18} strokeWidth={1.8} />
        </span>
        <span className="stat-card-period">{context}</span>
      </div>
      <p className="stat-card-label">{label}</p>
      <p className="stat-card-value">{value}</p>
      <p className="stat-card-detail">{detail}</p>
    </article>
  )
}

export default StatCard
