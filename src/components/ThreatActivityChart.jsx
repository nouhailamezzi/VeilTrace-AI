import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

function ThreatActivityChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data}
        margin={{ top: 12, right: 4, left: -24, bottom: 0 }}
      >
        <defs>
          <linearGradient id="activity-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--emerald)" stopOpacity={0.18} />
            <stop offset="100%" stopColor="var(--emerald)" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid
          stroke="var(--border)"
          strokeDasharray="3 5"
          vertical={false}
        />
        <XAxis dataKey="time" hide />
        <YAxis hide />
        <Tooltip
          contentStyle={{
            backgroundColor: 'var(--surface)',
            borderColor: 'var(--border)',
            borderRadius: '8px',
            color: 'var(--text)',
          }}
          itemStyle={{ color: 'var(--emerald)' }}
          labelStyle={{ color: 'var(--text)' }}
        />
        <Area
          type="monotone"
          dataKey="activity"
          stroke="var(--emerald)"
          fill="url(#activity-fill)"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export default ThreatActivityChart
