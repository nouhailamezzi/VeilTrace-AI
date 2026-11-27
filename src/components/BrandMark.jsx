function BrandMark({ className = '' }) {
  return (
    <svg
      className={className}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M24 4.5 40 10v12.2c0 10.1-6.1 17.3-16 21.3-9.9-4-16-11.2-16-21.3V10l16-5.5Z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="m13.5 18.5 6.1 10.2 5.2-7.5 4.6 8.1 5.1-14"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="34.5" cy="15.3" r="2" fill="currentColor" />
    </svg>
  )
}

export default BrandMark
