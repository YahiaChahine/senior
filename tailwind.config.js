module.exports = {
  content: [
    "./src/**/*.{html,ts}",
  ],
  theme: {
    extend: {
      colors: {
        'hacker-green': '#00ff00',
        'hacker-dark': '#0a0a0a',
        'hacker-panel': '#111111',
        'hacker-warning': '#ff5500',
      },
      fontFamily: {
        'mono': ['"Courier New"', 'monospace'],
      },
      boxShadow: {
        'retro': '0 0 10px rgba(0, 255, 0, 0.5)',
      }
    },
  },
  plugins: [],
}