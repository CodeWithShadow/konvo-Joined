/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./app.js",
    // Add any other files that use Tailwind classes
  ],
  theme: {
    extend: {
      colors: {
        // Match your CSS custom properties
        'konvo-bg': '#0a0a0a',
        'konvo-surface': '#1c1c1c',
        'konvo-border': '#333333',
        'konvo-text': '#ededed',
        'konvo-muted': '#888888',
      },
      fontFamily: {
        'inter': ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
       height: {
        'dvh': '100dvh',
        'svh': '100svh',
      },
    },
  },
  plugins: [],
}