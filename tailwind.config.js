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
        // Grayscale Theme
        'konvo-bg': '#121212',
        'konvo-surface': '#1E1E1E',
        'konvo-border': '#2C2C2C',
        'konvo-text': '#E0E0E0',
        'konvo-muted': '#9E9E9E',
        'konvo-accent': '#FFFFFF',
        'konvo-accent-vibrant': '#F5F5F5',
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