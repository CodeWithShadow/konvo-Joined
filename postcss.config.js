module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
    // Minify CSS in production
    ...(process.env.NODE_ENV === 'production' ? { cssnano: {} } : {})
  }
}