document.addEventListener('DOMContentLoaded', () => {
    const themeSelect = document.getElementById('themeSelect');
    const body = document.body;

    function applyTheme(theme) {
        // Remove all known theme classes
        body.classList.remove('bg-default', 'bg-aurora', 'bg-grid', 'bg-glass', 'bg-gray');
        // Add selected theme
        body.classList.add(theme);
        if (themeSelect) themeSelect.value = theme;
        localStorage.setItem('threadConsole_theme', theme);

        // Adjust card transparency for themes
        const card = document.querySelector('.auth-card');
        if (card) {
            if (theme === 'bg-default' || theme === 'bg-grid') {
                card.style.background = 'rgba(255, 255, 255, 0.95)';
            } else {
                card.style.background = 'rgba(255, 255, 255, 0.75)'; // More translucent for Aurora/Glass
            }
        }
    }

    // Init Theme
    const savedTheme = localStorage.getItem('threadConsole_theme') || 'bg-default';
    applyTheme(savedTheme);

    if (themeSelect) {
        themeSelect.addEventListener('change', (e) => {
            applyTheme(e.target.value);
        });
    }
});
