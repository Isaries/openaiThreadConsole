// Utility Functions
function showSleepMessage() {
    const wrapper = document.getElementById('avatar-wrapper');
    const msg = document.createElement('div');
    msg.innerText = 'Remember to sleep...';
    msg.className = 'floating-message';
    wrapper.appendChild(msg);
    setTimeout(() => msg.remove(), 1500);
}

function enableFocusToClear(inp) {
    if (!inp) return;
    inp.addEventListener('focus', () => {
        const currentVal = inp.value;
        if (!currentVal) return;
        inp.dataset.saved = currentVal;
        inp.value = '';
        inp.dispatchEvent(new Event('input', { bubbles: true }));
    });
    inp.addEventListener('blur', () => {
        if (inp.value.trim() === '' && inp.dataset.saved) {
            inp.value = inp.dataset.saved;
            inp.dispatchEvent(new Event('input', { bubbles: true }));
        }
    });
    inp.addEventListener('change', () => {
        if (inp.value) inp.dataset.saved = inp.value;
    });
}

// Spin Animation Injection
(function injectStyles() {
    const styleSheet = document.createElement("style");
    styleSheet.innerText = `
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        /* Force Datalist Arrow in modern browsers */
        input[list]::-webkit-calendar-picker-indicator {
            opacity: 1 !important;
            display: block !important;
            background: inherit;
            cursor: pointer;
        }
    `;
    document.head.appendChild(styleSheet);
})();
