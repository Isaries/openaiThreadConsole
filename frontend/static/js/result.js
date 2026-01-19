/**
 * result.js - Search Result Page Logic
 * Handles pagination, thread toggling, PDF downloads, and themes.
 */

// Global State
let currentPage = 0;
let currentController = null;

// Helper to access config safely
const getConfig = () => window.THREAD_CONFIG || {};

/**
 * Toggle Thread Expansion
 * Called via onclick in HTML
 */
window.toggleThread = function (headerElement) {
    // Support finding parent from inner elements
    if (headerElement.classList.contains('thread-header')) {
        headerElement.parentElement.classList.toggle('expanded');
    }
}

/**
 * Change Page
 * Called via onclick in HTML
 */
window.changePage = async function (delta) {
    const config = getConfig();
    const totalPages = config.totalPages || 1;

    const newPage = currentPage + delta;
    if (newPage < 0 || newPage >= totalPages) return;

    await loadPage(newPage);
}

/**
 * Helper: Generate Skeleton HTML
 */
function getSkeletonHTML() {
    let html = '';
    // Generate 5 items to mimic a page load
    for (let i = 0; i < 5; i++) {
        html += `
        <div class="skeleton-card">
            <div class="skeleton-left">
                <div class="skeleton-loading skeleton-title"></div>
            </div>
            <div class="skeleton-right">
                <div class="skeleton-loading skeleton-meta-line"></div>
                <div class="skeleton-loading skeleton-meta-line" style="width: 80px;"></div>
            </div>
        </div>`;
    }
    return html;
}

/**
 * Load Page Data via AJAX
 */
async function loadPage(pageIndex) {
    const config = getConfig();
    const taskId = config.taskId;

    const container = document.getElementById('thread-list-container');

    // UX Improvement: Inject Skeleton immediately
    if (container) {
        container.innerHTML = getSkeletonHTML();

        // Scroll to top to make it obvious
        const header = document.querySelector('.header');
        if (header) header.scrollIntoView({ behavior: 'smooth' });
    }

    try {
        const response = await fetch(`/search/result/${taskId}?page=${pageIndex}`, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        if (!response.ok) throw new Error("Load failed");

        const html = await response.text();
        if (container) container.innerHTML = html;

        currentPage = pageIndex;
        updatePaginationUI();

        // Re-attach listeners for new elements
        if (window.attachPdfListeners) window.attachPdfListeners();

    } catch (err) {
        console.error(err);
        if (container) {
            container.innerHTML = `
                <div class="no-result" style="text-align:center; padding: 40px;">
                    <div class="icon" style="font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
                    <h3>載入失敗</h3>
                    <p style="color: #666;">無法讀取資料，請稍後再試。</p>
                    <button onclick="location.reload()" class="btn btn-secondary" style="margin-top: 1rem;">重新整理頁面</button>
                </div>
            `;
        }
    } warning: {
        // No opacity cleanup needed anymore
    }
}

function updatePaginationUI() {
    const config = getConfig();
    const totalPages = config.totalPages || 1;

    const pageInfo = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');

    if (pageInfo) pageInfo.innerText = `第 ${currentPage + 1} 頁 / 共 ${totalPages} 頁`;
    if (prevBtn) prevBtn.disabled = (currentPage === 0);
    if (nextBtn) nextBtn.disabled = (currentPage >= totalPages - 1);
}

/**
 * Cancel PDF Download
 */
window.cancelDownload = function () {
    if (currentController) {
        currentController.abort();
    }
    const modal = document.getElementById('downloadModal');
    if (modal) modal.style.display = 'none';
}

document.addEventListener('DOMContentLoaded', () => {
    const config = getConfig();

    // Sync Initial Page State
    if (config.currentPage !== undefined) {
        currentPage = config.currentPage;
    }
    updatePaginationUI();

    // 1. Scroll To Top Button
    const scrollToTopBtn = document.getElementById("scrollTopBtn");
    if (scrollToTopBtn) {
        window.onscroll = function () {
            if (document.body.scrollTop > 300 || document.documentElement.scrollTop > 300) {
                scrollToTopBtn.style.display = "flex";
            } else {
                scrollToTopBtn.style.display = "none";
            }
        };
        scrollToTopBtn.addEventListener("click", function () {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }

    // 2. Apply Theme
    (function () {
        const savedTheme = localStorage.getItem('threadConsole_theme');
        if (savedTheme) {
            document.body.classList.add(savedTheme);
        } else {
            document.body.classList.add('bg-default');
        }
    })();

    // 3. Debug Log Console Output
    if (config.debugLog) {
        console.group("🚀 Thread Search Debug Console");
        console.log("📊 Search Summary (Scanned Threads):", config.debugLog);
        console.groupEnd();
    }

    // 4. PDF Download Logic
    window.attachPdfListeners = () => {
        document.querySelectorAll('.btn-pdf:not(.handled)').forEach(btn => {
            btn.classList.add('handled');
            btn.addEventListener('click', async (e) => {
                e.preventDefault();

                const url = btn.href;
                const modal = document.getElementById('downloadModal');

                if (modal) modal.style.display = 'flex';

                currentController = new AbortController();
                const signal = currentController.signal;

                try {
                    const response = await fetch(url, { signal });

                    if (!response.ok) {
                        const errText = await response.text();
                        throw new Error(errText || 'Download failed');
                    }

                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);

                    const a = document.createElement('a');
                    a.href = downloadUrl;

                    // Filename deduction
                    const disposition = response.headers.get('Content-Disposition');
                    let filename = 'download.pdf';
                    if (disposition && disposition.indexOf('attachment') !== -1) {
                        const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                        const matches = filenameRegex.exec(disposition);
                        if (matches != null && matches[1]) {
                            filename = matches[1].replace(/['"]/g, '');
                        }
                    }
                    if (!filename.endsWith('.pdf') && !filename.endsWith('.zip')) {
                        filename = url.split('/').pop() + '.pdf';
                    }

                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(downloadUrl);

                } catch (err) {
                    if (err.name === 'AbortError') {
                        console.log('Download cancelled by user');
                    } else {
                        console.error(err);
                        alert('下載失敗: ' + (err.message || '未知錯誤'));
                    }
                } finally {
                    if (modal) modal.style.display = 'none';
                    currentController = null;
                }
            });
        });
    };

    // Initial attachment
    window.attachPdfListeners();
});
