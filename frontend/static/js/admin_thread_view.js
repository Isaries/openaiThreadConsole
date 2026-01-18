/**
 * admin_thread_view.js
 * Handles PDF Download Logic for Admin View
 */

let currentController = null;

document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('downloadModal');

    // Attach listener to all PDF buttons
    const attachPdfListeners = () => {
        document.querySelectorAll('.btn-pdf:not(.handled)').forEach(btn => {
            btn.classList.add('handled');
            btn.addEventListener('click', async (e) => {
                e.preventDefault(); // Stop navigation

                const url = btn.href;

                // Show Modal
                if (modal) modal.style.display = 'flex';

                // Init AbortController
                currentController = new AbortController();
                const signal = currentController.signal;

                try {
                    const response = await fetch(url, { signal });

                    if (!response.ok) {
                        const errText = await response.text();
                        throw new Error(errText || 'Download failed');
                    }

                    // Create Blob
                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);

                    // Trigger Download
                    const a = document.createElement('a');
                    a.href = downloadUrl;

                    // Try to get filename
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

    attachPdfListeners();
});

function cancelDownload() {
    if (currentController) {
        currentController.abort();
    }
    const modal = document.getElementById('downloadModal');
    if (modal) modal.style.display = 'none';
}
