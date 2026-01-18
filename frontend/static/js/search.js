document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('searchForm');
    const loading = document.getElementById('loading');
    const btn = document.querySelector('button[type="submit"]');
    const targetName = document.getElementById('target_name');
    const startDate = document.getElementById('start_date');
    const endDate = document.getElementById('end_date');
    const dateInfo = document.getElementById('dateInfo');
    const errorMessage = document.getElementById('errorMessage');

    // Date Logic
    function updateDateInfo() {
        const start = startDate.value;
        const end = endDate.value;

        if (start && end) {
            if (start > end) {
                dateInfo.innerText = '⚠️ 結束日期不可早於開始日期';
                dateInfo.className = 'alert alert-warning';
            } else if (start === end) {
                dateInfo.innerText = '📅 搜尋單一日期: ' + start;
                dateInfo.className = 'alert alert-success';
            } else {
                dateInfo.innerText = '📅 搜尋範圍: ' + start + ' 至 ' + end;
                dateInfo.className = 'alert alert-success';
            }
        } else if (start || end) {
            const date = start || end;
            const type = start ? '之後' : '之前';
            dateInfo.innerText = `📅 搜尋 ${date} ${type}的紀錄`;
            dateInfo.className = 'alert badge-gray';
        } else {
            dateInfo.innerText = '💡 請填寫「關鍵字」或「日期」';
            dateInfo.className = 'alert badge-gray';
            dateInfo.style.background = 'var(--surface-bg)';
        }
        dateInfo.style.display = 'block';
    }

    if (startDate && endDate) {
        startDate.addEventListener('change', () => {
            if (startDate.value && !endDate.value) endDate.value = startDate.value;
            updateDateInfo();
            if (errorMessage) errorMessage.style.display = 'none';
        });

        endDate.addEventListener('change', () => {
            if (endDate.value && !startDate.value) startDate.value = endDate.value;
            updateDateInfo();
            if (errorMessage) errorMessage.style.display = 'none';
        });
    }

    if (targetName) {
        targetName.addEventListener('input', () => {
            if (targetName.value.trim() && errorMessage) errorMessage.style.display = 'none';
        });
    }

    // Async Search Logic
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();

            const keyword = targetName.value.trim();
            const start = startDate.value;
            const end = endDate.value;

            if (!keyword && !start && !end) {
                if (errorMessage) errorMessage.style.display = 'block';
                return false;
            }

            if (start && end && start > end) {
                alert('結束日期不可早於開始日期');
                return false;
            }

            if (errorMessage) errorMessage.style.display = 'none';
            // Show Loading State
            loading.style.display = 'block';
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 搜尋處理中...';

            // Status Area
            let statusDiv = document.getElementById('search-status');
            if (!statusDiv) {
                statusDiv = document.createElement('div');
                statusDiv.id = 'search-status';
                statusDiv.className = 'mt-3 alert alert-info text-center';
                statusDiv.style.borderRadius = '8px';
                // Insert after loading div
                loading.parentNode.insertBefore(statusDiv, loading.nextSibling);
            }
            statusDiv.style.display = 'block';
            statusDiv.textContent = '正在啟動任務...';

            try {
                const formData = new FormData(this);

                // 1. Submit Search Task
                const startResp = await fetch('/search', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });

                if (!startResp.ok) {
                    throw new Error(await startResp.text());
                }

                const startData = await startResp.json();
                const taskId = startData.task_id;
                const total = startData.total || '?';

                // Show Status + Cancel Button
                statusDiv.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span>🔍 正在搜尋 <strong>${total}</strong> 筆對話... <span id="timer">(0s)</span></span>
                        <button id="cancelSearchBtn" class="btn btn-sm btn-danger" style="margin-left:10px; padding: 4px 12px; font-size: 0.85rem; border-radius: 4px; border: none; cursor: pointer; background: #dc3545; color: white;">取消</button>
                    </div>
                `;

                // Bind Cancel Action
                const cancelBtn = document.getElementById('cancelSearchBtn');
                cancelBtn.onclick = async (ev) => {
                    ev.preventDefault();
                    if (!confirm('確定要取消搜尋嗎？')) return;

                    try {
                        cancelBtn.disabled = true;
                        cancelBtn.textContent = '取消中...';

                        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

                        await fetch(`/search/cancel/${taskId}`, {
                            method: 'POST',
                            headers: {
                                'X-CSRFToken': csrfToken
                            }
                        });

                        clearInterval(pollInterval);
                        statusDiv.className = 'mt-3 alert alert-warning';
                        statusDiv.textContent = '搜尋已取消';

                        // Reset UI State
                        btn.disabled = false;
                        btn.innerHTML = '開始搜尋';
                        loading.style.display = 'none';
                    } catch (err) {
                        alert('取消請求失敗: ' + err.message);
                        cancelBtn.disabled = false;
                        cancelBtn.textContent = '取消';
                    }
                };

                // 2. Poll for Status
                let elapsed = 0;
                let isRequestActive = false;

                const pollInterval = setInterval(async () => {
                    if (isRequestActive) return; // Prevent overlap
                    isRequestActive = true;

                    elapsed += 1;
                    const timer = document.getElementById('timer');
                    if (timer) timer.textContent = `(${elapsed}s)`;

                    try {
                        const res = await fetch(`/search/result/${taskId}`);
                        if (res.status === 200) {
                            // Success! 
                            clearInterval(pollInterval);
                            statusDiv.textContent = '搜尋完成，正在跳轉...';

                            // Redirect to result page
                            window.location.href = `/search/result/${taskId}`;
                        } else if (res.status === 500) {
                            clearInterval(pollInterval);
                            statusDiv.className = 'mt-3 alert alert-danger';
                            statusDiv.textContent = '搜尋發生錯誤: ' + await res.text();
                            btn.disabled = false;
                            btn.innerText = '開始搜尋';
                        }
                    } catch (err) {
                        console.error("Polling error", err);
                    } finally {
                        isRequestActive = false;
                    }
                }, 1000);

            } catch (error) {
                console.error('Search failed:', error);
                statusDiv.className = 'mt-3 alert alert-danger';
                statusDiv.textContent = '啟動搜尋失敗: ' + error.message;
                btn.disabled = false;
                btn.innerText = '開始搜尋';
                loading.style.display = 'none';
            }
        });
    }

    // Restore UI on Page Show (Back button)
    window.addEventListener('pageshow', (event) => {
        if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
            if (loading) loading.style.display = 'none';
            if (btn) {
                btn.disabled = false;
                btn.innerText = '開始搜尋';
            }
            if (errorMessage) errorMessage.style.display = 'none';
        }
    });
});
