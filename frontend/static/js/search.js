document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('searchForm');
    const loading = document.getElementById('loading');
    const btn = document.querySelector('button[type="submit"]');
    const targetName = document.getElementById('target_name');
    const startDate = document.getElementById('start_date');
    const endDate = document.getElementById('end_date');
    const dateInfo = document.getElementById('dateInfo');
    const errorMessage = document.getElementById('errorMessage');

    // --- Captcha Logic ---
    const modeRefresh = document.getElementById('modeRefresh');
    const captchaContainer = document.getElementById('captchaContainer');
    const captchaImg = document.getElementById('captchaImg');
    const captchaInput = document.getElementById('captchaInput');
    const toggleBtn = document.getElementById('toggleCaptchaMode');

    let captchaMode = 'normal'; // 'normal' or 'math'

    // Inject hidden input for UUID
    let captchaUidInput = document.createElement('input');
    captchaUidInput.type = 'hidden';
    captchaUidInput.name = 'captcha_uid';
    if (form) form.appendChild(captchaUidInput);

    // Simple UUID Generator
    // Secure UUID Generator
    function generateUUID() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        // Fallback for older browsers
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    let captchaTimeout;
    window.refreshCaptcha = function () {
        if (!captchaImg) return;

        // Debounce: Prevent rapid accumulation of sessions (Max 5 slots on backend)
        if (captchaTimeout) clearTimeout(captchaTimeout);

        captchaTimeout = setTimeout(() => {
            const timestamp = new Date().getTime();
            const uid = generateUUID();
            captchaUidInput.value = uid;
            captchaImg.src = `/captcha?type=${captchaMode}&uid=${uid}&t=${timestamp}`;
            captchaInput.value = '';
            if (captchaContainer.style.display !== 'none') {
                captchaInput.focus();
            }
        }, 300); // 300ms delay
    };

    function syncCaptchaState() {
        if (!modeRefresh || !captchaContainer) return;

        if (modeRefresh.checked) {
            captchaContainer.style.display = 'block';
            captchaInput.required = true;
            // Only refresh if empty source (first load) or invisible
            if (!captchaImg.src || captchaImg.src.endsWith('undefined')) {
                refreshCaptcha();
            }
        } else {
            captchaContainer.style.display = 'none';
            captchaInput.required = false;
            captchaInput.value = '';
        }
    }

    if (modeRefresh && captchaContainer) {
        modeRefresh.addEventListener('change', () => {
            // Force refresh on explicit user change to checked
            if (modeRefresh.checked) refreshCaptcha();
            syncCaptchaState();
        });

        // Initial Sync (Fixes browser cache verify issue)
        syncCaptchaState();
    }

    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            if (captchaMode === 'normal') {
                captchaMode = 'math';
                toggleBtn.innerHTML = '<span>🔤</span><span style="font-size: 0.7rem;">一般文字</span>';
                captchaInput.placeholder = '請計算 f\'(c)=?';
            } else {
                captchaMode = 'normal';
                toggleBtn.innerHTML = '<span>🧠</span><span style="font-size: 0.7rem;">挑戰數學</span>';
                captchaInput.placeholder = '請輸入圖片中的文字';
            }
            refreshCaptcha();
        });
    }

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
                    let errMsg = await startResp.text();
                    try {
                        const jsonErr = JSON.parse(errMsg);
                        if (jsonErr.error) errMsg = jsonErr.error;
                    } catch (e) {
                        // Not JSON, use text
                    }

                    // Auto-Refresh Captcha on specific errors
                    if ((startResp.status === 400 || startResp.status === 429) &&
                        modeRefresh && modeRefresh.checked) {
                        refreshCaptcha();
                    }

                    throw new Error(errMsg);
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

                // Cancel Logic will be bound after polling setup to capture timer

                // 2. Poll for Status with Exponential Backoff
                let elapsed = 0;
                let retryCount = 0; // Network Errors
                const MAX_RETRIES = 5;

                // Dynamic Timeout Calculation based on thread count
                const totalThreads = total || 100;
                let dynamicTimeout = 600; // base 10 minutes
                if (totalThreads <= 100) {
                    dynamicTimeout += totalThreads * 2;
                } else if (totalThreads <= 500) {
                    dynamicTimeout += 100 * 2 + (totalThreads - 100) * 1;
                } else {
                    dynamicTimeout += 100 * 2 + 400 * 1 + (totalThreads - 500) * 0.5;
                }
                dynamicTimeout = Math.min(dynamicTimeout * 1.2, 3600); // +20% buffer, cap at 60 min
                const MAX_TIMEOUT_SEC = Math.floor(dynamicTimeout);

                console.log(`Dynamic timeout set to ${MAX_TIMEOUT_SEC}s (${Math.floor(MAX_TIMEOUT_SEC / 60)} min) for ${totalThreads} threads`);

                let pollDelay = 1000; // Start with 1s
                const MAX_POLL_DELAY = 10000; // Cap at 10s

                let isRequestActive = false;
                let pollTimer = null;

                const pollFunction = async () => {
                    // Check Timeout
                    if (elapsed >= MAX_TIMEOUT_SEC) {
                        const timeoutMinutes = Math.floor(MAX_TIMEOUT_SEC / 60);
                        statusDiv.className = 'mt-3 alert alert-danger';
                        statusDiv.textContent = `搜尋請求超時 (${timeoutMinutes}分鐘)，請稍後再試或縮小搜尋範圍。`;
                        btn.disabled = false;
                        btn.innerText = '開始搜尋';
                        loading.style.display = 'none';
                        return;
                    }

                    try {
                        const res = await fetch(`/search/result/${taskId}`);

                        // Handle 200 OK (Success)
                        if (res.status === 200) {
                            statusDiv.className = 'mt-3 alert alert-success';
                            statusDiv.textContent = '搜尋完成，正在跳轉...';
                            window.location.href = `/search/result/${taskId}`;
                            return;
                        }
                        // Handle 202 Processing (Continue Polling)
                        else if (res.status === 202) {
                            retryCount = 0;

                            // Try to get progress data
                            try {
                                const data = await res.json();
                                if (data.progress) {
                                    const { current, total, percentage, phase } = data.progress;
                                    const phaseText = phase === 'syncing' ? '同步中' : '搜尋中';
                                    statusDiv.className = 'mt-3 alert alert-info';
                                    statusDiv.innerHTML = `
                                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
                                            <span>🔍 ${phaseText}... ${current}/${total} (${percentage}%)</span>
                                            <button id="cancelSearchBtn" class="btn btn-sm btn-danger" style="padding: 4px 12px; font-size: 0.85rem;">取消</button>
                                        </div>
                                        <div class="progress" style="height: 24px;">
                                            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                                 role="progressbar" 
                                                 style="width: ${percentage}%"
                                                 aria-valuenow="${percentage}" 
                                                 aria-valuemin="0" 
                                                 aria-valuemax="100">
                                                ${percentage}%
                                            </div>
                                        </div>
                                        <small class="text-muted d-block mt-2">已執行 ${Math.floor(elapsed)}秒 / 最多 ${Math.floor(MAX_TIMEOUT_SEC / 60)} 分鐘</small>
                                    `;

                                    // Re-bind cancel button
                                    const newCancelBtn = document.getElementById('cancelSearchBtn');
                                    if (newCancelBtn) {
                                        newCancelBtn.onclick = async () => {
                                            if (pollTimer) clearTimeout(pollTimer);
                                            await fetch(`/search/cancel/${taskId}`, { method: 'POST' });
                                            statusDiv.className = 'mt-3 alert alert-warning';
                                            statusDiv.textContent = '搜尋已取消';
                                            btn.disabled = false;
                                            btn.innerText = '開始搜尋';
                                            loading.style.display = 'none';
                                        };
                                    }
                                } else {
                                    // No progress data, show basic message
                                    const timer = document.getElementById('timer');
                                    if (timer) timer.textContent = `(${Math.floor(elapsed)}s)`;
                                }
                            } catch (e) {
                                // Fallback if JSON parsing fails
                                const timer = document.getElementById('timer');
                                if (timer) timer.textContent = `(${Math.floor(elapsed)}s)`;
                            }

                            // Exponential Backoff Logic
                            elapsed += (pollDelay / 1000);

                            // Increase delay by 50%, capped at 10s
                            pollDelay = Math.min(pollDelay * 1.5, MAX_POLL_DELAY);

                            pollTimer = setTimeout(pollFunction, pollDelay);
                        }
                        // Handle 404/403 (Task Lost or Forbidden)
                        else if (res.status === 404 || res.status === 403) {
                            statusDiv.className = 'mt-3 alert alert-danger';
                            statusDiv.textContent = '搜尋任務已失效或被拒絕 (Code ' + res.status + ')。請刷新頁面重新搜尋。';
                            btn.disabled = false;
                            btn.innerText = '開始搜尋';
                            loading.style.display = 'none';
                            return;
                        }
                        // Handle 500 (Server Error)
                        else if (res.status === 500) {
                            statusDiv.className = 'mt-3 alert alert-danger';
                            let errText = await res.text();
                            statusDiv.textContent = '搜尋發生伺服器錯誤: ' + errText;
                            btn.disabled = false;
                            btn.innerText = '開始搜尋';
                            loading.style.display = 'none';
                            return;
                        }
                        else {
                            throw new Error(`Unexpected status ${res.status}`);
                        }

                    } catch (err) {
                        if (window.location.hostname === 'localhost') {
                            console.error("Polling error", err);
                        }
                        retryCount++;
                        if (retryCount > MAX_RETRIES) {
                            statusDiv.className = 'mt-3 alert alert-danger';
                            statusDiv.textContent = '網路連線不穩定，已停止搜尋。請檢查網路並重試。';
                            btn.disabled = false;
                            btn.innerText = '開始搜尋';
                            loading.style.display = 'none';
                        } else {
                            // Retry with delay (don't increase backoff on network error, just wait)
                            pollTimer = setTimeout(pollFunction, 2000);
                        }
                    }
                };

                // Start Polling
                pollTimer = setTimeout(pollFunction, 1000);

                // Update Cancel Logic to clear Timeout
                // Re-bind to ensure closure captures pollTimer
                const cancelBtn = document.getElementById('cancelSearchBtn');
                // Remove old listener (helper) or just overwrite onclick
                cancelBtn.onclick = async (ev) => {
                    ev.preventDefault();
                    if (!confirm('確定要取消搜尋嗎？')) return;

                    if (pollTimer) clearTimeout(pollTimer);

                    try {
                        cancelBtn.disabled = true;
                        cancelBtn.textContent = '取消中...';
                        const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;

                        if (!csrfToken) {
                            alert('CSRF token 遺失，請重新整理頁面');
                            return;
                        }

                        await fetch(`/search/cancel/${taskId}`, {
                            method: 'POST',
                            headers: { 'X-CSRFToken': csrfToken }
                        });
                        statusDiv.className = 'mt-3 alert alert-warning';
                        statusDiv.textContent = '搜尋已取消';
                        btn.disabled = false;
                        btn.innerText = '開始搜尋';
                        loading.style.display = 'none';
                    } catch (e) {
                        alert('取消失敗');
                    }
                };

            } catch (error) {
                if (window.location.hostname === 'localhost') {
                    console.error('Search failed:', error);
                }
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
