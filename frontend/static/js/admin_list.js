/**
 * admin_list.js
 * Handles logic for the Admin Thread List (Selection, Export, Mobile Actions).
 * Moved from _thread_list.html to ensure execution outside of AJAX/innerHTML updates.
 */

(function () {
    console.log('admin_list.js loaded');

    // Make functions global so inline onclick HTML attributes can find them
    window.toggleThreadListSelection = function (source) {
        const checkboxes = document.querySelectorAll('.thread-checkbox');
        for (let i = 0; i < checkboxes.length; i++) {
            checkboxes[i].checked = source.checked;
        }
        window.checkSelectionState();
    }

    window.toggleAllMobile = function (btn) {
        if (window.event) {
            window.event.stopPropagation();
        }

        const checkboxes = document.querySelectorAll('.thread-checkbox');

        let anyUnchecked = false;
        for (let i = 0; i < checkboxes.length; i++) {
            if (!checkboxes[i].checked) {
                anyUnchecked = true;
                break;
            }
        }

        const newState = anyUnchecked;

        for (let i = 0; i < checkboxes.length; i++) {
            checkboxes[i].checked = newState;
        }

        const master = document.getElementById('masterCheckbox');
        if (master) master.checked = newState;

        window.checkSelectionState();

        // UI Feedback
        if (btn) {
            const originalText = "☑ 全選";
            // Check if it's the top toolbar button or bottom sheet button
            if (btn.classList.contains('mobile-only') || btn.id === 'mobileSelectAllBtn') {
                // Simple text toggle for feedback
                const originalHtml = btn.innerHTML;
                btn.innerHTML = newState ? "☑ 已全選" : "☐ 全選";
                setTimeout(() => { btn.innerHTML = originalHtml; }, 800);
            }
        }
    }

    window.checkSelectionState = function () {
        const checkboxes = document.querySelectorAll('.thread-checkbox');
        let checkedCount = 0;
        let allChecked = true;

        if (checkboxes.length === 0) allChecked = false;

        for (let c of checkboxes) {
            if (c.checked) {
                checkedCount++;
            } else {
                allChecked = false;
            }
        }

        // Master Checkbox Sync
        const master = document.getElementById('masterCheckbox');
        if (master) master.checked = allChecked;

        // Update Bottom Sheet
        const sheet = document.getElementById('bottomActionSheet');
        const countDisplay = document.getElementById('selectedCountDisplay');
        const mobileSelectBtn = document.getElementById('mobileSelectAllBtn');

        if (sheet && countDisplay) {
            countDisplay.innerText = checkedCount;
            if (checkedCount > 0) {
                sheet.classList.add('active');
            } else {
                sheet.classList.remove('active');
            }
        }

        // Update Mobile Select Button Text (Bottom Sheet)
        if (mobileSelectBtn) {
            mobileSelectBtn.textContent = allChecked ? "取消全選" : "全選";
        }

        // Banner Logic
        window.handleBannerVisibility(allChecked);
    }

    window.handleBannerVisibility = function (isAllPageChecked) {
        const banner = document.getElementById('selectAllBanner');
        if (!banner) return;

        // Use getAttribute for robustness
        const totalStr = banner.getAttribute('data-total');
        const countStr = banner.getAttribute('data-page-count');

        const total = parseInt(totalStr, 10) || 0;
        const onPage = parseInt(countStr, 10) || 0;

        console.log(`[SelectAll] AllChecked: ${isAllPageChecked}, Total: ${total}, OnPage: ${onPage}`);

        if (isAllPageChecked && total > onPage) {
            banner.style.display = 'block';
        } else {
            banner.style.display = 'none';
            // Only clear selection if we are hiding the banner AND the user hasn't explicitly activated "Select All Pages" mode?
            // Actually, if they uncheck one item, isAllPageChecked becomes false -> banner hides -> selection clears. Correct.
            window.clearSelection();
        }
    }

    window.selectAllAcrossPages = function () {
        const input = document.getElementById('selectAllPagesInput');
        if (input) input.value = 'true';

        const bannerText = document.getElementById('selectAllBannerText');
        if (bannerText) bannerText.style.display = 'none';

        const actionLink = document.querySelector('#selectAllBanner a[onclick^="selectAllAcrossPages"]');
        if (actionLink) actionLink.style.display = 'none';

        const msg = document.getElementById('allSelectedMsg');
        if (msg) msg.style.display = 'inline';

        const clearLink = document.getElementById('clearSelectionLink');
        if (clearLink) clearLink.style.display = 'inline';
    }

    window.clearSelection = function () {
        const input = document.getElementById('selectAllPagesInput');
        if (input) input.value = 'false';

        const bannerText = document.getElementById('selectAllBannerText');
        if (bannerText) bannerText.style.display = 'inline';

        const actionLink = document.querySelector('#selectAllBanner a[onclick^="selectAllAcrossPages"]');
        if (actionLink) actionLink.style.display = 'inline';

        const msg = document.getElementById('allSelectedMsg');
        if (msg) msg.style.display = 'none';

        const clearLink = document.getElementById('clearSelectionLink');
        if (clearLink) clearLink.style.display = 'none';
    }

    document.addEventListener('DOMContentLoaded', () => {
        // Other init...

        // Async IP Geo Loader
        const badges = document.querySelectorAll('.ip-geo-badge');
        if (badges.length > 0) {
            const ips = Array.from(badges).map(b => b.dataset.ip).filter(ip => ip && ip !== '127.0.0.1');
            const uniqueIps = [...new Set(ips)];

            if (uniqueIps.length > 0) {
                // Show badges as loading
                badges.forEach(b => b.style.display = 'inline-block');

                const csrfInput = document.querySelector('input[name="csrf_token"]');
                const token = csrfInput ? csrfInput.value : '';

                fetch('/admin/api/ip_geo', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': token
                    },
                    body: JSON.stringify({ ips: uniqueIps })
                })
                    .then(res => res.json())
                    .then(data => {
                        badges.forEach(b => {
                            const ip = b.dataset.ip;
                            if (data[ip]) {
                                b.textContent = `📍 ${data[ip]}`;
                            } else {
                                b.style.display = 'none'; // Hide if no data
                            }
                        });
                    })
                    .catch(err => {
                        console.warn("Geo IP Load Failed", err);
                        badges.forEach(b => b.style.display = 'none');
                    });
            }
        }
    });

    // Search Loading UX - Event Delegation
    document.addEventListener('submit', function (e) {
        if (e.target && e.target.id === 'searchForm') {
            const toast = document.createElement('div');
            toast.id = 'searchLoadingToast';
            toast.innerHTML = `
                <span>🔍 正在搜尋...</span>
                <button type="button" id="cancelSearchBtn" style="background:none; border:none; color:white; cursor:pointer; font-size:1.1em; opacity:0.8; padding:0 4px; display:flex; align-items:center;">✕</button>
            `;
            Object.assign(toast.style, {
                position: 'fixed', top: '20px', left: '50%', transform: 'translateX(-50%)',
                background: 'rgba(33, 150, 243, 0.95)', color: 'white', padding: '0.75rem 1.25rem',
                borderRadius: '50px', boxShadow: '0 4px 12px rgba(0,0,0,0.15)', zIndex: '9999',
                display: 'flex', alignItems: 'center', gap: '12px', fontWeight: '500'
            });
            document.body.appendChild(toast);

            const btn = document.getElementById('searchSubmitBtn');
            if (btn) {
                btn.dataset.originalText = btn.innerHTML;
                btn.innerHTML = '⏳';
                btn.style.cursor = 'wait';
                btn.style.opacity = '0.7';
            }

            // Cancel Logic
            document.getElementById('cancelSearchBtn').onclick = function () {
                window.stop();
                document.body.removeChild(toast);
                if (btn) {
                    btn.innerHTML = btn.dataset.originalText || '🔍';
                    btn.style.cursor = 'pointer';
                    btn.style.opacity = '1';
                }
            };
        }
    });

    // Bookmark Logic
    window.toggleBookmark = function (element, threadId, event) {
        // Prevent row click if any
        if (event) {
            event.stopPropagation();
        } else if (window.event) {
            window.event.stopPropagation();
        }

        const starSpan = element.querySelector('.star-icon');
        const isCurrentlyActive = starSpan.innerText.trim() === '★';

        // Optimistic UI Update
        const newStatus = !isCurrentlyActive;
        starSpan.innerText = newStatus ? '★' : '☆';
        starSpan.style.color = newStatus ? '#f59e0b' : '#ccc';
        starSpan.style.transform = 'scale(1.2)';
        setTimeout(() => starSpan.style.transform = 'scale(1)', 150);

        // Update Sidebar Count (Optimistic)
        updateSidebarCount(newStatus ? 1 : -1);

        const csrfInput = document.querySelector('input[name="csrf_token"]');
        const token = csrfInput ? csrfInput.value : '';

        fetch('/admin/threads/bookmark/toggle', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': token
            },
            body: JSON.stringify({ thread_id: threadId })
        })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    // Revert
                    if (isCurrentlyActive) {
                        starSpan.classList.add('active');
                        starSpan.innerText = '★';
                        starSpan.style.color = '#f59e0b';
                    } else {
                        starSpan.classList.remove('active');
                        starSpan.innerText = '☆';
                        starSpan.style.color = '#ccc';
                    }
                    updateSidebarCount(newStatus ? -1 : 1); // Revert count
                    alert('操作失敗: ' + (data.error || 'Unknown'));
                } else {
                    console.log('Bookmark toggled:', data.action);

                    // Update sidebar items dynamically
                    const listContainer = document.getElementById('sidebar-bookmarks-list');
                    const emptyMsg = document.getElementById('sidebar-bookmarks-empty');

                    if (data.action === 'removed') {
                        // Remove from sidebar
                        // Use attribute selector searching within the list container
                        const sidebarLink = listContainer ? listContainer.querySelector(`a[href*="/view/${threadId}"]`) : null;

                        if (sidebarLink) {
                            sidebarLink.remove();
                        }

                        // Check if sidebar is now empty
                        if (listContainer && listContainer.children.length === 0) {
                            if (emptyMsg) emptyMsg.style.display = 'block';
                        }

                        // Also update the star in the table if visible
                        const tableRows = document.querySelectorAll('tr');
                        tableRows.forEach(row => {
                            const threadIdCell = row.querySelector('[data-label="Thread ID"]');
                            if (threadIdCell && threadIdCell.innerText.trim() === threadId) {
                                const starCell = row.querySelector('.star-icon');
                                if (starCell) {
                                    starCell.classList.remove('active');
                                    starCell.innerText = '☆';
                                    starCell.style.color = '#ccc';
                                }
                            }
                        });
                    } else if (data.action === 'added') {
                        // Add to sidebar
                        // Try to get remark from table row
                        let remarkText = threadId;
                        let projectId = '';

                        const tableRow = element.closest('tr');
                        if (tableRow) {
                            const remarkCell = tableRow.querySelector('.editable-remark');
                            if (remarkCell) {
                                const displayedText = remarkCell.innerText.trim();
                                if (displayedText && displayedText !== '✏️') {
                                    remarkText = displayedText;
                                }
                                if (!remarkText || remarkText === threadId) {
                                    remarkText = remarkCell.dataset.remark || threadId;
                                }
                                projectId = remarkCell.dataset.projectId || remarkCell.dataset.groupId || '';
                            }
                            // Fallback to active group if not found on row
                            if (!projectId) {
                                projectId = new URLSearchParams(window.location.search).get('group_id') || '';
                            }
                        }

                        if (remarkText === '✏️') remarkText = threadId;

                        if (listContainer) {
                            // Hide "no items" message
                            if (emptyMsg) emptyMsg.style.display = 'none';

                            // Check if already exists to prevent duplicates (rare race condition)
                            if (!listContainer.querySelector(`a[href*="/view/${threadId}"]`)) {
                                const newItem = document.createElement('a');
                                newItem.href = `/admin/threads/view/${threadId}?group_id=${projectId}`;
                                newItem.className = 'btn btn-block sidebar-item';
                                newItem.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; font-size: 0.85rem; border-left: 2px solid transparent; justify-content: space-between;';
                                newItem.innerHTML = `
                                    <div style="display: flex; align-items: center; gap: 0.5rem; overflow: hidden;">
                                        <span class="star-icon active" style="font-size: 1rem;">★</span>
                                        <div style="text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 120px;" title="${threadId}">
                                            ${remarkText || threadId}
                                        </div>
                                    </div>
                                    <span onclick="event.preventDefault(); toggleBookmark(this.parentElement, '${threadId}', event)" 
                                          class="sidebar-unbookmark-btn" title="移除收藏"
                                          style="cursor: pointer; opacity: 0.5; font-size: 0.9rem; padding: 2px;">✖</span>
                                `;
                                listContainer.insertBefore(newItem, listContainer.firstChild);
                            }
                        }
                    }
                }
            })
            .catch(err => {
                // Revert
                if (isCurrentlyActive) {
                    starSpan.classList.add('active');
                    starSpan.innerText = '★';
                    starSpan.style.color = '#f59e0b';
                } else {
                    starSpan.classList.remove('active');
                    starSpan.innerText = '☆';
                    starSpan.style.color = '#ccc';
                }
                updateSidebarCount(newStatus ? -1 : 1); // Revert count
                console.error(err);
            });
    }

    function updateSidebarCount(delta) {
        const countSpan = document.getElementById('sidebar-bookmarks-count');
        if (countSpan) {
            const match = countSpan.innerText.match(/\((\d+)\)/);
            if (match) {
                let current = parseInt(match[1], 10);
                if (!isNaN(current)) {
                    current = Math.max(0, current + delta);
                    countSpan.innerText = `(${current})`;
                }
            }
        }
    }

    // Expose editRemark globally so it can be used by admin_thread_view.html too
    window.editRemark = function (threadId, groupId, currentRemark) {
        const newRemark = prompt("請輸入新的備註:", currentRemark);
        if (newRemark === null) return; // Cancelled
        if (newRemark === currentRemark) return; // No change

        const csrfInput = document.querySelector('input[name="csrf_token"]');
        const token = csrfInput ? csrfInput.value : '';

        // Use the existing update endpoint
        fetch('/admin/threads/update_remark', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': token
            },
            body: JSON.stringify({
                thread_id: threadId,
                group_id: groupId,
                remark: newRemark
            })
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    // Update UI in all places

                    // 1. specific handling for Thread View Header (avoids overwrite by generic list logic)
                    const viewHeader = document.querySelector('.thread-remark.editable-remark[data-thread-id="' + threadId + '"]');
                    if (viewHeader) {
                        viewHeader.innerText = '備註: ' + (newRemark || '-');
                        viewHeader.dataset.remark = newRemark;
                    }

                    // 2. Thread List Rows (exclude the view header if we just updated it)
                    const rows = document.querySelectorAll(`.editable-remark[data-thread-id="${threadId}"]`);
                    rows.forEach(el => {
                        // Skip if it's the viewHeader we already handled correctly
                        if (el === viewHeader) return;

                        el.innerText = newRemark || '✏️';
                        el.dataset.remark = newRemark;
                    });

                    // 3. Sidebar (if bookmarked)
                    const sidebarItem = document.querySelector(`.sidebar-item div[title="${threadId}"]`);
                    if (sidebarItem) {
                        // Update sidebar text, handle empty case
                        const displayText = (newRemark && newRemark.trim()) ? newRemark : threadId;
                        sidebarItem.innerText = displayText;
                    }
                } else {
                    alert('更新失敗: ' + (data.error || 'Unknown'));
                }
            })
            .catch(err => console.error(err));
    };

})();
