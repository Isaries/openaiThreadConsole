/**
 * Admin Dashboard Logic
 * Extracted from admin.html
 */

// Sidebar Toggle
const sidebar = document.getElementById('sidebar');
const overlay = document.getElementById('mobileOverlay');

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('mobileOverlay');
    if (sidebar && overlay) {
        sidebar.classList.toggle('active');
        overlay.classList.toggle('active');
    }
}

// Logic Preservation
// Logic moved to admin_list.js

function toggleSettings() {
    var el = document.getElementById('settingsSection');
    el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}

function toggleSection(id) {
    var el = document.getElementById(id);
    const isHidden = (el.style.display === 'none');
    el.style.display = isHidden ? 'block' : 'none';

    // Persist specific sections
    if (id === 'ipMonitorSection') {
        localStorage.setItem('ip_monitor_expanded', isHidden);
    }
}

// --- Log Tools ---
function copyLog(btn) {
    const wrapper = btn.closest('.log-wrapper');
    if (wrapper) {
        const pre = wrapper.querySelector('pre');
        if (pre) {
            navigator.clipboard.writeText(pre.innerText).then(() => {
                const original = btn.innerText;
                btn.innerText = '已複製!';
                setTimeout(() => btn.innerText = original, 2000);
            });
        }
    }
}

function toggleIpDetails(id) {
    const el = document.getElementById(id);
    if (el) {
        el.style.display = (el.style.display === 'none') ? 'block' : 'none';
    }
}

// Modals
function openResetModal(userId, username) {
    document.getElementById('resetUserId').value = userId;
    document.getElementById('resetTargetUser').innerText = username;
    document.getElementById('resetPasswordModal').style.display = 'flex';
}
function closeResetModal() {
    document.getElementById('resetPasswordModal').style.display = 'none';
}

function openEditUserModal(userId, username, email) {
    document.getElementById('editUserId').value = userId;
    document.getElementById('editUsername').value = username;
    document.getElementById('editEmail').value = email;
    document.getElementById('editUserModal').style.display = 'flex';
}
function closeEditUserModal() {
    document.getElementById('editUserModal').style.display = 'none';
}

function openProfileModal(username, email) {
    document.getElementById('profileUsername').value = username;
    document.getElementById('profileEmail').value = email;
    document.getElementById('profileModal').style.display = 'flex';
}
function closeProfileModal() {
    document.getElementById('profileModal').style.display = 'none';
}

// Smart ID
const manualInput = document.getElementById('manual_thread_input');
if (manualInput) {
    manualInput.addEventListener('input', function () {
        const val = this.value;
        const threadMatch = val.match(/(thread_[A-Za-z0-9]+)/);
        if (threadMatch && val !== threadMatch[1]) {
            this.value = threadMatch[1];
        }
    });
}

// --- IP Monitor Persistence & Notifications ---
document.addEventListener('DOMContentLoaded', function () {
    // Restore IP Monitor State
    if (localStorage.getItem('ip_monitor_expanded') === 'true') {
        const pan = document.getElementById('ipMonitorSection');
        if (pan) pan.style.display = 'block';
    }
});

/* --- Remark Editing --- */
document.addEventListener('DOMContentLoaded', function () {
    const remarkCells = document.querySelectorAll('.editable-remark');
    remarkCells.forEach(cell => {
        // Click to Edit
        cell.addEventListener('click', function (e) {
            // Prevent if clicking on the input itself
            if (e.target.tagName === 'INPUT') return;
            if (this.querySelector('input')) return;

            const currentText = this.innerText.trim();
            const value = (currentText === '-' || currentText === '✏️') ? '' : currentText;

            this.innerHTML = '';

            const input = document.createElement('input');
            input.type = 'text';
            input.value = value;
            input.className = 'input input-sm';
            input.style = 'min-width: 100%; box-sizing: border-box;';
            input.placeholder = '輸入備註...';

            // Save on Blur or Enter
            const save = () => {
                const newValue = input.value.trim();
                // Optimistic UI update
                this.innerHTML = newValue || '✏️';

                const tid = this.dataset.threadId;
                const gid = this.dataset.groupId;
                // CSRF Token - Try to find it in the DOM
                const csrfToken = document.querySelector('#deleteMultiForm input[name="csrf_token"]')?.value || document.querySelector('input[name="csrf_token"]')?.value;

                fetch('/admin/threads/update_remark', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({
                        thread_id: tid,
                        group_id: gid,
                        remark: newValue
                    })
                }).then(res => {
                    if (!res.ok) {
                        console.error('Save failed');
                        this.style.color = 'red';
                        this.title = '儲存失敗';
                    } else {
                        this.style.color = '';
                        this.title = '點擊編輯';
                    }
                }).catch(err => {
                    console.error(err);
                    this.innerHTML = value || '✏️'; // Revert
                    alert('儲存失敗');
                });
            };

            input.addEventListener('blur', save);
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    input.blur();
                }
            });

            this.appendChild(input);
            input.focus();
        });
    });
});


/* --- Tag Management --- */
function addTag(groupId) {
    const input = document.getElementById(`newTagInput_${groupId}`);
    const tagName = input.value.trim();
    if (!tagName) return;

    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;

    fetch('/admin/projects/tags/add', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ group_id: groupId, tag_name: tagName })
    })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                input.value = '';
                updateTagUI(groupId, data.tags);
            } else {
                alert(data.message || '新增失敗');
            }
        })
        .catch(err => {
            console.error('Tag add error:', err);
            alert('操作失敗，請檢查網路連線');
        });
}

function removeTag(groupId, tagName) {
    if (!confirm(`移除 Organization: ${tagName}?`)) return;

    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;

    fetch('/admin/projects/tags/remove', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ group_id: groupId, tag_name: tagName })
    })
        .then(res => {
            if (!res.ok) throw new Error('Network response was not ok');
            return res.json();
        })
        .then(data => {
            if (data.status === 'success') {
                updateTagUI(groupId, data.tags);
            } else {
                alert(data.message || '移除失敗');
            }
        })
        .catch(err => {
            console.error(err);
            alert('移除失敗: ' + err.message);
        });
}

function updateTagUI(groupId, tags) {
    const container = document.getElementById(`tagList_${groupId}`);
    if (!container) return;

    container.innerHTML = tags.map(tag => {
        // Escape single quotes for use inside onclick string
        const safeTag = tag.replace(/'/g, "\\'");
        return `
        <span class="badge badge-gray" style="display: inline-flex; align-items: center; gap: 4px;">
            ${tag}
            <button type="button" 
                data-group-id="${groupId}"
                data-tag-name="${safeTag}"
                onclick="removeTag(this.dataset.groupId, this.dataset.tagName)"
                style="background: none; border: none; cursor: pointer; color: #666; font-size: 1rem; line-height: 1; padding: 0 2px;">×</button>
        </span>
        `;
    }).join('');
}
