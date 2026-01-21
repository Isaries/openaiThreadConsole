document.addEventListener('DOMContentLoaded', () => {
    // Dependencies: ALL_PROJECTS (Global), enableFocusToClear (Global/Utils)

    const projectSelect = document.getElementById('projectSelect');
    const hiddenGroupId = document.getElementById('group_id');
    const tagFilter = document.getElementById('tagFilter');

    // Make sure we have the data
    if (typeof ALL_PROJECTS === 'undefined') {
        console.error("ALL_PROJECTS data not found!");
        return;
    }

    /**
     * Renders Project Options into the Select Element
     * Grouping strategy:
     * 1. If Tag Filter is active: Show only matching projects (Flat list or simplified grouping)
     * 2. If No Tag Filter: Show all projects grouped by their FIRST tag (or 'Uncategorized')
     */
    // Init Tom Select (Global variable to access in closures)
    let tomControl = null;

    if (window.TomSelect) {
        tomControl = new TomSelect('#projectSelect', {
            create: false,
            sortField: {
                field: "text",
                direction: "asc"
            },
            placeholder: '請選擇或搜尋 Project...',
            maxOptions: null // Show all
        });
    }

    /**
     * Renders Project Options into the Select Element
     * Grouping strategy:
     * 1. If Tag Filter is active: Show only matching projects (Flat list or simplified grouping)
     * 2. If No Tag Filter: Show all projects grouped by their FIRST tag (or 'Uncategorized')
     */
    function renderProjectOptions(projects, isFiltered = false) {
        // Clear current options (keep default disabled one)
        // Note: For TomSelect, modifying the underlying option and calling sync() is the way.

        // 1. Destroy old options if not using TomSelect (Vanilla Fallback)
        if (!tomControl) {
            projectSelect.innerHTML = '<option value="" disabled selected>請選擇 Project...</option>';
        } else {
            // For TomSelect, we can clear via API or clear DOM and sync.
            // Clearing DOM is safer for re-grouping logic.
            tomControl.clear();
            tomControl.clearOptions();
        }

        // Helper to add option
        const addOption = (parent, value, text) => {
            if (tomControl) {
                tomControl.addOption({ value: value, text: text });
            } else {
                const opt = document.createElement('option');
                opt.value = value;
                opt.textContent = text;
                parent.appendChild(opt);
            }
        };

        const addGroup = (label) => {
            if (tomControl) {
                tomControl.addOptionGroup(label, { label: label });
                return label; // ID is label
            } else {
                const el = document.createElement('optgroup');
                el.label = label;
                projectSelect.appendChild(el);
                return el;
            }
        };

        const addOptionToGroup = (groupHandle, value, text) => {
            if (tomControl) {
                tomControl.addOption({ value: value, text: text, optgroup: groupHandle });
            } else {
                const opt = document.createElement('option');
                opt.value = value;
                opt.textContent = text;
                groupHandle.appendChild(opt);
            }
        };

        if (projects.length === 0) {
            if (!tomControl) {
                const opt = document.createElement('option');
                opt.textContent = "(無符合專案)";
                opt.disabled = true;
                projectSelect.appendChild(opt);
            }
            // TomSelect handles empty state via 'no_results' option, but we can't easily push a disabled option to it dynamically as main option.
            return;
        }

        // Logic: Should we group?
        // If filtered by a specific tag, flat list is often better.
        // If showing all, grouping helps navigation.

        if (isFiltered) {
            // Flat list for specific filter
            projects.forEach(p => {
                addOption(projectSelect, p.id, `📁 ${p.name}`);
            });
        } else {
            // Group by Tag logic for "All Projects"
            const groups = {};
            const noTag = [];

            projects.forEach(p => {
                if (p.tags && p.tags.length > 0) {
                    // Use the first tag as primary group
                    const primaryTag = p.tags[0];
                    if (!groups[primaryTag]) groups[primaryTag] = [];
                    groups[primaryTag].push(p);
                } else {
                    noTag.push(p);
                }
            });

            // Render Groups (Sorted keys)
            Object.keys(groups).sort().forEach(tagName => {
                const groupHandle = addGroup(tagName);
                groups[tagName].forEach(p => {
                    addOptionToGroup(groupHandle, p.id, p.name);
                });
            });

            // Render Uncategorized
            if (noTag.length > 0) {
                const groupHandle = addGroup("未分類");
                noTag.forEach(p => {
                    addOptionToGroup(groupHandle, p.id, p.name);
                });
            }
        }

        if (tomControl) tomControl.refreshOptions(false);
    }

    function selectProject(id) {
        if (id) {
            if (tomControl) tomControl.setValue(id);
            else projectSelect.value = id;

            hiddenGroupId.value = id;
            localStorage.setItem('threadConsole_selectedGroupId', id);
        } else {
            if (tomControl) tomControl.clear();
            else projectSelect.value = "";

            hiddenGroupId.value = "";
        }
    }

    // Initial Population
    renderProjectOptions(ALL_PROJECTS);

    // Restore Selection logic
    const savedId = localStorage.getItem('threadConsole_selectedGroupId');
    if (savedId) {
        const exists = ALL_PROJECTS.find(p => p.id === savedId);
        if (exists) selectProject(savedId);
    }

    // Project Select Handler (Change event is robust for Selects)
    // TomSelect updates the original Select, so this Listener DOES fire.
    projectSelect.addEventListener('change', () => {
        const val = projectSelect.value;
        if (val) {
            hiddenGroupId.value = val;
            localStorage.setItem('threadConsole_selectedGroupId', val);
        } else {
            // Also handle clear
            hiddenGroupId.value = "";
        }
    });

    // Tag Filter Logic
    tagFilter.addEventListener('change', () => {
        const tagVal = tagFilter.value; // Select value is direct
        let filtered = ALL_PROJECTS;
        let isFilteredMode = false;

        if (tagVal && tagVal !== 'Ignore') {
            isFilteredMode = true;
            filtered = ALL_PROJECTS.filter(p => {
                const projectTags = p.tags || [];
                return projectTags.some(t => t === tagVal); // Exact match for Select option
            });
        }

        // Handle "Ignore" UI clear
        if (tagVal === 'Ignore') {
            tagFilter.value = ""; // Reset to default "Select Tag..."
            isFilteredMode = false;
        }

        // Re-render Select
        renderProjectOptions(filtered, isFilteredMode);

        // Auto-select logic
        if (filtered.length === 1) {
            selectProject(filtered[0].id);
        } else if (filtered.length > 0) {
            // Try to keep current selection if it's still valid
            const currentId = hiddenGroupId.value;
            const stillExists = filtered.find(p => p.id === currentId);

            if (!stillExists) {
                selectProject(""); // Clear if current selection is filtered out
            } else {
                // Ensure UI sync
                projectSelect.value = currentId;
            }
        } else {
            selectProject("");
        }
    });

    // We don't need 'enableFocusToClear' for Select elements as they don't have text to clear
});
