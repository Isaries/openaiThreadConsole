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
            maxOptions: null, // Show all
            valueField: 'id',
            labelField: 'name',
            searchField: ['name', 'tags'], // Search by name AND tags
            // Custom Rendering for Options and Items
            render: {
                option: function (data, escape) {
                    let orgBadge = '';
                    if (data.tags && data.tags.length > 0) {
                        orgBadge = `<span class="org-badge">${escape(data.tags[0])}</span>`;
                    }
                    return `<div>
                        <span class="option-title">${escape(data.name)}</span>
                        ${orgBadge}
                    </div>`;
                },
                item: function (data, escape) {
                    return `<div>${escape(data.name)}</div>`;
                }
            }
        });
    }

    /**
     * Renders Project Options into the Select Element
     */
    function renderProjectOptions(projects, isFiltered = false) {
        // Clear current options
        if (!tomControl) {
            projectSelect.innerHTML = '<option value="" disabled selected>請選擇 Project...</option>';
        } else {
            tomControl.clear();
            tomControl.clearOptions();
        }

        // Helper to add option (Vanilla Fallback)
        const addVanillaOption = (parent, value, text) => {
            const opt = document.createElement('option');
            opt.value = value;
            opt.textContent = text;
            parent.appendChild(opt);
        };

        const addVanillaGroup = (label) => {
            const el = document.createElement('optgroup');
            el.label = label;
            projectSelect.appendChild(el);
            return el;
        };

        if (projects.length === 0) {
            if (!tomControl) {
                const opt = document.createElement('option');
                opt.textContent = "(無符合專案)";
                opt.disabled = true;
                projectSelect.appendChild(opt);
            }
            return;
        }

        if (isFiltered) {
            // Flat list for specific filter
            projects.forEach(p => {
                if (tomControl) {
                    // TomSelect: Add full data object for custom render
                    tomControl.addOption(p);
                } else {
                    addVanillaOption(projectSelect, p.id, `📁 ${p.name}`);
                }
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
                if (tomControl) {
                    tomControl.addOptionGroup(tagName, { label: tagName });
                    groups[tagName].forEach(p => {
                        // Pass full object, specify group
                        tomControl.addOption({ ...p, optgroup: tagName });
                    });
                } else {
                    const groupHandle = addVanillaGroup(tagName);
                    groups[tagName].forEach(p => {
                        addVanillaOption(groupHandle, p.id, p.name);
                    });
                }
            });

            // Render Uncategorized
            if (noTag.length > 0) {
                if (tomControl) {
                    const label = "未分類";
                    tomControl.addOptionGroup(label, { label: label });
                    noTag.forEach(p => {
                        tomControl.addOption({ ...p, optgroup: label });
                    });
                } else {
                    const groupHandle = addVanillaGroup("未分類");
                    noTag.forEach(p => {
                        addVanillaOption(groupHandle, p.id, p.name);
                    });
                }
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

    // Project Select Handler
    projectSelect.addEventListener('change', () => {
        const val = projectSelect.value;
        if (val) {
            hiddenGroupId.value = val;
            localStorage.setItem('threadConsole_selectedGroupId', val);
        } else {
            hiddenGroupId.value = "";
        }
    });

    // Tag Filter Logic
    tagFilter.addEventListener('change', () => {
        const tagVal = tagFilter.value;
        let filtered = ALL_PROJECTS;
        let isFilteredMode = false;

        if (tagVal && tagVal !== 'Ignore') {
            isFilteredMode = true;
            filtered = ALL_PROJECTS.filter(p => {
                const projectTags = p.tags || [];
                return projectTags.some(t => t === tagVal);
            });
        }

        if (tagVal === 'Ignore') {
            tagFilter.value = "";
            isFilteredMode = false;
        }

        renderProjectOptions(filtered, isFilteredMode);

        if (filtered.length === 1) {
            selectProject(filtered[0].id);
        } else if (filtered.length > 0) {
            const currentId = hiddenGroupId.value;
            const stillExists = filtered.find(p => p.id === currentId);
            if (!stillExists) {
                selectProject("");
            } else {
                projectSelect.value = currentId;
            }
        } else {
            selectProject("");
        }
    });
});
