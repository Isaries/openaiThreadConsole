document.addEventListener('DOMContentLoaded', () => {
    // Dependencies: ALL_PROJECTS (Global), enableFocusToClear (Global/Utils)

    const projectInput = document.getElementById('projectSearchInput');
    const projectDatalist = document.getElementById('projectOptions');
    const hiddenGroupId = document.getElementById('group_id');
    const tagFilter = document.getElementById('tagFilter');

    // Make sure we have the data
    if (typeof ALL_PROJECTS === 'undefined') {
        console.error("ALL_PROJECTS data not found!");
        return;
    }

    function renderProjectOptions(projects) {
        // console.log('Rendering options:', projects.length);
        projectDatalist.innerHTML = '';
        projects.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.name;
            projectDatalist.appendChild(opt);
        });
    }

    function selectProject(project) {
        if (project) {
            projectInput.value = project.name;
            hiddenGroupId.value = project.id;
            // Save Persistence
            localStorage.setItem('threadConsole_selectedGroupId', project.id);
        } else {
            projectInput.value = '';
            hiddenGroupId.value = '';
            // Do NOT clear persistence if just clearing UI temporarily
        }
    }

    // Initial Population
    renderProjectOptions(ALL_PROJECTS);

    // Restore Selection logic
    const savedId = localStorage.getItem('threadConsole_selectedGroupId');
    let initialProject = null;

    if (savedId) {
        const found = ALL_PROJECTS.find(p => p.id === savedId);
        if (found) initialProject = found;
    }

    // Apply Selection
    selectProject(initialProject);

    // Project Input Handler
    projectInput.addEventListener('input', () => {
        const val = projectInput.value;
        const match = ALL_PROJECTS.find(p => p.name === val);
        if (match) {
            hiddenGroupId.value = match.id;
            localStorage.setItem('threadConsole_selectedGroupId', match.id);
        } else {
            hiddenGroupId.value = ''; // Invalid/Custom selection
        }
    });

    // Ensure ID is set on change (for click selection)
    projectInput.addEventListener('change', () => {
        const val = projectInput.value;
        const match = ALL_PROJECTS.find(p => p.name === val);
        if (match) hiddenGroupId.value = match.id;
    });

    // Tag Filter Logic
    tagFilter.addEventListener('input', () => {
        const tagVal = tagFilter.value.trim().toLowerCase();
        let filtered = ALL_PROJECTS;

        if (tagVal && tagVal !== 'ignore') {
            filtered = ALL_PROJECTS.filter(p => {
                const projectTags = p.tags || []; // Safety check
                return projectTags.some(t => t.toLowerCase().includes(tagVal));
            });
        }

        // Re-render Datalist
        renderProjectOptions(filtered);

        // Auto-select logic
        if (filtered.length === 1) {
            selectProject(filtered[0]);
        } else if (filtered.length > 0) {
            const currentName = projectInput.value;
            const currentInList = filtered.find(p => p.name === currentName);
            const isReset = (!tagVal || tagVal === 'ignore');

            if (!currentInList || isReset) {
                selectProject(null);
            }
        } else {
            selectProject(null);
        }

        // Handle "Ignore" UI clear
        if (tagVal === 'ignore') {
            tagFilter.value = '';
            tagFilter.dataset.saved = '';
        }
    });

    // Apply Utils: Focus To Clear
    if (typeof enableFocusToClear === 'function') {
        enableFocusToClear(tagFilter);
        enableFocusToClear(projectInput);
    }
});
