# Frontend Architecture

The frontend is a server-side rendered application using Jinja2 templates, enhanced with modern Vanilla JavaScript and a custom Glassmorphism CSS design system. It is designed to be lightweight, responsive, and dependency-free (no build step required).

## 📂 Directory Structure

```text
frontend/
├── templates/             # HTML Templates (Jinja2)
│   ├── admin/             # Admin panel views (System, Users, Projects)
│   ├── index.html         # Main Search interface
│   ├── result.html        # Search Results view
│   ├── login.html         # Authentication page
│   └── base.html          # Master layout with common specific metadata
└── static/
    ├── css/               # Styling
    │   ├── base/          # Reset & Variables
    │   ├── components/    # Buttons, Cards, Inputs
    │   ├── layout/        # Grid & Flex structures
    │   └── tom-select.css # Vendor styles
    ├── js/                # Client-side Logic
    │   ├── admin_list.js  # Admin data tables & polling
    │   ├── search.js      # Search bar logic & captcha handling
    │   ├── result.js      # Result page interactivity
    │   └── utils.js       # Common helpers (Debounce, Formatters)
    └── favicon.svg
```

## 🎨 Design System

The application implements a "Glassmorphism" aesthetic characterized by:
*   **Translucency**: Frosted glass effects using `backdrop-filter: blur()`.
*   **Vivid Colors**: High-saturation background gradients to create depth.
*   **Floating Elements**: Cards and panels float above the background.

### CSS Architecture
*   **Variables**: Global tokens for colors, spacing, and typography are defined in `css/base/variables.css` (inferred).
*   **Modular**: Styles are broken down into `components/` (Buttons, Inputs) and `pages/` (specific layouts).
*   **Responsive**: Native CSS Grid and Flexbox are used for mobile-first layouts.

## ⚡ JavaScript Modules

All scripts are written in ES6+ and do not require compilation (Webpack/Vite is **not** used).

*   **`admin_list.js`**:
    *   Manages the Admin Dashboard thread list.
    *   Implements **Polling** to check background task status (Active/Completed).
    *   Dynamically updates DOM elements without page reloads.
*   **`search.js`**:
    *   Handles the main search input with **Debouncing** to prevent server overload.
    *   Manages the CAPTCHA modal workflow.
*   **`utils.js`**:
    *   Shared utility functions like `debounce()`, `formatDate()`, and `copyToClipboard()`.
*   **`theme.js`**:
    *   Handles Dark/Light mode preferences (persisted in detection).

## 🛠️ Templating (Jinja2)

*   **Inheritance**: All pages extend `base.html` to share headers, navigation, and meta tags.
*   **Auto-Escaping**: Enabled by default to prevent XSS-attacks.
*   **Macros**: Reusable UI snippets are used for common elements like pagination or status badges.

## 🚀 Development

### Live Updates
Since there is no build step, you can verify changes immediately:
1.  Edit a `.html` or `.css` file.
2.  Refresh the browser.
3.  (Optional) Disable browser cache to ensure static files reload.

### Adding New Page
1.  Create `frontend/templates/new_page.html` extending `base.html`.
2.  Create a route in `backend/app/routes/` to render it.
3.  Add specific styles in `frontend/static/css/pages/` if needed.
