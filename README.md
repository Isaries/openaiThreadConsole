# Thread Console

A centralized management platform for OpenAI Assistant Threads, featuring an advanced search engine, project organization, and secure administration capabilities.

## Overview

Thread Console is designed to bridge the gap between raw OpenAI Assistant interactions and meaningful business data. It allows administrators to organize threads into "Projects", tag them for categorization, and perform high-performance full-text searches across thousands of conversations.

Key improvements in version 2.0 include a move to a modular architecture, the introduction of asynchronous task processing for heavy operations, and a completely redesigned user interface optimized for both desktop and mobile devices.

## Features

### Core Functionality
-   **Centralized Dashboard**: Manage multiple OpenAI API keys and projects from a single interface.
-   **Advanced Search**: Full-text search capability across thread messages, metadata, and IDs. Supports date range filtering and Boolean logic.
-   **Project Management**: Organize threads into Projects (e.g., by client or department). Each project can have its own dedicated API Key and Access Control List (ACL).
-   **Tagging System**: Robust tagging architecture enforcing a "Single Tag per Project" policy for strict categorization.
-   **Remark System**: Add searchable remarks/notes to any thread for internal context.

### Performance & Architecture
-   **SQL-Based Search**: Optimized search engine using SQLAlchemy JOINs to handle large datasets efficiently.
-   **Asynchronous Processing**: Integrated Huey Task Queue to offload time-consuming operations (like "Fresh Search" API synchronization) to background workers, preventing UI blocking.
-   **Local-First Caching**: Search operations prioritize local database records for millisecond-level response times, syncing with the OpenAI API only when explicitly requested.
-   **Rate Limiting**: Intelligent rate limiting for API-intensive operations to protect quota and ensure system stability.

### User Interface
-   **Mobile-Optimized**: Responsive design featuring native OS-level pickers for dropdowns and touch-friendly controls.
-   **Glassmorphism Theme**: Modern visual aesthetic with dynamic background effects and customizable themes.
-   **Real-time Feedback**: Polling-based progress bars and status updates for long-running background tasks.
-   **Tag Autocomplete**: Admin interface features smart suggestions for existing tags to maintain consistency.

### Security
-   **Role-Based Access Control (RBAC)**: Distinctions between Super Admins (global access) and Project Owners (scoped access).
-   **Secure Credentials**: API Keys and Admin Passwords are managed via environment variables and stored with encryption. Front-end display uses masking for sensitive data.
-   **Protection Mechanisms**: CSRF Token validation, input sanitization, and IP-based ban lists for brute-force protection.
-   **Git Safety**: Configuration ensures local database files are treated as binary to prevent cross-platform corruption and are ignored by version control to protect production data.

## Architecture

The system follows a modular Flask application factory pattern.

### Backend
-   **Framework**: Flask (Python)
-   **Database**: SQLite with SQLAlchemy ORM
-   **Task Queue**: Huey (SqliteHuey)
-   **Structure**:
    -   `app/routes`: Blueprint definitions for Main, Auth, Admin, and Subscriber endpoints.
    -   `app/models`: SQLAlchemy data models (User, Project, Thread, Message, AuditLog).
    -   `app/services`: Business logic isolation.
    -   `app/tasks`: Background task definitions.

### Frontend
-   **Templating**: Jinja2 (Serverside rendering)
-   **Styling**: Custom CSS with Glassmorphism variables.
-   **JavaScript**: Modular ES6 scripts handling AJAX, UI interaction, and Polling.

## Installation & Deployment

### Prerequisities
-   Docker and Docker Compose
-   Git

### Quick Start
1.  **Clone the repository**
    ```bash
    git clone <repository_url>
    cd threadConsole
    ```

2.  **Configuration**
    Create a `.env` file in the root directory:
    ```env
    SECRET_KEY=your_secure_random_string
    ADMIN_PASSWORD=your_admin_password
    FLASK_DEBUG=false
    ```

3.  **Deploy with Docker**
    ```bash
    docker-compose up -d --build
    ```

4.  **Access**
    -   Web Interface: `http://localhost:8010`
    -   Default Admin User: Use the password defined in `.env`.

### Updating
To update the application while preserving your database:
```bash
git pull origin main
docker-compose down
docker-compose up -d --build
```
*Note: The local database file `backend/app.db` is configured to be ignored by Git updates to prevent data loss.*

## Administration

### Managing Projects
Log in as Admin to create new projects and assign "Owners". Owners can manage their specific project settings but cannot see system-wide logs or other projects unless authorized.

### Search Operations
-   **Quick Search**: Queries the local database. Fast and free.
-   **Fresh Search**: Connects to OpenAI API to fetch the latest threads. Consumes API quota and takes longer. Use the "Force Refresh" checkbox to trigger this.

### Logs & Auditing
The Admin Panel provides comprehensive logs for:
-   **Audit Logs**: Action history (Login, Search, Update).
-   **Access Logs**: Raw HTTP requests.
-   **IP Monitoring**: Track and ban suspicious IP addresses.

## License

Proprietary Software. All rights reserved.
