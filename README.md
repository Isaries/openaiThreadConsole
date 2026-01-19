# Thread Console

A centralized management platform for OpenAI Assistant Threads, featuring an advanced search engine, project organization, and secure administration capabilities. This system bridges the gap between raw OpenAI Assistant interactions and meaningful business data, allowing administrators to organize threads into "Projects", tag them for categorization, and perform high-performance full-text searches.

## Architecture

The system follows a modular Flask application factory pattern, separating concerns between a robust backend API and a responsive frontend interface.

### Backend (`backend/`)
*   **Framework**: Flask (Python).
*   **Database**: SQLite with SQLAlchemy ORM.
*   **Task Queue**: Huey (SqliteHuey) for asynchronous background processing (Search, Sync, Metrics).
*   **Security**:
    *   **Rate Limiting**: `Flask-Limiter` for DoS protection.
    *   **Input Sanitization**: `bleach` and `markupsafe` for XSS prevention.
    *   **Cryptography**: AES encryption for storing API Keys.
*   **Structure**:
    *   `app/routes`: Blueprint definitions for Main, Auth, Admin, and API endpoints.
    *   `app/models`: SQLAlchemy data models (User, Project, Thread, Message, AuditLog, SystemMetric).
    *   `app/services`: Business logic isolation (Excel export, PDF generation, CAPTCHA).
    *   `app/tasks`: Background task definitions for Huey workers.

### Frontend (`frontend/`)
*   **Templating**: Jinja2 (Serverside rendering) with dynamic HTML injection.
*   **Styling**: Custom CSS implementing a modern Glassmorphism aesthetic.
*   **JavaScript**: Modular ES6 scripts (`admin_list.js`, `search.js`) managing AJAX requests, polling, and DOM manipulation.
*   **Features**:
    *   **Responsive Design**: Mobile-optimized layouts with native OS-level controls.
    *   **Real-time Feedback**: Polling-based progress bars for background tasks.
    *   **Debounced Interactions**: Optimized UX to prevent server overload.

## Features

### Core Capabilities
*   **Centralized Dashboard**: Manage multiple OpenAI API keys and projects from a single interface.
*   **Advanced Search**: Full-text search capability across thread messages, metadata, and IDs. Supports date range filtering and Boolean logic.
*   **Project Management**: Organize threads into Projects. Each project supports independent API Keys and Access Control Lists (ACL).
*   **Math CAPTCHA V2**: A robust, dual-mode CAPTCHA system (Text/Math) protecting resource-intensive endpoints. The Math mode generates calculus problems (Polynomial, Trigonometry, Chain Rule) that guarantee integer answers to prevent bot automated attacks.

### Performance & Scalability
*   **SQL-Based Search**: Optimized search engine using SQLAlchemy `subqueryload` to prevent N+1 query performance issues.
*   **Asynchronous Processing**: Integrated Huey Task Queue offloads heavy operations (like "Fresh Search" API synchronization) to background workers.
*   **Auto-Refresh**: Configurable background tasks ensuring data remains up-to-date without manual intervention, featuring race-condition protection for settings updates.
*   **System Metrics**: Real-time monitoring of CPU and Memory usage displayed in the Admin dashboard.

## Security Hardening

Following a comprehensive Red Team audit, the system includes multiple layers of defense:

1.  **Injection Protection**:
    *   **Excel/CSV**: All exported data is sanitized to prevent Formula Injection (CSV Injection) attacks on administrator workstations.
    *   **XSS**: Markdown rendering strictly escapes HTML attributes and creates safe HTML structures to prevent Cross-Site Scripting.
2.  **Rate Limiting**: Critical endpoints (Login, Refresh, Export) are protected by IP-based rate limits to mitigate Denial of Service (DoS) attacks.
3.  **Server-Side Request Forgery (SSRF) Protection**: File proxy endpoints enforce strict regex validation on file IDs to prevent path traversal or internal network scanning.
4.  **Timezone Integrity**: All date handling and scheduled tasks strictly enforce UTC+8 (Asia/Taipei) timezones to ensure data consistency across different server environments.

## Installation & Deployment

### Prerequisites
*   Docker and Docker Compose
*   Git

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
    *   Web Interface: `http://localhost:8010`
    *   Default Admin User: Use the password defined in `.env`.

### Updating
To update the application while preserving your database:
```bash
git pull origin main
docker-compose down
docker-compose up -d --build
```
*Note: The local database file `backend/app.db` is configured to be ignored by Git to prevent data loss.*

## Administration

### Managing Projects
Log in as Admin to create new projects and assign "Owners". Owners can manage their specific project settings but cannot see system-wide logs or other projects unless authorized.

### Search Operations
*   **Quick Search**: Queries the local database. Fast and efficient.
*   **Fresh Search**: Connects to the OpenAI API to fetch the latest threads. This consumes API quota and requires a valid CAPTCHA token to initiate.

### Logs & Auditing
The Admin Panel provides comprehensive logs for:
*   **Audit Logs**: Action history (Login, Settings Change, Data Export).
*   **System Performance**: Historical CPU/Memory usage charts.
*   **IP Monitoring**: Track and ban suspicious IP addresses.

## License

Proprietary Software. All rights reserved.
