# Thread Console

A centralized management platform for OpenAI Assistant Threads, featuring an advanced search engine, project organization, and secure administration capabilities. This system bridges the gap between raw OpenAI Assistant interactions and meaningful business data, allowing administrators to organize threads into Projects, tag them for categorization, and perform high-performance full-text searches.

## Architecture

The system follows a modular Flask application factory pattern, separating concerns between a robust backend API and a responsive frontend interface.

### Backend
*   **Framework**: Flask (Python)
*   **Database**: SQLite with SQLAlchemy ORM
*   **Task Queue**: Huey (SqliteHuey) for asynchronous background processing (Search, Sync, Metrics)
*   **Security**:
    *   **Rate Limiting**: DOS protection via Flask-Limiter
    *   **Input Sanitization**: XSS prevention via Bleach and MarkupSafe
    *   **Cryptography**: AES encryption for API Key storage
*   **Key Components**:
    *   **Smart Refresh System**: Adaptive polling mechanism that prioritizes active threads and reduces API consumption for stale ones.
    *   **Token Analytics**: Built-in tracking for input/output tokens to monitor usage and costs.

### Frontend
*   **Templating**: Jinja2 (Server-side rendering) with dynamic HTML injection
*   **Styling**: Custom CSS implementing a modern, responsive Glassmorphism aesthetic
*   **JavaScript**: Modular ES6 scripts managing AJAX requests, polling, and DOM updates
*   **UX**: Real-time progress bars, debounced interactions, and mobile-optimized layouts

## Features

### Core Capabilities
*   **Centralized Dashboard**: Manage multiple OpenAI API keys and projects from a single interface.
*   **Advanced Search**: Full-text search capability across thread messages, metadata, and IDs. Supports date range filtering and Boolean logic.
*   **Project Management**: Organize threads into Projects. Each project supports independent API Keys and Access Control Lists (ACL).
*   **Math CAPTCHA V2**: A robust, dual-mode CAPTCHA system (Text/Math) protecting resource-intensive endpoints. The Math mode generates calculus problems (Polynomial, Trigonometry, Chain Rule) to prevent automated attacks.

### Intelligent Data Management
*   **Smart Refresh**: The system intelligently schedules updates based on thread activity. Active threads are refreshed frequently, while stale threads are moved to lower priority queues to conserve API quotas.
*   **Token Usage Tracking**: Automatically records and aggregates token usage (total, prompt, completion) per thread and system-wide, aiding in cost analysis.
*   **SQL-Based Search**: Optimized search engine using SQLAlchemy techniques to prevent N+1 query performance issues.

### Security Hardening
*   **Injection Protection**:
    *   **Excel/CSV**: Exports are sanitized to prevent Formula Injection.
    *   **XSS**: Markdown rendering strictly escapes HTML attributes.
*   **Rate Limiting**: Critical endpoints (Login, Refresh, Export) are protected by IP-based limits.
*   **SSRF Protection**: Strict validation on file proxy endpoints.
*   **Audit Logging**: comprehensive tracking of all admin actions, including logins, settings changes, and data exports.

## Installation & Deployment

### Prerequisites
*   Docker and Docker Compose
*   Or Python 3.11+ for manual installation

### Docker Deployment (Recommended)

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

3.  **Start Services**
    ```bash
    docker-compose up -d --build
    ```

4.  **Access**
    *   Web Interface: `http://localhost:8010`
    *   Default Admin Password: As defined in your `.env` file.

### Manual Installation

1.  **Install Dependencies**
    ```bash
    cd backend
    pip install -r requirements.txt
    ```

2.  **Run Application**
    ```bash
    python run.py
    ```

## Updating & Migrations

If you are updating an existing installation, you may need to apply database schema changes.

1.  **Pull latest changes**
    ```bash
    git pull origin main
    ```

2.  **Run Migrations** (If not using a fresh database)
    The system includes specific migration scripts for new features like Smart Refresh and Token Tracking. Run these scripts from the `backend` directory:
    ```bash
    cd backend
    python migrate_smart_refresh.py
    python migrate_tokens.py
    ```

3.  **Restart Services**
    ```bash
    docker-compose down
    docker-compose up -d --build
    ```

## Administration

### Managing Projects
Log in as Admin to create new projects and assign "Owners". Owners can manage their specific project settings (API Keys, Tags) but cannot see system-wide logs or other projects unless authorized.

### Search Operations
*   **Quick Search**: Queries the local database. Fast and efficient.
*   **Fresh Search**: Connects to the OpenAI API to fetch the latest threads. This consumes API quota and requires a valid CAPTCHA token.

### Logs & Monitoring
The Admin Panel provides:
*   **Audit Logs**: History of sensitive actions.
*   **System Metrics**: CPU/Memory usage and Total Managed Tokens count.
*   **IP Monitoring**: Tools to track and ban suspicious IP addresses.

## License

Proprietary Software. All rights reserved.
