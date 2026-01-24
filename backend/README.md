# Backend Architecture

The backend is a robust Flask application structured around the Application Factory pattern, designed to provide high-performance search, secure administration, and asynchronous background processing.

## 📂 Directory Structure

```text
backend/
├── app/
│   ├── routes/          # Blueprint definitions
│   │   ├── admin/       # Management interface (Users, Projects, Settings)
│   │   ├── api.py       # REST API endpoints for frontend interaction
│   │   ├── auth.py      # Authentication logic
│   │   └── main.py      # Core page routing
│   ├── services/        # Business Logic Layer
│   │   ├── captcha_service.py # Math CAPTCHA generation / validation
│   │   ├── excel_service.py   # Secure data export (CSV injection protected)
│   │   └── pdf_service.py     # HTML to PDF conversion for thread export
│   ├── tasks.py         # Huey background tasks (Search, Sync, Metrics)
│   ├── models.py        # SQLAlchemy Database Models
│   └── security.py      # Encryption & Hashing utilities
├── migrations/          # Legacy migration scripts (manual scripts preferred)
├── instance/            # Application instance config & SQLite DB
├── run.py               # WSGI Entry point
├── config.py            # Flask Configuration classes
└── requirements.txt     # Python dependencies
```

## 🛠️ Technology Stack

*   **Core Framework**: Flask (Python 3.11+)
*   **Database**: SQLite with SQLAlchemy ORM
*   **Async Queue**: Huey (SqliteHuey)
    *   Handles "Fresh Search" requests against OpenAI API.
    *   Background synchronization of thread data.
    *   System metric collection (CPU/Memory).
*   **Security**:
    *   `Flask-Limiter`: Rate limiting policies.
    *   `Bleach` & `MarkupSafe`: Content sanitization.
    *   `Cryptography`: AES encryption for sensitive keys.

## 🧩 Key Components

### 1. Data Models (`app/models.py`)
*   **Thread**: Central entity storing message counts, token usage, and refresh status.
    *   *Smart Refresh*: Uses `last_message_timestamp` and `refresh_priority` to optimize API syncing.
*   **Project**: Organizational unit for threads, containing specific API Keys and Owners.
*   **SystemMetric**: Time-series data for server resource monitoring.

### 2. Services
*   **CaptchaService**: Generates cryptographic Math problems (Chain Rule, Polynomials) to verify human presence before expensive API calls.
*   **ExcelService**: Sanitizes all cell data to prevent CSV/Formula injection attacks when admins export data.

### 3. Background Tasks (`app/tasks.py`)
*   `perform_search_task`: Executes complex full-text search strategies.
*   `fetch_thread_task`: Syncs a specific thread with OpenAI's servers.
*   `collect_system_metrics`: Periodic job to log CPU/RAM usage.

## 🚀 Getting Started

### Prerequisites
*   Python 3.11+
*   Pip

### Local Development

1.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Environment Setup**
    Create a `.env` file (or set variables in your IDE):
    ```env
    FLASK_APP=run.py
    FLASK_DEBUG=True
    SECRET_KEY=dev
    ```

3.  **Run Worker (Windows)**
    ```bash
    run_worker.bat
    ```

4.  **Run Server**
    ```bash
    python run.py
    ```

## ⚠️ Important Notes

*   **Database**: The default database is located at `app.db` (or `instance/app.db`). Do not commit this file to version control.
*   **Migrations**: Use the standalone scripts (`migrate_smart_refresh.py`, `migrate_tokens.py`) in the root folder to update schemas.
