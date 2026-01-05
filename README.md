# OpenAI Thread Console

This is a Flask-based management system for OpenAI Assistant Threads. It allows educational institutions or teams to manage multiple thread groups, providing role-based access control (Admin/Teacher), keyword searching, conversation viewing, and a comprehensive backend monitoring system.

---

## Key Features

### 1. Search Portal
*   **Cross-Group Search**: Users can select specific groups to search through conversation history.
*   **Keyword Highlighting**: Keywords in search results are highlighted with a yellow background.
*   **Date Filtering**: Supports filtering conversations by start and end dates.
*   **Visibility Control**: Only displays groups marked as "Visible".

### 2. Admin Panel
*   **Group Management**:
    *   Create, rename, and delete groups.
    *   **Role Assignment**: Assign groups to specific teachers or transfer ownership to the administrator.
    *   **API Key Management**: Supports group-specific OpenAI API Keys (stored with AES-256 encryption) or falls back to the system default key.
    *   **Visibility Toggle**: Hide or show groups with a single click.
*   **Thread Data Management**:
    *   **Batch Processing**: Supports uploading Excel files (`.xlsx`) to batch add or delete Thread IDs (column names are case-insensitive).
    *   Single entry add/delete functionality.
    *   **Optimistic Locking**: Prevents data overwrite issues when multiple users edit simultaneously.
*   **User Management**:
    *   Administrators can create, delete, and edit teacher accounts.
    *   Reset user passwords.
    *   Password strength validation and encrypted storage (PBKDF2).

### 3. Security & Monitoring
*   **IP Access Monitoring**:
    *   Real-time monitoring of all IP activities (Login, Search, Visit, Data Modification).
    *   Smart Identification: Automatically tags known teacher usernames based on session data.
    *   Activity Logs: Detailed history of actions performed by each IP.
*   **Ban System**:
    *   Support for temporary (15m, 1h, 8h...) or permanent IP bans.
    *   **Self-Ban Protection**: The system prevents administrators from banning their own current IP address.
*   **Login Protection**:
    *   Automatic IP lockout after multiple failed login attempts (Brute-force protection).
    *   CSRF protection on all forms.

---

## Architecture

The project follows a modular architecture to ensure maintainability:

*   **`app.py`**: Route Controller, handling HTTP requests and page navigation.
*   **`config.py`**: System configuration, managing environment variables and constants.
*   **`database.py`**: Persistence Layer, handling JSON file I/O (`users.json`, `groups.json`) and Audit Logs.
*   **`security.py`**: Security module, handling encryption (Fernet), password hashing, IP ban logic, and lockout mechanisms.
*   **`services.py`**: Business logic and external services, including OpenAI API calls and data processing.
*   **`utils.py`**: Utility functions, including HTML sanitization and time formatting.

---

## Installation & Usage

### 1. Requirements
*   Python 3.8+
*   Pip (Python Package Manager)

### 2. Install Dependencies
```bash
pip install flask flask-wtf flask-limiter cryptography bleach pandas requests openpyxl python-dotenv
```

### 3. Environment Variables (.env)
Create a `.env` file in the project root directory:
```ini
# Flask Secret Key (Critical for session encryption)
SECRET_KEY=your-super-secret-key-change-this

# OpenAI API Key (System default fallback key)
OPENAI_API_KEY=sk-proj-...

# Admin Password (Root administrator password)
ADMIN_PASSWORD=your-admin-password
```

### 4. Run Server
```bash
python app.py
```
The server will start at `http://localhost:5000` by default.

---

## Data Storage

This system uses JSON files as a lightweight database, eliminating the need for a SQL server:

*   `users.json`: Stores user account information (User ID, Username, Email, Password Hash).
*   `groups.json`: Stores group information, Thread ID lists, and encrypted API Keys.
*   `settings.json`: Stores global settings.
*   `ip_bans.json`: Stores the list of banned IP addresses.
*   `audit.log`: Stores system operation audit logs.

> **Note**: All `.json` and `.log` files should be excluded from version control (except example files) to prevent sensitive data leakage.

---

## Security Mechanisms

1.  **Data Encryption**: All API Keys are encrypted using `Fernet` (symmetric encryption) before being written to `groups.json`. The key is derived from the `SECRET_KEY`. Attackers cannot retrieve the actual API Key even if they gain access to the JSON files.
2.  **Input Sanitization**: All user inputs and OpenAI responses are processed by `bleach` to retain only safe tags (e.g., `<b>`, `<mark>`), preventing XSS attacks.
3.  **Rate Limiting**: Rate limits are applied to login and search interfaces (e.g., 10 requests per minute) to prevent brute-force attacks and DoS.

---

## Recent Updates
*   **Refactor**: Split monolithic `app.py` into MVC-structured modules.
*   **Feat**: Added IP monitoring panel and ban functionality.
*   **Feat**: Added support for batch add/delete via Excel (case-insensitive column headers).
*   **Fix**: Fixed issue where `<mark>` tags in search results were being escaped.
*   **UX**: Added modern animated gradient background to the search page.

---

&copy; 2024 Thread Console System.
