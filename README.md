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
    *   **API Key Management**: Supports group-specific OpenAI API Keys (stored with AES-256 encryption) or falls back to the system default key. Invalid keys are clearly flagged.
    *   **Visibility Toggle**: Hide or show groups with a single click.
*   **Thread Data Management**:
    *   **Batch Processing**: Supports uploading Excel files (.xlsx) to batch add or delete Thread IDs (column names are case-insensitive).
    *   Single entry add/delete functionality.
    *   **Optimistic Locking**: Prevents data overwrite issues when multiple users edit simultaneously.
*   **User Management**:
    *   Administrators can create, delete, and edit teacher accounts.
    *   **Password Hints**: First and last 2 characters of passwords are stored as hints for easy recovery/verification (only for new/reset accounts).
    *   **Session Info**: Displays logged-in user email in the dashboard navbar.

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

*   **app.py**: Route Controller, handling HTTP requests and page navigation.
*   **config.py**: System configuration, managing environment variables and constants.
*   **database.py**: Persistence Layer, handling JSON file I/O (users.json, groups.json) and Audit Logs.
*   **security.py**: Security module, handling encryption (Fernet), password hashing, IP ban logic, and lockout mechanisms.
*   **services.py**: Business logic and external services, including OpenAI API calls and data processing.
*   **utils.py**: Utility functions, including HTML sanitization and time formatting.

---

## Installation & Deployment

### Method 1: Docker (Recommended)

1.  **Clone Repository**
    ```bash
    git clone <repository_url>
    cd openaiThreadConsole
    ```

2.  **Configure Environment**
    Create a .env file with your credentials:
    ```ini
    SECRET_KEY=your-random-secure-secret-key
    OPENAI_API_KEY=sk-proj-your-default-openai-key
    ADMIN_PASSWORD=your-admin-password
    ```

3.  **Prepare Data Files**
    You must create these files locally to ensure Docker mounts them as files (not directories) and to ensure you have write permissions.
    ```bash
    touch groups.json ip_bans.json audit.log access.log users.json
    echo "[]" > groups.json
    echo "{}" > ip_bans.json
    echo "[]" > users.json
    ```

4.  **Build and Run**
    ```bash
    docker build -t thread-console .
    
    docker run -d \
      --name thread-console \
      --restart always \
      -p 8010:8000 \
      --env-file .env \
      -v $(pwd)/users.json:/app/users.json \
      -v $(pwd)/groups.json:/app/groups.json \
      -v $(pwd)/ip_bans.json:/app/ip_bans.json \
      -v $(pwd)/audit.log:/app/audit.log \
      -v $(pwd)/access.log:/app/access.log \
      thread-console
    ```

### Method 2: Local Python Environment

1.  **Install Dependencies**
    ```bash
    pip install flask flask-wtf flask-limiter cryptography bleach pandas requests openpyxl python-dotenv
    ```

2.  **Run Server**
    ```bash
    python app.py
    ```
    The server will start at http://localhost:5000 by default.

---

## Data Storage

This system uses JSON files as a lightweight database:

*   **users.json**: User account information (ID, Username, Email, Password Hash, Hints).
*   **groups.json**: Group information, Thread ID lists, and encrypted API Keys.
*   **ip_bans.json**: Registry of banned IP addresses.
*   **audit.log**: System operation audit logs.

> **Note**: These files are excluded from git by default to prevent sensitive data leakage.

---

## Security Mechanisms

1.  **Data Encryption**: API Keys are encrypted using Fernet (AES-128 mode) before storage. The key is derived from the SECRET_KEY environment variable. If the SECRET_KEY changes, old API keys will be flagged as invalid rather than displaying garbled text.
2.  **Input Sanitization**: User inputs and OpenAI responses are processed by Bleach to retain only safe tags, preventing XSS attacks.
3.  **Rate Limiting**: Applied to login and search interfaces to maintain service stability.

---

Copyright (c) 2024 Thread Console System.
