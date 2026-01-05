# OpenAI Thread Console

This is a Flask-based management system for OpenAI Assistant Threads. It allows educational institutions or teams to manage multiple thread projects, providing role-based access control (Admin/Teacher), keyword searching, conversation viewing, and a comprehensive backend monitoring system.

---

## Key Features

### 1. Project Management
*   **Multi-Owner Support**: Projects can be assigned to multiple teachers. Admins have full control over assignment, while teachers can only view projects they are assigned to.
*   **Optimistic Locking**: Prevents data overwrite conflicts when multiple administrators edit the same project simultaneously.
*   **Orphan Handling**: Automatically cleans up ownership when a user account is deleted. If a project has no owners left, it reverts to Admin management.
*   **API Key Management**: Supports project-specific OpenAI API Keys (stored with AES-256 encryption via Fernet) or falls back to the system default key.

### 2. Search Portal
*   **Cross-Project Search**: Users can select specific projects to search through conversation history.
*   **Keyword Highlighting**: Keywords in search results are highlighted for easier reading.
*   **Date Filtering**: Supports filtering conversations by start and end dates.
*   **Visibility Control**: Only displays projects marked as "Visible" to general users.

### 3. User & Session Management
*   **Role-Based Access**:
    *   **Admins**: Full access to all projects, user management, and system settings. Login via Password (or optional username 'admin').
    *   **Teachers**: Restricted access to assigned projects only. Login via Email + Password.
*   **Session Security**:
    *   Strict 1-hour session timeout.
    *   Automatic IP lockout after multiple failed login attempts.
*   **User Management**: Administrators can create, delete, and edit teacher accounts. Password hints are stored for recovery assistance.

### 4. System Security & Monitoring
*   **IP Access Control**:
    *   **Monitoring**: Real-time logging of all actions (Login, Search, Visit, Data Modification) grouped by IP address.
    *   **Ban System**: Administrators can ban IP addresses for specific durations (15m, 1h, 8h, 1d, 30d, Permanent).
    *   **Real IP Detection**: Prioritizes `X-Forwarded-For` header to support Nginx Proxy Manager, crucial for Docker deployments.
*   **Audit Logging**: Comprehensive logs for all critical actions, viewable directly from the admin dashboard.
*   **Data Protection**: API Keys are encrypted at rest. Files are excluded from git.

---

## Architecture

The project follows a modular architecture to ensure maintainability:

*   **app.py**: Route Controller, handling HTTP requests, authentication, and view logic.
*   **config.py**: System configuration, managing environment variables and constants.
*   **database.py**: Persistence Layer, handling JSON file I/O (users.json, groups.json, ip_bans.json) and thread-safe locking.
*   **security.py**: Security module, handling encryption (Fernet), password hashing, IP ban enforcement, and session validation.
*   **services.py**: Business logic and external services, including OpenAI API interactions and message content processing.
*   **utils.py**: Utility functions for date formatting, HTML sanitization, and helper tools.

---

## Installation & Deployment

### Prerequisites
*   Docker and Docker Compose
*   (Recommended) Nginx Proxy Manager for SSL and real IP forwarding

### Docker Deployment

1.  **Clone Repository**
    ```bash
    git clone <repository_url>
    cd openaiThreadConsole
    ```

2.  **Configure Environment**
    Create a `.env` file with your credentials:
    ```ini
    SECRET_KEY=your-random-secure-secret-key
    OPENAI_API_KEY=sk-proj-your-default-openai-key
    ADMIN_PASSWORD=your-admin-password
    ```

3.  **Prepare Data Files**
    You must create these files locally to ensure Docker mounts them correctly with persistence.
    ```bash
    touch groups.json ip_bans.json audit.log users.json
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
      thread-console
    ```

### Networking Note (Important)
By default, Docker containers in Bridge mode will mask the client IP address. To view real user IPs in the Admin Panel (essential for the Ban System to work correctly), it is highly recommended to run this container behind a reverse proxy like Nginx Proxy Manager and configure it to pass the `X-Forwarded-For` header.

---

## Data Storage

This system uses JSON files as a lightweight, persistent database:

*   **users.json**: User account information (ID, Username, Email, Password Hash).
*   **groups.json**: Project configurations, including Thread IDs, Owner IDs, and encrypted API Keys.
*   **ip_bans.json**: Registry of currently banned IP addresses and their expiration times.
*   **audit.log**: System operation audit logs in text format.

> **Note**: These files are critical for data persistence. Ensure they are properly mounted when using Docker.

---

## Copyright

Copyright (c) 2024 Thread Console System. All Rights Reserved.
