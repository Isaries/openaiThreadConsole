# OpenAI Thread Console

This is a comprehensive management system for OpenAI Assistant Threads, built with Flask. It is designed for educational institutions and teams to manage multiple thread "Projects" securely. The system provides role-based access control (Admin/Teacher), advanced search capabilities, server-side PDF generation, and a robust monitoring system.

---

## Key Features

### 1. Project & Thread Management
*   **Multi-Owner Projects**: Projects can be assigned to multiple teachers. Administrators maintain full control over assignments, while teachers can only access projects explicitly assigned to them.
*   **Smart Thread Management**: 
    *   **Optimistic Locking**: Prevents data conflicts when multiple administrators modify project settings simultaneously.
    *   **Orphan Handling**: Automatically reassigns project ownership to Administrators if a teacher account is deleted.
    *   **Smart ID Extraction**: Automatically extracts Thread IDs from full URLs pasted into the Admin interface.
*   **Encrypted API Keys**: Project-specific OpenAI API keys are stored using AES-256 encryption (Fernet), ensuring security at rest.

### 2. Search & Discovery
*   **Advanced Search**: Users can search for threads across specific projects using keywords, date ranges, or direct Thread IDs.
*   **Visibility Control**: Projects can be toggled as "Visible" or "Hidden". Hidden projects are inaccessible to the public and require authentication for all actions.
*   **Keyword Highlighting**: Search terms are automatically highlighted within the conversation preview for quick reference.

### 3. PDF Export & Reporting
*   **Server-Side Generation**: Utilizes WeasyPrint to generate high-fidelity PDFs directly on the server, ensuring consistent rendering across all devices (Desktop, Tablet, Mobile).
*   **Split-PDF Logic**: Long conversations (over 50 messages) are automatically split into multiple PDF files and bundled into a ZIP archive for easier downloading and printing.
*   **Visitor Access**: Publicly visible projects allow visitors to download conversation PDFs without requiring a login. Private projects remain strictly protected behind authentication.
*   **Full Language Support**: Includes fonts for CJK (Chinese, Japanese, Korean) characters to ensure correct rendering.

### 4. User & Session Security
*   **Role-Based Access Control (RBAC)**:
    *   **Administrators**: Complete system access, including user management, IP bans, and audit logs.
    *   **Teachers**: Access limited to assigned projects.
*   **Enhanced Security**:
    *   **Session Management**: Strict 1-hour session timeout.
    *   **IP Security**: Automatic lockout after multiple failed login attempts and an administrative IP ban system.
    *   **Email Validation**: Enforces unique email addresses and character limits during user creation.
*   **Responsive Design**: The entire interface is optimized for mobile and tablet devices, providing a seamless experience on any screen size.

### 5. System Monitoring
*   **Real-Time Audit Log**: Tracks all critical actions (Login, Search, Data Modification) with timestamps and user details.
*   **IP Monitoring**: visualizes activity grouped by IP address, allowing administrators to identify and block suspicious traffic.
*   **Real-IP Support**: Configured to respect `X-Forwarded-For` headers, ensuring accurate IP logging when deployed behind a reverse proxy (e.g., Nginx).

---

## Architecture

The application follows a modular structure for scalability and maintainability:

*   **app.py**: The central controller handling HTTP routes, request processing, and view rendering.
*   **services.py**: Contains core business logic, including OpenAI API integration and message processing.
*   **database.py**: Manages data persistence using JSON flat-files with thread-safe locking mechanisms.
*   **security.py**: Handles encryption, password hashing, session validation, and IP blocking enforcement.
*   **utils.py**: Provides helper functions for HTML sanitization, date formatting, and markdown processing.

---

## Installation & Deployment

### Prerequisites
*   Docker and Docker Compose
*   (Recommended) Nginx Proxy Manager for SSL termination and Real-IP forwarding.

### Docker Deployment

1.  **Clone Repository**
    ```bash
    git clone https://github.com/Isaries/openaiThreadConsole
    cd openaiThreadConsole
    ```

2.  **Configure Environment**
    Create a `.env` file in the root directory:
    ```ini
    SECRET_KEY=your-secure-random-key
    OPENAI_API_KEY=sk-proj-your-default-key
    ADMIN_PASSWORD=your-admin-password
    ```

3.  **Initialize Data Files**
    Create the necessary JSON files for data persistence:
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

### Networking Note
To ensure the Admin Panel correctly displays user IP addresses, deploying behind a reverse proxy (like Nginx) is highly recommended. Ensure the proxy passes the `X-Forwarded-For` header.

---

## Data Storage

The system uses local JSON files for lightweight, portable data storage:

*   **users.json**: Stores user credentials and profile data.
*   **groups.json**: Stores project configurations, thread associations, and encrypted API keys.
*   **ip_bans.json**: Registry of banned IP addresses and expiration times.
*   **audit.log**: Chronological log of system events.

> **Important**: Ensure these files are mounted to persistent volumes in Docker to prevent data loss during container restarts.

---

## Copyright

Copyright (c) 2026 Isaries All Rights Reserved.
