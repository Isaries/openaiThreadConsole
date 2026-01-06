# OpenAI Thread Console

This application is a secure, role-based management system for OpenAI Assistant Threads, built with Flask. It enables educational institutions and enterprise teams to manage multi-tenant projects, enforce access controls, and monitor usage with auditing capabilities.

## Key Features

### Project & Thread Management
*   **Role-Based Access Control (RBAC)**: Supports strict separation of duties. Administrators have full system control, while Teachers/Users are restricted to explicitly assigned projects.
*   **Multi-Owner Projects**: Projects can be securely shared among multiple owners, managed centrally by administrators.
*   **Concurrency Control**: Implements optimistic locking to prevent data corruption during simultaneous updates.
*   **Orphan Management**: Automatically reassigns ownership of projects to administrators if a user account is deleted to prevent data loss.

### Search & Discovery
*   **Advanced Filtering**: precise filtering by Project, Keyword, Date Range, or direct Thread ID.
*   **Smart ID Extraction**: Automatically parses Thread IDs from pasted URLs in administrative inputs.
*   **Contextual Highlighting**: Search terms are highlighted within message previews for rapid context identification.
*   **Persistent User Preferences**: Automatically remembers user interface choices such as the selected project and visual theme (e.g., Gray, Grid).

### PDF Export & Reporting
*   **Server-Side Rendering**: Uses WeasyPrint to generate consistent, high-fidelity PDFs regardless of the client device.
*   **Intelligent Splitting**: Automatically segments long conversation threads into multiple PDF files and bundles them into a ZIP archive for efficient handling.
*   **CJK Support**: Built-in support for Chinese, Japanese, and Korean character sets.

---

## Security Architecture

This application prioritizes security by design, implementing defense-in-depth strategies to protect user data and system integrity.

### 1. Network & Transport Security
*   **Strict Transport Security (HSTS)**: Enforces HTTPS connections to preventing protocol downgrade attacks (via Flask-Talisman).
*   **Security Headers**: Implements standard HTTP headers including `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and strict `Content-Security-Policy` (CSP) to mitigate XSS and Clickjacking.
*   **Real-IP Resolution**: Configured to trust `X-Forwarded-For` headers from secure upstream proxies (e.g., Nginx), ensuring accurate logging and rate limiting.

### 2. Authentication & Session Management
*   **Secure Sessions**: Session cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Lax` attributes to prevent Cross-Site Scripting (XSS) theft and Cross-Site Request Forgery (CSRF).
*   **Strict Timeouts**: Sessions automatically expire after 1 hour of inactivity.
*   **Brute-Force Protection**: Automatic account lockout (15 minutes) after 5 failed login attempts from a single IP address.
*   **IP Banning**: Administrators can permanently ban malicious IP addresses from the system.

### 3. Data Protection
*   **Encryption at Rest**: Sensitive data, such as OpenAI API Keys, is encrypted using AES-256 (Fernet) before storage. Keys are never exposed in logs or the frontend.
*   **Password Hashing**: User passwords are salted and hashed using robust algorithms (Scrypt/PBKDF2 via Werkzeug).
*   **Input Sanitization**: All user inputs are sanitized to prevent Stored XSS, while template rendering uses context-aware escaping.

---

## Architecture

The system follows a modular architecture for maintainability:

*   **app.py**: Central application controller handling routing, configuration, and security middleware integration.
*   **services.py**: Core business logic layer managing OpenAI API interactions and threading operations.
*   **database.py**: Data persistence layer using thread-safe file operations for JSON-based storage.
*   **security.py**: Cryptographic operations, authentication logic, and intrusion detection mechanisms.
*   **utils.py**: Utility functions for data processing, HTML sanitization, and formatting.

---

## Installation & Deployment

### Prerequisites
*   Docker and Docker Compose
*   (Recommended) Nginx or similar reverse proxy for SSL termination.

### Deployment Steps

1.  **Clone Repository**
    ```bash
    git clone https://github.com/Isaries/openaiThreadConsole.git
    cd openaiThreadConsole
    ```

2.  **Configuration**
    Create a `.env` file in the root directory:
    ```ini
    SECRET_KEY=your-secure-random-key-change-this
    OPENAI_API_KEY=sk-proj-your-system-default-key
    ADMIN_PASSWORD=your-strong-admin-password
    ```

3.  **Data Initialization**
    Initialize the required JSON data stores:
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

---

### 4. Operational Security
*   **Rate Limiting**: Implements `Flask-Limiter` to restrict request frequency (e.g., 10 req/sec), mitigating Denial of Service (DoS) risks.
*   **Comprehensive Auditing**: Every critical system action (Login, Search, Configuration Change) is immutable logged to `audit.log`, providing a complete paper trail for forensic analysis.
*   **Error Suppression**: Production configuration conceals stack traces from end-users to prevent information leakage.

---

## Privacy & Data Sovereignty

*   **Zero External Dependencies**: The system operates entirely independently of external databases or cloud storage services, ensuring full data sovereignty.
*   **Data Minimization**: Only essential user data is stored locally in JSON format, facilitating easy compliance with data privacy regulations (e.g., GDPR, CCPA) regarding right-to-access and right-to-erase.
*   **Transparent Logging**: All system logs are plain-text and human-readable, ensuring complete transparency of system operations.

Copyright (c) 2026 Isaries. All Rights Reserved.
