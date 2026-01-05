# Thread Console

This is an OpenAI Thread Management System designed for education and team collaboration. It allows administrators and teachers to manage multiple conversation groups, provides fast full-text search capabilities, and features comprehensive Role-Based Access Control (RBAC) and security protection mechanisms.

## Key Features

### Search and Browsing
*   **Full-Text Search**: Deep search for conversation content with keyword highlighting.
*   **Advanced Filtering**: Filter search results by date range.
*   **Secure Browsing**: Built-in XSS protection (Bleach) automatically filters malicious HTML tags to ensure safe browsing.
*   **High Performance**: In-Memory search architecture ensures sub-second response times even with large datasets.

### Management Panel
*   **Role-Based Access Control (RBAC)**:
    *   **Admin**: Has full access to manage all groups, create/delete/reset teacher passwords, and view system audit logs.
    *   **Teacher**: Has a dedicated workspace and can only manage groups created by themselves, ensuring data privacy and isolation.
*   **Group Management**:
    *   Support for creating multiple project or course groups.
    *   **Independent API Key**: Each group can be bound to a separate OpenAI API Key for quota control.
    *   **Validation**: Prevents the creation of groups with duplicate names.
*   **Account Management**:
    *   **Password Hint**: Admins can view partial password hints for teachers (e.g., `Le***lo`) to verify identity.
    *   **Password Reset**: Admins can directly reset teacher passwords.
*   **Data Import/Export**: Support for uploading Excel (`.xlsx`) files to batch add or remove Thread IDs.

### Security Protection
*   **Account Lockout**: After 5 consecutive failed login attempts from a single IP, the account is locked for 15 minutes to prevent brute-force attacks.
*   **Password Policy**: Teacher passwords must be 10-15 characters long and contain both letters and numbers.
*   **Data Encryption**: API Keys are encrypted using Fernet symmetric encryption before storage.
*   **Audit Log**: The system records all sensitive operations (login, account creation/deletion, group modification, password reset, etc.) for tracking purposes.

---

## Deployment Guide

### Docker Deployment (Recommended)

This project is fully containerized. It is recommended to use Docker for deployment.

#### 1. Prepare Environment File
Create a `.env` file in the project root directory:
```env
# Default System OpenAI API Key (Used when a group has no key set)
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx

# Admin Passwords (Comma-separated for multiple admins)
ADMIN_PASSWORD=admin888,root1234

# Session Secret Key (Must be a long random string)
SECRET_KEY=change-this-to-a-very-long-random-secret-key-123456

# Service Port (Internal container port, usually does not need modification)
PORT=8000
```

#### 2. Prepare Data Files
Create necessary empty files on the host to avoid Docker mounting errors:
```bash
touch threads.json users.json audit.log access.log
```

#### 3. Start Service
Run the following commands to build and start the container (Exposed on port `8010`):

```bash
# 1. Build Image
docker build -t thread-console .

# 2. Run Container
docker run -d \
  --name thread-console \
  --restart always \
  -p 8010:8000 \
  --env-file .env \
  -v $(pwd)/threads.json:/app/threads.json \
  -v $(pwd)/users.json:/app/users.json \
  -v $(pwd)/audit.log:/app/audit.log \
  -v $(pwd)/access.log:/app/access.log \
  thread-console
```

After starting, visit `http://localhost:8010` to access the home page.

---

## Nginx Proxy Manager Setup (SSL / HTTPS)

If you are using Nginx Proxy Manager for reverse proxy, the recommended settings are:

1.  **Domain Names**: `thread.yourdomain.com`
2.  **Scheme**: `http`
3.  **Forward Hostname / IP**: `host.docker.internal` (if NPM and App are on the same machine) or `Server IP`
4.  **Forward Port**: `8010`
5.  **Block Common Exploits**: Enable
6.  **SSL**: Request a Let's Encrypt certificate and check `Force SSL`.

---

## Project Structure

*   `app.py`: Core application logic (Flask).
*   `templates/`: HTML templates.
    *   `index.html`: Search home page.
    *   `admin.html`: Admin management panel.
    *   `login.html`: Login page.
*   `threads.json`: Stores group structure and Thread IDs.
*   `users.json`: Stores teacher account information (Hashed passwords).
*   `audit.log`: System security audit log.

## Developer Info

*   **Author**: Leolo / Isaries
*   **Version**: 1.2.0
*   **Last Update**: 2026-01-05
