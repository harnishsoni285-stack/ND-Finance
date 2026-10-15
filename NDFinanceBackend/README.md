# ND Finance backend

This backend stores the app data permanently in `ndfinance.db` using SQLite and serves the configured HTML app at `http://localhost:5080`.
The database is stored in `%LOCALAPPDATA%\ND Finance\ndfinance.db`, separate from the HTML source and outside build output.

The SQLite database contains customer profiles and loan information and is not encrypted by the application. Only authenticator secrets are encrypted using `NDF_AUTH_PEPPER`. In production, run the backend under a dedicated OS identity, restrict access to the database directory, use host/disk encryption, and keep encrypted, tested backups. A static-only hosting service cannot run this backend or provide its required persistent database.

## Authentication and security setup

- Passwords are hashed by the server with salted PBKDF2-SHA256 (600,000 iterations). Passwords must be at least 12 characters.
- Login uses an opaque, database-backed, 8-hour session in an `HttpOnly`, `SameSite=Strict` cookie. The cookie is `Secure` outside Development.
- Login and authentication endpoints are rate-limited by client IP. Five failed password attempts lock the account for 15 minutes.
- Email verification and password-reset codes are generated and checked on the server, expire after 10 minutes, and allow at most five verification attempts. Email sending is throttled per address.
- Users may optionally enroll an authenticator app for TOTP-based MFA from Settings.
- Authenticated APIs expose only the caller's loans and profile. Owner-only access is checked by the server; the old browser-side owner password is no longer used.
- Run the application only behind HTTPS in production. Do not expose port 5080 directly to the internet.
- The app limits scripts and API connections with a Content Security Policy; inline code remains enabled for the existing UI handlers. This is defense in depth, not a guarantee against compromise. Keep the OS, .NET, Nginx, and dependencies patched, and protect deployment secrets.

Configure the initial owner and SMTP delivery in the host's environment/secret manager before first startup. Do not put real credentials in source files:

```text
NDF_ADMIN_USERNAME=<initial owner username>
NDF_ADMIN_PASSWORD=<unique password of at least 12 characters>
NDF_ADMIN_EMAIL=<owner email address>
NDF_AUTH_PEPPER=<base64-encoded random key of at least 32 bytes>
NDF_SMTP_HOST=<SMTP host>
NDF_SMTP_PORT=587
NDF_SMTP_FROM=<verified sender address>
NDF_SMTP_USERNAME=<SMTP username, if required>
NDF_SMTP_PASSWORD=<SMTP password, if required>
```

The owner account is bootstrapped only if no owner exists. After it is created, remove the three `NDF_ADMIN_*` startup values. SMTP settings remain necessary for registration verification and password resets. Without SMTP configured, verification/reset delivery fails closed; the app never displays or locally generates OTPs.

Generate `NDF_AUTH_PEPPER` with a cryptographically secure random-number generator and store it in the same secret manager. It protects one-time-code verifiers and encrypts authenticator secrets in SQLite. Keep the same value across restarts and back it up separately; losing or changing it prevents verification of pending email codes and enrolled authenticators.

On startup, legacy accounts already stored in the backend SQLite `ndf_users` value are migrated into the server-side account table, retaining their stored password hashes (and upgrading legacy plaintext hashes). The legacy built-in `ND@TOP` owner account is deliberately not migrated because its password was fixed in browser code; provision a new owner as above. Browser-only `file://` data is no longer used as an authentication or data-storage fallback. Back up any browser-only records separately before switching to this server-backed version.

## Run

The ASP.NET Core backend serves both the frontend and `/api/*` on the same local origin. The site runs in a normal browser; Node.js and npm are not required to run it. Opening `index.html` directly waits for the backend and redirects to the app when it is ready; the file itself cannot start the database server.

### Windows browser app

1. Install the .NET 8 SDK and trust this workspace when VS Code asks to enable automatic tasks.
2. Opening the workspace starts the `Run ND Finance Web` task and opens `http://localhost:5080/`. You can also double-click the root `start-nd-finance.bat` file or run the task manually.
3. Keep the **ND Finance Server** terminal open while using the site. The database remains in `%LOCALAPPDATA%\ND Finance\ndfinance.db` after restarts.

To start the server in the current terminal instead, run `npm start` from the project root and open `http://localhost:5080/` in a browser. Node.js is only needed for the project test command; no npm install is needed to run the website.

### VS Code Live Server

Live Server is optional. The normal app uses only the backend at `http://localhost:5080/`. For frontend preview, start the backend task, then use the Live Server extension's **Go Live** command on `index.html`; its URL is usually `http://127.0.0.1:5500/` and API requests route to port 5080. If port 5500 is unavailable, start Live Server from the editor status bar or the HTML file's context menu.

### Windows local development

1. Install the .NET 8 SDK (the runtime alone is not enough to build this project). If it is not installed, the included installer can install it for the current user:

```powershell
powershell -ExecutionPolicy Bypass -File .\dotnet-install.ps1 -Channel 8.0 -InstallDir "$env:USERPROFILE\.dotnet"
$env:PATH = "$env:USERPROFILE\.dotnet;$env:PATH"
```

2. Before the first launch, configure the bootstrap owner and a stable pepper in the same PowerShell window. Use an owner password of at least 12 characters. Keep the generated pepper securely and reuse it on later starts:

```powershell
$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:NDF_AUTH_PEPPER = [Convert]::ToBase64String($bytes)
$env:NDF_ADMIN_USERNAME = 'your-owner-username'
$env:NDF_ADMIN_PASSWORD = Read-Host 'Initial owner password (12+ characters)'
$env:NDF_ADMIN_EMAIL = 'owner@example.com'
```

For account registration and password recovery, configure a real SMTP relay as well. OTP delivery fails closed without SMTP and the stable pepper:

```powershell
$env:NDF_SMTP_HOST = 'smtp.your-provider.com'
$env:NDF_SMTP_PORT = '587'
$env:NDF_SMTP_FROM = 'noreply@your-domain.com'
$env:NDF_SMTP_USERNAME = 'your-smtp-username'
$env:NDF_SMTP_PASSWORD = Read-Host 'SMTP password'
```

3. Initialize the database and start the server. SQLite schema initialization and the initial owner account bootstrap happen on the first backend startup. The database is stored at `%LOCALAPPDATA%\ND Finance\ndfinance.db`.

```powershell
dotnet restore .\NDFinanceBackend\NDFinanceBackend.csproj
dotnet run --project .\NDFinanceBackend\NDFinanceBackend.csproj
```

Or run the web launcher after setting the environment values above:

```powershell
.\NDFinanceBackend\start-nd-finance.bat
```

It checks `/api/health` and opens `http://localhost:5080/` in the default browser when SQLite responds. The root `start-nd-finance.bat` delegates to this launcher.

The frontend's API paths are same-origin paths; when served here they resolve to this backend. In production, serve the site and proxy `/api/` to the backend through the same HTTPS origin as described in [HTTPS_DEPLOYMENT.md](../HTTPS_DEPLOYMENT.md). Do not expose port 5080 directly to the internet.

To run the backend manually from the backend folder instead:

```powershell
dotnet run --project .\NDFinanceBackend.csproj
```

The health endpoint `GET /api/health` opens SQLite and runs `SELECT 1`; it returns HTTP 200 only when the database is available. API method/path/status/duration and health-check database errors are written to the backend logs.

The launcher starts the backend in its own terminal window. The backend database is separate from the project and persists across app and computer restarts.

Set a different HTML path if needed:

```powershell
$env:ND_HTML_PATH = 'C:\path\to\ND.HTML'
dotnet run --project .\NDFinanceBackend.csproj
```

The SQLite database survives rebuilds and computer restarts. Keep encrypted backups separately for protection against disk loss. The legacy browser-only storage fallback has been removed; it must not be used for login or account recovery.

An owner can download a full JSON backup from **All Data**. It contains account profiles, shop settings, the loan counter, loan records, and attached photos; it excludes password hashes, authenticator secrets, and active sessions. Keep downloaded backups encrypted and access-controlled. The app database remains at `%LOCALAPPDATA%\ND Finance\ndfinance.db`.
