# ND Finance – HTTPS & HSTS Deployment Guide

This guide covers production deployment of the **ND Finance web application** with full HTTPS, Let's Encrypt TLS, HSTS enforcement, and high-traffic performance tuning.

> **This is a web application.** `index.html` is served by Nginx, and the ASP.NET Core backend (port 5080) runs behind Nginx as a reverse proxy.

---

## Architecture Overview

```
Browser ──HTTPS──► Nginx :443
                       ├── /          → /var/www/nd-finance/index.html  (static)
                       └── /api/*     → http://127.0.0.1:5080           (proxy)
```

## Local development

Open the trusted VS Code workspace to start its `Run ND Finance Web` task automatically, or double-click `start-nd-finance.bat`; both start the backend and serve the website at `http://localhost:5080/`. Opening `index.html` as a local file waits for the backend and redirects when it is ready, but the HTML file cannot start the database server. The site runs in any modern browser; npm packages are not required. Live Server is optional: start the backend first, then use **Go Live** and open its loopback URL, usually `http://127.0.0.1:5500/`; development CORS permits loopback origins. For isolated tests, set `NDF_DATA_DIR` to a temporary directory; otherwise the database remains in the normal per-user application-data directory.

## Go-live blockers to resolve

- This is not a static-only application. Login, registration, loan records, and backups require the ASP.NET Core API and its persistent SQLite database. Google Sites or static hosting alone cannot run the complete app.
- The current backend stores SQLite under the operating system's local application-data directory. Do not deploy it on an ephemeral filesystem; use a persistent, access-controlled disk and verified backups. The SQLite database is not application-encrypted, so protect it with host/disk encryption and restrictive service-account/OS permissions.
- Replace every `example.com` value and certificate path in `nginx.conf` with the real domain and issued certificate paths before enabling the Nginx site. The checked-in file is a template, not a deployable configuration.
- The deployment must supply the owner bootstrap credentials, stable `NDF_AUTH_PEPPER`, and SMTP settings through a secret manager/environment configuration. Never commit real values to the repository.

---

## 1. Nginx Configuration Summary

The configuration is located in [nginx.conf](file:///c:/Users/asus/ND-Finance/nginx.conf).

### Port 80 (HTTP Redirect to HTTPS)
```nginx
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;

    return 301 https://example.com$request_uri;
}
```

### Port 443 (HTTPS + TLS + HSTS)
```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # Let's Encrypt TLS Certificates
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    # Strong protocols & ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HTTP Strict Transport Security (HSTS)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests" always;
    add_header X-XSS-Protection "0" always;

    # High-traffic session cache (never disable HTTPS during surges)
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Keepalive & connection scaling
    keepalive_timeout 75s;
    keepalive_requests 10000;

    # Root & static files
    root /var/www/nd-finance;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy to ASP.NET Core backend
    location /api/ {
        proxy_pass http://127.0.0.1:5080/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection keep-alive;
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 2. Generating Free TLS Certificates with Let's Encrypt (Certbot)

To issue production certificates for your domain:

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install certbot python3-certbot-nginx -y

# Obtain certificate automatically configuring Nginx
sudo certbot --nginx -d example.com -d www.example.com
```

Certbot automatically schedules auto-renewal via cron / systemd timers. You can test renewal with:
```bash
sudo certbot renew --dry-run
```

---

## 3. Why HTTPS Should NOT Be Disabled During High Traffic

1. **HSTS Lock-in**: Once a browser receives `Strict-Transport-Security`, it refuses to communicate over insecure HTTP for `31536000` seconds (1 year). If you disable HTTPS during high traffic, users will see blocking browser security warnings (`SSL_ERROR_RX_RECORD_TOO_LONG` or `NET::ERR_SSL_PROTOCOL_ERROR`) instead of your site.
2. **Data & Credential Exposure**: Disabling HTTPS exposes session tokens, passwords, customer loans, and financial data in plaintext over public networks.
3. **Negligible Overhead**: With modern CPUs and hardware AES-NI encryption, TLS consumes less than 1% of CPU resources.
4. **Session Resumption & HTTP/2**:
   - `ssl_session_cache shared:SSL:50m` enables resumption of TLS sessions without repeating expensive cryptographic handshakes.
   - HTTP/2 multiplexes hundreds of requests over a single TLS connection, eliminating repeated connection overhead under heavy load.

---

## 4. Required Environment Variables

Set these before starting the backend in production (`ASPNETCORE_ENVIRONMENT=Production`):

| Variable | Purpose | Example |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | Must be `Production` to activate HSTS & HTTPS redirect | `Production` |
| `ND_BACKEND_URL` | Backend bind address | `http://127.0.0.1:5080` |
| `ND_HTML_PATH` | Absolute path to `index.html` | `/var/www/nd-finance/index.html` |
| `NDF_AUTH_PEPPER` | Base64-encoded random secret ≥ 32 bytes (OTP & MFA encryption) | `openssl rand -base64 48` |
| `NDF_SMTP_HOST` | SMTP relay hostname | `smtp.your-provider.com` |
| `NDF_SMTP_PORT` | SMTP port (default: 587) | `587` |
| `NDF_SMTP_FROM` | Sender address for emails | `noreply@your-domain.com` |
| `NDF_SMTP_USERNAME` | SMTP auth username | *(optional)* |
| `NDF_SMTP_PASSWORD` | SMTP auth password | *(optional)* |
| `NDF_ADMIN_USERNAME` | Owner bootstrap username (first run only) | `admin` |
| `NDF_ADMIN_PASSWORD` | Owner bootstrap password (first run only, ≥12 chars) | strong password |
| `NDF_ADMIN_EMAIL` | Owner bootstrap email (first run only) | `admin@your-domain.com` |

**Generate pepper:**
```bash
openssl rand -base64 48
```

---

## 5. Security Features Summary

| Feature | Implementation |
|---|---|
| Password hashing | PBKDF2-SHA256, 600,000 iterations, 16-byte salt |
| Session tokens | 256-bit random, SHA-256 hashed in DB |
| Session cookie | `HttpOnly`, `Secure`, `SameSite=Strict`, 8-hour lifetime |
| TOTP (MFA) | RFC 6238, ±1 window, AES-GCM encrypted secret at rest |
| OTP codes | 6-digit HMAC-SHA256, 10-min expiry, 5-attempt limit |
| Account lockout | 15-minute lockout after 5 failed login attempts |
| Rate limiting | 12 auth requests per IP per 10 minutes |
| CSRF protection | `SameSite=Strict` + Origin/Referer/X-Requested-With check |
| Authorization | Loan data server-side filtered per user; IDOR prevented |
| Input validation | Server-side regex, length, email, mobile format checks |
| XSS prevention | `escapeHtml()` everywhere; `sanitizeImageSrc()` for images |
| HSTS | `max-age=31536000; includeSubDomains` via Nginx + ASP.NET Core |
| CSP | Restricts scripts to `self` + `cdn.jsdelivr.net`; `frame-ancestors 'none'` |
