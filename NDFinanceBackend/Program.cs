using System.Net;
using System.Net.Mail;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;

var appDataDirectory = Environment.GetEnvironmentVariable("NDF_DATA_DIR");
if (string.IsNullOrWhiteSpace(appDataDirectory))
{
    appDataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ND Finance");
}
appDataDirectory = Path.GetFullPath(appDataDirectory);
Directory.CreateDirectory(appDataDirectory);
var databasePath = Path.Combine(appDataDirectory, "ndfinance.db");
var connectionString = $"Data Source={databasePath};Cache=Shared";
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 12,
                Window = TimeSpan.FromMinutes(10),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});
builder.Services.AddCors(options =>
{
    options.AddPolicy("LocalDevelopment", policy =>
        policy.SetIsOriginAllowed(origin =>
            Uri.TryCreate(origin, UriKind.Absolute, out var parsedOrigin) &&
            parsedOrigin.Scheme == Uri.UriSchemeHttp &&
        parsedOrigin.IsLoopback)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials());
});

builder.Services.AddHsts(options =>
{
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownProxies.Clear();
    options.KnownNetworks.Clear();
    options.KnownProxies.Add(IPAddress.Loopback);
    options.KnownProxies.Add(IPAddress.IPv6Loopback);
    options.ForwardLimit = 1;
});
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("ND_BACKEND_URL") ?? "http://localhost:5080");
var app = builder.Build();
var isProduction = !app.Environment.IsDevelopment();
app.UseForwardedHeaders();
if (app.Environment.IsDevelopment())
    app.UseCors("LocalDevelopment");
// HTTPS enforcement removed for development/testing
// if (isProduction)
// {
//     app.UseHsts();
//     app.UseHttpsRedirection();
// }
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    var contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    if (!app.Environment.IsDevelopment())
        contentSecurityPolicy += "; upgrade-insecure-requests";

    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append("Content-Security-Policy", contentSecurityPolicy);
    context.Response.Headers["Cache-Control"] = "no-store";

    var originHeader = context.Request.Headers["Origin"].ToString();
    if (context.Request.Path.StartsWithSegments("/api") &&
        context.Request.Method is not ("GET" or "HEAD" or "OPTIONS"))
    {
        var refererHeader = context.Request.Headers["Referer"].ToString();
        var requestedWith = context.Request.Headers["X-Requested-With"].ToString();
        var host = context.Request.Host.Value;

        bool IsAllowedOrigin(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var parsedOrigin)) return false;
            if (string.Equals(parsedOrigin.Authority, host, StringComparison.OrdinalIgnoreCase)) return true;
            return app.Environment.IsDevelopment() &&
                   parsedOrigin.Scheme == Uri.UriSchemeHttp &&
                   parsedOrigin.IsLoopback &&
                   IsLoopbackHost(context.Request.Host.Host);
        }

        bool IsLoopbackHost(string hostname)
        {
            return string.Equals(hostname, "localhost", StringComparison.OrdinalIgnoreCase) ||
                   (IPAddress.TryParse(hostname, out var address) && IPAddress.IsLoopback(address));
        }

        if (!string.IsNullOrEmpty(originHeader))
        {
            if (!IsAllowedOrigin(originHeader))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        }
        else if (!string.IsNullOrEmpty(refererHeader))
        {
            if (!IsAllowedOrigin(refererHeader))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        }
        else if (!string.Equals(requestedWith, "XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
    }

    await next();
});

await using (var connection = new SqliteConnection(connectionString))
{
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS storage (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_users (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_owner INTEGER NOT NULL DEFAULT 0,
            email_verified INTEGER NOT NULL DEFAULT 0,
            profile_json TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            mfa_secret TEXT,
            pending_mfa_secret TEXT,
            created_at TEXT NOT NULL,
            stored_password TEXT
        );
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(username);
        CREATE TABLE IF NOT EXISTS auth_codes (
            email TEXT NOT NULL COLLATE NOCASE,
            purpose TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            sent_at TEXT NOT NULL,
            PRIMARY KEY(email, purpose)
        );
        CREATE TABLE IF NOT EXISTS mfa_challenges (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0
        );
        """;
    await command.ExecuteNonQueryAsync();

    try
    {
        await using var alterCmd = connection.CreateCommand();
        alterCmd.CommandText = "ALTER TABLE auth_users ADD COLUMN stored_password TEXT;";
        await alterCmd.ExecuteNonQueryAsync();
    }
    catch (SqliteException) { }
}

await MigrateLegacyUsersAsync(connectionString);
await BootstrapOwnerAsync(connectionString, app.Logger);
if (!AuthSecurity.IsPepperConfigured)
    app.Logger.LogWarning("NDF_AUTH_PEPPER is missing or invalid; email codes and authenticator MFA will fail closed.");

var defaultHtmlPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "index.html"));
var htmlPath = Environment.GetEnvironmentVariable("ND_HTML_PATH") ?? defaultHtmlPath;
app.MapGet("/api/health", async (CancellationToken cancellationToken) =>
{
    try
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1";
        await command.ExecuteScalarAsync(cancellationToken);
        return Results.Ok(new { status = "ok", database = "connected" });
    }
    catch (SqliteException exception)
    {
        app.Logger.LogError(exception, "Database health check failed.");
        return Results.Json(new { status = "unavailable", database = "unavailable" },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapGet("/", () =>
    File.Exists(htmlPath)
        ? Results.File(htmlPath, "text/html")
        : Results.NotFound("ND.HTML was not found. Set ND_HTML_PATH to its full path."));

app.MapGet("/api/auth/bootstrap/status", async (HttpContext context) =>
{
    if (!IsLocalBootstrapRequest(context)) return Results.NotFound();
    return Results.Ok(new { available = !await OwnerExistsAsync(connectionString) });
});

app.MapPost("/api/auth/bootstrap", async (RegisterRequest body, HttpContext context) =>
{
    if (!IsLocalBootstrapRequest(context)) return Results.NotFound();

    var username = body.Username?.Trim() ?? "";
    var email = NormalizeEmail(body.Email);
    if (username.Length is < 3 or > 40 || !username.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.'))
        return Results.BadRequest(new { error = "Username must be 3-40 letters, numbers, dots, underscores, or dashes." });
    if (!IsValidEmail(email)) return Results.BadRequest(new { error = "Enter a valid email address." });
    if (body.Password is null || body.Password.Length < 12 || body.Password.Length > 256)
        return Results.BadRequest(new { error = "Use a password between 12 and 256 characters." });
    if (string.IsNullOrWhiteSpace(body.ShopName) || string.IsNullOrWhiteSpace(body.OwnerName) ||
        string.IsNullOrWhiteSpace(body.City) || string.IsNullOrWhiteSpace(body.Mobile))
        return Results.BadRequest(new { error = "Complete all required profile fields." });
    if (!System.Text.RegularExpressions.Regex.IsMatch(body.Mobile, @"^\d{10}$"))
        return Results.BadRequest(new { error = "Mobile number must be exactly 10 digits." });

    var profile = new UserProfile(username, body.ShopName.Trim(), body.OwnerName.Trim(),
        body.ShopLogo ?? "", body.Mobile.Trim(), email, body.City.Trim(), true, "Owner", null);
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    try
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO auth_users (username, email, password_hash, is_owner, email_verified, profile_json, created_at)
            SELECT $username, $email, $hash, 1, 1, $profile, $created
            WHERE NOT EXISTS (SELECT 1 FROM auth_users WHERE is_owner = 1);
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$hash", AuthSecurity.HashPassword(body.Password));
        command.Parameters.AddWithValue("$profile", JsonSerializer.Serialize(profile));
        command.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
        if (await command.ExecuteNonQueryAsync() != 1)
            return Results.Conflict(new { error = "The owner account has already been created." });
        await IssueSessionAsync(connectionString, context, username, isProduction);
        return Results.Ok(new { ok = true });
    }
    catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
    {
        return Results.Conflict(new { error = "That username or email is already registered." });
    }
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/register", async (RegisterRequest body, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    if (!actor.IsOwner) return Results.Forbid();

    var username = body.Username?.Trim() ?? "";
    var email = NormalizeEmail(body.Email);
    if (username.Length is < 3 or > 40 || !username.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.'))
        return Results.BadRequest(new { error = "Username must be 3-40 letters, numbers, dots, underscores, or dashes." });
    if (!IsValidEmail(email)) return Results.BadRequest(new { error = "Enter a valid email address." });
    if (body.Password is null || body.Password.Length < 12 || body.Password.Length > 256)
        return Results.BadRequest(new { error = "Use a password between 12 and 256 characters." });
    if (string.IsNullOrWhiteSpace(body.ShopName) || string.IsNullOrWhiteSpace(body.OwnerName) ||
        string.IsNullOrWhiteSpace(body.City) || string.IsNullOrWhiteSpace(body.Mobile))
        return Results.BadRequest(new { error = "Complete all required profile fields." });
    if (!System.Text.RegularExpressions.Regex.IsMatch(body.Mobile, @"^\d{10}$"))
        return Results.BadRequest(new { error = "Mobile number must be exactly 10 digits." });
    var membershipPlan = GetMembershipPlan(body.Membership);
    if (membershipPlan is null)
        return Results.BadRequest(new { error = "Choose a valid client membership." });
    var profile = new UserProfile(username, body.ShopName.Trim(), body.OwnerName.Trim(),
        body.ShopLogo ?? "", body.Mobile.Trim(), email, body.City.Trim(), false,
        membershipPlan.Name, membershipPlan.MaxPrincipal);
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    try
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO auth_users (username, email, password_hash, is_owner, email_verified, profile_json, created_at)
            VALUES ($username, $email, $hash, 0, 1, $profile, $created);
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$hash", AuthSecurity.HashPassword(body.Password));
        command.Parameters.AddWithValue("$profile", JsonSerializer.Serialize(profile));
        command.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
        return Results.Ok(new { ok = true });
    }
    catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
    {
        return Results.Conflict(new { error = "That username or email is already registered." });
    }
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/login", async (LoginRequest body, HttpContext context) =>
{
    var username = body.Username?.Trim() ?? "";
    var record = await FindUserAsync(connectionString, username);
    if (record is null)
    {
        AuthSecurity.VerifyPassword(body.Password ?? "", AuthSecurity.DummyPasswordHash, out _);
        return Results.Json(new { error = "Invalid username or password." }, statusCode: StatusCodes.Status401Unauthorized);
    }
    if (record.LockedUntil is not null && DateTimeOffset.TryParse(record.LockedUntil, out var lockedUntil) && lockedUntil > DateTimeOffset.UtcNow)
        return Results.Json(new { error = "Too many failed attempts. Try again later." }, statusCode: StatusCodes.Status423Locked);
    if (!AuthSecurity.VerifyPassword(body.Password ?? "", record.PasswordHash, out var needsUpgrade))
    {
        await RecordLoginFailureAsync(connectionString, username);
        return Results.Json(new { error = "Invalid username or password." }, statusCode: StatusCodes.Status401Unauthorized);
    }
    if (record.MfaSecret is not null)
    {
        var challenge = AuthSecurity.RandomToken(32);
        await CreateMfaChallengeAsync(connectionString, challenge, record.Username);
        return Results.Ok(new { mfaRequired = true, challengeId = challenge });
    }
    if (needsUpgrade) await UpdatePasswordHashAsync(connectionString, record.Username, AuthSecurity.HashPassword(body.Password!));
    await ClearLoginFailuresAsync(connectionString, record.Username);
    await IssueSessionAsync(connectionString, context, record.Username, isProduction);
    return Results.Ok(new { user = record.Profile });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/login/mfa", async (MfaLoginRequest body, HttpContext context) =>
{
    if (string.IsNullOrWhiteSpace(body.ChallengeId) || string.IsNullOrWhiteSpace(body.Code))
        return Results.BadRequest(new { error = "Enter the authenticator code." });
    var record = await GetMfaChallengeAsync(connectionString, body.ChallengeId);
    if (record is null || record.User.MfaSecret is null)
        return Results.Json(new { error = "Invalid or expired authenticator challenge." }, statusCode: StatusCodes.Status401Unauthorized);
    if (!AuthSecurity.VerifyTotp(record.User.MfaSecret, body.Code))
    {
        await RecordMfaFailureAsync(connectionString, body.ChallengeId);
        return Results.Json(new { error = "Invalid or expired authenticator code." }, statusCode: StatusCodes.Status401Unauthorized);
    }
    await DeleteMfaChallengeAsync(connectionString, body.ChallengeId);
    await ClearLoginFailuresAsync(connectionString, record.User.Username);
    await IssueSessionAsync(connectionString, context, record.User.Username, isProduction);
    return Results.Ok(new { user = record.User.Profile });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/password/reset/request", async (ResetRequest body, ILogger<Program> logger) =>
{
    if (!AuthSecurity.IsSmtpConfigured || !AuthSecurity.IsPepperConfigured)
        return Results.Problem("Email delivery or authentication secret is not configured. Contact the site administrator.", statusCode: StatusCodes.Status503ServiceUnavailable);
    var identifier = body.UsernameOrEmail?.Trim() ?? "";
    var record = await FindUserAsync(connectionString, identifier);
    if (record is not null &&
        !await SendCodeAsync(connectionString, record.Email, "password-reset", "ND Finance password reset"))
        logger.LogWarning("Password reset email dispatch did not complete.");
    return Results.Ok(new { message = "If the account exists, a password reset code has been sent to its verified email." });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/password/reset", async (ResetPasswordRequest body) =>
{
    if (body.NewPassword is null || body.NewPassword.Length < 12 || body.NewPassword.Length > 256)
        return Results.BadRequest(new { error = "Use a password between 12 and 256 characters." });
    var record = await FindUserAsync(connectionString, body.UsernameOrEmail?.Trim() ?? "");
    if (record is null || !await VerifyCodeAsync(connectionString, record.Email, "password-reset", body.Code ?? "", consume: true))
        return Results.BadRequest(new { error = "Invalid or expired reset code." });
    await UpdatePasswordHashAsync(connectionString, record.Username, AuthSecurity.HashPassword(body.NewPassword));
    await RevokeSessionsAsync(connectionString, record.Username);
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/password/reset-local", async (LocalPasswordResetRequest body, HttpContext context) =>
{
    if (!IsLocalBootstrapRequest(context)) return Results.NotFound();
    if (body.NewPassword is null || body.NewPassword.Length < 12 || body.NewPassword.Length > 256)
        return Results.BadRequest(new { error = "Use a password between 12 and 256 characters." });
    var record = await FindUserAsync(connectionString, body.UsernameOrEmail?.Trim() ?? "");
    if (record is null || !record.IsOwner)
        return Results.BadRequest(new { error = "Owner account not found." });

    await UpdatePasswordHashAsync(connectionString, record.Username, AuthSecurity.HashPassword(body.NewPassword));
    await RevokeSessionsAsync(connectionString, record.Username);
    await IssueSessionAsync(connectionString, context, record.Username, isProduction);
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("auth");

app.MapGet("/api/auth/me", async (HttpContext context) =>
{
    var user = await GetSessionUserAsync(connectionString, context);
    return user is null ? Results.Unauthorized() : Results.Ok(new
    {
        user = user.Profile,
        mfaEnabled = user.MfaSecret is not null,
        expiresAt = user.ExpiresAt
    });
});

app.MapGet("/api/auth/users", async (HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    if (!actor.IsOwner) return Results.Ok(new[] { actor.Profile });
    var users = await GetAllUserDetailsAsync(connectionString);
    return Results.Ok(users);
});

app.MapDelete("/api/auth/users/{username}", async (string username, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    if (!actor.IsOwner) return Results.Forbid();

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    using var transaction = connection.BeginTransaction();

    await using var lookup = connection.CreateCommand();
    lookup.Transaction = transaction;
    lookup.CommandText = "SELECT username, email FROM auth_users WHERE username = $username COLLATE NOCASE AND is_owner = 0";
    lookup.Parameters.AddWithValue("$username", username);
    string? targetUsername = null;
    string? targetEmail = null;
    await using (var reader = await lookup.ExecuteReaderAsync())
    {
        if (await reader.ReadAsync())
        {
            targetUsername = reader.GetString(0);
            targetEmail = reader.GetString(1);
        }
    }
    if (targetUsername is null || targetEmail is null) return Results.NotFound(new { error = "Client account not found." });

    await using var storageLookup = connection.CreateCommand();
    storageLookup.Transaction = transaction;
    storageLookup.CommandText = "SELECT value FROM storage WHERE key = 'ndf_loans'";
    var storedLoans = await storageLookup.ExecuteScalarAsync() as string;
    var loans = storedLoans is null ? new JsonArray() : JsonNode.Parse(storedLoans) as JsonArray;
    if (loans is null)
        return Results.Problem("Stored loan data is invalid; the account was not deleted.", statusCode: StatusCodes.Status500InternalServerError);

    var remainingLoans = new JsonArray();
    foreach (var loan in loans)
    {
        if (!BelongsTo(loan, targetUsername))
            remainingLoans.Add(loan?.DeepClone());
    }

    await using var deleteUser = connection.CreateCommand();
    deleteUser.Transaction = transaction;
    deleteUser.CommandText = "DELETE FROM auth_users WHERE username = $username COLLATE NOCASE AND is_owner = 0";
    deleteUser.Parameters.AddWithValue("$username", targetUsername);
    if (await deleteUser.ExecuteNonQueryAsync() != 1)
        return Results.NotFound(new { error = "Client account not found." });

    await using var cleanup = connection.CreateCommand();
    cleanup.Transaction = transaction;
    cleanup.CommandText = """
        DELETE FROM auth_sessions WHERE username = $username COLLATE NOCASE;
        DELETE FROM mfa_challenges WHERE username = $username COLLATE NOCASE;
        DELETE FROM auth_codes WHERE email = $email COLLATE NOCASE;
        """;
    cleanup.Parameters.AddWithValue("$username", targetUsername);
    cleanup.Parameters.AddWithValue("$email", targetEmail);
    await cleanup.ExecuteNonQueryAsync();

    await using var saveLoans = connection.CreateCommand();
    saveLoans.Transaction = transaction;
    saveLoans.CommandText = """
        INSERT INTO storage (key, value, updated_at) VALUES ('ndf_loans', $value, $updatedAt)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """;
    saveLoans.Parameters.AddWithValue("$value", remainingLoans.ToJsonString());
    saveLoans.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
    await saveLoans.ExecuteNonQueryAsync();

    transaction.Commit();
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/loans/next-id", async (HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    var reserved = await ReserveLoanIdAsync(connectionString);
    return Results.Ok(reserved);
});

app.MapPut("/api/auth/profile", async (ProfileRequest body, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    var profile = actor.Profile with
    {
        ShopName = body.ShopName?.Trim() ?? actor.Profile.ShopName,
        OwnerName = body.OwnerName?.Trim() ?? actor.Profile.OwnerName,
        ShopLogo = body.ShopLogo ?? actor.Profile.ShopLogo,
        Mobile = body.Mobile?.Trim() ?? actor.Profile.Mobile,
        City = body.City?.Trim() ?? actor.Profile.City
    };
    await SaveProfileAsync(connectionString, actor.Username, profile);
    if (actor.IsOwner)
    {
        await SetStorageValueAsync(connectionString, "ndf_shop", JsonSerializer.Serialize(new
        {
            name = profile.ShopName,
            ownerName = profile.OwnerName,
            mobile = profile.Mobile,
            email = profile.Email,
            city = profile.City,
            logo = profile.ShopLogo
        }));
    }
    return Results.Ok(new { user = profile });
});

app.MapPost("/api/auth/password/change", async (ChangePasswordRequest body, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    var record = await FindUserAsync(connectionString, actor.Username);
    if (record is null || !AuthSecurity.VerifyPassword(body.CurrentPassword ?? "", record.PasswordHash, out _))
        return Results.BadRequest(new { error = "Current password is incorrect." });
    if (body.NewPassword is null || body.NewPassword.Length < 12 || body.NewPassword.Length > 256)
        return Results.BadRequest(new { error = "Use a password between 12 and 256 characters." });
    await UpdatePasswordHashAsync(connectionString, actor.Username, AuthSecurity.HashPassword(body.NewPassword));
    await RevokeSessionsAsync(connectionString, actor.Username);
    await IssueSessionAsync(connectionString, context, actor.Username, isProduction);
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/auth/mfa/setup", async (HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    if (!AuthSecurity.IsPepperConfigured)
        return Results.Problem("Authenticator MFA is unavailable until NDF_AUTH_PEPPER is configured.", statusCode: StatusCodes.Status503ServiceUnavailable);
    var secret = AuthSecurity.GenerateTotpSecret();
    await SetPendingMfaAsync(connectionString, actor.Username, secret);
    var label = Uri.EscapeDataString($"ND Finance:{actor.Email}");
    var issuer = Uri.EscapeDataString("ND Finance");
    return Results.Ok(new { secret, otpauthUri = $"otpauth://totp/{label}?secret={secret}&issuer={issuer}" });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/mfa/enable", async (MfaEnableRequest body, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    var secret = await GetPendingMfaAsync(connectionString, actor.Username);
    if (secret is null || !AuthSecurity.VerifyTotp(secret, body.Code ?? ""))
        return Results.BadRequest(new { error = "The authenticator code is invalid or setup has expired." });
    await EnableMfaAsync(connectionString, actor.Username, secret);
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/mfa/disable", async (MfaDisableRequest body, HttpContext context) =>
{
    var actor = await GetSessionUserAsync(connectionString, context);
    if (actor is null) return Results.Unauthorized();
    var record = await FindUserAsync(connectionString, actor.Username);
    if (record?.MfaSecret is null || !AuthSecurity.VerifyPassword(body.Password ?? "", record.PasswordHash, out _) ||
        !AuthSecurity.VerifyTotp(record.MfaSecret, body.Code ?? ""))
        return Results.BadRequest(new { error = "Password or authenticator code is incorrect." });
    await DisableMfaAsync(connectionString, actor.Username);
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/logout", async (HttpContext context) =>
{
    var token = context.Request.Cookies[AuthSecurity.CookieName];
    if (!string.IsNullOrEmpty(token))
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM auth_sessions WHERE token_hash = $token";
        command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
        await command.ExecuteNonQueryAsync();
    }
    context.Response.Cookies.Delete(AuthSecurity.CookieName, AuthSecurity.CookieOptions(isProduction));
    return Results.NoContent();
});

app.MapGet("/api/storage/{key}", async (string key, HttpContext context) =>
{
    var user = await GetSessionUserAsync(connectionString, context);
    if (user is null) return Results.Unauthorized();
    if (key == "ndf_users") return Results.NotFound();
    if (key is not ("ndf_loans" or "ndf_counter" or "ndf_shop")) return Results.NotFound();
    if (key == "ndf_shop" && !user.IsOwner) return Results.Forbid();

    var effectiveKey = key;
    var value = await GetStorageValueAsync(connectionString, effectiveKey);
    if (value is null)
        value = key switch
        {
            "ndf_loans" => "[]",
            "ndf_counter" => "1",
            "ndf_shop" => """{"name":"","ownerName":"","mobile":"","email":"","city":"","logo":""}""",
            _ => null
        };
    if (value is null) return Results.NotFound();
    if (key == "ndf_loans" && !user.IsOwner)
    {
        var all = JsonNode.Parse(value) as JsonArray ?? new JsonArray();
        var own = new JsonArray(all.Where(loan => BelongsTo(loan, user.Username)).Select(loan => loan?.DeepClone()).ToArray());
        value = own.ToJsonString();
    }
    return Results.Ok(new { value });
});

app.MapPut("/api/storage/{key}", async (string key, StorageValue body, HttpContext context) =>
{
    var user = await GetSessionUserAsync(connectionString, context);
    if (user is null) return Results.Unauthorized();
    if (key == "ndf_users" || key is not ("ndf_loans" or "ndf_counter" or "ndf_shop")) return Results.NotFound();
    if (key == "ndf_shop" && !user.IsOwner) return Results.Forbid();
    if (key == "ndf_counter" && !user.IsOwner) return Results.Forbid();
    if (string.IsNullOrWhiteSpace(body.Value) || body.Value.Length > 20_000_000)
        return Results.BadRequest(new { error = "A valid storage value is required." });

    var effectiveKey = key;
    string value = body.Value;
    if (key == "ndf_loans")
    {
        if (JsonNode.Parse(value) is not JsonArray submitted) return Results.BadRequest(new { error = "Loans must be an array." });
        var submittedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var loan in submitted)
        {
            if (!user.IsOwner && !BelongsTo(loan, user.Username)) return Results.Forbid();
            var id = (string?)loan?["id"];
            if (string.IsNullOrWhiteSpace(id) || !submittedIds.Add(id))
                return Results.BadRequest(new { error = "Loan IDs must be present and unique." });
        }
        var merge = await MergeUserLoansAsync(connectionString, submitted, user.Username, user.IsOwner);
        if (merge.HasIdConflict) return Results.Conflict(new { error = "A loan ID is already in use by another account." });
        if (merge.HasInvalidAmount) return Results.BadRequest(new { error = "Active loan principal must be a positive amount." });
        if (merge.LimitExceeded)
            return Results.Conflict(new { error = $"This membership allows up to {merge.MaximumPrincipal:N0} in active principal. Current total would be {merge.ActivePrincipal:N0}." });
        return Results.NoContent();
    }
    if (key == "ndf_counter" && (!long.TryParse(value, out var counter) || counter < 1 || counter > 10_000_000_000L))
        return Results.BadRequest(new { error = "Counter value is invalid." });
    await SetStorageValueAsync(connectionString, effectiveKey, value);
    return Results.NoContent();
});

app.MapGet("/api/backup", async (HttpContext context) =>
{
    var user = await GetSessionUserAsync(connectionString, context);
    if (user is null) return Results.Unauthorized();
    if (!user.IsOwner) return Results.Forbid();

    var loans = await GetStorageValueAsync(connectionString, "ndf_loans") ?? "[]";
    var counter = await GetStorageValueAsync(connectionString, "ndf_counter") ?? "1";
    var shop = await GetStorageValueAsync(connectionString, "ndf_shop") ?? "{}";
    return Results.Ok(new
    {
        format = "nd-finance-backup",
        version = 1,
        exportedAt = DateTimeOffset.UtcNow,
        users = await GetAllProfilesAsync(connectionString),
        loans = JsonNode.Parse(loans),
        counter = JsonNode.Parse(counter),
        shop = JsonNode.Parse(shop)
    });
});

app.MapPost("/api/backup", async (BackupData body, HttpContext context) =>
{
    var user = await GetSessionUserAsync(connectionString, context);
    if (user is null) return Results.Unauthorized();
    if (!user.IsOwner) return Results.Forbid();
    if (body.Users.ValueKind != JsonValueKind.Array || body.Loans.ValueKind != JsonValueKind.Array ||
        !body.Counter.TryGetInt32(out var counter) || counter < 1 || body.Shop.ValueKind != JsonValueKind.Object)
        return Results.BadRequest("Backup data is invalid.");

    var values = new Dictionary<string, string>
    {
        ["ndf_loans"] = body.Loans.GetRawText(),
        ["ndf_counter"] = body.Counter.GetRawText(),
        ["ndf_shop"] = body.Shop.GetRawText()
    };
    foreach (var (key, value) in values) await SetStorageValueAsync(connectionString, key, value);
    return Results.NoContent();
});

app.Use(async (context, next) =>
{
    var startedAt = DateTimeOffset.UtcNow;
    try
    {
        await next();
    }
    finally
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            app.Logger.LogInformation("HTTP {Method} {Path} responded {StatusCode} in {ElapsedMilliseconds} ms",
                context.Request.Method, context.Request.Path, context.Response.StatusCode,
                (DateTimeOffset.UtcNow - startedAt).TotalMilliseconds);
        }
    }
});

app.Run();

static bool IsValidEmail(string email) =>
    email.Length <= 254 && System.Text.RegularExpressions.Regex.IsMatch(email, @"^[^\s@]+@[^\s@]+\.[^\s@]+$");

static string NormalizeEmail(string? email) => email?.Trim().ToLowerInvariant() ?? "";

static MembershipPlan? GetMembershipPlan(string? membership) => membership?.Trim().ToLowerInvariant() switch
{
    "silver" => new MembershipPlan("Silver", 5_000_000m),
    "gold" => new MembershipPlan("Gold", 10_000_000m),
    "platinum" => new MembershipPlan("Platinum", 30_000_000m),
    "luxury" => new MembershipPlan("Luxury", null),
    _ => null
};

static UserProfile NormalizeUserProfile(UserProfile profile)
{
    var plan = GetMembershipPlan(profile.Membership) ?? GetMembershipPlan("Silver")!;
    return profile with
    {
        Membership = plan.Name,
        MaxPrincipal = profile.MaxPrincipal ?? plan.MaxPrincipal
    };
}

static bool BelongsTo(JsonNode? loan, string username)
{
    var owner = (string?)loan?["owner"] ?? (string?)loan?["createdBy"];
    return string.Equals(owner, username, StringComparison.OrdinalIgnoreCase);
}

static async Task<bool> SendCodeAsync(string connectionString, string email, string purpose, string subject)
{
    if (!AuthSecurity.IsSmtpConfigured || !AuthSecurity.IsPepperConfigured) return false;
    var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
    await using (var connection = new SqliteConnection(connectionString))
    {
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sent_at FROM auth_codes WHERE email = $email AND purpose = $purpose
            """;
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$purpose", purpose);
        var sentAt = await command.ExecuteScalarAsync();
        if (sentAt is string previous && DateTimeOffset.TryParse(previous, out var previousTime) &&
            previousTime > DateTimeOffset.UtcNow.AddSeconds(-60))
            return false;

        command.CommandText = """
            INSERT INTO auth_codes (email, purpose, code_hash, expires_at, attempts, verified, sent_at)
            VALUES ($email, $purpose, $hash, $expires, 0, 0, $sent)
            ON CONFLICT(email, purpose) DO UPDATE SET
                code_hash = excluded.code_hash, expires_at = excluded.expires_at,
                attempts = 0, verified = 0, sent_at = excluded.sent_at
            """;
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$purpose", purpose);
        command.Parameters.AddWithValue("$hash", AuthSecurity.HashCode(email, purpose, code));
        command.Parameters.AddWithValue("$expires", DateTimeOffset.UtcNow.AddMinutes(10).ToString("O"));
        command.Parameters.AddWithValue("$sent", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
    }
    try
    {
        await SendEmailAsync(email, subject, $"Your ND Finance code is {code}. It expires in 10 minutes. Do not share this code.");
        return true;
    }
    catch (SmtpException)
    {
        return false;
    }
}

static async Task SendEmailAsync(string to, string subject, string body)
{
    var host = Environment.GetEnvironmentVariable("NDF_SMTP_HOST")!;
    var port = int.TryParse(Environment.GetEnvironmentVariable("NDF_SMTP_PORT"), out var configuredPort) ? configuredPort : 587;
    var from = Environment.GetEnvironmentVariable("NDF_SMTP_FROM")!;
    using var message = new MailMessage(from, to, subject, body);
    using var client = new SmtpClient(host, port)
    {
        EnableSsl = true,
        DeliveryMethod = SmtpDeliveryMethod.Network,
        Timeout = 15000
    };
    var username = Environment.GetEnvironmentVariable("NDF_SMTP_USERNAME");
    var password = Environment.GetEnvironmentVariable("NDF_SMTP_PASSWORD");
    if (!string.IsNullOrWhiteSpace(username)) client.Credentials = new NetworkCredential(username, password);
    await client.SendMailAsync(message);
}

static async Task<bool> VerifyCodeAsync(string connectionString, string email, string purpose, string code,
    bool consume, bool requireVerified = false)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    using var transaction = connection.BeginTransaction();
    await using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = "SELECT code_hash, expires_at, attempts, verified FROM auth_codes WHERE email = $email AND purpose = $purpose";
    command.Parameters.AddWithValue("$email", email);
    command.Parameters.AddWithValue("$purpose", purpose);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return false;
    var hash = reader.GetString(0);
    var expires = DateTimeOffset.Parse(reader.GetString(1));
    var attempts = reader.GetInt32(2);
    var verified = reader.GetInt32(3) == 1;
    await reader.CloseAsync();
    if (expires <= DateTimeOffset.UtcNow || attempts >= 5) return false;
    if (requireVerified) return verified;
    if (code.Length != 6 || !code.All(char.IsAsciiDigit) ||
        !AuthSecurity.FixedTimeEquals(hash, AuthSecurity.HashCode(email, purpose, code)))
    {
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE auth_codes SET attempts = attempts + 1 WHERE email = $email AND purpose = $purpose";
        update.Parameters.AddWithValue("$email", email);
        update.Parameters.AddWithValue("$purpose", purpose);
        await update.ExecuteNonQueryAsync();
        transaction.Commit();
        return false;
    }
    if (consume)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM auth_codes WHERE email = $email AND purpose = $purpose";
        delete.Parameters.AddWithValue("$email", email);
        delete.Parameters.AddWithValue("$purpose", purpose);
        await delete.ExecuteNonQueryAsync();
    }
    else
    {
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE auth_codes SET verified = 1 WHERE email = $email AND purpose = $purpose";
        update.Parameters.AddWithValue("$email", email);
        update.Parameters.AddWithValue("$purpose", purpose);
        await update.ExecuteNonQueryAsync();
    }
    transaction.Commit();
    return true;
}

static bool IsLocalBootstrapRequest(HttpContext context)
{
    var remoteAddress = context.Connection.RemoteIpAddress;
    var host = context.Request.Host.Host;
    return remoteAddress is not null && IPAddress.IsLoopback(remoteAddress) &&
        (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
         IPAddress.TryParse(host, out var hostAddress) && IPAddress.IsLoopback(hostAddress));
}

static async Task<bool> OwnerExistsAsync(string connectionString)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT EXISTS (SELECT 1 FROM auth_users WHERE is_owner = 1)";
    return Convert.ToInt32(await command.ExecuteScalarAsync()) == 1;
}

static async Task<UserRecord?> FindUserAsync(string connectionString, string usernameOrEmail)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
         SELECT username, email, password_hash, is_owner, email_verified, profile_json,
             failed_attempts, locked_until, mfa_secret
        FROM auth_users WHERE username = $identifier COLLATE NOCASE OR email = $identifier COLLATE NOCASE
        """;
    command.Parameters.AddWithValue("$identifier", usernameOrEmail);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return null;
    var profile = NormalizeUserProfile(JsonSerializer.Deserialize<UserProfile>(reader.GetString(5))!);
    return new UserRecord(reader.GetString(0), reader.GetString(1), reader.GetString(2),
        reader.GetInt32(3) == 1, reader.GetInt32(4) == 1, profile, reader.GetInt32(6),
        reader.IsDBNull(7) ? null : reader.GetString(7),
        reader.IsDBNull(8) ? null : AuthSecurity.UnprotectSecret(reader.GetString(8)));
}

static async Task<SessionUser?> GetSessionUserAsync(string connectionString, HttpContext context)
{
    var token = context.Request.Cookies[AuthSecurity.CookieName];
    if (string.IsNullOrEmpty(token)) return null;
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        SELECT u.username, u.email, u.is_owner, u.profile_json, u.mfa_secret, s.expires_at
        FROM auth_sessions s JOIN auth_users u ON u.username = s.username
        WHERE s.token_hash = $token AND s.expires_at > $now
        """;
    command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
    command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return null;
    return new SessionUser(reader.GetString(0), reader.GetString(1), reader.GetInt32(2) == 1,
        NormalizeUserProfile(JsonSerializer.Deserialize<UserProfile>(reader.GetString(3))!),
        reader.IsDBNull(4) ? null : AuthSecurity.UnprotectSecret(reader.GetString(4)),
        reader.GetString(5));
}

static async Task IssueSessionAsync(string connectionString, HttpContext context, string username, bool isProduction)
{
    var token = AuthSecurity.RandomToken(32);
    var expires = DateTimeOffset.UtcNow.AddHours(8);
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using (var cleanup = connection.CreateCommand())
    {
        cleanup.CommandText = """
            DELETE FROM auth_sessions WHERE expires_at <= $now;
            DELETE FROM mfa_challenges WHERE expires_at <= $now;
            """;
        cleanup.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        await cleanup.ExecuteNonQueryAsync();
    }
    await using var command = connection.CreateCommand();
    command.CommandText = "INSERT INTO auth_sessions (token_hash, username, expires_at) VALUES ($hash, $username, $expires)";
    command.Parameters.AddWithValue("$hash", AuthSecurity.TokenHash(token));
    command.Parameters.AddWithValue("$username", username);
    command.Parameters.AddWithValue("$expires", expires.ToString("O"));
    await command.ExecuteNonQueryAsync();
    context.Response.Cookies.Append(AuthSecurity.CookieName, token, AuthSecurity.CookieOptions(isProduction, expires));
}

static async Task CreateMfaChallengeAsync(string connectionString, string token, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "INSERT INTO mfa_challenges (token_hash, username, expires_at) VALUES ($token, $username, $expires)";
    command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
    command.Parameters.AddWithValue("$username", username);
    command.Parameters.AddWithValue("$expires", DateTimeOffset.UtcNow.AddMinutes(5).ToString("O"));
    await command.ExecuteNonQueryAsync();
}

static async Task SetPendingMfaAsync(string connectionString, string username, string secret)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "UPDATE auth_users SET pending_mfa_secret = $secret WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$secret", AuthSecurity.ProtectSecret(secret));
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task<string?> GetPendingMfaAsync(string connectionString, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT pending_mfa_secret FROM auth_users WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$username", username);
    var stored = await command.ExecuteScalarAsync() as string;
    return stored is null ? null : AuthSecurity.UnprotectSecret(stored);
}

static async Task EnableMfaAsync(string connectionString, string username, string secret)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        UPDATE auth_users SET mfa_secret = $secret, pending_mfa_secret = NULL
        WHERE username = $username COLLATE NOCASE
        """;
    command.Parameters.AddWithValue("$secret", AuthSecurity.ProtectSecret(secret));
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task DisableMfaAsync(string connectionString, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        UPDATE auth_users SET mfa_secret = NULL, pending_mfa_secret = NULL
        WHERE username = $username COLLATE NOCASE
        """;
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task<MfaChallenge?> GetMfaChallengeAsync(string connectionString, string token)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        SELECT username, attempts FROM mfa_challenges
        WHERE token_hash = $token AND expires_at > $now
        """;
    command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
    command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync() || reader.GetInt32(1) >= 5) return null;
    var username = reader.GetString(0);
    await reader.CloseAsync();
    var user = await FindUserAsync(connectionString, username);
    return user is null ? null : new MfaChallenge(user);
}

static async Task RecordMfaFailureAsync(string connectionString, string token)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = $token";
    command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
    await command.ExecuteNonQueryAsync();
}

static async Task DeleteMfaChallengeAsync(string connectionString, string token)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "DELETE FROM mfa_challenges WHERE token_hash = $token";
    command.Parameters.AddWithValue("$token", AuthSecurity.TokenHash(token));
    await command.ExecuteNonQueryAsync();
}

static async Task RecordLoginFailureAsync(string connectionString, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        UPDATE auth_users
        SET locked_until = CASE WHEN failed_attempts + 1 >= 5 THEN $locked ELSE locked_until END,
            failed_attempts = CASE WHEN failed_attempts + 1 >= 5 THEN 0 ELSE failed_attempts + 1 END
        WHERE username = $username COLLATE NOCASE
        """;
    command.Parameters.AddWithValue("$locked", DateTimeOffset.UtcNow.AddMinutes(15).ToString("O"));
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task ClearLoginFailuresAsync(string connectionString, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "UPDATE auth_users SET failed_attempts = 0, locked_until = NULL WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task UpdatePasswordHashAsync(string connectionString, string username, string hash)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "UPDATE auth_users SET password_hash = $hash, failed_attempts = 0, locked_until = NULL WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$hash", hash);
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task RevokeSessionsAsync(string connectionString, string username)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "DELETE FROM auth_sessions WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task<List<UserProfile>> GetAllProfilesAsync(string connectionString)
{
    var result = new List<UserProfile>();
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT profile_json FROM auth_users ORDER BY username";
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
        result.Add(NormalizeUserProfile(JsonSerializer.Deserialize<UserProfile>(reader.GetString(0))!));
    return result;
}

static async Task<List<object>> GetAllUserDetailsAsync(string connectionString)
{
    var result = new List<object>();
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT profile_json, created_at, email, username, is_owner FROM auth_users ORDER BY created_at DESC";
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        var profile = NormalizeUserProfile(JsonSerializer.Deserialize<UserProfile>(reader.GetString(0))!);
        var createdAt = reader.IsDBNull(1) ? (string?)null : reader.GetString(1);
        var email = reader.IsDBNull(2) ? profile.Email : reader.GetString(2);
        var username = reader.IsDBNull(3) ? profile.Username : reader.GetString(3);
        var isOwner = reader.GetInt32(4) == 1;

        var isNewClient = false;
        if (!isOwner && createdAt is not null && DateTimeOffset.TryParse(createdAt, out var createdDt))
        {
            isNewClient = (DateTimeOffset.UtcNow - createdDt).TotalDays <= 30;
        }

        result.Add(new
        {
            username,
            profile.ShopName,
            profile.OwnerName,
            profile.ShopLogo,
            profile.Mobile,
            email,
            profile.City,
            profile.Membership,
            profile.MaxPrincipal,
            isOwner,
            createdAt,
            isNewClient,
            clientType = isOwner ? "Owner" : (isNewClient ? "New Client" : "Old Client")
        });
    }
    return result;
}

static async Task SaveProfileAsync(string connectionString, string username, UserProfile profile)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "UPDATE auth_users SET profile_json = $profile WHERE username = $username COLLATE NOCASE";
    command.Parameters.AddWithValue("$profile", JsonSerializer.Serialize(profile));
    command.Parameters.AddWithValue("$username", username);
    await command.ExecuteNonQueryAsync();
}

static async Task<string?> GetStorageValueAsync(string connectionString, string key)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = "SELECT value FROM storage WHERE key = $key";
    command.Parameters.AddWithValue("$key", key);
    var value = await command.ExecuteScalarAsync();
    return value as string;
}

static async Task SetStorageValueAsync(string connectionString, string key, string value)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = """
        INSERT INTO storage (key, value, updated_at) VALUES ($key, $value, $updatedAt)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """;
    command.Parameters.AddWithValue("$key", key);
    command.Parameters.AddWithValue("$value", value);
    command.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
    await command.ExecuteNonQueryAsync();
}

static async Task<LoanMergeResult> MergeUserLoansAsync(string connectionString, JsonArray submitted, string username, bool isOwner)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using (var pragma = connection.CreateCommand())
    {
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        await pragma.ExecuteNonQueryAsync();
    }
    using var transaction = connection.BeginTransaction();
    await using var select = connection.CreateCommand();
    select.Transaction = transaction;
    select.CommandText = "SELECT value FROM storage WHERE key = 'ndf_loans'";
    var stored = await select.ExecuteScalarAsync() as string;
    var current = stored is null ? new JsonArray() : JsonNode.Parse(stored) as JsonArray ?? new JsonArray();

    if (!isOwner)
    {
        var existingForeignIds = current
            .Where(loan => !BelongsTo(loan, username))
            .Select(loan => (string?)loan?["id"])
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (submitted.Any(loan => existingForeignIds.Contains((string?)loan?["id"] ?? "")))
            return new LoanMergeResult(true, false, false, 0, null);

        var merged = new JsonArray();
        foreach (var loan in current.Where(loan => !BelongsTo(loan, username)))
            merged.Add(loan?.DeepClone());
        foreach (var loan in submitted)
            merged.Add(loan?.DeepClone());

        await using var profileCommand = connection.CreateCommand();
        profileCommand.Transaction = transaction;
        profileCommand.CommandText = "SELECT profile_json FROM auth_users WHERE username = $username COLLATE NOCASE";
        profileCommand.Parameters.AddWithValue("$username", username);
        var profileJson = await profileCommand.ExecuteScalarAsync() as string;
        var profile = profileJson is null
            ? NormalizeUserProfile(new UserProfile(username, "", "", "", "", "", "", false))
            : NormalizeUserProfile(JsonSerializer.Deserialize<UserProfile>(profileJson)!);

        decimal activePrincipal = 0;
        foreach (var loan in merged.Where(loan => BelongsTo(loan, username) &&
                     string.Equals((string?)loan?["status"], "active", StringComparison.OrdinalIgnoreCase)))
        {
            if (!decimal.TryParse(loan?["amount"]?.ToString(), NumberStyles.Number,
                    CultureInfo.InvariantCulture, out var amount) || amount <= 0)
                return new LoanMergeResult(false, true, false, activePrincipal, profile.MaxPrincipal);
            activePrincipal += amount;
        }
        if (profile.MaxPrincipal is decimal maxPrincipal && activePrincipal > maxPrincipal)
            return new LoanMergeResult(false, false, activePrincipal > maxPrincipal, activePrincipal, maxPrincipal);

        var value = merged.ToJsonString();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            INSERT INTO storage (key, value, updated_at) VALUES ('ndf_loans', $value, $updatedAt)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """;
        update.Parameters.AddWithValue("$value", value);
        update.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
        await update.ExecuteNonQueryAsync();
        transaction.Commit();
        return new LoanMergeResult(false, false, false, activePrincipal, profile.MaxPrincipal);
    }
    else
    {
        var submittedMap = new Dictionary<string, JsonNode?>(StringComparer.OrdinalIgnoreCase);
        foreach (var loan in submitted)
        {
            var id = (string?)loan?["id"];
            if (!string.IsNullOrWhiteSpace(id))
                submittedMap[id] = loan;
        }

        var merged = new JsonArray();
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var loan in current)
        {
            var id = (string?)loan?["id"];
            if (string.IsNullOrWhiteSpace(id)) continue;
            seenIds.Add(id);
            if (submittedMap.TryGetValue(id, out var updatedLoan))
                merged.Add(updatedLoan?.DeepClone());
            else
                merged.Add(loan?.DeepClone());
        }

        foreach (var loan in submitted)
        {
            var id = (string?)loan?["id"];
            if (!string.IsNullOrWhiteSpace(id) && seenIds.Add(id))
                merged.Add(loan?.DeepClone());
        }

        var value = merged.ToJsonString();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            INSERT INTO storage (key, value, updated_at) VALUES ('ndf_loans', $value, $updatedAt)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """;
        update.Parameters.AddWithValue("$value", value);
        update.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
        await update.ExecuteNonQueryAsync();
        transaction.Commit();
        return new LoanMergeResult(false, false, false, 0, null);
    }
}

static async Task<object> ReserveLoanIdAsync(string connectionString)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using (var pragma = connection.CreateCommand())
    {
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        await pragma.ExecuteNonQueryAsync();
    }
    using var transaction = connection.BeginTransaction();

    long counter = 1;
    await using (var counterCommand = connection.CreateCommand())
    {
        counterCommand.Transaction = transaction;
        counterCommand.CommandText = "SELECT value FROM storage WHERE key = 'ndf_counter'";
        if (long.TryParse(await counterCommand.ExecuteScalarAsync() as string, out var storedCounter))
            counter = Math.Clamp(storedCounter, 1L, 10_000_000_000L);
    }

    await using (var loansCommand = connection.CreateCommand())
    {
        loansCommand.Transaction = transaction;
        loansCommand.CommandText = "SELECT value FROM storage WHERE key = 'ndf_loans'";
        var storedLoans = await loansCommand.ExecuteScalarAsync() as string;
        if (storedLoans is not null && JsonNode.Parse(storedLoans) is JsonArray loans)
        {
            var highestId = loans
                .Select(loan => (string?)loan?["id"])
                .Select(id => System.Text.RegularExpressions.Regex.Match(id ?? "", @"^ND-(\d{1,10})$"))
                .Where(match => match.Success && long.TryParse(match.Groups[1].Value, out var n) && n is >= 1L and < 10_000_000_000L)
                .Select(match => long.Parse(match.Groups[1].Value))
                .DefaultIfEmpty(0L)
                .Max();
            if (highestId >= counter)
                counter = highestId + 1;
        }
    }

    var nextCounter = counter < 10_000_000_000L ? counter + 1 : counter;
    await using var update = connection.CreateCommand();
    update.Transaction = transaction;
    update.CommandText = """
        INSERT INTO storage (key, value, updated_at) VALUES ('ndf_counter', $value, $updatedAt)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """;
    update.Parameters.AddWithValue("$value", nextCounter.ToString());
    update.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O"));
    await update.ExecuteNonQueryAsync();
    transaction.Commit();
    return new { id = $"ND-{counter:D5}", counter = nextCounter };
}

static async Task MigrateLegacyUsersAsync(string connectionString)
{
    var legacy = await GetStorageValueAsync(connectionString, "ndf_users");
    if (legacy is null) return;
    var users = JsonSerializer.Deserialize<List<LegacyUser>>(
        legacy, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? [];
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    await using var count = connection.CreateCommand();
    count.CommandText = "SELECT COUNT(*) FROM auth_users";
    if (Convert.ToInt32(await count.ExecuteScalarAsync()) > 0) return;
    foreach (var user in users)
    {
        if (string.Equals(user.Username, "ND@TOP", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(user.Username) || string.IsNullOrWhiteSpace(user.Email) ||
            string.IsNullOrWhiteSpace(user.Password)) continue;
        var profile = new UserProfile(user.Username, user.ShopName ?? "", user.OwnerName ?? "",
            user.ShopLogo ?? "", user.Mobile ?? "", NormalizeEmail(user.Email), user.City ?? "", false);
        await using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT OR IGNORE INTO auth_users (username, email, password_hash, is_owner, email_verified, profile_json, created_at)
            VALUES ($username, $email, $hash, 0, 1, $profile, $created)
            """;
        insert.Parameters.AddWithValue("$username", user.Username);
        insert.Parameters.AddWithValue("$email", NormalizeEmail(user.Email));
        insert.Parameters.AddWithValue("$hash", AuthSecurity.NormalizeLegacyPasswordHash(user.Password));
        insert.Parameters.AddWithValue("$profile", JsonSerializer.Serialize(profile));
        insert.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
        try { await insert.ExecuteNonQueryAsync(); }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19) { }
    }
    await SetStorageValueAsync(connectionString, "ndf_users", "[]");
}

static async Task BootstrapOwnerAsync(string connectionString, ILogger logger)
{
    var username = Environment.GetEnvironmentVariable("NDF_ADMIN_USERNAME")?.Trim();
    var password = Environment.GetEnvironmentVariable("NDF_ADMIN_PASSWORD");
    var rawEmail = Environment.GetEnvironmentVariable("NDF_ADMIN_EMAIL");

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    await using var count = connection.CreateCommand();
    count.CommandText = "SELECT COUNT(*) FROM auth_users WHERE is_owner = 1";
    if (Convert.ToInt32(await count.ExecuteScalarAsync()) > 0) return;

    if (string.IsNullOrWhiteSpace(username) && string.IsNullOrWhiteSpace(password) &&
        string.IsNullOrWhiteSpace(rawEmail))
    {
        logger.LogInformation("No initial owner is configured; create the first owner from the local website.");
        return;
    }

    var email = NormalizeEmail(rawEmail);
    if (string.IsNullOrWhiteSpace(username) || username.Length is < 3 or > 40 ||
        !username.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.') ||
        string.IsNullOrEmpty(password) || password.Length < 12 || password.Length > 256 ||
        !IsValidEmail(email))
        throw new InvalidOperationException("The initial owner bootstrap configuration is incomplete or invalid.");

    await using var insert = connection.CreateCommand();
    insert.CommandText = """
        INSERT INTO auth_users (username, email, password_hash, is_owner, email_verified, profile_json, created_at)
        VALUES ($username, $email, $hash, 1, 1, $profile, $created)
        ON CONFLICT(username) DO NOTHING
        """;
    insert.Parameters.AddWithValue("$username", username);
    insert.Parameters.AddWithValue("$email", email);
    insert.Parameters.AddWithValue("$hash", AuthSecurity.HashPassword(password));
    insert.Parameters.AddWithValue("$profile", JsonSerializer.Serialize(
        new UserProfile(username, "ND Finance", "ND Finance Owner", "", "", email, "Owner Account", true, "Owner", null)));
    insert.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
    await insert.ExecuteNonQueryAsync();
}

record StorageValue(string Value);
record BackupData(JsonElement Users, JsonElement Loans, JsonElement Counter, JsonElement Shop);
record RegisterRequest(string? Username, string? Password, string? Email, string? ShopName,
    string? OwnerName, string? ShopLogo, string? Mobile, string? City, string? Membership = null);
record LoginRequest(string? Username, string? Password);
record MfaLoginRequest(string? ChallengeId, string? Code);
record ResetRequest(string? UsernameOrEmail);
record ResetPasswordRequest(string? UsernameOrEmail, string? Code, string? NewPassword);
record LocalPasswordResetRequest(string? UsernameOrEmail, string? NewPassword);
record ProfileRequest(string? ShopName, string? OwnerName, string? ShopLogo, string? Mobile, string? City);
record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);
record MfaEnableRequest(string? Code);
record MfaDisableRequest(string? Password, string? Code);
record UserProfile(string Username, string ShopName, string OwnerName, string ShopLogo,
    string Mobile, string Email, string City, bool IsOwner, string Membership = "Silver",
    decimal? MaxPrincipal = 5_000_000m);
record MembershipPlan(string Name, decimal? MaxPrincipal);
record LoanMergeResult(bool HasIdConflict, bool HasInvalidAmount, bool LimitExceeded,
    decimal ActivePrincipal, decimal? MaximumPrincipal);
record UserRecord(string Username, string Email, string PasswordHash, bool IsOwner,
    bool EmailVerified, UserProfile Profile, int FailedAttempts, string? LockedUntil, string? MfaSecret);
record SessionUser(string Username, string Email, bool IsOwner, UserProfile Profile, string? MfaSecret, string ExpiresAt);
record MfaChallenge(UserRecord User);
record LegacyUser(string? Username, string? Password, string? ShopName, string? OwnerName,
    string? ShopLogo, string? Mobile, string? Email, string? City);
