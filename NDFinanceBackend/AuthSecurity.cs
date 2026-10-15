using System.Security.Cryptography;
using System.Text;

static class AuthSecurity
{
    public const string CookieName = "ndf_session";
    private const int PasswordIterations = 600_000;
    public static readonly string DummyPasswordHash = HashPassword(RandomToken(32));

    public static bool IsSmtpConfigured =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NDF_SMTP_HOST")) &&
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NDF_SMTP_FROM"));

    public static bool IsPepperConfigured => TryGetPepper(out _);

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, PasswordIterations, HashAlgorithmName.SHA256, 32);
        return $"$pbkdf2${PasswordIterations}${Convert.ToHexString(salt).ToLowerInvariant()}${Convert.ToHexString(hash).ToLowerInvariant()}";
    }

    public static bool VerifyPassword(string password, string stored, out bool needsUpgrade)
    {
        needsUpgrade = false;
        if (stored.StartsWith("$pbkdf2$", StringComparison.Ordinal))
        {
            var parts = stored.Split('$');
            if (parts.Length != 5 ||
                !int.TryParse(parts[2], out var iterations) || iterations is < 10_000 or > 2_000_000)
                return false;
            try
            {
                var salt = Convert.FromHexString(parts[3]);
                var expected = Convert.FromHexString(parts[4]);
                var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
                needsUpgrade = iterations < PasswordIterations || salt.Length < 16;
                return CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            catch (FormatException) { return false; }
        }

        if (stored.StartsWith("$sha256$", StringComparison.Ordinal))
        {
            var actual = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            needsUpgrade = true;
            return FixedTimeEquals(Convert.ToHexString(actual).ToLowerInvariant(), stored[8..]);
        }

        if (stored.Length == 64 && stored.All(Uri.IsHexDigit))
        {
            var actual = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            needsUpgrade = true;
            return FixedTimeEquals(Convert.ToHexString(actual), stored.ToUpperInvariant());
        }

        return false;
    }

    public static string NormalizeLegacyPasswordHash(string legacy)
    {
        if (legacy.StartsWith("$pbkdf2$", StringComparison.Ordinal)) return legacy;
        if (legacy.Length == 64 && legacy.All(Uri.IsHexDigit)) return "$sha256$" + legacy.ToLowerInvariant();
        return HashPassword(legacy);
    }

    public static string HashCode(string email, string purpose, string code)
    {
        var input = Encoding.UTF8.GetBytes($"{email}\n{purpose}\n{code}");
        return Convert.ToHexString(HMACSHA256.HashData(GetPepper(), input)).ToLowerInvariant();
    }

    public static string ProtectSecret(string secret)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(secret);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(GetPepper(), tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return Convert.ToBase64String([.. nonce, .. tag, .. ciphertext]);
    }

    public static string UnprotectSecret(string protectedSecret)
    {
        var payload = Convert.FromBase64String(protectedSecret);
        if (payload.Length < 28) throw new CryptographicException("Protected authenticator secret is invalid.");
        var plaintext = new byte[payload.Length - 28];
        using var aes = new AesGcm(GetPepper(), 16);
        aes.Decrypt(payload.AsSpan(0, 12), payload.AsSpan(28), payload.AsSpan(12, 16), plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
               CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    public static string RandomToken(int bytes)
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string TokenHash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    public static CookieOptions CookieOptions(bool secure, DateTimeOffset? expires = null) => new()
    {
        HttpOnly = true,
        Secure = secure,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expires,
        MaxAge = expires is null ? null : expires.Value - DateTimeOffset.UtcNow
    };

    public static string GenerateTotpSecret()
    {
        return Base32Encode(RandomNumberGenerator.GetBytes(20));
    }

    public static bool VerifyTotp(string secret, string code)
    {
        if (code.Length != 6 || !code.All(char.IsAsciiDigit)) return false;
        byte[] key;
        try { key = Base32Decode(secret); }
        catch (FormatException) { return false; }
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var offset = -1; offset <= 1; offset++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, now + offset);
            var hash = HMACSHA1.HashData(key, counter);
            var index = hash[^1] & 0x0f;
            var binary = ((hash[index] & 0x7f) << 24) |
                         ((hash[index + 1] & 0xff) << 16) |
                         ((hash[index + 2] & 0xff) << 8) |
                         (hash[index + 3] & 0xff);
            var expected = (binary % 1_000_000).ToString("D6");
            if (FixedTimeEquals(expected, code)) return true;
        }
        return false;
    }

    private static byte[] GetPepper()
    {
        if (!TryGetPepper(out var pepper))
            throw new InvalidOperationException("NDF_AUTH_PEPPER must be configured as a base64-encoded random key of at least 32 bytes.");
        return pepper;
    }

    private static bool TryGetPepper(out byte[] pepper)
    {
        pepper = [];
        var configured = Environment.GetEnvironmentVariable("NDF_AUTH_PEPPER");
        if (string.IsNullOrWhiteSpace(configured)) return false;
        try
        {
            pepper = Convert.FromBase64String(configured);
            return pepper.Length >= 32;
        }
        catch (FormatException) { return false; }
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                result.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) result.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return result.ToString();
    }

    private static byte[] Base32Decode(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new List<byte>();
        var buffer = 0;
        var bits = 0;
        foreach (var character in value.TrimEnd('=').ToUpperInvariant())
        {
            var digit = alphabet.IndexOf(character);
            if (digit < 0) throw new FormatException("Invalid base32 value.");
            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits >= 8)
            {
                result.Add((byte)((buffer >> (bits - 8)) & 255));
                bits -= 8;
            }
        }
        return result.ToArray();
    }
}
