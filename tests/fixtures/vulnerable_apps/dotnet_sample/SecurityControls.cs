using System.Net.Security;
using System.Security.Cryptography;

public static class SecurityControls
{
    public static string ApiKey =>
        Environment.GetEnvironmentVariable("SERVICE_API_KEY") ?? throw new InvalidOperationException();

    public static string SafePath(string root, string requested)
    {
        var canonicalRoot = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(canonicalRoot, requested));
        if (!full.StartsWith(canonicalRoot, StringComparison.Ordinal))
            throw new UnauthorizedAccessException();
        return full;
    }

    public static bool ValidateCertificate(SslPolicyErrors errors) =>
        errors == SslPolicyErrors.None;

    public static string Token() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
}
