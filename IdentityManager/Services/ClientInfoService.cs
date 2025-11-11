
using IdentityManager.Models;

namespace IdentityManager.Services
{

    public class ClientInfoService : IClientInfoService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<ClientInfoService> _logger;

        public ClientInfoService(IHttpContextAccessor httpContextAccessor,ILogger<ClientInfoService> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        /// <summary>
        /// Get client IP address with proper proxy/load balancer support
        /// </summary>
        public string GetClientIpAddress()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                _logger.LogWarning("HttpContext is null");
                return "Unknown";
            }

            try
            {
                // 1. Check X-Forwarded-For header (most common for proxies/load balancers)
                var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
                if (!string.IsNullOrEmpty(forwardedFor))
                {
                    // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                    // The first one is the original client IP
                    var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    if (ips.Length > 0)
                    {
                        var clientIp = ips[0].Trim();
                        if (IsValidIpAddress(clientIp))
                        {
                            _logger.LogDebug("IP from X-Forwarded-For: {IpAddress}", clientIp);
                            return clientIp;
                        }
                    }
                }

                // 2. Check X-Real-IP header (used by Nginx and some other proxies)
                var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(realIp) && IsValidIpAddress(realIp))
                {
                    _logger.LogDebug("IP from X-Real-IP: {IpAddress}", realIp);
                    return realIp;
                }

                // 3. Check CF-Connecting-IP (Cloudflare)
                var cfIp = httpContext.Request.Headers["CF-Connecting-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(cfIp) && IsValidIpAddress(cfIp))
                {
                    _logger.LogDebug("IP from CF-Connecting-IP: {IpAddress}", cfIp);
                    return cfIp;
                }

                // 4. Check True-Client-IP (Akamai and Cloudflare)
                var trueClientIp = httpContext.Request.Headers["True-Client-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(trueClientIp) && IsValidIpAddress(trueClientIp))
                {
                    _logger.LogDebug("IP from True-Client-IP: {IpAddress}", trueClientIp);
                    return trueClientIp;
                }

                // 5. Check X-Client-IP (less common)
                var clientIpHeader = httpContext.Request.Headers["X-Client-IP"].FirstOrDefault();
                if (!string.IsNullOrEmpty(clientIpHeader) && IsValidIpAddress(clientIpHeader))
                {
                    _logger.LogDebug("IP from X-Client-IP: {IpAddress}", clientIpHeader);
                    return clientIpHeader;
                }

                // 6. Fallback to RemoteIpAddress (direct connection)
                var remoteIp = httpContext.Connection.RemoteIpAddress;
                if (remoteIp != null)
                {
                    // Handle IPv6 localhost
                    if (remoteIp.ToString() == "::1")
                    {
                        _logger.LogDebug("IP is localhost (IPv6)");
                        return "127.0.0.1";
                    }

                    // Handle IPv4-mapped IPv6 addresses
                    if (remoteIp.IsIPv4MappedToIPv6)
                    {
                        var ipv4 = remoteIp.MapToIPv4().ToString();
                        _logger.LogDebug("IP from RemoteIpAddress (mapped IPv4): {IpAddress}", ipv4);
                        return ipv4;
                    }

                    var ip = remoteIp.ToString();
                    _logger.LogDebug("IP from RemoteIpAddress: {IpAddress}", ip);
                    return ip;
                }

                _logger.LogWarning("Could not determine client IP address");
                return "Unknown";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting client IP address");
                return "Unknown";
            }
        }

        /// <summary>
        /// Get User-Agent string
        /// </summary>
        public string GetUserAgent()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
                return "Unknown";

            return httpContext.Request.Headers["User-Agent"].FirstOrDefault() ?? "Unknown";
        }

        /// <summary>
        /// Get or generate Device ID
        /// Tries multiple sources in order of preference:
        /// 1. Custom X-Device-Id header (from client)
        /// 2. Generate fingerprint from User-Agent and other headers
        /// </summary>
        public string GetDeviceId()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
                return "Unknown";

            try
            {
                // 1. Check for custom device ID header sent by client
                var customDeviceId = httpContext.Request.Headers["X-Device-Id"].FirstOrDefault();
                if (!string.IsNullOrEmpty(customDeviceId) && IsValidDeviceId(customDeviceId))
                {
                    _logger.LogDebug("Device ID from X-Device-Id header: {DeviceId}", customDeviceId);
                    return SanitizeDeviceId(customDeviceId);
                }

                // 2. Generate device fingerprint from headers
                var deviceFingerprint = GenerateDeviceFingerprint(httpContext);
                _logger.LogDebug("Generated device fingerprint: {DeviceId}", deviceFingerprint);

                return deviceFingerprint;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device ID");
                return "Unknown";
            }
        }

        /// <summary>
        /// Get comprehensive client information
        /// </summary>
        public ClientInfo GetClientInfo()
        {
            var userAgent = GetUserAgent();

            return new ClientInfo
            {
                IpAddress = GetClientIpAddress(),
                DeviceId = GetDeviceId(),
                UserAgent = userAgent,
                Browser = ParseBrowser(userAgent),
                OperatingSystem = ParseOperatingSystem(userAgent),
                DeviceType = ParseDeviceType(userAgent),
                IsMobile = IsMobileDevice(userAgent)
            };
        }

        // ============================================
        // PRIVATE HELPER METHODS
        // ============================================

        private bool IsValidIpAddress(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            // Try to parse as IP address
            return System.Net.IPAddress.TryParse(ipAddress, out _);
        }

        private string ParseBrowser(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return "Unknown";

            if (userAgent.Contains("Edg/", StringComparison.OrdinalIgnoreCase))
                return "Edge";
            if (userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase))
                return "Chrome";
            if (userAgent.Contains("Safari", StringComparison.OrdinalIgnoreCase) &&
                !userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase))
                return "Safari";
            if (userAgent.Contains("Firefox", StringComparison.OrdinalIgnoreCase))
                return "Firefox";
            if (userAgent.Contains("MSIE", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("Trident", StringComparison.OrdinalIgnoreCase))
                return "Internet Explorer";
            if (userAgent.Contains("Opera", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("OPR", StringComparison.OrdinalIgnoreCase))
                return "Opera";

            return "Unknown";
        }

        private string ParseOperatingSystem(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return "Unknown";

            if (userAgent.Contains("Windows NT 10.0", StringComparison.OrdinalIgnoreCase))
                return "Windows 10/11";
            if (userAgent.Contains("Windows NT 6.3", StringComparison.OrdinalIgnoreCase))
                return "Windows 8.1";
            if (userAgent.Contains("Windows NT 6.2", StringComparison.OrdinalIgnoreCase))
                return "Windows 8";
            if (userAgent.Contains("Windows NT 6.1", StringComparison.OrdinalIgnoreCase))
                return "Windows 7";
            if (userAgent.Contains("Windows", StringComparison.OrdinalIgnoreCase))
                return "Windows";
            if (userAgent.Contains("Mac OS X", StringComparison.OrdinalIgnoreCase))
                return "macOS";
            if (userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase))
                return "Android";
            if (userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase))
                return "iOS";
            if (userAgent.Contains("Linux", StringComparison.OrdinalIgnoreCase))
                return "Linux";

            return "Unknown";
        }

        private string ParseDeviceType(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return "Unknown";

            if (userAgent.Contains("Mobile", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase))
                return "Mobile";
            if (userAgent.Contains("Tablet", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase))
                return "Tablet";
            if (userAgent.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("Macintosh", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("Linux", StringComparison.OrdinalIgnoreCase))
                return "Desktop";

            return "Unknown";
        }

        private bool IsMobileDevice(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return false;

            return userAgent.Contains("Mobile", StringComparison.OrdinalIgnoreCase) ||
                   userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase) ||
                   userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
                   userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Generate a device fingerprint based on User-Agent and other headers
        /// This creates a consistent identifier for the same device/browser combination
        /// </summary>
        private string GenerateDeviceFingerprint(HttpContext httpContext)
        {
            var userAgent = httpContext.Request.Headers["User-Agent"].FirstOrDefault() ?? "";
            var acceptLanguage = httpContext.Request.Headers["Accept-Language"].FirstOrDefault() ?? "";
            var acceptEncoding = httpContext.Request.Headers["Accept-Encoding"].FirstOrDefault() ?? "";
            var accept = httpContext.Request.Headers["Accept"].FirstOrDefault() ?? "";

            // Combine headers to create a unique fingerprint
            var fingerprintData = $"{userAgent}|{acceptLanguage}|{acceptEncoding}|{accept}";

            // Create SHA256 hash
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(fingerprintData));

            // Convert to base64 and make it URL-safe
            var fingerprint = Convert.ToBase64String(hashBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "")
                .Substring(0, 32); // Take first 32 chars for reasonable length

            return fingerprint;
        }

        /// <summary>
        /// Validate device ID format
        /// </summary>
        private bool IsValidDeviceId(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return false;

            // Check length (reasonable limits)
            if (deviceId.Length < 8 || deviceId.Length > 128)
                return false;

            // Allow alphanumeric, hyphens, and underscores only
            return deviceId.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
        }

        /// <summary>
        /// Sanitize device ID to remove potentially dangerous characters
        /// </summary>
        private string SanitizeDeviceId(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
                return "Unknown";

            // Remove any characters that aren't alphanumeric, hyphen, or underscore
            var sanitized = new string(deviceId
                .Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_')
                .ToArray());

            // Limit length
            const int maxLength = 100;
            if (sanitized.Length > maxLength)
                sanitized = sanitized.Substring(0, maxLength);

            return string.IsNullOrEmpty(sanitized) ? "Unknown" : sanitized;
        }
    }
}
    // ============================================
    // 4. EXTENSION METHOD (Alternative Approach)
    // ============================================

    public static class HttpContextExtensions
    {
        /// <summary>
        /// Extension method to get IP address directly from HttpContext
        /// </summary>
        public static string GetClientIpAddress(this HttpContext httpContext)
        {
            if (httpContext == null)
                return "Unknown";

            // Check forwarded headers
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (ips.Length > 0)
                {
                    var clientIp = ips[0].Trim();
                    if (System.Net.IPAddress.TryParse(clientIp, out _))
                        return clientIp;
                }
            }

            var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp) && System.Net.IPAddress.TryParse(realIp, out _))
                return realIp;

            var cfIp = httpContext.Request.Headers["CF-Connecting-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(cfIp) && System.Net.IPAddress.TryParse(cfIp, out _))
                return cfIp;

            // Fallback to remote IP
            var remoteIp = httpContext.Connection.RemoteIpAddress;
            if (remoteIp != null)
            {
                if (remoteIp.ToString() == "::1")
                    return "127.0.0.1";

                if (remoteIp.IsIPv4MappedToIPv6)
                    return remoteIp.MapToIPv4().ToString();

                return remoteIp.ToString();
            }

            return "Unknown";
        }
    }

    // ============================================
    // 5. USAGE EXAMPLES
    // ============================================





    // Example 3: Using in Middleware
    public class IpLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<IpLoggingMiddleware> _logger;

        public IpLoggingMiddleware(RequestDelegate next, ILogger<IpLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var ipAddress = context.GetClientIpAddress();
            _logger.LogInformation("Request from IP: {IpAddress}", ipAddress);

            await _next(context);
        }
    }

// ============================================
// 6. PROGRAM.CS REGISTRATION
// ============================================

/*
// In Program.cs

// Register the service
builder.Services.AddScoped<IClientInfoService, ClientInfoService>();

// Make sure HttpContextAccessor is registered
builder.Services.AddHttpContextAccessor();

// If behind proxy/load balancer (important!)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Add middleware (before UseRouting)
app.UseForwardedHeaders();
app.UseIpLoggingMiddleware(); // If using custom middleware
*/

// ============================================
// 7. TESTING DIFFERENT SCENARIOS
// ============================================

/*
DEVICE ID SCENARIOS:
====================

SCENARIO 1: Client Sends Custom Device ID
----------------------------------------
Headers: X-Device-Id: abc123-device-xyz
Result: Uses custom device ID from header
Example: "abc123-device-xyz"

SCENARIO 2: No Custom Device ID (Generate Fingerprint)
----------------------------------------
Headers: User-Agent, Accept-Language, Accept-Encoding, etc.
Result: Generates SHA256 fingerprint from headers
Example: "8f3d7b2a9c1e5f4d6a8b0c2e4f6a8b0d"

SCENARIO 3: Invalid Custom Device ID
----------------------------------------
Headers: X-Device-Id: "../../../etc/passwd" (malicious)
Result: Falls back to generated fingerprint
Example: "8f3d7b2a9c1e5f4d6a8b0c2e4f6a8b0d"

CLIENT-SIDE IMPLEMENTATION:
===========================

JavaScript Example (Web):
-------------------------
// Generate and store device ID
function getOrCreateDeviceId() {
    let deviceId = localStorage.getItem('deviceId');
    if (!deviceId) {
        deviceId = 'web-' + generateUUID();
        localStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        var v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Send with every request
fetch('/api/auth/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': getOrCreateDeviceId()
    },
    body: JSON.stringify(loginData)
});

Mobile App Example (Flutter):
------------------------------
import 'package:device_info_plus/device_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<String> getDeviceId() async {
  final prefs = await SharedPreferences.getInstance();
  String? deviceId = prefs.getString('device_id');
  
  if (deviceId == null) {
    final deviceInfo = DeviceInfoPlugin();
    if (Platform.isAndroid) {
      final androidInfo = await deviceInfo.androidInfo;
      deviceId = 'android-${androidInfo.id}';
    } else if (Platform.isIOS) {
      final iosInfo = await deviceInfo.iosInfo;
      deviceId = 'ios-${iosInfo.identifierForVendor}';
    }
    await prefs.setString('device_id', deviceId);
  }
  
  return deviceId;
}

IP ADDRESS SCENARIOS:
====================

SCENARIO 1: Direct Connection (No Proxy)
----------------------------------------
Result: Gets IP from HttpContext.Connection.RemoteIpAddress
Example: "192.168.1.100"

SCENARIO 2: Behind Nginx Proxy
----------------------------------------
Headers: X-Real-IP: 203.0.113.42
Result: Gets IP from X-Real-IP header
Example: "203.0.113.42"

SCENARIO 3: Behind Load Balancer
----------------------------------------
Headers: X-Forwarded-For: 203.0.113.42, 10.0.0.1, 10.0.0.2
Result: Gets first IP (client IP)
Example: "203.0.113.42"

SCENARIO 4: Behind Cloudflare
----------------------------------------
Headers: CF-Connecting-IP: 203.0.113.42
Result: Gets IP from CF-Connecting-IP
Example: "203.0.113.42"

SCENARIO 5: Local Development
----------------------------------------
Result: "127.0.0.1" or "::1" (converted to "127.0.0.1")

COMPLETE USAGE EXAMPLE:
========================

// In your Login/Register/Token Generation
var clientInfo = _clientInfoService.GetClientInfo();

var refreshToken = new RefreshToken
{
    UserId = user.Id,
    Token = GenerateSecureToken(),
    Expires = DateTime.UtcNow.AddDays(7),
    Created = DateTime.UtcNow,
    CreatedByIp = clientInfo.IpAddress,
    DeviceId = clientInfo.DeviceId,
    Device = clientInfo.DeviceType,
    UserAgent = clientInfo.UserAgent,
    IsUsed = false,
    IsRevoked = false
};
*/