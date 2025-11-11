using IdentityManager.Models;

namespace IdentityManager.Services
{
    public interface IClientInfoService
    {
        string GetClientIpAddress();
        string GetDeviceId();
        string GetUserAgent();
        ClientInfo GetClientInfo();
    }
}
