using IdentityManager.Helpers;
using IdentityManager.Models;

namespace IdentityManager.Services
{
    public interface ITokenRevocationService
    {
        public Task<ServiceResult<bool>> RevokeTokenAsync(string refreshToken,string userId, string reason = null);
        public Task<ServiceResult<int>> RevokeUserTokensAsync(string userId, string reason = null);
        public Task<ServiceResult<bool>> RevokeTokensByDeviceAsync(string userId, string deviceId, string reason = null);
        public Task<ServiceResult<int>> RevokeExpiredTokensAsync();
        public Task<ServiceResult<bool>> IsTokenRevokedAsync(string refreshToken);
        public Task<ServiceResult<List<RefreshToken>>> GetActiveSessions(string userId);
    }
}