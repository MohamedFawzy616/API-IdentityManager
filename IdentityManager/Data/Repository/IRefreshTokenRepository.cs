using IdentityManager.Models;

namespace IdentityManager.Data.Repository
{
    public interface IRefreshTokenRepository
    {
        public Task<RefreshToken> AddAsync(RefreshToken refreshToken);
        public Task<RefreshToken> UpdateAsync(RefreshToken refreshToken);
        public Task<List<RefreshToken>> GetAllTokensAsync();
        public Task<RefreshToken> GetByTokenAsync(string token);
        public Task<List<RefreshToken>> GetTokensByUserIdAsync(string userId);
        public Task<RefreshToken> GetTokenByDeviceIdandUserIdAsync(string userId, string deviceId);
        public Task<List<RefreshToken>> GetExpiredTokensAsync();
        public Task<bool> IsTokenRevokedAsync(string token);
        public Task<List<RefreshToken>> GetActiveSessions(string userId);
    }
}