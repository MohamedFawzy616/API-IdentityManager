using IdentityManager.Data;
using IdentityManager.Data.Repository;
using IdentityManager.Helpers;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityManager.Services
{
    public class TokenRevocationService : ITokenRevocationService
    {
        private readonly IClientInfoService clientInfo;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IRefreshTokenRepository refreshTokenRepository;

        public TokenRevocationService(IClientInfoService _clientInfo, UserManager<IdentityUser> UserManager, IRefreshTokenRepository RefreshTokenRepository)
        {
            userManager = UserManager;
            refreshTokenRepository = RefreshTokenRepository;
            clientInfo = _clientInfo;
        }


        public async Task<ServiceResult<bool>> RevokeTokenAsync(string refreshToken, string userId, string reason)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                return ServiceResult<bool>.Fail("Token is null or empty.");
            }


            var token = await refreshTokenRepository.GetByTokenAsync(refreshToken);
            if (token == null)
            {
                return ServiceResult<bool>.Fail("Invalid Token.");
            }
            if (token.UserId != userId)
            {
                return ServiceResult<bool>.Fail("Invalid Token.");
            }

            if (token.IsRevoked)
            {
                return ServiceResult<bool>.Fail("Token already Revoked.");
            }

            var IpAddress = clientInfo.GetClientIpAddress();

            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = IpAddress;
            token.RevokedReason = reason;

            await refreshTokenRepository.UpdateAsync(token);

            var user = await userManager.FindByIdAsync(token.UserId);
            if (user == null)
            {
                return ServiceResult<bool>.Fail("Invalid User.");
            }

            await userManager.UpdateSecurityStampAsync(user);

            return ServiceResult<bool>.Ok(true, "Token Revoked Successfully.");
        }

        public async Task<ServiceResult<int>> RevokeUserTokensAsync(string userId, string reason)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return ServiceResult<int>.Fail("Invalid User.");
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<int>.Fail("Invalid User.");
            }

            var tokens = await refreshTokenRepository.GetTokensByUserIdAsync(userId);

            if (tokens.Count == 0)
            {
                return ServiceResult<int>.Fail("No Active Token for This User.");
            }

            var ipAddress = clientInfo.GetClientIpAddress();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = ipAddress;
                token.RevokedReason = reason;

                await refreshTokenRepository.UpdateAsync(token);
            }

            await userManager.UpdateSecurityStampAsync(user);

            return ServiceResult<int>.Ok(tokens.Count, $"{tokens.Count} Tokens Revoked Successfully for this User.");
        }

        public async Task<ServiceResult<bool>> RevokeTokensByDeviceAsync(string userId, string deviceId, string reason)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return ServiceResult<bool>.Fail("Invalid user.");
            }

            if (string.IsNullOrEmpty(deviceId))
            {
                return ServiceResult<bool>.Fail("Invalid device Data.");
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<bool>.Fail("Invalid user.");
            }


            var token = await refreshTokenRepository.GetTokenByDeviceIdandUserIdAsync(userId, deviceId);
            if (token == null)
            {
                return ServiceResult<bool>.Fail("Invalid Token.");
            }

            if (token.UserId != userId)
            {
                return ServiceResult<bool>.Fail("Invalid Token.");
            }

            var IpAddress = clientInfo.GetClientIpAddress();

            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = IpAddress;
            token.RevokedReason = reason;

            await refreshTokenRepository.UpdateAsync(token);

            await userManager.UpdateSecurityStampAsync(user);

            return ServiceResult<bool>.Ok(true, $"Tokens Revoked Successfully for device {deviceId}.");
        }

        public async Task<ServiceResult<int>> RevokeExpiredTokensAsync()
        {
            var tokens = await refreshTokenRepository.GetExpiredTokensAsync();

            if (tokens == null)
            {
                return ServiceResult<int>.Fail("No Expire Token Found.");
            }

            var IpAddress = clientInfo.GetClientIpAddress();
            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = IpAddress;
                token.RevokedReason = "Expired Token";

                await refreshTokenRepository.UpdateAsync(token);
            }

            return ServiceResult<int>.Ok(tokens.Count, $"{tokens.Count} Has been Revoked Sucessfully.");
        }

        public async Task<ServiceResult<bool>> IsTokenRevokedAsync(string refreshToken)
        {
            var token = await refreshTokenRepository.GetByTokenAsync(refreshToken);

            if (token == null)
            {
                return ServiceResult<bool>.Fail("Invalid Token.");
            }

            var result = await refreshTokenRepository.IsTokenRevokedAsync(refreshToken);

            return ServiceResult<bool>.Ok(result);
        }

        public async Task<ServiceResult<List<RefreshToken>>> GetActiveSessions(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return ServiceResult<List<RefreshToken>>.Fail("Invalid User.");
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<List<RefreshToken>>.Fail("Invalid User.");
            }


            var activeSessions = await refreshTokenRepository.GetActiveSessions(userId);

            return ServiceResult<List<RefreshToken>>.Ok(activeSessions);
        }
    }
}