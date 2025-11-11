using IdentityManager.DTOs;
using IdentityManager.Helpers;

namespace IdentityManager.Services
{
    public interface IPasswordService
    {
        Task<ServiceResult<ChangePasswordResponseDto>> ChangePasswordAsync(string userId, string currentPassword, string newPassword, bool revokeAllTokens = true);
        Task<ServiceResult<bool>> ResetPasswordAsync(string email, string resetToken, string newPassword);
        Task<ServiceResult<string>> GeneratePasswordResetTokenAsync(string email);
        Task<ServiceResult<bool>> ValidatePasswordAsync(string userId, string password);
    }
}