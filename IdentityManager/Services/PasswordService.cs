using IdentityManager.Data;
using IdentityManager.DTOs;
using IdentityManager.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityManager.Services
{
    public class PasswordService : IPasswordService
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly ApplicationDbContext context;
        private readonly ITokenRevocationService tokenRevocationService;
        private readonly IEmailService emailService;
        //private readonly ILogger<PasswordService> _logger;

        public PasswordService(UserManager<IdentityUser> _userManager, ApplicationDbContext _context, ITokenRevocationService _tokenRevocationService, IEmailService _emailService)
        {
            userManager = _userManager;
            context = _context;
            tokenRevocationService = _tokenRevocationService;
            emailService = _emailService;
            //emailService = _emailService;
            //logger = _logger;
        }

        public async Task<ServiceResult<ChangePasswordResponseDto>> ChangePasswordAsync(string userId, string currentPassword, string newPassword, bool revokeAllTokens)
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<ChangePasswordResponseDto>.Fail("User not found");
            }


            var isCurrentPasswordValid = await userManager.CheckPasswordAsync(user, currentPassword);
            if (!isCurrentPasswordValid)
            {
              return  ServiceResult<ChangePasswordResponseDto>.Fail("Current password incorrect");
            }

            if (newPassword == currentPassword)
            {
                return ServiceResult<ChangePasswordResponseDto>.Fail("New Password can't be the same current password");
            }


            var result = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ServiceResult<ChangePasswordResponseDto>.Fail($"Password changed failed : {errors}");
            }


            await userManager.GetSecurityStampAsync(user);

            int revokedTokensCount = 0;

            await tokenRevocationService.RevokeUserTokensAsync(userId, "Password Change");

            await emailService.SendPasswordChangedNotificationAsync(user.Email, user.UserName);

            var response = new ChangePasswordResponseDto { Success = true, Message = "Password changed successflly", RevokedTokensCount = revokedTokensCount };
            return ServiceResult<ChangePasswordResponseDto>.Ok(response);
        }


        public async Task<ServiceResult<bool>> ResetPasswordAsync(string email, string resetToken, string newPassword)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null) {
                return ServiceResult<bool>.Fail("Invalid User");
            }


            var decodedToken = Uri.UnescapeDataString(resetToken);

            var result =await userManager.ResetPasswordAsync(user, decodedToken, newPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ServiceResult<bool>.Fail(errors);
            }

            await userManager.UpdateSecurityStampAsync(user);

            await tokenRevocationService.RevokeUserTokensAsync(user.Id, "Reset password");

            await userManager.UpdateSecurityStampAsync(user);

            await emailService.SendPasswordResetConfirmationAsync(user.Email, user.UserName);


            return ServiceResult<bool>.Ok(true, "Password reset successflly");
        }

        public async Task<ServiceResult<string>> GeneratePasswordResetTokenAsync(string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return ServiceResult<string>.Fail("Invalid User");
            }

            var generatedPassword = await userManager.GeneratePasswordResetTokenAsync(user);

            await emailService.SendPasswordResetEmailAsync(user.Email, user.UserName, generatedPassword);

            return ServiceResult<string>.Ok("","Check your email");
        }

        public async Task<ServiceResult<bool>> ValidatePasswordAsync(string userId, string password)
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<bool>.Fail("Invalid User");
            }

            var result = await userManager.CheckPasswordAsync(user, password);

            return ServiceResult<bool>.Ok(result);
        }
    }
}