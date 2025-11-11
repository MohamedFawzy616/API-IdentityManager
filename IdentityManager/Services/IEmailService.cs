namespace IdentityManager.Services
{
    public interface IEmailService
    {
        Task SendPasswordChangedNotificationAsync(string email, string userName);
        Task SendPasswordResetEmailAsync(string email, string userName, string resetToken);
        Task SendPasswordResetConfirmationAsync(string email, string userName);
    }
}
