using IdentityManager.Models;
using Microsoft.Extensions.Options;
using MimeKit;

namespace IdentityManager.Services
{
    public class EmailService : IEmailService
    {
        private readonly SmtpSettings _smtpSettings;
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, IOptions<SmtpSettings> smtpSettings, ILogger<EmailService> logger)
        {
            _logger = logger;
            _smtpSettings = smtpSettings.Value;
            _configuration = configuration;
        }

        public async Task SendPasswordChangedNotificationAsync(string email, string userName)
        {
            var subject = "Password Changed Successfully";
            var body = $@"
            <h2>Password Changed</h2>
            <p>Hello {userName},</p>
            <p>Your password has been changed successfully.</p>
            <p>If you did not make this change, please contact support immediately.</p>
            <p>Best regards,<br/>Your App Team</p>
        ";

            await SendEmailAsync(email, subject, body,true);
        }

        public async Task SendPasswordResetEmailAsync(string email, string userName, string resetToken)//---
        {
            var resetUrl = $"{_configuration["AppUrl"]}/reset-password?token={Uri.EscapeDataString(resetToken)}&email={Uri.EscapeDataString(email)}";

            var subject = "Reset Your Password";
            var body = $@"
            <h2>Password Reset Request</h2>
            <p>Hello {userName},</p>
            <p>You requested to reset your password. Click the link below to reset it:</p>
            <p><a href='{resetUrl}'>Reset Password</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not request this, please ignore this email.</p>
            <p>Best regards,<br/>Your App Team</p>
        ";

            await SendEmailAsync(email, subject, body, true);
        }

        public async Task SendPasswordResetConfirmationAsync(string email, string userName)
        {
            var subject = "Password Reset Successful";
            var body = $@"
            <h2>Password Reset Successful</h2>
            <p>Hello {userName},</p>
            <p>Your password has been reset successfully.</p>
            <p>If you did not make this change, please contact support immediately.</p>
            <p>Best regards,<br/>Your App Team</p>
        ";

            await SendEmailAsync(email, subject, body,true);
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body, bool isHtml = false)
        {

            var host = _configuration.GetSection("SmtpSettings:Host").Value;
            var port = int.Parse(_configuration.GetSection("SmtpSettings:Port").Value);
            var username = _configuration.GetSection("SmtpSettings:Username").Value;
            var password = _configuration.GetSection("SmtpSettings:Password").Value;
            var fromEmail = _configuration.GetSection("SmtpSettings:FromEmail").Value;
            var fromName = _configuration.GetSection("SmtpSettings:FromName").Value;


            var email = new MimeMessage();
            email.From.Add(new MailboxAddress(fromName, fromEmail));
            email.To.Add(MailboxAddress.Parse(toEmail));
            email.Subject = subject;

            var builder = new BodyBuilder();
         
            if (isHtml)
                builder.HtmlBody = body;
            else
                builder.TextBody = body;

            email.Body = builder.ToMessageBody();

            using var smtp = new MailKit.Net.Smtp.SmtpClient();
            await smtp.ConnectAsync(host, port, MailKit.Security.SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(username, password);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }
    }
}