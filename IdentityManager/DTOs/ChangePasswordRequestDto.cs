using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class ChangePasswordRequestDto
    {
        [Required(ErrorMessage = "Current password is required")]
        public string CurrentPassword { get; set; }

        //[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
        //    ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character")]
        [Required(ErrorMessage = "New Password is required")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("NewPassword", ErrorMessage = "New password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

        public bool RevokeAllTokens { get; set; } = true;
    }
}