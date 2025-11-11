using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class ResetPasswordRequestDto
    {
        [Required(ErrorMessage ="Email is required")]
        [EmailAddress(ErrorMessage ="Invalid email address")]
        public string Email { get;  set; }


        [Required(ErrorMessage ="Reset token is required")]
        public string ResetToken { get; set; }

        [Required(ErrorMessage ="New password is required")]
        [StringLength(100,MinimumLength =6,ErrorMessage ="Password must be at least 6 characters long")]
        public string NewPassword { get;  set; }



        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("NewPassword", ErrorMessage = "New password and confirmation password do not match")]
        public string ConfirmNewPassword { get; set; }
    }
}