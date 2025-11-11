using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class ForgotPasswordRequestDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }
    }
}