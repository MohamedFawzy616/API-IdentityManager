using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class CreateNewUserDto
    {
        [Required]
        [StringLength(100, MinimumLength = 3)]
        public string Name { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }


        [Required]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters.")]
        public string Password { get; set; }


        [Required]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        public List<string> Roles { get; set; } = new List<string>();
    }
}