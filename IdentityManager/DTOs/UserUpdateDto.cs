using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class UserUpdateDto
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
    }
}