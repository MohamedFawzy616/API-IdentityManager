using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class ValidatePasswordDto
    {
        [Required]
        public string Password { get; set; }
    }
}
