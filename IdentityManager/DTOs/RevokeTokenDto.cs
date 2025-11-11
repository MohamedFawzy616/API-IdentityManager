using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class RevokeTokenDto
    {
        [Required(ErrorMessage = "Token is required")]
        public string token { get; set; }
    }
}