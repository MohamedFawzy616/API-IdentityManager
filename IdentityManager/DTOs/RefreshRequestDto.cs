using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class RefreshRequestDto
    {
        [Required(ErrorMessage = "Token is required")]
        public string token { get; set; } = default!;
    }
}